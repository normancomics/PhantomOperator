'use strict';

/**
 * lib/elysium-billing.js
 *
 * Phase 1 Elysium USDC payment verifier (Chain ID 99901, eip155:99901).
 *
 * Security model:
 *  - Base-USDC x402 remains the primary default payment rail.
 *  - Elysium USDC (0xb47c4C8F73F009CC0C0d3f92B388d13E293F0B65, 6 decimals)
 *    is verified via quote-bound on-chain receipt verification + EIP-191 payer
 *    signature + SQLite WAL atomic replay protection.
 *  - Receiver is strictly PhantomOperator's operational wallet
 *    (0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6 via x402.PAY_TO).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { ethers } = require('ethers');
const x402 = require('./x402');

const ELYSIUM_CHAIN_ID = 99901;
const ELYSIUM_NETWORK = 'eip155:99901';
const ELYSIUM_USDC = '0xb47c4C8F73F009CC0C0d3f92B388d13E293F0B65';
const ELYSIUM_USDC_DECIMALS = 6;
const DEFAULT_ELYSIUM_RPC = 'https://rpc.elysium.kinetiq.xyz';
const QUOTE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const TRANSFER_IFACE = new ethers.Interface([
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);
const TRANSFER_TOPIC = TRANSFER_IFACE.getEvent('Transfer').topicHash;

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function requestHash(body) {
  return crypto.createHash('sha256').update(canonicalJson(body || {})).digest('hex');
}

function buildSigningMessage({ quoteId, txHash, routeId, reqHash }) {
  return [
    'PhantomOperator Elysium-USDC Payment',
    `network: ${ELYSIUM_NETWORK}`,
    `quoteId: ${quoteId}`,
    `txHash: ${String(txHash).toLowerCase()}`,
    `route: ${routeId}`,
    `requestHash: ${reqHash}`,
  ].join('\n');
}

function parsePaymentHeader(rawHeader) {
  if (!rawHeader || typeof rawHeader !== 'string') return null;
  const trimmed = rawHeader.trim();
  if (!trimmed || trimmed.length > 8192) return null;
  try {
    if (trimmed.startsWith('{')) return JSON.parse(trimmed);
    return JSON.parse(Buffer.from(trimmed, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

class ElysiumUsdcBilling {
  constructor(options = {}) {
    this.filename =
      options.filename ||
      process.env.ELYSIUM_PAYMENT_DB ||
      path.join(__dirname, '..', 'data', 'elysium-payments.sqlite');
    this.rpcUrl = options.rpcUrl || process.env.ELYSIUM_RPC_URL || DEFAULT_ELYSIUM_RPC;
    this.provider = options.provider || null;

    fs.mkdirSync(path.dirname(this.filename), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(this.filename);
    try {
      fs.chmodSync(this.filename, 0o600);
    } catch {
      /* platform dependent */
    }
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS elysium_quotes (
        quote_id TEXT PRIMARY KEY,
        route TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        payer TEXT NOT NULL,
        pay_to TEXT NOT NULL,
        asset TEXT NOT NULL,
        chain_id INTEGER NOT NULL,
        amount_atomic TEXT NOT NULL,
        price_usd REAL NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        redeemed_at INTEGER,
        tx_hash TEXT,
        log_index INTEGER
      );
      CREATE TABLE IF NOT EXISTS elysium_consumed_transfers (
        transfer_key TEXT PRIMARY KEY,
        quote_id TEXT NOT NULL UNIQUE,
        tx_hash TEXT NOT NULL,
        log_index INTEGER NOT NULL,
        payer TEXT NOT NULL,
        amount_atomic TEXT NOT NULL,
        claimed_at INTEGER NOT NULL
      );
    `);

    this.insertQuoteStmt = this.db.prepare(`
      INSERT INTO elysium_quotes (
        quote_id, route, request_hash, payer, pay_to, asset, chain_id,
        amount_atomic, price_usd, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    this.getQuoteStmt = this.db.prepare('SELECT * FROM elysium_quotes WHERE quote_id = ?');
    this.claimTransferStmt = this.db.prepare(`
      INSERT INTO elysium_consumed_transfers (
        transfer_key, quote_id, tx_hash, log_index, payer, amount_atomic, claimed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    this.markRedeemedStmt = this.db.prepare(`
      UPDATE elysium_quotes
      SET redeemed_at = ?, tx_hash = ?, log_index = ?
      WHERE quote_id = ? AND redeemed_at IS NULL
    `);
    this.deleteTransferClaimStmt = this.db.prepare(
      'DELETE FROM elysium_consumed_transfers WHERE transfer_key = ? AND quote_id = ?'
    );
    this.unmarkRedeemedStmt = this.db.prepare(
      'UPDATE elysium_quotes SET redeemed_at = NULL, tx_hash = NULL, log_index = NULL WHERE quote_id = ?'
    );
  }

  getProvider() {
    if (!this.provider) {
      this.provider = new ethers.JsonRpcProvider(this.rpcUrl, ELYSIUM_CHAIN_ID, {
        staticNetwork: true,
      });
    }
    return this.provider;
  }

  createQuote({ route, body, payer, baseUrl }) {
    if (!route || !route.id) throw new Error('Valid skill route is required.');
    if (!payer || typeof payer !== 'string') {
      throw new Error('payer (0x EVM address on Elysium) is required.');
    }
    let normalizedPayer;
    try {
      normalizedPayer = ethers.getAddress(payer.trim());
    } catch {
      throw new Error('payer must be a valid 0x EVM address.');
    }

    const payTo = ethers.getAddress(x402.PAY_TO);
    const asset = ethers.getAddress(ELYSIUM_USDC);
    const amountAtomic = x402.atomic(route.priceUsd);
    const reqHash = requestHash(body || {});
    const quoteId = crypto.randomUUID();
    const now = Date.now();
    const expiresAt = now + QUOTE_TTL_MS;

    this.insertQuoteStmt.run(
      quoteId,
      route.id,
      reqHash,
      normalizedPayer,
      payTo,
      asset,
      ELYSIUM_CHAIN_ID,
      amountAtomic,
      Number(route.priceUsd),
      now,
      expiresAt
    );

    return {
      quoteId,
      paymentMethod: 'elysium-usdc',
      network: ELYSIUM_NETWORK,
      chainId: ELYSIUM_CHAIN_ID,
      rpcUrl: this.rpcUrl,
      asset,
      symbol: 'USDC',
      decimals: ELYSIUM_USDC_DECIMALS,
      payTo,
      payer: normalizedPayer,
      amountAtomic,
      amountUsd: Number(route.priceUsd).toFixed(2),
      route: route.id,
      targetPath: route.path,
      requestHash: reqHash,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
      redemptionInstructions: {
        step1: `Transfer ${Number(route.priceUsd).toFixed(2)} USDC (${amountAtomic} atomic units) of ${asset} on Elysium (chainId ${ELYSIUM_CHAIN_ID}) from ${normalizedPayer} to ${payTo}.`,
        step2: 'Sign the redemption message below with personal_sign (EIP-191) using the payer wallet.',
        step3: `POST ${baseUrl || ''}${route.path} with the exact same JSON body, header "X-Payment-Method: elysium-usdc", and header "X-Payment" set to base64 or JSON of {"quoteId","txHash","signature"}.`,
        signingMessageTemplate: buildSigningMessage({
          quoteId,
          txHash: '<0x_YOUR_ELYSIUM_TX_HASH>',
          routeId: route.id,
          reqHash,
        }),
      },
    };
  }

  getQuoteStatus(quoteId) {
    const row = this.getQuoteStmt.get(String(quoteId || ''));
    if (!row) return null;
    const expired = !row.redeemed_at && Date.now() > row.expires_at;
    return {
      quoteId: row.quote_id,
      paymentMethod: 'elysium-usdc',
      network: ELYSIUM_NETWORK,
      chainId: row.chain_id,
      route: row.route,
      payer: row.payer,
      payTo: row.pay_to,
      asset: row.asset,
      amountAtomic: row.amount_atomic,
      priceUsd: row.price_usd,
      requestHash: row.request_hash,
      status: row.redeemed_at ? 'redeemed' : expired ? 'expired' : 'pending',
      createdAt: new Date(row.created_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
      redeemedAt: row.redeemed_at ? new Date(row.redeemed_at).toISOString() : null,
      txHash: row.tx_hash || null,
    };
  }

  async verifyForRequest(rawPaymentHeader, route, body) {
    const proof = parsePaymentHeader(rawPaymentHeader);
    if (!proof || typeof proof !== 'object') {
      return {
        ok: false,
        status: 402,
        message:
          'X-Payment header required with {"quoteId","txHash","signature"} for X-Payment-Method: elysium-usdc.',
      };
    }

    const { quoteId, txHash, signature } = proof;
    if (!quoteId || typeof quoteId !== 'string') {
      return { ok: false, status: 402, message: 'Missing quoteId in Elysium payment header.' };
    }
    if (!txHash || typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash.trim())) {
      return { ok: false, status: 402, message: 'Valid 32-byte 0x txHash is required.' };
    }
    if (!signature || typeof signature !== 'string') {
      return { ok: false, status: 402, message: 'EIP-191 payer signature is required.' };
    }

    const normalizedTxHash = txHash.trim().toLowerCase();
    const quote = this.getQuoteStmt.get(quoteId.trim());
    if (!quote) {
      return { ok: false, status: 402, message: 'Elysium payment quote not found.' };
    }
    if (quote.redeemed_at) {
      return { ok: false, status: 409, message: 'Elysium payment quote already redeemed.' };
    }
    if (Date.now() > quote.expires_at) {
      return { ok: false, status: 402, message: 'Elysium payment quote has expired.' };
    }
    if (quote.route !== route.id) {
      return { ok: false, status: 402, message: 'Elysium quote route does not match requested skill.' };
    }

    const reqHash = requestHash(body || {});
    if (quote.request_hash !== reqHash) {
      return {
        ok: false,
        status: 402,
        message: 'Request body does not match the body bound to this Elysium quote.',
      };
    }

    const expectedMsg = buildSigningMessage({
      quoteId: quote.quote_id,
      txHash: normalizedTxHash,
      routeId: route.id,
      reqHash,
    });
    let recovered;
    try {
      recovered = ethers.getAddress(ethers.verifyMessage(expectedMsg, signature.trim()));
    } catch {
      return { ok: false, status: 402, message: 'Invalid EIP-191 signature in Elysium payment proof.' };
    }
    if (recovered !== quote.payer) {
      return {
        ok: false,
        status: 402,
        message: 'Signature signer does not match the quote payer address.',
      };
    }

    let receipt;
    let block;
    let tipBlock;
    try {
      const provider = this.getProvider();
      receipt = await provider.getTransactionReceipt(normalizedTxHash);
      if (!receipt) {
        return {
          ok: false,
          status: 402,
          message: 'Elysium transaction receipt not found yet on chain.',
        };
      }
      if (Number(receipt.status) !== 1) {
        return { ok: false, status: 402, message: 'Elysium transaction reverted on chain.' };
      }
      [block, tipBlock] = await Promise.all([
        provider.getBlock(receipt.blockNumber),
        provider.getBlockNumber(),
      ]);
    } catch (err) {
      return {
        ok: false,
        status: 502,
        message: `Elysium RPC verification error: ${err.message}`,
      };
    }

    const minConfirmations = Math.max(1, Number(process.env.ELYSIUM_MIN_CONFIRMATIONS || 1));
    const confirmations = Math.max(0, Number(tipBlock) - Number(receipt.blockNumber) + 1);
    if (confirmations < minConfirmations) {
      return {
        ok: false,
        status: 402,
        message: `Elysium transaction has ${confirmations} confirmations; ${minConfirmations} required.`,
      };
    }

    // Reject stale transactions mined more than 60s before quote creation
    if (block && Number(block.timestamp) > 0) {
      const minTimestampSec = Math.floor(quote.created_at / 1000) - 60;
      if (Number(block.timestamp) < minTimestampSec) {
        return {
          ok: false,
          status: 402,
          message: 'Elysium transaction predates this payment quote.',
        };
      }
    }

    const requiredAmount = BigInt(quote.amount_atomic);
    const expectedAsset = quote.asset.toLowerCase();
    let matchedLog = null;

    for (const log of receipt.logs || []) {
      if (!log || String(log.address || '').toLowerCase() !== expectedAsset) continue;
      if (!Array.isArray(log.topics) || log.topics[0] !== TRANSFER_TOPIC) continue;
      try {
        const parsed = TRANSFER_IFACE.parseLog({ topics: log.topics, data: log.data });
        if (!parsed) continue;
        const from = ethers.getAddress(parsed.args.from);
        const to = ethers.getAddress(parsed.args.to);
        const value = BigInt(parsed.args.value);
        if (from === quote.payer && to === quote.pay_to && value >= requiredAmount) {
          matchedLog = {
            logIndex: Number(log.index ?? log.logIndex ?? 0),
            from,
            to,
            value: value.toString(),
          };
          break;
        }
      } catch {
        /* ignore malformed log */
      }
    }

    if (!matchedLog) {
      return {
        ok: false,
        status: 402,
        message: `No matching Elysium USDC Transfer(${quote.payer} -> ${quote.pay_to}, >= ${quote.amount_atomic}) found in transaction receipt.`,
      };
    }

    const transferKey = `${normalizedTxHash}:${matchedLog.logIndex}`;
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.claimTransferStmt.run(
        transferKey,
        quote.quote_id,
        normalizedTxHash,
        matchedLog.logIndex,
        quote.payer,
        matchedLog.value,
        now
      );
      const updated = this.markRedeemedStmt.run(
        now,
        normalizedTxHash,
        matchedLog.logIndex,
        quote.quote_id
      );
      if (updated.changes !== 1) {
        this.db.exec('ROLLBACK');
        return { ok: false, status: 409, message: 'Elysium payment quote already redeemed.' };
      }
      this.db.exec('COMMIT');
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* already closed */
      }
      if (String(err.message || '').includes('UNIQUE')) {
        return {
          ok: false,
          status: 409,
          message: 'Elysium USDC transfer has already been used for a request.',
        };
      }
      return { ok: false, status: 500, message: `Payment ledger error: ${err.message}` };
    }

    return {
      ok: true,
      settlement: {
        quoteId: quote.quote_id,
        transferKey,
        txHash: normalizedTxHash,
        logIndex: matchedLog.logIndex,
        network: ELYSIUM_NETWORK,
        chainId: ELYSIUM_CHAIN_ID,
        asset: quote.asset,
        payer: quote.payer,
        payTo: quote.pay_to,
        amountAtomic: matchedLog.value,
        confirmations,
      },
    };
  }

  unclaim(quoteId, transferKey) {
    if (!quoteId || !transferKey) return;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.deleteTransferClaimStmt.run(String(transferKey), String(quoteId));
      this.unmarkRedeemedStmt.run(String(quoteId));
      this.db.exec('COMMIT');
    } catch {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* ignore */
      }
    }
  }
}

module.exports = {
  ELYSIUM_CHAIN_ID,
  ELYSIUM_NETWORK,
  ELYSIUM_USDC,
  ELYSIUM_USDC_DECIMALS,
  DEFAULT_ELYSIUM_RPC,
  ElysiumUsdcBilling,
  buildSigningMessage,
  requestHash,
};

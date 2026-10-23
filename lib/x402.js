'use strict';

const { constants, utils } = require('ethers');
const DEFAULT_PAY_TO = '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NETWORK = 'eip155:8453';
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function atomic(usd) {
  const micros = usd * 1e6;
  if (typeof usd !== 'number' || !Number.isFinite(usd) || !Number.isSafeInteger(Math.round(micros)) || Math.round(micros) < 1 || Math.abs(micros - Math.round(micros)) > 1e-8) throw new Error('Invalid USDC price: use positive whole micro-USDC');
  return String(Math.round(micros));
}

function bazaar(route) {
  return {
    info: {
      input: { type: 'http', method: 'POST', bodyType: 'json', body: route.inputExample },
      output: { type: 'json', example: route.outputExample },
    },
    schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object',
      properties: {
        input: { type: 'object', properties: {
          type: { type: 'string', const: 'http' }, method: { type: 'string', const: 'POST' },
          bodyType: { type: 'string', const: 'json' }, body: route.bodySchema,
        }, required: ['type', 'method', 'bodyType', 'body'], additionalProperties: false },
        output: { type: 'object', properties: { type: { type: 'string', const: 'json' }, example: { type: 'object' } }, required: ['type', 'example'], additionalProperties: false },
      }, required: ['input', 'output'], additionalProperties: false,
    },
  };
}

function createPaymentClient({ fetchImpl = (...args) => fetch(...args), payTo = process.env.PAY_TO || process.env.PAYMENT_RECEIVER_ADDRESS || DEFAULT_PAY_TO, facilitatorUrl = process.env.FACILITATOR_URL || 'https://facilitator.payai.network' } = {}) {
  const receiver = utils.getAddress(payTo);
  if (receiver === constants.AddressZero) throw new Error('Payment receiver must be a nonzero Ethereum address');
  const facilitatorBase = new URL(facilitatorUrl);
  if (facilitatorBase.protocol !== 'https:' || facilitatorBase.username || facilitatorBase.password || facilitatorBase.search || facilitatorBase.hash) throw new Error('FACILITATOR_URL must be an HTTPS URL without credentials or query');
  const facilitator = facilitatorBase.href.replace(/\/$/, '');
  function requirements(route) {
    return { scheme: 'exact', network: NETWORK, amount: atomic(route.priceUsd), asset: USDC_BASE, payTo: receiver, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } };
  }
  function paymentRequired(route, base, error = 'Payment required') {
    return {
      x402Version: 2, error,
      resource: { url: base + route.path, description: route.description, mimeType: 'application/json', serviceName: 'PhantomOperator', tags: route.tags || ['privacy', 'opsec', route.path.split('/').pop()], iconUrl: base + '/icon.svg' },
      accepts: [requirements(route)], extensions: { bazaar: bazaar(route) },
    };
  }
  async function callFacilitator(operation, payload, route) {
    const response = await fetchImpl(`${facilitator}/${operation}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ x402Version: 2, paymentPayload: payload, paymentRequirements: requirements(route) }), signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error('Facilitator HTTP error');
    if (Number(response.headers?.get('content-length') || 0) > 262144) throw new Error('Facilitator response too large');
    let result;
    if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      const chunks = []; let bytes = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes > 262144) { await reader.cancel(); throw new Error('Facilitator response too large'); }
          chunks.push(Buffer.from(value));
        }
      } finally { reader.releaseLock(); }
      result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } else {
      result = await response.json();
    }
    if (!object(result)) throw new Error('Malformed facilitator response');
    return result;
  }
  async function verify(req, route, base) {
    const deny = error => { const body = paymentRequired(route, base, error); return { ok: false, status: 402, body, headers: { 'PAYMENT-REQUIRED': b64(body) } }; };
    const header = req.headers['payment-signature'] || req.headers['x-payment'];
    if (!header) return deny('Payment required');
    let payload;
    try {
      if (typeof header !== 'string' || header.length > 32768 || !/^[A-Za-z0-9+/]+={0,2}$/.test(header)) throw new Error('Malformed header');
      payload = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
      if (!object(payload) || payload.x402Version !== 2 || !object(payload.payload) || !object(payload.accepted)) throw new Error('Malformed payload');
      const selected = payload.accepted;
      const offer = requirements(route);
      if (selected.scheme !== offer.scheme || selected.network !== offer.network || selected.amount !== offer.amount ||
          typeof selected.asset !== 'string' || selected.asset.toLowerCase() !== offer.asset.toLowerCase() ||
          typeof selected.payTo !== 'string' || selected.payTo.toLowerCase() !== offer.payTo.toLowerCase() ||
          selected.maxTimeoutSeconds !== offer.maxTimeoutSeconds) throw new Error('Payment requirements do not match this resource');
      if (selected.extra !== undefined) {
        if (!object(selected.extra)) throw new Error('Invalid payment extras');
        if (selected.extra.assetTransferMethod !== undefined && selected.extra.assetTransferMethod !== 'eip3009') throw new Error('Unsupported transfer method');
        if (selected.extra.paymentFlow !== undefined && selected.extra.paymentFlow !== 'authorization') throw new Error('Unsupported payment flow');
      }
      if (payload.extensions !== undefined && !object(payload.extensions)) throw new Error('Invalid payment extensions');
      if (payload.resource !== undefined && (!object(payload.resource) || payload.resource.url !== base + route.path)) throw new Error('Resource mismatch');
    } catch { return deny('Malformed payment header'); }
    try {
      const result = await callFacilitator('verify', payload, route);
      if (typeof result.isValid !== 'boolean') throw new Error('Malformed verification response');
      if (!result.isValid) return deny(typeof result.invalidReason === 'string' ? result.invalidReason.slice(0, 256) : 'Invalid payment');
      return { ok: true, payload };
    } catch { return { ok: false, status: 502, body: { error: 'Facilitator verification unavailable; no payment was settled by this request' }, headers: {} }; }
  }
  async function settle(payload, route) {
    try {
      const result = await callFacilitator('settle', payload, route);
      if (typeof result.success !== 'boolean') throw new Error('Malformed settlement response');
      if (!result.success && result.errorReason === 'settlement_pending') {
        return { ok: false, status: 502, body: { error: 'Settlement is pending. Check your wallet and the transaction before retrying.', code: 'SETTLEMENT_PENDING', transaction: /^0x[0-9a-fA-F]{64}$/.test(result.transaction || '') ? result.transaction : null, network: result.network === NETWORK ? NETWORK : null } };
      }
      if (!result.success) return { ok: false, status: 402, body: { error: 'Settlement failed', reason: typeof result.errorReason === 'string' ? result.errorReason.slice(0, 256) : 'Payment was not accepted' } };
      if (result.network !== NETWORK || !/^0x[0-9a-fA-F]{64}$/.test(result.transaction || '')) throw new Error('Settlement receipt is incomplete');
      const receipt = { success: true, transaction: result.transaction, network: result.network };
      if (typeof result.payer === 'string' && /^0x[0-9a-fA-F]{40}$/.test(result.payer)) receipt.payer = result.payer;
      return { ok: true, receipt, headers: { 'PAYMENT-RESPONSE': b64(receipt), 'X-PAYMENT-RESPONSE': b64(receipt) } };
    } catch { return { ok: false, status: 502, body: { error: 'Settlement could not be confirmed. Check your wallet before retrying.' } }; }
  }
  return { PAY_TO: receiver, FACILITATOR: facilitator, USDC_BASE, NETWORK, atomic, requirements, paymentRequired, verify, settle };
}
module.exports = { ...createPaymentClient(), createPaymentClient, bazaar };

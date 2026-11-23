#!/usr/bin/env node
'use strict';

/**
 * Read-only Elysium -> Base $PHNTMOP Migration Reconciliation Checker.
 *
 * Verifies:
 *   1. Elysium PHNTMOP balance held by MigrationLockbox >= lockbox.totalLocked()
 *   2. lockbox.totalLocked() >= BasePhntmop.totalSupply()
 *   3. BasePhntmop.totalSupply() <= 1,000,000,000e18 (MAX_SUPPLY)
 *   4. Every Base MigrationMinted(elysiumDepositId, recipient, amount) event
 *      reconciles 1:1 to a unique, finalized Elysium DepositLocked event.
 *
 * Modes:
 *   node scripts/reconcile-migration.js --self-test
 *   node scripts/reconcile-migration.js --elysium-lockbox 0x... --base-token 0x... [--min-confirmations 12]
 */

const assert = require('node:assert/strict');
const { ethers } = require('ethers');

const MAX_SUPPLY = 1_000_000_000n * 10n ** 18n;
const DEFAULT_ELYSIUM_RPC = process.env.ELYSIUM_RPC_URL || 'https://rpc.elysium.kinetiq.xyz';
const DEFAULT_BASE_RPC = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const DEFAULT_ELYSIUM_TOKEN = '0x3156C23C07a88Eb91049DfA97106823E8e418BA3';

const LOCKBOX_ABI = [
    'function token() view returns (address)',
    'function totalLocked() view returns (uint256)',
    'function nextNonce() view returns (uint256)',
    'event DepositLocked(bytes32 indexed depositId, uint256 indexed nonce, address indexed depositor, address baseRecipient, uint256 amount)'
];

const ERC20_ABI = [
    'function balanceOf(address account) view returns (uint256)',
    'function totalSupply() view returns (uint256)'
];

const BASE_PHNTMOP_ABI = [
    'function totalSupply() view returns (uint256)',
    'function migrationSafe() view returns (address)',
    'function migrationClosed() view returns (bool)',
    'function processedDeposit(bytes32 depositId) view returns (bool)',
    'event MigrationMinted(bytes32 indexed elysiumDepositId, address indexed recipient, uint256 amount)'
];

function reconcileSnapshot({
    elysiumLockboxBalance,
    elysiumTotalLocked,
    baseTotalSupply,
    deposits,
    mints
}) {
    const errors = [];
    const depositMap = new Map();
    let sumDeposits = 0n;

    for (const d of deposits) {
        const id = d.depositId.toLowerCase();
        const recipient = ethers.getAddress(d.baseRecipient);
        const amount = BigInt(d.amount);
        if (depositMap.has(id)) {
            errors.push(`Duplicate Elysium depositId observed: ${d.depositId}`);
        }
        depositMap.set(id, {
            depositId: d.depositId,
            nonce: BigInt(d.nonce),
            depositor: ethers.getAddress(d.depositor),
            baseRecipient: recipient,
            amount,
            txHash: d.txHash || null,
            blockNumber: d.blockNumber ?? null
        });
        sumDeposits += amount;
    }

    const seenMints = new Set();
    let sumMints = 0n;
    const unmatchedMints = [];

    for (const m of mints) {
        const id = m.elysiumDepositId.toLowerCase();
        const recipient = ethers.getAddress(m.recipient);
        const amount = BigInt(m.amount);

        if (seenMints.has(id)) {
            errors.push(`Duplicate Base MigrationMinted for depositId: ${m.elysiumDepositId}`);
        }
        seenMints.add(id);
        sumMints += amount;

        const matchingDeposit = depositMap.get(id);
        if (!matchingDeposit) {
            unmatchedMints.push(m.elysiumDepositId);
            errors.push(`Unbacked Base mint for unknown Elysium depositId: ${m.elysiumDepositId}`);
            continue;
        }
        if (matchingDeposit.baseRecipient !== recipient) {
            errors.push(
                `Recipient mismatch for depositId ${m.elysiumDepositId}: Elysium=${matchingDeposit.baseRecipient} Base=${recipient}`
            );
        }
        if (matchingDeposit.amount !== amount) {
            errors.push(
                `Amount mismatch for depositId ${m.elysiumDepositId}: Elysium=${matchingDeposit.amount} Base=${amount}`
            );
        }
    }

    const lockboxBalance = BigInt(elysiumLockboxBalance);
    const totalLocked = BigInt(elysiumTotalLocked);
    const baseSupply = BigInt(baseTotalSupply);

    if (lockboxBalance < totalLocked) {
        errors.push(`Elysium lockbox token balance (${lockboxBalance}) < lockbox.totalLocked (${totalLocked})`);
    }
    if (totalLocked !== sumDeposits) {
        errors.push(`lockbox.totalLocked (${totalLocked}) != sum of DepositLocked events (${sumDeposits})`);
    }
    if (baseSupply !== sumMints) {
        errors.push(`Base totalSupply (${baseSupply}) != sum of MigrationMinted events (${sumMints})`);
    }
    if (totalLocked < baseSupply) {
        errors.push(`Collateral shortfall: lockbox.totalLocked (${totalLocked}) < Base totalSupply (${baseSupply})`);
    }
    if (baseSupply > MAX_SUPPLY) {
        errors.push(`Base totalSupply (${baseSupply}) exceeds MAX_SUPPLY (${MAX_SUPPLY})`);
    }

    const pendingDeposits = [];
    for (const [id, d] of depositMap.entries()) {
        if (!seenMints.has(id)) {
            pendingDeposits.push(d);
        }
    }

    return {
        ok: errors.length === 0,
        invariants: {
            lockboxBalanceCoversTotalLocked: lockboxBalance >= totalLocked,
            totalLockedMatchesDepositEvents: totalLocked === sumDeposits,
            baseSupplyMatchesMintEvents: baseSupply === sumMints,
            lockedCoversMinted: totalLocked >= baseSupply,
            baseSupplyWithinCap: baseSupply <= MAX_SUPPLY,
            allMintsBackedOneToOne: unmatchedMints.length === 0 && errors.length === 0
        },
        totals: {
            elysiumLockboxBalance: lockboxBalance.toString(),
            elysiumTotalLocked: totalLocked.toString(),
            baseTotalSupply: baseSupply.toString(),
            pendingUnmintedLocked: (totalLocked - baseSupply).toString(),
            depositCount: deposits.length,
            mintCount: mints.length,
            pendingDepositCount: pendingDeposits.length
        },
        pendingDeposits: pendingDeposits.map((d) => ({
            depositId: d.depositId,
            nonce: d.nonce.toString(),
            depositor: d.depositor,
            baseRecipient: d.baseRecipient,
            amount: d.amount.toString()
        })),
        errors
    };
}

function runSelfTest() {
    const dep1 = ethers.id('deposit-1');
    const dep2 = ethers.id('deposit-2');
    const alice = '0x00000000000000000000000000000000000A11cE';
    const bob = '0x0000000000000000000000000000000000000B0b';

    const validReport = reconcileSnapshot({
        elysiumLockboxBalance: 300n * 10n ** 18n,
        elysiumTotalLocked: 300n * 10n ** 18n,
        baseTotalSupply: 100n * 10n ** 18n,
        deposits: [
            { depositId: dep1, nonce: 0n, depositor: alice, baseRecipient: bob, amount: 100n * 10n ** 18n },
            { depositId: dep2, nonce: 1n, depositor: alice, baseRecipient: bob, amount: 200n * 10n ** 18n }
        ],
        mints: [
            { elysiumDepositId: dep1, recipient: bob, amount: 100n * 10n ** 18n }
        ]
    });
    assert.equal(validReport.ok, true, 'valid reconciliation snapshot should pass');
    assert.equal(validReport.totals.pendingDepositCount, 1);

    const unbackedReport = reconcileSnapshot({
        elysiumLockboxBalance: 100n * 10n ** 18n,
        elysiumTotalLocked: 100n * 10n ** 18n,
        baseTotalSupply: 100n * 10n ** 18n,
        deposits: [
            { depositId: dep1, nonce: 0n, depositor: alice, baseRecipient: bob, amount: 100n * 10n ** 18n }
        ],
        mints: [
            { elysiumDepositId: ethers.id('forged-deposit'), recipient: bob, amount: 100n * 10n ** 18n }
        ]
    });
    assert.equal(unbackedReport.ok, false, 'unbacked mint must fail reconciliation');

    const shortfallReport = reconcileSnapshot({
        elysiumLockboxBalance: 100n * 10n ** 18n,
        elysiumTotalLocked: 100n * 10n ** 18n,
        baseTotalSupply: 150n * 10n ** 18n,
        deposits: [
            { depositId: dep1, nonce: 0n, depositor: alice, baseRecipient: bob, amount: 100n * 10n ** 18n }
        ],
        mints: [
            { elysiumDepositId: dep1, recipient: bob, amount: 150n * 10n ** 18n }
        ]
    });
    assert.equal(shortfallReport.ok, false, 'amount mismatch & shortfall must fail reconciliation');

    console.log(JSON.stringify({ selfTest: 'passed', sampleValidReport: validReport }, null, 2));
}

async function runLiveCheck(args) {
    const getArg = (flag, fallback = null) => {
        const idx = args.indexOf(flag);
        return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : fallback;
    };

    const lockboxAddr = getArg('--elysium-lockbox');
    const baseTokenAddr = getArg('--base-token');
    const fromElysiumBlock = Number(getArg('--elysium-from-block', '0'));
    const fromBaseBlock = Number(getArg('--base-from-block', '0'));
    const minConfirmations = Number(getArg('--min-confirmations', '12'));

    if (!lockboxAddr || !baseTokenAddr) {
        console.error(
            'Usage: node scripts/reconcile-migration.js --self-test OR --elysium-lockbox <0x...> --base-token <0x...>'
        );
        process.exit(2);
    }

    const elysiumProvider = new ethers.JsonRpcProvider(DEFAULT_ELYSIUM_RPC);
    const baseProvider = new ethers.JsonRpcProvider(DEFAULT_BASE_RPC);

    const elysiumTip = await elysiumProvider.getBlockNumber();
    const safeElysiumBlock = Math.max(0, elysiumTip - minConfirmations);

    const lockbox = new ethers.Contract(lockboxAddr, LOCKBOX_ABI, elysiumProvider);
    const tokenAddr = await lockbox.token();
    if (tokenAddr.toLowerCase() !== DEFAULT_ELYSIUM_TOKEN.toLowerCase()) {
        throw new Error(`Lockbox token mismatch: expected ${DEFAULT_ELYSIUM_TOKEN}, got ${tokenAddr}`);
    }
    const elysiumToken = new ethers.Contract(tokenAddr, ERC20_ABI, elysiumProvider);
    const baseToken = new ethers.Contract(baseTokenAddr, BASE_PHNTMOP_ABI, baseProvider);

    const [lockboxBalance, totalLocked, baseTotalSupply, depositLogs, mintLogs] = await Promise.all([
        elysiumToken.balanceOf(lockboxAddr, { blockTag: safeElysiumBlock }),
        lockbox.totalLocked({ blockTag: safeElysiumBlock }),
        baseToken.totalSupply(),
        lockbox.queryFilter(lockbox.filters.DepositLocked(), fromElysiumBlock, safeElysiumBlock),
        baseToken.queryFilter(baseToken.filters.MigrationMinted(), fromBaseBlock, 'latest')
    ]);

    const deposits = depositLogs.map((l) => ({
        depositId: l.args.depositId,
        nonce: l.args.nonce,
        depositor: l.args.depositor,
        baseRecipient: l.args.baseRecipient,
        amount: l.args.amount,
        txHash: l.transactionHash,
        blockNumber: l.blockNumber
    }));

    const mints = mintLogs.map((l) => ({
        elysiumDepositId: l.args.elysiumDepositId,
        recipient: l.args.recipient,
        amount: l.args.amount,
        txHash: l.transactionHash,
        blockNumber: l.blockNumber
    }));

    const report = reconcileSnapshot({
        elysiumLockboxBalance: lockboxBalance,
        elysiumTotalLocked: totalLocked,
        baseTotalSupply,
        deposits,
        mints
    });

    console.log(JSON.stringify({ safeElysiumBlock, minConfirmations, ...report }, null, 2));
    if (!report.ok) {
        process.exit(1);
    }
}

if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.includes('--self-test')) {
        runSelfTest();
    } else {
        runLiveCheck(args).catch((err) => {
            console.error(err.message || err);
            process.exit(1);
        });
    }
}

module.exports = { reconcileSnapshot };

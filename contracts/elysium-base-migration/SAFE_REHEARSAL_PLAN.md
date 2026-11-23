# PHNTMOP migration Safe and rehearsal plan

**Status:** preparation only. Do not execute mainnet deployments, create liquidity, or move user funds from this document.

## Intended Safe configuration

Create a dedicated migration Safe on the relevant chains with the owner-provided signers:

1. `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6`
2. `0x050f74E4591F9897FdB311C8150c07dFFfbEf5e1`
3. `0x3d95D4A6DbaE0Cd0643a82b13A13b08921D6ADf7`

Threshold: **2-of-3**.

Use a dedicated Safe for migration authority. Do not substitute a personal hot wallet, a single Bankr/OAuth login, or the Base-USDC x402 receiver for the Safe contract itself.

## Preconditions before a rehearsal

- Independent review scope is agreed and source revision is pinned.
- Existing Elysium token source/behavior and holder/custody context are independently verified.
- A migration window policy and confirmation/reorg policy are published.
- Elysium and Base deployment bytecode/source-verification commands are reviewed without broadcast.
- A read-only reconciliation tool/report format is ready.

## Owner-authorized rehearsal sequence

1. Deploy contracts to appropriate non-production environments, or run a tightly bounded mainnet rehearsal only after explicit owner authorization.
2. Configure the Base token's immutable `migrationSafe` as the actual 2-of-3 Safe address.
3. Use a small test amount of the real Elysium token only if authorized; otherwise use a mock/test environment.
4. Deposit through the Elysium lockbox with a known Base recipient.
5. Wait the published Elysium confirmation threshold.
6. Have two Safe signers independently verify the deposit event, recipient, amount, contract address, chain ID, and non-processed deposit ID.
7. Propose and execute one Base `mintForDeposit` Safe transaction.
8. Compare Elysium lockbox balance, lockbox `totalLocked`, Base `totalSupply`, processed deposit ID, and both transaction hashes.
9. Attempt a duplicate mint in the test environment and confirm rejection.
10. Publish the reconciliation evidence and owner-approved rehearsal conclusion.

## Stop conditions

Stop and do not activate migration if any of these occur:

- token source/behavior cannot be verified;
- Elysium event, amount, recipient, or chain ID mismatch;
- Base mint differs from locked amount;
- duplicate ID can be processed;
- Safe threshold/configuration is not exactly 2-of-3;
- a high/critical independent-review finding remains unresolved.

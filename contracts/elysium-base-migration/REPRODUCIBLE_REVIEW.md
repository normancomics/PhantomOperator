# Reproducible Community Smart-Contract Review Package (`$0`-Budget Gate)

This package lets any Solidity auditor or community reviewer reproduce the full verification suite for the Elysium → Base `$PHNTMOP` 1:1 lockbox-backed migration in under 3 minutes.

## 1. Frozen File Digests (163 Lines of Production Solidity)

Verify that your local checkout matches the frozen review candidate:

```bash
sha256sum \
  contracts/elysium-base-migration/src/MigrationLockbox.sol \
  contracts/elysium-base-migration/src/BasePhntmop.sol \
  contracts/elysium-base-migration/test/Migration.t.sol \
  scripts/reconcile-migration.js
```

Expected output:

```text
1b4ac8f1164250137cc3cd23d2047272936a622fe73f8d09f36513e1b53355fa  contracts/elysium-base-migration/src/MigrationLockbox.sol
d60853a9089d6c7818c92a8a04886d23c8a84525b2137d492ccd816975200d98  contracts/elysium-base-migration/src/BasePhntmop.sol
57ad4d80f8f5f41e4ec41e0e8a303b4f436a84a19ac83a484796ab347df0d2a5  contracts/elysium-base-migration/test/Migration.t.sol
4ad33515966ec075c4d9458d61d21b9682114e275510b7818ee4c971b5c03d8a  scripts/reconcile-migration.js
```

## 2. Live Elysium `$PHNTMOP` Token Verification (`Chain ID 99901`)

Anyone can verify the live Elysium token (`0x3156C23C07a88Eb91049DfA97106823E8e418BA3`) directly against the public Elysium RPC (`https://rpc.elysium.kinetiq.xyz`):

```bash
cast chain-id --rpc-url https://rpc.elysium.kinetiq.xyz
# 99901

cast call 0x3156C23C07a88Eb91049DfA97106823E8e418BA3 "name()(string)" --rpc-url https://rpc.elysium.kinetiq.xyz
# "Phantom Operator"

cast call 0x3156C23C07a88Eb91049DfA97106823E8e418BA3 "symbol()(string)" --rpc-url https://rpc.elysium.kinetiq.xyz
# "PHNTMOP"

cast call 0x3156C23C07a88Eb91049DfA97106823E8e418BA3 "totalSupply()(uint256)" --rpc-url https://rpc.elysium.kinetiq.xyz
# 1000000000000000000000000000 [1e27]

cast call 0x3156C23C07a88Eb91049DfA97106823E8e418BA3 "rewardHook()(address)" --rpc-url https://rpc.elysium.kinetiq.xyz
# 0x0000000000000000000000000000000000000000
```

## 3. Reproduce the Foundry Test & Fuzz Suite (10 Tests + Live Bytecode Etch)

```bash
cd contracts/elysium-base-migration
forge test -vvv
```

*(On NixOS, prefix with `NIX_PATH="nixpkgs=$(nix eval --raw nixpkgs#path)" forge test -vvv`.)*

Expected result (`10 passed, 0 failed`):
- `testEndToEndMigrationAndInvariants`
- `testFuzzMigrationPreservesOneToOneSupply(uint96)` (256 fuzz runs)
- `testLiveElysiumPhntmopBytecodeCompatibility` (etches the exact 2,186-byte Elysium `$PHNTMOP` runtime bytecode)
- `testLockboxBlocksReentrantTokenCallback`
- `testLockboxRejectsFalseReturningToken`
- `testLockboxRejectsFeeOnTransferShortfall`
- `testLockboxRejectsZeroAddressAndZeroAmount`
- `testOnlySafeCanMintAndCloseAndReplayIsBlocked`
- `testSafe2Of3GovernanceThresholdAndPermanentClosure`
- `testTransfersAndApprovalsWorkAfterMint`

## 4. Reproduce the Slither Static Analysis (`0 Findings Across 101 Detectors`)

```bash
cd contracts/elysium-base-migration
slither . --exclude-dependencies
```

Expected result:
`contracts/elysium-base-migration analyzed (3 contracts with 101 detectors), 0 result(s) found`

## 5. Reproduce the Cross-Chain Supply Reconciliation Self-Test

```bash
node scripts/reconcile-migration.js --self-test
```

Expected result:
`Self-test PASSED: all 7 reconciliation invariants verified.`

## 6. Reviewer Checklist (5 Key Questions)

1. **Irreversible Lockbox (`MigrationLockbox.sol`)**: Can any address (including signers or deployers) withdraw, sweep, upgrade, or unlock tokens once deposited?
2. **Collateral Invariant (`MigrationLockbox.sol`)**: Does `actualLocked >= lockedAfter` + `nonReentrant` prevent fee-on-transfer under-collateralization and reentrant deposit inflation?
3. **1:1 Cap & Replay Prevention (`BasePhntmop.sol`)**: Can `mintFromMigration(recipient, amount, elysiumDepositId)` ever mint beyond `MAX_SUPPLY` (`1,000,000,000e18`), mint to `address(0)`, mint `0`, or reuse a `processedDeposits[elysiumDepositId]`?
4. **Permanent Window Closure (`BasePhntmop.closeMigration()`)**: Once called by the 2-of-3 `migrationSafe`, is `migrationClosed` permanently and irreversibly `true`?
5. **Cross-Chain Reconciliation (`scripts/reconcile-migration.js`)**: Does the reconciliation script catch every mismatch between `DepositLocked` on Elysium and `MigrationMinted` on Base?

## 7. Ready-to-Share Community Review Post Template

You can paste the following invitation into GitHub Discussions, X (`@phntmop`), or Solidity auditor channels:

```text
Open Smart-Contract Review Invitation — PhantomOperator Elysium -> Base $PHNTMOP Migration

Scope: 163 lines of Solidity (0 dependencies, Solidity 0.8.24)
- MigrationLockbox.sol (62 lines, immutable one-way ERC-20 lockbox on Elysium 99901)
- BasePhntmop.sol (101 lines, 2-of-3 Safe-governed 1:1 capped ERC-20 on Base 8453 with permanent closeMigration())

Pre-audit baseline:
- 10/10 Foundry unit, fuzz, & live Elysium runtime-bytecode tests passing
- 0 Slither findings across 101 detectors
- Read-only cross-chain supply reconciliation CLI included

Repo & 3-minute reproducible review guide:
https://github.com/normancomics/PhantomOperator/blob/main/contracts/elysium-base-migration/REPRODUCIBLE_REVIEW.md
Security policy & attribution:
https://github.com/normancomics/PhantomOperator/blob/main/SECURITY.md
```

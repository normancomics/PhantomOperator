# External auditor brief — PHNTMOP Elysium → Base migration

## Objective

Review a proposed one-way, 1:1 migration for `$PHNTMOP` from Elysium (chain ID `99901`) to a separately deployed Base ERC-20 representation.

This is not a claim of a trustless cross-chain bridge. Base minting is authorized by a dedicated 2-of-3 migration Safe after signers verify Elysium lockbox deposits.

## Code under review

Repository: `https://github.com/normancomics/PhantomOperator`

Directory:

```text
contracts/elysium-base-migration/
```

Review must pin a specific Git commit and source hash before work begins. Do not review a moving branch.

## Components

1. `MigrationLockbox.sol` — deployed on Elysium. Locks only the existing Elysium `$PHNTMOP` token and emits a unique deposit event binding each deposit to a Base recipient.
2. `BasePhntmop.sol` — deployed on Base. Has a 1B maximum supply and allows `mintForDeposit` only from the configured migration Safe. It permanently rejects duplicate deposit IDs.
3. A standard Safe configured with the three owner-provided signer addresses at 2-of-3 threshold. Safe deployment/configuration is part of the operational review even if it is not in this source directory.

## Core invariants

- Base `totalSupply <= 1_000_000_000e18`.
- A Base mint cannot be executed by any caller other than the migration Safe.
- A given Elysium deposit ID can produce at most one Base mint.
- Lockbox accounting never exceeds actual Elysium token balance.
- Every Base mint must be publicly reconcilable to a finalized Elysium `DepositLocked` event.
- The lockbox has no arbitrary administrator withdrawal or upgrade pathway.

## Explicit trust boundary

There is no established on-chain Elysium light-client proof verifier on Base in this design. The 2-of-3 Safe is therefore an attestation authority. Review the risk of signer compromise, signer collusion, incorrect off-chain event verification, transaction replay, reorg handling, and public reconciliation gaps.

## Required review areas

- lockbox accounting and ERC-20 transfer edge cases;
- reentrancy and callback behavior;
- Safe/minter authorization and misconfiguration;
- supply-cap enforcement and deposit-ID replay resistance;
- chain ID/domain separation;
- Elysium finality/reorg policy and minimum confirmation guidance;
- operational monitoring/reconciliation design;
- deployment, source verification, and emergency communication plan;
- user-facing migration disclosure accuracy.

## Known limitations / required diligence

- Public Elysium explorer verification endpoints rate-limited during initial diligence. Existing Elysium token source/administrative behavior must be independently verified before deployment.
- The prototype assumes standard ERC-20 `transferFrom` semantics and verifies post-transfer collateral against aggregate accounting.
- The migration window remains undecided.
- No Base-USDC liquidity is in scope for this review. Any future pool is subject to a separate $250 maximum-loss policy and requires this review plus an authorized rehearsal.

## Existing internal checks

At the time of the internal pre-audit report, Foundry tests passed and Slither 0.11.5 reported zero findings. These are pre-flight checks only and are not a substitute for an independent manual review.

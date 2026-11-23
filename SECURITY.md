# Security Policy & Smart-Contract Review Program

PhantomOperator welcomes independent security review of both its web/API payment infrastructure and its staged Elysium → Base `$PHNTMOP` migration contracts.

## 1. Current Smart-Contract Review Gate (`$0`-Budget Community Review)

The Elysium → Base `$PHNTMOP` migration contracts (`163` lines of production Solidity across two files) are currently in **pre-deployment review**. Neither contract has been deployed to Elysium mainnet (`99901`) or Base mainnet (`8453`), and zero Base liquidity will be seeded until external review and a public 2-of-3 Safe rehearsal are completed.

- **Review bundle & reproduction commands**: [`contracts/elysium-base-migration/REPRODUCIBLE_REVIEW.md`](./contracts/elysium-base-migration/REPRODUCIBLE_REVIEW.md)
- **Public review tracking thread**: [`GitHub Issue #14`](https://github.com/normancomics/PhantomOperator/issues/14)
- **Auditor brief & threat model**: [`contracts/elysium-base-migration/EXTERNAL_AUDITOR_BRIEF.md`](./contracts/elysium-base-migration/EXTERNAL_AUDITOR_BRIEF.md)
- **Stage 1 pre-audit report (Foundry + Slither + bytecode disassembly)**: [`contracts/elysium-base-migration/PRE_AUDIT_2026-11-23.md`](./contracts/elysium-base-migration/PRE_AUDIT_2026-11-23.md)

### Scope

| Component | Path | Lines | SHA-256 |
|---|---|---:|---|
| Elysium Lockbox | `contracts/elysium-base-migration/src/MigrationLockbox.sol` | 62 | `1b4ac8f1164250137cc3cd23d2047272936a622fe73f8d09f36513e1b53355fa` |
| Base Mintable ERC-20 | `contracts/elysium-base-migration/src/BasePhntmop.sol` | 101 | `d60853a9089d6c7818c92a8a04886d23c8a84525b2137d492ccd816975200d98` |
| Foundry Test Suite | `contracts/elysium-base-migration/test/Migration.t.sol` | 325 | `57ad4d80f8f5f41e4ec41e0e8a303b4f436a84a19ac83a484796ab347df0d2a5` |
| Supply Reconciliation CLI | `scripts/reconcile-migration.js` | 212 | `4ad33515966ec075c4d9458d61d21b9682114e275510b7818ee4c971b5c03d8a` |

## 2. How to Report a Vulnerability or Submit a Review

- **Email**: `admin@freysaai.freysa.dev` (include `[SECURITY]` or `[CONTRACT-REVIEW]` in the subject line)
- **GitHub**: Open a private security advisory on `https://github.com/normancomics/PhantomOperator/security/advisories/new` or submit a public review note if no exploitable live vulnerability is involved.

Please include:
1. Affected file, contract, function, or API endpoint.
2. Commit hash and reproduction steps (or a failing Foundry test in `test/Migration.t.sol`).
3. Impact assessment (e.g., supply invariant violation, replay vector, lockbox accounting mismatch, payment bypass).

## 3. Rules of Engagement

- Only test against local Foundry instances or your own authorized targets.
- Do **not** perform denial-of-service testing, credential stuffing, or automated scanning of third-party websites through `https://freysaai.freysa.dev`.
- Never submit secrets, private keys, or unauthorized personal data.

## 4. Reviewer Attribution

All independent reviewers who submit a verified smart-contract review or valid security finding are credited in [`contracts/elysium-base-migration/PRE_AUDIT_2026-11-23.md`](./contracts/elysium-base-migration/PRE_AUDIT_2026-11-23.md) and the project release notes (unless anonymity is requested).

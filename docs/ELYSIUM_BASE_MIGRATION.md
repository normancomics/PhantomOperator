# Elysium → Base `$PHNTMOP` migration design

**Status:** design only — no contracts deployed, no liquidity created, and no funds moved.

## Purpose

Provide a transparent path for holders of the Elysium `$PHNTMOP` token to receive a Base representation without silently duplicating supply.

- **Elysium token:** `0x3156C23C07a88Eb91049DfA97106823E8e418BA3`
- **Elysium chain ID:** `99901`
- **Observed token metadata:** `Phantom Operator` / `PHNTMOP` / 18 decimals
- **Observed initial supply:** `1,000,000,000 PHNTMOP`
- **Observed initial mint:** block `7005680`, transaction `0xb6ee3bc3c80019fb274bbded305b4df8050fb85d343a54af6cca36366646720b`, to `0xd8bb9413ffabff303a8f85c42e00ce51cb15ba50`

## Why this is a migration, not a claim of one universal token

The deployed Elysium token does not expose a public `burn()` selector in its runtime dispatcher. A separately deployed Base ERC-20 would therefore be a distinct contract. It must never be described as automatically interchangeable with Elysium `$PHNTMOP` unless it is backed by locked Elysium tokens and a documented migration process.

## Recommended model: one-way lockbox-backed Base representation

### 1. Elysium migration lockbox

A minimal Elysium contract accepts deposits of the exact Elysium token after holder approval.

For each deposit it emits an immutable event containing:

- sequential `depositId`;
- Elysium depositor;
- intended Base recipient;
- exact amount;
- Elysium transaction/block reference.

Deposited tokens remain in the lockbox. There is no administrator withdrawal path to arbitrary wallets.

### 2. Base representation token

Deploy a separately-addressed Base ERC-20, clearly named as the Base representation in public documentation and its metadata.

Its bridge minter may mint only an amount that corresponds to a unique confirmed Elysium `depositId`. It must maintain:

```text
Base PHNTMOP minted <= Elysium PHNTMOP locked in the migration lockbox
```

No public mint function. No unrestricted owner minting. Each processed deposit ID is permanently marked used.

### 3. Attestation/execution

A fully trustless proof bridge requires a validated Elysium light-client/proof system on Base. That has not been established for this route.

Until such infrastructure is independently verified, the correct description is **multisig-attested migration**, not “trustless bridge.” Base mint operations should require threshold approval by a dedicated migration Safe, ideally 2-of-3 or stronger, with independent signers and hardware-wallet keys.

Every attestation should publish:

- `depositId`, Elysium transaction hash and block;
- Base mint transaction hash;
- amount and recipient;
- post-operation locked amount, Base issued amount, and variance (must equal zero).

### 4. Reconciliation and user verification

Publish a read-only migration status page/API that allows a user to check a deposit ID and independently compare:

- Elysium lockbox balance;
- Base representation total supply;
- processed Elysium deposit IDs;
- Base mint transaction.

The public interface must state confirmation requirements, the governance/attestation model, pause conditions, and support/contact route.

## Mandatory launch gates

Do not activate deposits, mint Base supply, or create a Base-USDC pool until all are complete:

1. Obtain and preserve verified source/bytecode evidence for the existing Elysium token.
2. Confirm control and legitimacy of the Elysium initial-holder/admin operational model.
3. Publish the migration ratio, eligibility, confirmation count, and whether migration is one-way or reversible.
4. Use a separate migration Safe; never use a hot wallet or a single Bankr/OAuth account as bridge authority.
5. Write unit, invariant, fuzz, integration, and replay-protection tests.
6. Obtain an independent smart-contract security review before mainnet activation.
7. Deploy verified source code on Elysium and Base.
8. Run a low-value, owner-authorized end-to-end test migration and reconcile the result.
9. Publish token addresses and a clear anti-impersonation notice before any liquidity is seeded.
10. Approve exact Base-USDC liquidity amount, fee tier, venue, and maximum loss budget separately. Liquidity is not part of the migration contract.

## Explicit non-features for v1

- No automatic two-way bridge.
- No anonymous relayer with unilateral mint authority.
- No claim that Base and Elysium contracts are the same asset before lock-and-mint backing exists.
- No token acceptance for PhantomOperator services until a reliable quote/settlement design exists.
- No Base-USDC liquidity pool creation without explicit capital authorization.

## Owner decisions recorded on 2026-11-23

- **Public Base asset name/ticker:** `$PHNTMOP`.
- **Migration ratio:** `1 Elysium PHNTMOP : 1 Base PHNTMOP`.
- **Proposed migration-Safe signers:**
  1. `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6` — PhantomOperator operational wallet.
  2. `0x050f74E4591F9897FdB311C8150c07dFFfbEf5e1` — Freysa EOA.
  3. `0x3d95D4A6DbaE0Cd0643a82b13A13b08921D6ADf7` — supplied as `normancomics.eth` signer address.

**Recorded migration-Safe threshold:** `2-of-3`. Any two of the listed signers must approve a migration mint; no signer can act alone.

**Recorded eligibility:** every Elysium `$PHNTMOP` holder is eligible for the one-way `1:1` migration.

**Recorded Base liquidity policy:** `$0` current budget; up to `$250 USDC` only after independent review, a successful owner-authorized migration rehearsal, and demonstrated product usage. Maximum acceptable loss is the full `$250`.

**Recorded migration window policy:** publish at least 30 days before activation; keep the one-way migration open for 180 days; allow an extension only through a 2-of-3 migration-Safe decision announced publicly at least 30 days before the prior window expires. After final closure, no new Base migration mints are permitted and final reconciliation must be published.

**Still required before implementation:** approve a named independent auditor/review process.

The signer addresses above are migration governance inputs only. They must not be substituted for the published Base-USDC x402 payment receiver or used to imply payment authorization.

## Current diligence evidence and limitations

Read-only RPC calls on 2026-11-23 verified chain ID, metadata, decimals, supply, runtime bytecode, and the initial `Transfer(0x0, recipient, 1B)` event. The public Elysium explorer rate-limited token verification lookups during this review; source verification and administrative controls remain unresolved until retried or independently obtained.

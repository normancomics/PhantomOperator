# Production dependency review

Reviewed on 2026-10-23 with Node 24.19.0 and npm 11.9.0. This review covers the
hosted `server.js` application and its deployment installation. npm advisory
counts describe affected packages, including propagated dependency findings;
they are not counts of independently exploitable vulnerabilities.

## Changes

- Upgrade Axios from 1.14.0 to 1.20.0 within its existing major version. The
  fixed-provider public search request uses Axios' HTTP adapter. The newer
  release also selects patched `form-data` and `follow-redirects` versions.
- Upgrade Ethers from 5.7.2 to 5.8.0, preserving the application's v5 APIs and
  replacing the old Elliptic signing dependency with 6.6.1.
- Override only `@ethersproject/providers@5.8.0`'s pinned `ws` dependency to
  8.21.0. This stays within WebSocket library major version 8 and fixes
  [GHSA-96hv-2xvq-fx4p](https://github.com/advisories/GHSA-96hv-2xvq-fx4p)
  and [GHSA-58qx-3vcg-4xpx](https://github.com/advisories/GHSA-58qx-3vcg-4xpx).
  Revisit this override when upgrading Ethers or its provider package.
- Move the legacy Superfluid SDK to `optionalDependencies`, alongside the
  Solana SDK. The hosted server and its tests do not import these SDKs or the
  legacy `PhantomOperatorCore` entry point. Render and CI install with
  `npm ci --omit=optional`; a full `npm ci` still installs the legacy tools.

The lockfile retains registry integrity hashes. No forced audit fix, Ethers
major-version migration, or dependency integrity bypass was used.

## Audit results

| Installation or graph | Critical | High | Moderate | Low |
| --- | ---: | ---: | ---: | ---: |
| Previous lock, `npm audit --omit=optional` (Superfluid was mandatory) | 32 | 23 | 49 | 8 |
| Updated production install, `npm audit --omit=optional` | 0 | 0 | 0 | 14 |
| Updated full graph, including optional legacy tools | 11 | 18 | 44 | 28 |

These are point-in-time npm registry results. GitHub may use different advisory
grouping or report the default branch until this change is merged. Retaining
the optional tooling does not resolve its remaining advisories.

CI checks the deployed dependency set with:

```sh
npm ci --omit=optional --no-audit --no-fund
npm audit --omit=optional --audit-level=moderate
npm test
```

The audit command fails CI for moderate, high, or critical production findings.
Its use of the public npm advisory service does not require application API
keys or wallet credentials.

## Remaining production finding

The 14 low findings propagate from Elliptic 6.6.1's
[GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84),
"Elliptic Uses a Cryptographic Primitive with a Risky Implementation."
Elliptic 6.6.1 was the latest published release at review time; npm recommends
a breaking Ethers major-version upgrade to remove this dependency.

The hosted application uses Ethers for address validation and constants. It
does not load wallet keys, sign ECDSA messages or transactions, or create RPC
providers as part of serving its three skills. Payment verification and
settlement go to the configured x402 facilitator. Ethers' root module still
loads the signing/provider modules into the dependency graph, so the finding
remains recorded rather than being dismissed as absent or universally
unreachable. Any future wallet, signature, or RPC functionality needs a new
review before relying on these assumptions.

The optional Superfluid/Solana tools retain additional advisories. They are
excluded from the hosted artifact and CI's production installation. Running
the legacy demo or Solana tooling requires a full installation and a separate
review of its dependency and wallet exposure.

## Verification

A fresh temporary copy installed the production artifact with
`npm ci --omit=optional`, adding 89 packages. The Superfluid, Solana, Truffle,
and Hardhat packages were absent. Verification passed:

- All 177 fixture and local HTTP tests against the production installation.
- All 30 discovery, health, and unpaid x402 checks against the actual
  `NODE_ENV=production npm start` process.
- A local request through Axios 1.20.0's real HTTP adapter using the search
  request configuration and HTML parser.
- Local Ethers 5.8.0 WebSocket-provider JSON-RPC round trips using the scoped
  `ws` 8.21.0 override.
- The production audit gate, with 0 moderate/high/critical findings.

The compatibility checks used local fixtures. They did not perform public
searches, sign messages, send funds, register identities, or deploy services.

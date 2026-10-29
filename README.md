# PhantomOperator

[![Live service](https://img.shields.io/badge/live-freysaai.freysa.dev-00b894?style=flat-square)](https://freysaai.freysa.dev/status)
[![x402](https://img.shields.io/badge/x402-Base%20native%20USDC-0052FF?style=flat-square)](https://freysaai.freysa.dev/.well-known/x402)
[![MCP](https://img.shields.io/badge/MCP-remote%20server-7C3AED?style=flat-square)](https://freysaai.freysa.dev/mcp)
[![A2A](https://img.shields.io/badge/A2A-agent%20card-FF6B35?style=flat-square)](https://freysaai.freysa.dev/.well-known/agent-card.json)
[![ERC--8004](https://img.shields.io/badge/ERC--8004-agent%20%23821239-627EEA?style=flat-square)](https://freysaai.freysa.dev/.well-known/agent-registration.json)
[![License](https://img.shields.io/badge/license-MIT-111827?style=flat-square)](LICENSE)

**PhantomOperator** is a pay-per-call privacy and public-exposure analysis service for authorized users and AI agents. It provides structured checks for web metadata leakage, public-web exposure, breach indicators, privacy posture, and wallet hygiene.

> **Authorization required:** Only assess URLs, identities, email addresses, wallets, and systems you own or are expressly authorized to assess. Do not submit seed phrases, passwords, API keys, or other secrets.

## Live service

**Service:** [https://freysaai.freysa.dev](https://freysaai.freysa.dev)

**Source:** [github.com/normancomics/PhantomOperator](https://github.com/normancomics/PhantomOperator)

**Updates:** [@phntmop on X](https://x.com/phntmop)

| Resource | URL |
| --- | --- |
| Human landing page | [/](/) |
| Agent quickstart | [/quickstart](https://freysaai.freysa.dev/quickstart) |
| Free illustrative report | [/sample-report](https://freysaai.freysa.dev/sample-report) |
| Free Monero address-decoding preview | `POST /demo/monero-decode` |
| OpenAPI 3.1 | [/openapi.json](https://freysaai.freysa.dev/openapi.json) |
| MCP endpoint | [/mcp](https://freysaai.freysa.dev/mcp) |
| x402 discovery | [/.well-known/x402](https://freysaai.freysa.dev/.well-known/x402) |
| A2A agent card | [/.well-known/agent-card.json](https://freysaai.freysa.dev/.well-known/agent-card.json) |
| ERC-8004 registration | [/.well-known/agent-registration.json](https://freysaai.freysa.dev/.well-known/agent-registration.json) |
| LLM guide | [/llms.txt](https://freysaai.freysa.dev/llms.txt) |
| Aggregate service telemetry | [/usage](https://freysaai.freysa.dev/usage) |
| Service status | [/status](https://freysaai.freysa.dev/status) |
| Terms and scope | [/terms](https://freysaai.freysa.dev/terms) |

## Payments

### Primary rail: Base native USDC via x402

Paid routes at `POST /skills/*` use x402 v2 exact payments.

| Field | Value |
| --- | --- |
| Network | Base mainnet, `eip155:8453` |
| Asset | Native Base USDC |
| USDC contract | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Payment receiver | `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6` |
| Production facilitator | Coinbase CDP x402 |
| ERC-8004 agent | `821239` |
| ERC-8004 identity registry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |

An unpaid valid request receives HTTP `402 Payment Required`. An x402-compatible client signs the stated payment requirement and retries the same request. Never send a plain ERC-20 transfer as a substitute for the x402 payment credential.

### Optional secondary rail: MPP Tempo OUSD

Equivalent routes are available at `POST /mpp/skills/*` through MPP with Tempo OUSD. This is a separate optional rail; it is **not** required to use Base USDC x402.

### Optional privacy rail: Monero invoices

A production Monero flow is included but is **disabled by default**. It requires a privately reachable, view-only `monero-wallet-rpc`, a fixed XMR/USD quote configuration, and a local proof secret. Once configured, a client:

1. requests `POST /billing/monero-quote` with `{ "skillId": "metadata-audit", "input": { ... } }`;
2. receives a unique wallet subaddress, exact atomic-XMR amount, expiry, and status URL;
3. pays the amount, then polls `GET /billing/monero-invoice/:invoiceId` until required confirmations are reached;
4. retries the requested skill with `X-Payment-Method: monero` and the returned `X-Payment` proof.

The service uses the view-only wallet RPC only to allocate subaddresses and verify incoming confirmed amounts. It never needs a Monero spend key. Configuration names are documented in [`.env.example`](.env.example).

## Available operations

The canonical schemas, payment requirements, and examples are generated at [`/openapi.json`](https://freysaai.freysa.dev/openapi.json). Prices are denominated in USDC and may be read from that document before payment.

| Operation | What it does | Base x402 price |
| --- | --- | ---: |
| `metadata-audit` | Reviews public HTTP headers, HTML metadata/comments, and third-party trackers for exposure signals. | $0.05 |
| `threat-scan` | Searches public-web results for potential PII exposure associated with an authorized identity. | $0.10 |
| `breach-check` | Checks an email against available breach intelligence and optionally performs a k-anonymity password-range check. | $0.10 |
| `opsec-score` | Produces a structured public-exposure score and prioritized mitigations. | $0.25 |
| `monero-opsec-audit` | Decodes a supplied Monero address and returns privacy-posture guidance. | $0.25 |
| `data-removal` | Identifies supported broker-removal paths and drafts a removal request; it does not submit requests without explicit authorization. | $0.50 |
| `spam-caller-removal` | Prepares official caller-ID unlisting and spam-label dispute steps; it does not submit requests. | $0.10 |
| `wallet-opsec-audit` | Reviews public Base/EVM wallet hygiene signals. | $0.50 |
| `full-privacy-sweep` | Combines relevant authorized checks into one report. | $1.00 |
| `cypherpunk-redteam-dossier` | Combines multiple authorized assessment modules. | $5.00 |
| `sovereign-opsec-retainer` | Produces an organization-level authorized assessment package. | $25.00 |

## Agent quickstart

1. Fetch [`/openapi.json`](https://freysaai.freysa.dev/openapi.json), [`/.well-known/x402`](https://freysaai.freysa.dev/.well-known/x402), or [`/mcp`](https://freysaai.freysa.dev/mcp).
2. Validate that the target and submitted information are authorized and non-sensitive.
3. Call the selected `POST /skills/<operation>` route with valid JSON.
4. On `402`, inspect the returned x402 requirement and retry using an x402-compatible Base-USDC client.
5. Validate the returned JSON against the published operation schema.

For MCP clients, send JSON-RPC 2.0 `initialize`, `tools/list`, and `tools/call` requests to `POST /mcp`. The paid-tool handoff returns the exact HTTP route and payment guidance.

## Local development

```bash
npm install
cp .env.example .env
npm test
npm start
```

The server defaults to port `3000`. Set `PUBLIC_BASE_URL` to the deployed HTTPS origin and use a protected `.env` file. See [`.env.example`](.env.example) for non-secret configuration names. Do not commit credentials, payment keys, private keys, or customer data.

## Deployment and discovery

The public service publishes OpenAPI, x402, A2A, ERC-8004, MCP, `llms.txt`, robots, and sitemap discovery documents. Its current distribution work includes ERC-8004, MPPScan, Global A2A Registry, Agent Tools, 402 Index, Coinbase Bazaar, and a Bankr skills pull request. A directory is only described as listed after acceptance is verifiable; indexes may crawl asynchronously.

## Privacy and telemetry

`/usage` displays aggregate settled-service telemetry. It intentionally excludes request bodies, raw IP addresses, customer wallets, and payment credentials. See [`TERMS.md`](TERMS.md) for the service scope and limits.

## License

MIT.

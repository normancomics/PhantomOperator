---
name: phantom-operator
description: Authorized privacy and public-exposure analysis through Base-USDC x402, optional MPP Tempo, MCP, and A2A discovery.
tags: [privacy, opsec, security, x402, base, mcp, a2a, erc-8004]
---

# PhantomOperator

PhantomOperator is a paid, machine-readable service for **authorized** privacy and public-exposure analysis. It is not a data-removal automation service, a financial service, or a substitute for legal/security advice.

## Start here

- Base URL: `https://freysaai.freysa.dev`
- Quickstart: `https://freysaai.freysa.dev/quickstart`
- OpenAPI: `https://freysaai.freysa.dev/openapi.json`
- x402 discovery: `https://freysaai.freysa.dev/.well-known/x402`
- MCP: `POST https://freysaai.freysa.dev/mcp`
- A2A card: `https://freysaai.freysa.dev/.well-known/agent-card.json`
- ERC-8004 agent ID: `821239`

## Payment rails

### Base USDC x402 (primary)

- Network: `eip155:8453` (Base mainnet)
- Native USDC: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
- Receiver: `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6`
- Flow: call `POST /skills/<id>`, inspect the HTTP 402 payment requirement, then retry using an x402-compatible payment credential.

### MPP Tempo (optional)

Equivalent operations are available at `POST /mpp/skills/<id>` using MPP Tempo OUSD. This is separate from Base x402.

### Monero invoices (optional, deployment-configured)

When enabled by the operator, obtain a unique subaddress quote at `POST /billing/monero-quote`, wait for confirmations, then use the issued proof with `X-Payment-Method: monero`. See the repository README for the exact flow and configuration prerequisites.

## Operations

| ID | Purpose | Base x402 price |
| --- | --- | ---: |
| `metadata-audit` | Public HTTP/HTML metadata, header, comment, and tracker review | $0.05 |
| `threat-scan` | Authorized public-web exposure scan | $0.10 |
| `breach-check` | Email breach indicators and optional k-anonymity password-range check | $0.10 |
| `opsec-score` | Structured public-exposure score and mitigations | $0.25 |
| `monero-opsec-audit` | Monero address and privacy-posture audit | $0.25 |
| `data-removal` | Supported removal-path matching and draft request generation | $0.50 |
| `wallet-opsec-audit` | Public Base/EVM wallet hygiene review | $0.50 |
| `full-privacy-sweep` | Combined authorized privacy report | $1.00 |
| `cypherpunk-redteam-dossier` | Combined multi-module authorized dossier | $5.00 |
| `sovereign-opsec-retainer` | Organization-level assessment package | $25.00 |

## Safety requirements

- Assess only assets and identities that the requester owns or is authorized to assess.
- Never submit seed phrases, private keys, API credentials, or plaintext secrets.
- Treat results as potentially incomplete or stale signals; review before acting.
- Data-removal outputs provide guidance and drafts; they do not send requests or guarantee removal.

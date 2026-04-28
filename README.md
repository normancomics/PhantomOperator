# PhantomOperator

PhantomOperator — automated privacy-removal orchestration with real-time Superfluid payouts on Base.

Why PhantomOperator?
- Automated data-broker opt-outs and prioritised threat remediation
- Real-time micropayments via Superfluid USDCx on Base (streams & IDAs)
- On-chain agent identity & skill registration (8004scan.io, CryptoSkill.org)
- x402 HTTP payment protocol support (Superfluid facilitator + CDP Bazaar)
- Secure, sandboxed agents and enterprise-ready orchestration

Getting started

1) Configure environment
	- Copy `.env.example` to `.env` and fill in your keys (never commit `.env`).
	- At minimum set `PRIVATE_KEY` and `PHANTOM_OPERATOR_ADDRESS`.

2) Install Node dependencies
```bash
npm ci
```

3) Run a quick test (uses `test.js`):
```bash
node test.js
```

---

Agent Registration

The `npm run register` command (or `node scripts/registerAgent.js`) runs a 5-step pipeline for **each** sub-agent:

| Step | Registry | Contract / URL |
|------|----------|----------------|
| 1 | On-chain Identity Registry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` (Base) |
| 2 | On-chain Reputation/Skill Registry | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` (Base) |
| 3 | CryptoSkill.org | https://cryptoskill.org/ |
| 4 | Superfluid x402 Facilitator | https://x402.superfluid.org/ |
| 5 | CDP x402 Bazaar | https://docs.cdp.coinbase.com/x402/bazaar |

Required `.env` variables for registration:

| Variable | Description |
|----------|-------------|
| `PRIVATE_KEY` | Agent owner wallet private key (signs on-chain txs) |
| `PHANTOM_OPERATOR_ADDRESS` | Deployed agent wallet address |
| `BASE_RPC_URL` | Base mainnet JSON-RPC (default: `https://mainnet.base.org`) |
| `AGENT_SERVICE_ENDPOINT` | Public HTTPS URL where the agent accepts requests |
| `AGENT_METADATA_URI` | IPFS or HTTPS URI to the agent metadata JSON |
| `CRYPTOSKILL_API_KEY` | CryptoSkill.org API key |
| `CDP_API_KEY` | Coinbase Developer Platform API key (for Bazaar listing) |

Optional:

| Variable | Default |
|----------|---------|
| `PRICE_PER_REQUEST` | `0.001` (USDCx) |
| `X402_FACILITATOR_URL` | `https://x402.superfluid.org` |
| `X402_BAZAAR_URL` | `https://api.developer.coinbase.com/rpc/v1/base` |
| `CRYPTOSKILL_API` | `https://cryptoskill.org/api/v1` |

Run registration:
```bash
npm run register
```

Each step is fault-tolerant — if one registry is unavailable the script logs the error and continues with the rest.

---

Services

| File | Purpose |
|------|---------|
| `services/RegistryService.js` | Ethers.js calls to the identity & reputation registry contracts on Base |
| `services/SkillRegistryService.js` | REST calls to the CryptoSkill.org API |
| `services/X402Service.js` | Superfluid x402 facilitator + CDP Bazaar registration |
| `services/SuperfluidService.js` | Superfluid streaming (start/stop flow) |

Registration & Priority Payouts

Want priority payouts and featured placement? Create a registration issue using the `Register PhantomOperator Agent` template in `.github/ISSUE_TEMPLATE/register_agent.md` and include your ENS / on-chain identity (e.g., `normancomics.base.eth`).

Files added in this repo
- `PhantomOperator.js` — orchestrator
- `agents/SearchAgent.js` — search & threat analysis
- `agents/BrokerAgent.js` — data broker automation (placeholder)
- `services/RegistryService.js` — on-chain identity & reputation registry
- `services/SkillRegistryService.js` — CryptoSkill.org integration
- `services/X402Service.js` — Superfluid x402 & CDP Bazaar integration
- `services/SuperfluidService.js` — Base-compatible Superfluid helper
- `scripts/registerAgent.js` — agent registration CLI
- `test.js` — example runner
- `.env.example` — environment variable template (DO NOT commit secrets)
- `.github/workflows/superfluid-test.yml` — GitHub Actions test workflow

Security notes
- All sensitive keys must live in `.env` locally and in GitHub Actions Secrets for CI.
- Run `npm audit` and `npm audit fix` before publishing. Review any critical advisories manually.

SEO / Quick Pitch

Automated opt-outs + Superfluid x402 streaming payouts on Base — registered with CryptoSkill.org, 8004scan identity & reputation registries, and the CDP Bazaar.


# SovereignAgent

**SovereignAgent — automated privacy-removal orchestration with real-time Superfluid payouts on Base.**

SovereignAgent coordinates secure, sandboxed agents to:

- Automate **data-broker opt-outs** and prioritized threat remediation.
- Handle **real-time micropayments** via **Superfluid USDCx** on **Base** (streams & IDAs).
- Provide on-chain identity + reputation via Base registries.
- x402 payment middleware — callers pay per skill invocation.
- Listed on CryptoSkill and the Coinbase CDP Bazaar for agent-to-agent discovery.

---

## Step-by-Step Setup & Registration

### Step 1 — Configure environment

Copy `.env.example` to `.env` and fill in every value. **Never commit `.env`.**

```bash
cp .env.example .env
# Edit .env with your real wallet key, RPC URL, and API keys
```

Key variables to fill in:

| Variable | Where to get it |
|---|---|
| `PRIVATE_KEY` | Your wallet private key (Base mainnet, must hold ETH for gas) |
| `RPC_URL` | `https://mainnet.base.org` or an Alchemy/Infura Base endpoint |
| `SOVEREIGN_AGENT_ADDRESS` | Your wallet's public address (derived from `PRIVATE_KEY`) |
| `CRYPTOSKILL_API_KEY` | Sign up at https://cryptoskill.org |
| `CDP_API_KEY_NAME` / `CDP_API_KEY_PRIVATE_KEY` | https://portal.cdp.coinbase.com |
| `AGENT_SERVER_URL` | Public URL of your running `server.js` (use ngrok for local dev) |
| `AGENT_METADATA_URI` | Public URL of your `agent-manifest.json` (GitHub raw URL works) |

### Step 2 — Install dependencies

```bash
npm ci
```

### Step 3 — Run the registration script

This single script handles on-chain identity, reputation, and CryptoSkill registration:

```bash
npm run register
# or: node scripts/register.js
```

What it does:
1. **Base Identity Registry** (`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`) — calls `registerAgent(metadataURI)` to store your agent's on-chain identity.
2. **Base Reputation Registry** (`0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`) — calls `initializeAgent()` to create your reputation record.
3. **CryptoSkill** — POSTs your agent profile and all skills from `agent-manifest.json` to the CryptoSkill API. (Skipped if `CRYPTOSKILL_API_KEY` not set.)
4. **Verification** — reads back both registry contracts to confirm registration succeeded and prints BaseScan links.

### Step 4 — Start the x402 payment server

```bash
npm start
# or: node server.js
```

This starts an HTTP server with x402 payment middleware on the port in your `.env` (`PORT=3000` by default). Callers must attach a valid payment proof in the `X-PAYMENT` header to use paid endpoints.

Available endpoints:

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | Free | Liveness check |
| `GET` | `/manifest` | Free | Returns `agent-manifest.json` |
| `POST` | `/skills/threat-scan` | 1.00 USDCx | Web threat scan |
| `POST` | `/skills/data-removal` | 5.00 USDCx | Data broker opt-out |
| `POST` | `/skills/full-privacy-sweep` | 10.00 USDCx | Full scan + removal |
| `POST` | `/skills/opsec-score` | 5.00 USDCx | Multi-vector OPSEC exposure score |
| `POST` | `/skills/breach-check` | 2.00 USDCx | HIBP k-anonymity breach lookup |
| `POST` | `/skills/metadata-audit` | 1.00 USDCx | HTTP/HTML metadata privacy audit |

For local development, expose the server publicly with [ngrok](https://ngrok.com):
```bash
ngrok http 3000
# Copy the https URL into AGENT_SERVER_URL in your .env
```

### Step 5 — List on the Coinbase CDP x402 Bazaar

```bash
npm run list-bazaar
# or: node scripts/list-on-bazaar.js
```

This submits your agent to the [Coinbase CDP Bazaar](https://docs.cdp.coinbase.com/x402/bazaar), making it discoverable by other agents and users. Requires `AGENT_SERVER_URL`, `CDP_API_KEY_NAME`, and `CDP_API_KEY_PRIVATE_KEY` to be set.

### Step 6 — Verify on-chain

After the registration transactions confirm (~5–30 seconds on Base mainnet), verify on BaseScan:

- Identity Registry: https://basescan.org/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432#readContract
  - Call `getAgentMetadata(yourAddress)` — should return your `AGENT_METADATA_URI`
  - Call `isRegistered(yourAddress)` — should return `true`
- Reputation Registry: https://basescan.org/address/0x8004BAa17C55a88189AE136b182e5fdA19dE9b63#readContract
  - Call `getReputation(yourAddress)` — should return your initialized record
  - Call `isInitialized(yourAddress)` — should return `true`

### Quick Test (optional)

SovereignAgent ships with a simple example runner:

```bash
node test.js
```

This exercises the orchestrator's basic flows (scan/threat analysis, Superfluid wiring) and logs output so you can confirm everything is wired correctly.

---

## Public API

SovereignAgent exposes a JavaScript API:

- `scanExposures(user)` – run threat / exposure search.
- `scheduleOptOuts(exposures, user)` – schedule broker opt-outs.
- `openRewardStream(to, flowRate)` – open a Superfluid USDCx stream on Base.
- `stopRewardStream(to)` – stop an existing stream.
- `runPrivacyWorkflow(user)` – end-to-end "scan + schedule opt-outs" workflow.

See [`SovereignAgent.js`](./SovereignAgent.js) and `skills/sovereignagent.md` for details.

---

## File Reference

```
sovereignagent/
├── agent-manifest.json         ← Agent identity + skills (publish this publicly)
├── abis/
│   ├── IdentityRegistry.json   ← ABI for Base Identity Registry
│   └── ReputationRegistry.json ← ABI for Base Reputation Registry
├── scripts/
│   ├── register.js             ← Steps 2+3+4: on-chain + CryptoSkill registration
│   └── list-on-bazaar.js       ← Step 5: CDP Bazaar listing
├── server.js                   ← x402 payment server (Step 4)
├── middleware/
│   └── security.js             ← Rate limiter, security headers, input sanitizer
├── services/
│   ├── RegistryService.js      ← Base Identity + Reputation registry interactions
│   ├── CryptoSkillService.js   ← CryptoSkill API integration
│   ├── RagService.js           ← Zero-dependency RAG retrieval layer
│   └── SuperfluidService.js    ← Superfluid payment streaming (Base mainnet)
├── agents/
│   ├── SearchAgent.js          ← Web threat scanner + RAG reranking
│   ├── BrokerAgent.js          ← Data broker opt-out (placeholder)
│   ├── OpsecAgent.js           ← Multi-vector OPSEC exposure scoring
│   ├── BreachAgent.js          ← HIBP k-anonymity breach lookup
│   └── MetadataAgent.js        ← HTTP/HTML metadata privacy audit
├── SovereignAgent.js           ← Main orchestrator
├── test.js                     ← Quick smoke test (Superfluid flow only)
├── .env.example                ← All required environment variables
└── .github/workflows/
    └── superfluid-test.yml     ← GitHub Actions CI
```

---

## Skills

See the [`skills/`](./skills) directory for detailed skill docs:

- `skills/sovereignagent.md` — top-level SovereignAgent skill.
- `skills/search-agent.md` — Threat & Exposure Search sub-skill.
- `skills/broker-agent.md` — Data-Broker Automation sub-skill (beta).
- `skills/superfluid-streaming.md` — Superfluid USDCx streaming sub-skill.

---

## Registration & Priority Payouts

Want **priority payouts** and **featured placement** in SovereignAgent-compatible registries and listings?

1. Open a **"Register Sovereign Agent"** issue using the provided template:
   - `.github/ISSUE_TEMPLATE/register_agent.md`
2. Include your **ENS / on-chain identity**, for example:
   - `normancomics.base.eth`
   - or a Base address

This helps:

- Associate your agent deployment with your on-chain identity.
- Qualify for future **priority payouts**, **beta A/B tests**, and **featured slots** in supported agent registries.

---

## Security Notes

- **Never commit `.env`** — it is already in `.gitignore`.
- For GitHub Actions CI, add all secrets to the repository's **Secrets** settings.
- `PRIVATE_KEY` should belong to a dedicated agent wallet, not your personal wallet.
- Run `npm audit` before publishing and address any critical findings.
- Treat any external broker endpoints and integrations as untrusted:
  - Validate and sanitize inputs/outputs.
  - Avoid leaking identifying data beyond what's strictly necessary for opt-out flows.

---

## Network

All on-chain activity targets **Base mainnet** (Chain ID `8453`).
The old `Base Goerli` testnet (Chain ID `84531`) is deprecated and no longer works.
For staging, use **Base Sepolia** (Chain ID `84532`) — update `CHAIN_ID` and `RPC_URL` accordingly.

---

## SEO / Quick Pitch

> **Automated opt-out workflows + Superfluid streaming payouts on Base.**
> Join the SovereignAgent beta for priority payouts, featured listings, and agent-native privacy orchestration.

SovereignAgent is designed to plug into on-chain agent ecosystems, skill registries, and Base-native x402 payment flows, making it a natural fit for:

- Privacy-focused AI agents
- Data removal / opt-out services
- Agent swarms that need both **privacy** and **payment** primitives on Base.

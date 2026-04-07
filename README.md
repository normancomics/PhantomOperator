# sovereignagent

SovereignAgent — automated privacy-removal orchestration with real-time Superfluid payouts on Base, registered on-chain with the Base Identity & Reputation Registries and discoverable on CryptoSkill and the Coinbase CDP x402 Bazaar.

## Why SovereignAgent?
- Automated data-broker opt-outs and prioritized threat remediation
- Real-time micropayments via Superfluid USDCx on Base mainnet
- On-chain identity + reputation via Base registries
- x402 payment middleware — callers pay per skill invocation
- Listed on CryptoSkill and the Coinbase CDP Bazaar for agent-to-agent discovery

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
3. **CryptoSkill** — POSTs your agent profile and all three skills from `agent-manifest.json` to the CryptoSkill API. (Skipped if `CRYPTOSKILL_API_KEY` not set.)
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

---

## File Reference

```
sovereignagent/
├── agent-manifest.json         ← Agent identity + 3 skills (publish this publicly)
├── abis/
│   ├── IdentityRegistry.json   ← ABI for Base Identity Registry
│   └── ReputationRegistry.json ← ABI for Base Reputation Registry
├── scripts/
│   ├── register.js             ← Steps 2+3+4: on-chain + CryptoSkill registration
│   └── list-on-bazaar.js       ← Step 5: CDP Bazaar listing
├── server.js                   ← x402 payment server (Step 4)
├── services/
│   ├── RegistryService.js      ← Base Identity + Reputation registry interactions
│   ├── CryptoSkillService.js   ← CryptoSkill API integration
│   └── SuperfluidService.js    ← Superfluid payment streaming (Base mainnet)
├── agents/
│   ├── SearchAgent.js          ← Web threat scanner
│   └── BrokerAgent.js          ← Data broker opt-out (placeholder)
├── SovereignAgent.js           ← Main orchestrator
├── test.js                     ← Quick smoke test (Superfluid flow only)
└── .env.example                ← All required environment variables
```

---

## Security Notes

- **Never commit `.env`** — it is already in `.gitignore`.
- For GitHub Actions CI, add all secrets to the repository's **Secrets** settings.
- `PRIVATE_KEY` should belong to a dedicated agent wallet, not your personal wallet.
- Run `npm audit` before publishing and address any critical findings.

---

## Network

All on-chain activity targets **Base mainnet** (Chain ID `8453`).
The old `Base Goerli` testnet (Chain ID `84531`) is deprecated and no longer works.
For staging, use **Base Sepolia** (Chain ID `84532`) — update `CHAIN_ID` and `RPC_URL` accordingly.


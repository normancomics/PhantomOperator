# PhantomOperator

Created by normancomics — normancomics.eth · normancomics.base.eth · normancomics.reserve.superfluid.eth · 0x3d95d4a6dbae0cd0643a82b13a13b08921d6adf7

**PhantomOperator** is a **multi-operator privacy and OPSEC framework** for people who want to *vanish* from data brokers, minimize surveillance, and maintain stealth online.

- Agentic swarms coordinate:
  - Automated data-broker opt-outs and prioritized threat remediation
  - OSINT / PII threat scans
  - OPSEC exposure scoring
  - Metadata and tracking audits
  - Breach checks via k-anonymity
- Monetized on **Base** (USDCx / ERC-20 via x402).
- Optional **Monero payments** for users who do not want any public-chain correlation.
- Designed for integration with RAG and MCP so other agents / LLMs can call PhantomOperator as a backend.
- Intended for listing on **CryptoSkill**, **Coinbase CDP Bazaar**, **8004scan.io**, and other agent registries.

---

## Architecture Overview

PhantomOperator is **not** a single agent. It is an **agentic framework** composed of cooperating operators and swarms.

### 1. OrchestratorOperator (Core Brain)

The `OrchestratorOperator` coordinates everything:

- Receives high-level intents via:
  - HTTP API (`/skills/...`)
  - Future: scheduled jobs (Postgres + `pg_cron`)
  - Future: MCP tool calls
- Decomposes work into sub-tasks:
  - Which data brokers to target
  - Which OSINT surfaces to scan
  - Which breach / metadata checks to run
- Delegates tasks to domain operators.
- Tracks job status and aggregates results for the caller.

### 2. Domain Operators

Each operator focuses on a specific piece of the privacy / OPSEC surface:

- **SearchOperator**  
  (backed by `SearchAgent`)  
  OSINT / PII search and threat discovery.

- **BrokerOperator**  
  (backed by `BrokerAgent`)  
  Data-broker opt-outs and prioritized threat remediation.

- **OpsecOperator**  
  (backed by `OpsecAgent`)  
  Multi-vector OPSEC exposure scoring (handles, emails, names).

- **BreachOperator**  
  (backed by `BreachAgent`)  
  Email/password breach checks via k-anonymity APIs.

- **MetadataOperator**  
  (backed by `MetadataAgent`)  
  HTTP/HTML metadata, trackers, and fingerprinting audits.

Existing `/skills/*` endpoints already map to these capabilities; over time they will be internally routed through `OrchestratorOperator`.

### 3. Sub-Operators & Swarms (Planned)

PhantomOperator extends into swarms of smaller operators:

- **Broker-specific sub-operators**
  - One per broker (Spokeo, Whitepages, BeenVerified, etc.).
  - Encapsulates URLs, form flows, and required PII.
- **Scraper sub-operators**
  - Focused crawlers / scrapers for specific OSINT surfaces.
- **Swarms**
  - A swarm is a set of sub-operators executing in parallel across a target identity.
  - Triggered by:
    - Direct calls like `POST /skills/full-privacy-sweep`
    - Scheduled pg_cron jobs (e.g. weekly sweeps)
    - Events (e.g. a new breach detection).

### 4. Storage, Jobs & Scheduling (Planned)

Planned job system (optional but recommended):

- **Postgres** as a central store:
  - `jobs` table — queued tasks with type, payload, status, timestamps.
  - `job_results` table — normalized results per operator run.
- **`pg_cron`** for scheduling recurring tasks:
  - e.g. daily OSINT sweeps, weekly broker re-checks, breach monitoring.
- **Worker processes**:
  - One or more Node.js workers poll `jobs` where `status = 'pending'`,
    delegate to operators, and write back `status` and results.

PhantomOperator runs as a regular Node.js HTTP server; Postgres is only required when you enable scheduled jobs and persistence.

---

## Payments & Monetization

### On-chain (Base via x402)

PhantomOperator uses an x402-compatible payment middleware (HTTP 402 Payment Required):

- For a paid skill:
  1. Client calls `POST /skills/{id}` without payment.
  2. Server responds with `402` and a JSON x402 descriptor:
     - network: Base mainnet
     - asset: payment token (e.g. USDCx)
     - payTo: receiver address
     - maxAmountRequired: skill price
  3. Client pays and submits a signed proof in the `X-PAYMENT` header.
  4. PhantomOperator validates the proof and serves the response.

See [`server.js`](server.js) for:

- `SKILL_PRICES`
- `validateAnyPayment(...)`
- x402 enforcement in `handlePaidSkill(...)`

### Monero (True Privacy Path)

For users who do **not** want any public-chain trace:

- Primary Monero address:

  `83povooYdUgEArc13ZzaVp5vqGpDpKJ6WJ971NL94sbRcneqBtXB7N3XLN57v1fqddbinPjYCcwjk7AkrrwVJupFNU84XCq`

#### Intended Monero Flow (Design)

1. Client requests a Monero quote:

   `POST /billing/monero-quote`  
   `{ "skillId": "full-privacy-sweep" }`

2. PhantomOperator (or a trusted Monero bridge service) returns:

   - XMR amount
   - Monero address or subaddress
   - One-time invoice token.

3. Client pays from their Monero wallet.

4. Bridge service detects payment and issues a signed proof (JSON/JWT) bound to the invoice token.

5. Client calls `POST /skills/{id}` with:

   - `X-PAYMENT-METHOD: monero`
   - `X-PAYMENT: <base64(moneroProofJson)>`

6. PhantomOperator verifies the proof via the bridge:

   - If valid and unused → executes the skill.
   - Otherwise → returns `402` with payment instructions.

> Implementation detail: Monero wallet/node operations are intended to run in a separate service; this repo focuses on integration and validation hooks.

---

## RAG & MCP Integration

PhantomOperator can be used as a **back-end OPSEC engine** for other agents via RAG and MCP.

### RAG (Retrieval-Augmented Generation)

Two retrieval layers:

1. **Broker / Legal Knowledge**
   - Vector index of:
     - Broker privacy policies
     - Opt-out documentation
     - Data protection laws (GDPR, CCPA, etc.).
   - Operators query this index to generate:
     - Correct removal flows
     - Compliant letters / emails / webform payloads.

2. **User Context**
   - Per-identity “case file”:
     - Known brokers with profiles removed
     - Successful / pending removals
     - Preferred channels and previous findings.
   - RAG ensures each new action builds on history; reduces redundant work.

### MCP (Model Context Protocol)

PhantomOperator exposes skills as MCP tools, so LLMs and agent frameworks can call it directly:

Planned MCP tools (examples):

- `phantom_threat_scan`
- `phantom_data_removal`
- `phantom_full_privacy_sweep`
- `phantom_opsec_score`
- `phantom_breach_check`
- `phantom_metadata_audit`

MCP manifests and tool schemas live under `/mcp/` and map to:

- HTTP endpoints (e.g. `/skills/threat-scan`)
- JSON parameter/response schemas
- Pricing hints (x402 + Monero paths)

---

## Agent Registries & Discovery

PhantomOperator is built to integrate with:

- **CryptoSkill** (x402 skill registry)
- **Coinbase CDP Bazaar** (agent registry on Base)
- **8004scan.io** (autonomous agent explorer)
- Other agent registries.

Registry manifests live under:

```text
/registry-manifests
  cryptoskill.json
  cdp-bazaar.json
  8004scan.json
```

Each manifest defines:

- Name, description, maintainer
- Public base URL
- List of skills, paths, and methods
- Chain (Base), token address, and payment receiver
- Optional Monero payment details.

Your deployment just needs to expose:

- `GET /health`
- `GET /manifest` (also served at `/.well-known/agent.json`)

For agent and LLM discovery it also serves `/openapi.json`, `/SKILL.md` and `/llms.txt`.

and host at a stable public URL.

### Getting listed

1. Deploy publicly and set `PUBLIC_BASE_URL` (e.g. `https://phantom-operator.onrender.com`) so discovery documents carry the right URLs.
2. Register on-chain identity (ERC-8004, shown on 8004scan.io): `npm run register`; point the agent's metadata at `<base>/.well-known/agent.json`.
3. List on the Coinbase CDP x402 Bazaar: `npm run list-bazaar` (needs `AGENT_SERVER_URL`, `CDP_API_KEY_NAME`, `CDP_API_KEY_PRIVATE_KEY`). The 402 response includes an `outputSchema` so facilitators can index each skill's inputs.
4. Submit the base URL to other x402 directories and agent platforms (e.g. bankr.bot) by hand — they crawl `/openapi.json`, `/llms.txt` and `/.well-known/x402`.
5. Add GitHub topics (`x402`, `ai-agent`, `privacy`, `opsec`, `erc-8004`, `mcp`) in the repository settings.

---

## HTTP API (Current)

Public endpoints (all GET, CORS-enabled, rate-limited):

| Path | Description |
|---|---|
| `/` | JSON index of endpoints, prices and links |
| `/health` | Liveness check |
| `/manifest` | Agent manifest (`agent-manifest.json`) |
| `/.well-known/agent.json` | Same manifest, at the well-known discovery path |
| `/openapi.json` | OpenAPI 3.1 spec generated from `SKILL_PRICES` and the manifest, including the 402 response |
| `/.well-known/x402` | x402 discovery document (receiver, asset, priced resources) |
| `/robots.txt` | Crawler policy |
| `/SKILL.md` | Skill description (`text/markdown`) |
| `/llms.txt` | LLM-friendly site summary (`text/plain`) |

Paid skill endpoints (x402 / Monero):

| Endpoint | Price (USDCx) |
|---|---|
| `POST /skills/threat-scan` | 1.00 |
| `POST /skills/data-removal` | 5.00 |
| `POST /skills/full-privacy-sweep` | 10.00 |
| `POST /skills/opsec-score` | 5.00 |
| `POST /skills/breach-check` | 2.00 |
| `POST /skills/metadata-audit` | 1.00 |

An unpaid call returns `402` with an x402 descriptor. If no payment receiver is configured, paid endpoints return `503` (`Payment receiver not configured`). `OPTIONS` preflight returns `204`; allowed headers are `X-PAYMENT`, `X-PAYMENT-METHOD` and `Content-Type`.

```bash
curl -i -X POST http://localhost:3000/skills/opsec-score \
  -H "Content-Type: application/json" -d '{}'
# HTTP/1.1 402 Payment Required
```

See [`server.js`](server.js) for expected request bodies and validation.

---

## Running Locally & Deploying

```bash
npm install
cp .env.example .env     # set PAYMENT_RECEIVER_ADDRESS at minimum
npm start                # listens on 0.0.0.0:$PORT (default 3000)
npm test                 # runs the workflow demo plus HTTP server checks
```

Key environment variables:

- `PAYMENT_RECEIVER_ADDRESS` — required for paid skills (falls back to `SOVEREIGN_AGENT_ADDRESS` / `PHANTOM_OPERATOR_ADDRESS`). Without it the server starts with a warning and paid endpoints return 503.
- `PORT` — HTTP port (Render sets this automatically).
- `PUBLIC_BASE_URL` — optional; base URL used in `/` and `/openapi.json`.
- `PAYMENT_TOKEN_ADDRESS`, `CHAIN_ID` — optional overrides (default USDCx on Base, 8453).

The server binds to `0.0.0.0`, so it runs on Render as a plain Node web service (`npm install` build, `npm start` start command).

---

## Python Prototype

`src/search_agent/search_agent.py` is a **standalone research prototype** — it is _not_ integrated with the Node.js HTTP server.  It replicates the same DuckDuckGo search + threat-analysis heuristics that are production-implemented in [`agents/SearchAgent.js`](agents/SearchAgent.js), and is kept here for offline/CLI use and as a reference implementation.

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run a manual threat scan
python src/search_agent/search_agent.py "Full Name"
# → saves <Full_Name>_threat_analysis.json in the current directory
```

For production use, call `POST /skills/threat-scan` on the running `server.js` instead.

---

## Solana Deployment

PhantomOperator includes a native **Solana BPF/SBF program** written in Rust
that mirrors the skill catalogue on-chain, accepting SOL payments and recording
every invocation in a per-operator registry account.

> **Integration note:** The Solana program is an independent on-chain payment
> surface.  It does **not** share runtime state with the Node.js HTTP server
> (`server.js`) — they are two separate entry points into the PhantomOperator
> skill catalogue:
>
> | Surface | Runtime | Payment token | Entry point |
> |---|---|---|---|
> | HTTP API | Node.js | USDCx on Base (x402) or Monero | `server.js` |
> | On-chain program | Solana BPF/SBF | SOL (lamports) | `solana/programs/phantom_operator/` |
>
> A future integration layer (e.g. a shared job queue or cross-chain bridge)
> will allow either surface to trigger the same privacy-sweep logic.

### Quick start

1. **Install prerequisites**

   ```bash
   # Rust toolchain
   curl https://sh.rustup.rs -sSf | sh

   # Solana CLI tool suite
   sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
   ```

2. **Verify the toolchain**

   ```bash
   ./solana/scripts/check-solana.sh
   ```

3. **Build the program**

   ```bash
   ./solana/scripts/build.sh
   # Compiled binary: solana/deploy/phantom_operator.so
   ```

4. **Deploy to devnet**

   ```bash
   ./solana/scripts/deploy.sh --cluster devnet
   ```

   The script prints the **Program ID**. Add it to your `.env`:

   ```env
   SOLANA_PROGRAM_ID=<printed-program-id>
   ```

5. **Initialise the on-chain registry** (once per operator)

   ```bash
   npm install @solana/web3.js
   node scripts/solana-invoke.js init-registry
   ```

6. **Invoke a skill from Node.js**

   ```bash
   node scripts/solana-invoke.js invoke-skill --skill-id 0 --amount 1000000
   ```

7. **Deploy to mainnet-beta**

   ```bash
   ./solana/scripts/deploy.sh --cluster mainnet-beta
   ```

See **[`solana/README.md`](solana/README.md)** for the full guide, including
skill IDs, upgrade instructions, environment variables, and troubleshooting.

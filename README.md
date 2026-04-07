# SovereignAgent

**SovereignAgent — automated privacy-removal orchestration with real-time Superfluid payouts on Base.**

SovereignAgent coordinates secure, sandboxed agents to:

- Automate **data-broker opt-outs** and prioritized threat remediation.
- Handle **real-time micropayments** via **Superfluid USDCx** on **Base** (streams & IDAs).
- Provide **enterprise-ready orchestration** for privacy workflows and agent swarms.

---

## Why SovereignAgent?

SovereignAgent is built for agent-native, on-chain privacy workflows:

- **Automated data-broker opt-outs and remediation**
  - Submits and tracks opt-out / deletion requests across data brokers.
  - Maintains a prioritized queue of threats and exposures.

- **Real-time micropayments via Superfluid on Base**
  - Uses USDCx streams and IDAs to compensate agents and contributors.
  - Designed to integrate with x402-style payment flows and on-chain usage metering.

- **Secure, sandboxed agents & orchestration**
  - `SovereignAgent.js` orchestrates sub-agents for search, analysis, and broker automation.
  - Built to be extended into agent swarms and sovereign sub-agents with clear roles.

---

## Getting Started

### 1. Configure Environment

1. Copy `.env.example` to `.env`:

   ```bash
   cp .env.example .env
   ```

2. Fill in your test keys (Superfluid, Base RPC, etc.).  
   **Important:** never commit `.env` or any secrets to the repo.

### 2. Install Dependencies

```bash
npm ci
```

### 3. Run a Quick Test

SovereignAgent ships with a simple example runner:

```bash
node test.js
```

This will:

- Initialize the SovereignAgent orchestrator.
- Exercise basic flows (search/threat analysis, Superfluid service wiring, etc.).
- Log output so you can confirm everything is wired correctly.

---

## Public API

SovereignAgent exposes a simple JavaScript API:

- `scanExposures(user)` – run threat / exposure search.
- `scheduleOptOuts(exposures, user)` – schedule broker opt-outs.
- `openRewardStream(to, flowRate)` – open a Superfluid USDCx stream on Base.
- `stopRewardStream(to)` – stop an existing stream.
- `runPrivacyWorkflow(user)` – end-to-end “scan + schedule opt-outs” workflow.

See [`SovereignAgent.js`](./SovereignAgent.js) and `skills/sovereignagent.md` for details.

---

## Registration & Priority Payouts

Want **priority payouts** and **featured placement** in SovereignAgent-compatible registries and listings?

1. Open a **“Register Sovereign Agent”** issue using the provided template:
   - `.github/ISSUE_TEMPLATE/register_agent.md`
2. Include your **ENS / on-chain identity**, for example:
   - `normancomics.base.eth`
   - or a Base address

This helps:

- Associate your agent deployment with your on-chain identity.
- Qualify for future **priority payouts**, **beta A/B tests**, and **featured slots** in supported agent registries.

---

## Repository Layout

Key files in this repo:

- `SovereignAgent.js` — main orchestrator.
- `agents/SearchAgent.js` — search & threat analysis.
- `agents/BrokerAgent.js` — data-broker automation (placeholder / WIP).
- `services/SuperfluidService.js` — Base-compatible Superfluid helper.
- `test.js` — example runner / quick test harness.
- `.env.example` — environment variable template (**DO NOT** commit secrets).
- `.github/workflows/superfluid-test.yml` — GitHub Actions workflow to test Superfluid integration.

---

## Skills

See the [`skills/`](./skills) directory for detailed skill docs:

- `skills/sovereignagent.md` — top-level SovereignAgent skill.
- `skills/search-agent.md` — Threat & Exposure Search sub-skill.
- `skills/broker-agent.md` — Data-Broker Automation sub-skill (beta).
- `skills/superfluid-streaming.md` — Superfluid USDCx streaming sub-skill.

---

## Security Notes

- All sensitive keys **must** live in:
  - Local `.env` for development.
  - GitHub Actions **Secrets** for CI.

- Before publishing or deploying:

  ```bash
  npm audit
  npm audit fix
  ```

  Manually review any **critical** advisories.

- Treat any external broker endpoints and integrations as untrusted:
  - Validate and sanitize inputs/outputs.
  - Avoid leaking identifying data beyond what’s strictly necessary for opt-out flows.

---

## SEO / Quick Pitch

> **Automated opt-out workflows + Superfluid streaming payouts on Base.**  
> Join the SovereignAgent beta for priority payouts, featured listings, and agent-native privacy orchestration.

SovereignAgent is designed to plug into on-chain agent ecosystems, skill registries, and Base-native x402 payment flows, making it a natural fit for:

- Privacy-focused AI agents
- Data removal / opt-out services
- Agent swarms that need both **privacy** and **payment** primitives on Base.

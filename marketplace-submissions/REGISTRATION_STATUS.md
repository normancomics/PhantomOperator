# PhantomOperator discovery and listing status

Last verified: 2026-10-29
Canonical public URL: `https://freysaai.freysa.dev`
Base payment receiver: `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6`
ERC-8004 agent ID: `821239`

## Verified
- ERC-8004 registration is on Base: owner `0x050f74E4591F9897FdB311C8150c07dFFfbEf5e1`; metadata URI is `https://freysaai.freysa.dev/.well-known/agent-registration.json`.
- Live discovery endpoints: `/`, `/health`, `/manifest`, `/.well-known/x402`, `/.well-known/agent-registration.json`, `/.well-known/agent-card.json`, `/openapi.json`, `/llms.txt`, `/SKILL.md`, `/mcp`.
- **Coinbase x402 Bazaar:** `metadata-audit` is publicly indexed under the canonical Base receiver and endpoint. On 2026-10-29 the public merchant catalog reported 2 calls from 2 unique payers in the preceding 30 days. Verify with `node scripts/list-on-bazaar.js`; this read-only lookup needs no CDP credentials.
- **Agent Tools Cloud:** 10 x402 listings, one MCP listing, and one A2A listing resolve publicly with current free-preview and Base-USDC positioning.

## Needs third-party confirmation/submission
- **8004scan:** On-chain identity is complete. Confirm agent search/profile indexing from the explorer UI; no API key should be needed for the on-chain identity.
- **x402scan:** Recheck the existing registered origin using its dashboard/wallet login and request a fresh crawl if it is not public.
- **402index:** Recheck the existing verification token and public listing; request a recrawl if missing.
- **Bankr skills:** submit `marketplace-submissions/bankr/phantom-operator/` as a GitHub PR to `BankrBot/skills`.
- **Bankr x402 marketplace:** listing is review/batch enabled by Bankr; there is no self-service discovery toggle or support request to accelerate it. A callable public x402 endpoint and correct metadata are prerequisites.
- **CDP Bazaar:** discovery is automatic after successful CDP-facilitated settlement with Bazaar metadata. Other skills will appear only after legitimate paid use; do not fabricate calls or payments to populate the catalog.

## Owner credentials/actions required
- GitHub authentication only to fork/push/open the Bankr PR.
- Context.dev API key only if optional Context research calls are enabled.
- CDP credentials only after current Bazaar onboarding has been verified.

## 2026-10-25 distribution update
- 402 Index: 10 x402 endpoints self-registered; each returned `201` and `Service registered and live (domain verified)`.
- Agent Tools: six x402 endpoint listings, the MCP listing (`/mcp/servers/phantomoperator-mcp`), and the A2A listing (`/a2a/agents/phantomoperator`) accepted. Four x402 listings are queued for bounded rate-limit retry.
- Bankr skills: pull request open at https://github.com/BankrBot/skills/pull/815.

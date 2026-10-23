# PhantomOperator

Evidence-based public-web privacy assessments for people and agents. Pay per completed assessment with **x402 v2, exact, USDC on Base**. No subscription or server-side signing wallet is needed for the three enabled skills.

| Skill | Per successful call | What it does |
| --- | ---: | --- |
| `metadata-audit` | $0.05 USDC | Inspects a public page's HTTP headers, HTML metadata/comments and third-party resource origins; returns observations, evidence and remediation. |
| `threat-scan` | $0.10 USDC | Classifies authorized public search-result snippets for potential PII exposure and returns source links and reasons. |
| `opsec-score` | $0.25 USDC | Combines authorized public-search evidence into a heuristic exposure score, coverage report and practical remediation. |

`threat-scan` and `opsec-score` require `"consent": true` and may be used only for yourself or an explicitly authorized client. A result is not proof of identity, a clean bill of privacy, or exhaustive web coverage. Search-provider blocks are errors, not benign findings. No unsupported automatic broker removals, breach-database access, image EXIF analysis or Monero payments are advertised.

The distinctive product proposition is **explainable privacy preflight for agent workflows**: source-backed observations, explicit coverage and uncertainty, machine-readable contracts, and payments settled only after the assessment succeeds. These are useful implementation properties, not a claim that no competing product exists.

## Run and test

Use the existing checkout; a cloud task already provides isolation. Do not create another Git worktree for routine setup.

```bash
npm ci --omit=optional
npm test
```

The default test suite uses local fixtures and mock facilitator responses; it never makes a payment. `npm run test:demo` is a legacy optional-SDK prototype; it is excluded from the production install and is not production validation.

Start with public runtime settings:

```bash
PAY_TO=0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6 \
PUBLIC_URL=https://phantom-operator.onrender.com \
npm start
```

On Render, set `PAY_TO` in **Environment**; `RENDER_EXTERNAL_URL` supplies the canonical origin unless `PUBLIC_URL` is set. The server reads process variables rather than automatically loading `.env`. For local Node versions supporting it, `node --use-env-proxy --env-file=.env server.js` is available. Never copy example private-key placeholders into this production workflow. The payment receiver is independent from the repository author's identity and from an ERC-8004 token owner.

The repository lock is now synchronized with its manifest. A direct frozen `npm ci --omit=optional` replaces the earlier cloud-only external-lock workaround. Unused Superfluid and Solana libraries are excluded from the hosted artifact; a full install is only for separately reviewed legacy tooling. Node24 is used in the Render blueprint. No extra database, Solana toolchain, or wallet key is required to serve the enabled API.

## Use the API

The public service URL supplied by the operator is `https://phantom-operator.onrender.com`. These examples target that origin; its current deployment must still pass the live verification checklist.

```bash
curl https://phantom-operator.onrender.com/skills
curl https://phantom-operator.onrender.com/openapi.json
curl -i https://phantom-operator.onrender.com/skills/metadata-audit \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://example.com"}'
```

Valid unpaid requests return HTTP402 with a base64 `PAYMENT-REQUIRED` header and the equivalent JSON body. A compatible x402 v2 client signs the authorization and retries with `PAYMENT-SIGNATURE`; `X-PAYMENT` is accepted for client compatibility. Input is validated before verification, assessment failures are not settled, and results are released only after a confirmed settlement receipt. If settlement confirmation is interrupted, check your wallet before retrying.

Public discovery endpoints:

- `/` and `/skills/{id}`: human-readable product and skill pages, indexed by ordinary crawlers.
- `/skills` and `/manifest`: current prices, actual runtime receiver and supported inputs.
- `/openapi.json`: OpenAPI3.1 HTTP contracts.
- `/llms.txt`: concise agent integration instructions.
- `/.well-known/x402`: x402 requirements and Bazaar metadata.
- `/agent-registration.json`: ERC-8004 registration file.
- `/.well-known/agent-registration.json`: registration association; remains empty until a real ID and registry are configured.
- `/robots.txt`, `/sitemap.xml`, `/icon.svg`: crawler guidance and a valid fallback icon.

An OpenAPI document does not implement MCP or A2A. Neither protocol is advertised as a working service here.

## Verify a deployment

```bash
npm run check-deployment -- https://phantom-operator.onrender.com \
  --expected-pay-to 0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6
```

This performs public GETs and valid unpaid challenges; it does not spend money. A passing preflight does not prove a real paid transaction settled, external search is unblocked, a directory accepted a listing, or an on-chain identity exists. Use the separate skill fixtures and one explicitly approved payment test to establish those properties.

## Discovery and registration

Follow [the launch checklist](docs/DISCOVERY-LAUNCH.md). Register once on a supported chain using the official ERC-8004 workflow, then let compatible explorers index that identity. Do not invent an agent ID or advertise registration before the transaction succeeds.

```bash
npm run prepare-registration -- \
  --registry VERIFIED_BASE_IDENTITY_REGISTRY \
  --owner YOUR_PUBLIC_OWNER_ADDRESS \
  --agent-uri https://phantom-operator.onrender.com/agent-registration.json
```

This command prepares an **unsigned** `register(string)` proposal for review in your wallet. It never requests a private key or sends a transaction. Verify the contract in the official ERC-8004 deployment records and block explorer before signing. After registration, configure the real `AGENT_ID` and `AGENT_REGISTRY` on Render and verify the registration URI, token owner, association file and any wallet proof requested by the directory.

`npm run register -- ...` is an unsigned preparation alias. `npm run list-bazaar -- https://phantom-operator.onrender.com` prints discovery links and explicitly does not claim to submit a listing. Old custom registration ABIs and guessed CDP API-key submission flows are not used by this launch workflow.

## Privacy, reliability and hosting

Read [Terms](TERMS.md) and [the security/privacy review](docs/SECURITY-PRIVACY.md). Search queries go to DuckDuckGo. Metadata audits contact the target page. Render/the network provider can observe request metadata, and Base payment transactions are public. No claim of anonymous payments is made. Application logs avoid search targets and payment proofs; successful settlement events record only the skill, amount, network and public transaction hash.

Public-page fetches validate and pin DNS results, block private/special destinations, revalidate redirects, and cap time and response size. Forward proxies without documented DNS-pinning semantics are unsupported for arbitrary metadata targets; the server fails closed rather than bypassing proxy policy. Search uses a fixed provider endpoint. External-provider blocking, throttling and incompleteness remain operational risks.

Render's free tier can sleep: cold starts can cause crawlers or paying agents to time out. Choose an always-on plan and stable canonical domain before promoting a reliability claim. This is an owner billing decision, not something the software silently enables.

The production dependency audit has no moderate, high or critical findings at review time; 14 low findings remain documented in [the dependency review](docs/DEPENDENCY-REVIEW.md). Optional legacy tools retain additional advisories and are excluded from Render and CI.

Declared package license: MIT. See [LICENSE](LICENSE). Self-hosting source and the HTTP client contract remain available if the hosted endpoint or facilitator becomes unavailable; no user funds are held by this server.

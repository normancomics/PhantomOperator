# PhantomOperator discovery and launch packet

Status: **prepared locally; no directory submission, Bankr contribution, registry
transaction, social post, or paid production call is implied by this document**.
Production target: <https://phantom-operator.onrender.com>. Run the deployment
checks below after publishing this revision; prepared source does not establish
that the deployed service has been updated.

## Offer and copy to reuse

**Name:** PhantomOperator

**One line:** Evidence-based metadata privacy audits and authorized public-web
exposure checks for people and agents, paid per successful call in USDC on Base.

**Directory description:** PhantomOperator provides three HTTP JSON tools:
static HTML and HTTP-header metadata audits (0.05 USDC), authorized public
search-result exposure triage (0.10 USDC), and heuristic OPSEC exposure scoring
with coverage and remediation (0.25 USDC). Integrate through OpenAPI and x402 v2
exact payments on Base. Reports include observed evidence and source links.
Personal-exposure checks require explicit subject authorization. Coverage is
limited; the service does not remove data or guarantee privacy.

**Useful searches to serve:** `x402 metadata audit API`, `USDC privacy API Base`,
`authorized public-web exposure API`, `OPSEC exposure score API`, and
`HTTP headers metadata privacy audit`. These are editorial topics, not promises
of search volume or rankings. The practical positioning is a low-cost metadata
check with evidence and remediation that another agent can consume. Existing
security services, including Bankr's listed BlueAgent skill, mean a claim that
this category has never existed would be unsupported.[1]

| Implemented tool | Price per successful call | Request body example |
| --- | --- | --- |
| `POST /skills/metadata-audit` | 0.05 USDC (`50000` atomic units) | `{"url":"https://example.com"}` |
| `POST /skills/threat-scan` | 0.10 USDC (`100000` atomic units) | `{"fullName":"Jane Example","consent":true}` |
| `POST /skills/opsec-score` | 0.25 USDC (`250000` atomic units) | `{"handle":"janeexample","consent":true}` |

Metadata Audit reads static HTML and response headers; it does not inspect image
EXIF. Search results can match a different person or be incomplete. Do not market
disabled breach checks, broker removals, full privacy sweeps, MCP, or A2A as
available tools. Use the live OpenAPI document as the request contract.

## Publish and verify the actual service

Configure the hosting service with these public values, then deploy:

```dotenv
PUBLIC_URL=https://phantom-operator.onrender.com
PAY_TO=0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6
```

The runtime uses `eip155:8453` (Base mainnet), x402 v2 `exact`, and native Base
USDC. Keep the runtime catalog, payment challenges, manifest, and listing copy in
agreement. The receiving wallet is a public address, not a signing key. An old
environment value can override the new code default, so check the deployed
receiver rather than assuming a redeploy changed it.

```bash
npm test
npm run check-deployment -- https://phantom-operator.onrender.com \
  --expected-pay-to 0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6
npm run list-bazaar -- https://phantom-operator.onrender.com
```

`check-deployment` checks public documents and unpaid 402 challenges. It never
signs or pays, and does not establish successful paid execution or on-chain
registration. `list-bazaar` prints a discovery handoff with
`listing-not-submitted`; it does not send a listing to an invented API. Keep the
actual verification report with the release record. Run a separately authorized
paid canary and retain its receipt before advertising production settlement as
verified. A hosting cold start can delay requests; do not describe unmeasured
availability or response-time guarantees.

| Public surface | Purpose |
| --- | --- |
| <https://phantom-operator.onrender.com/> | Human-readable landing page and offer |
| <https://phantom-operator.onrender.com/skills/metadata-audit> | Crawlable metadata audit page; POST to the same path to invoke |
| <https://phantom-operator.onrender.com/skills/threat-scan> | Crawlable authorized exposure page; POST to invoke |
| <https://phantom-operator.onrender.com/skills/opsec-score> | Crawlable OPSEC page; POST to invoke |
| <https://phantom-operator.onrender.com/openapi.json> | OpenAPI request, response, price, and consent contract |
| <https://phantom-operator.onrender.com/skills> | Machine-readable runtime tool catalog |
| <https://phantom-operator.onrender.com/manifest> | Runtime manifest with current endpoints and payment receiver |
| <https://phantom-operator.onrender.com/.well-known/x402> | x402 resource and Bazaar discovery metadata |
| <https://phantom-operator.onrender.com/llms.txt> | Agent-readable integration instructions |
| <https://phantom-operator.onrender.com/agent-registration.json> | ERC-8004 registration-file candidate |
| <https://phantom-operator.onrender.com/.well-known/agent-registration.json> | Domain association with confirmed registry identity |
| <https://phantom-operator.onrender.com/robots.txt> | Crawl policy and sitemap reference |
| <https://phantom-operator.onrender.com/sitemap.xml> | Canonical landing and tool page URLs |
| <https://phantom-operator.onrender.com/icon.svg> | Public square image for the agent and tools |
| <https://phantom-operator.onrender.com/terms> | Authorization, payment, and acceptable-use terms |

## ERC-8004 identity and 8004scan

ERC-8004 links a registry NFT identity to an `agentURI` registration file. Hosting
JSON alone does not register an agent. A valid identity is the confirmed pair
`agentRegistry` and `agentId`; do not insert a guessed token ID or copy another
agent's identity. Until confirmed, this deployment emits `registrations:[]` and
does not assert verified reputation.[2]

1. Check for an existing PhantomOperator identity before minting another one.
   Inspect existing transaction receipts and registry `Registered` events for
   the operator's known owner wallets, then check `ownerOf`, `tokenURI`, and
   `getAgentWallet` against the intended agent. Include the requested receiver
   wallet in the search, but remember the identity owner and payment receiver
   can differ. Search supported explorers as a convenience and verify any
   candidate on-chain. A name search alone does not prove ownership.
2. Verify the current Base Identity Registry address and deployed contract from
   the official ERC-8004 deployments, and check 8004scan supports that deployment.
   8004scan documents support only for the deployments linked from the official
   contracts repository; a custom contract may not be indexed.[3][4]
3. If an owned identity already represents this agent, prepare an update to its
   `agentURI` if needed. If no existing identity applies, prepare a new unsigned
   proposal. The following requires verified public registry and owner
   addresses; it does not connect to an RPC, load a wallet, sign, or send:

   ```bash
   npm run prepare-registration -- \
     --registry "$VERIFIED_BASE_IDENTITY_REGISTRY" \
     --owner "$VERIFIED_AGENT_OWNER" \
     --agent-uri https://phantom-operator.onrender.com/agent-registration.json \
     --service-url https://phantom-operator.onrender.com \
     --output /tmp/phantom-operator-registration-proposal.json
   ```

4. Review the exact proposed transaction, network, registration file, owner,
   and gas in the operator's wallet before any future signing. The preparation
   command only prepares `register(string)`; it does not discover an existing
   identity or replace the duplicate check. An update to an existing identity
   instead uses the standard owner's `setAgentURI` operation.
5. Only after a confirmed registration or verified existing identity, record the
   real `Registered` event ID. Set `AGENT_ID` and
   `AGENT_REGISTRY=eip155:8453:<verified-identity-registry-address>` in the deployed
   service so the hosted registration file and well-known association agree.
   Recheck `ownerOf`, `tokenURI`, and the live documents.
6. Check `getAgentWallet`. The registry initially associates the transaction
   sender as the agent wallet. If that differs from the requested USDC receiver,
   use the standard `setAgentWallet` proof-of-control flow; a JSON field cannot
   change it. Keep payment recipient association accurate.[2]
7. Verify that 8004scan has indexed the confirmed identity and resolves the
   production services. Record the actual explorer URL then. Indexer delay or
   admission rules can prevent immediate display. Do not invent a profile URL,
   stars, trust badge, ranking, feedback, or expected indexing time.

Collect genuine customer feedback only after real use. Registration is discovery
infrastructure; it does not establish capability quality or a safety endorsement.
Do not manufacture reputation events or submit feedback as the agent's owner.[2]

## x402 discovery and community directories

The official x402 README points to the following **community-maintained**
directories. This verifies their mention by the project; it does not establish
that any directory has accepted or endorsed PhantomOperator.[5]

| Destination | Handoff and follow-through |
| --- | --- |
| [x402scan](https://x402scan.com) | Check its current add-service or crawl process; provide the production origin, resource URLs, and OpenAPI. Verify the resulting record. |
| [Agentic.Market](https://agentic.market) | Inspect its current provider submission flow and supply the same verified offer and endpoints. |
| [Pay.sh](https://pay.sh) | Check current service eligibility and contribution instructions before submitting. |
| [Ampersend Discover](https://app.ampersend.ai/discover) | Inspect its current catalog intake or discovery requirements and confirm actual inclusion. |
| [x402-list](https://x402-list.com) | Check the current listing form or contribution flow; retain the accepted listing URL. |

No form, fee, account requirement, approval deadline, or submission API for these
sites was verified in this preparation. Their public domains could not be opened
from the preparation environment because its network proxy returned 403; the
links above were verified in official source. Inspect each current intake flow
before any future submission. Use the reusable description and public URLs above
without exposing assessment targets or personal reports.

For Bazaar discovery, the service advertises `extensions.bazaar` with method,
input schema, and illustrative output in each 402 challenge. A compatible paying
client must echo the extension in its `PaymentPayload`; a supporting facilitator
can validate and catalog it. An omitted extension prevents this discovery path.
Storage and indexing are facilitator-specific, and discovery endpoints such as
`GET /discovery/resources` are optional. There is no verified universal
`POST /bazaar/listings` submission API.[6]

The configured facilitator's successful payment verification is separate from
Bazaar indexing support. Check its documentation and actual discovery result;
inspect any `EXTENSION-RESPONSES` Bazaar status if available. An HTTP 402, a
well-known document, or one settled payment does not guarantee placement in all
five directories. Record each destination as `not submitted`, `submitted`,
`accepted`, or `verified live`, with its real URL and observation date.

## Bankr contribution packet

The likely intended platform is [Bankr](https://bankr.bot), whose official skills
repository is [BankrBot/skills](https://github.com/BankrBot/skills). The older
`BankrBot/openclaw-skills` raw README resolves to the same current instructions.
Use the canonical repository named in those instructions; do not assume a
separate `Banker.bot` service has been integrated.[1]

The prepared folder is
[`integrations/bankr/phantom-operator`](../integrations/bankr/phantom-operator).
Its `SKILL.md` supplies the required `name` and `description` frontmatter, tool
contract, consent rules, usage examples, payment checks, and honest limitations.
Its `catalog.json` uses `schemaVersion:1`, matching folder/slug/repoPath, the real
production provider URL, an unpaid curl demo, setup steps, and the prescribed
Bankr install-command form. The command names the **proposed** upstream path and
cannot be presented as installable until that contribution exists there.

The official README requires a valid `catalog.json` for Discover inclusion and
recommends a square logo. The packet bundles the service's `public/icon.svg` as
`logo.svg`, and `catalog.json` points to that local file. Its structure follows
the official example and the existing BlueAgent catalog.[1][7]

After production verification, copy the folder to the root of a fork of the
official skills repository. Ensure the slug and paths still match, run that
repository's current validation, and open a contribution PR describing the three
tools and payment behavior. Include the verified production URL and unpaid demo,
and describe any unverified paid-client compatibility. A PR requires maintainer
acceptance; it is not a guarantee of Bankr catalog display or tool execution.
This repository contains the packet only: **no PR or catalog submission has been
made by preparing it**.

Suggested contribution title: `Add PhantomOperator metadata and privacy tools`.

Suggested contribution description:

> Adds PhantomOperator, three HTTP JSON tools for HTML metadata audits and
> consent-based public-web exposure assessments. Uses x402 v2 exact payments
> in USDC on Base at 0.05 / 0.10 / 0.25 USDC per successful call. Includes
> request examples, payment-recipient checks, consent requirements, source
> coverage limitations, and an unpaid 402 demo. Production contract:
> https://phantom-operator.onrender.com/openapi.json. Paid execution and settlement
> should be verified separately; the included demo does not sign or pay.

## Search visibility and demand validation

The landing page and three tool pages supply crawlable HTML, canonical URLs,
descriptions, social metadata, structured service data, an actual SVG icon,
robots/sitemap, and machine-readable integration documents. Keep these URLs
stable and their claims consistent with the live runtime. `llms.txt` helps agents
read the contract; it does not guarantee inclusion in an AI model's answers.

1. After deployment checks pass, verify the production site's ownership in
   Google Search Console and Bing Webmaster Tools and submit the live sitemap
   through their current account flows. Check indexing and canonical selection
   rather than assuming a sitemap forces a ranking.
2. Publish one reproducible audit of an owned or authorized public page: request,
   observed headers/HTML, timestamp, source evidence, remediation, and a second
   observation after a fix. Label examples and redact any personal data. Link to
   the corresponding tool page and OpenAPI. Do not fabricate customer results.
3. Use the same concrete offer in relevant directories and developer channels.
   Start with agents maintaining public websites and authorized privacy
   consultants who can act on the returned evidence. A future announcement can
   lead with the 0.05 USDC metadata audit and show a real report. Drafting this
   packet does not publish or message anyone.
4. Review actual page impressions, qualified visits, unpaid challenges,
   successful settlements, repeat paying callers, failures, support/refund
   costs, and net revenue. Derive payment counts from confirmed successful
   settlement records and deduplicate transaction hashes; HTTP requests are not
   sales. Keep target names, emails, and report contents out of analytics.
5. Compare paid conversion and repeat use across the three tools before adding
   more capabilities. Gross receipts are the call count times its listed price;
   net income depends on hosting, search providers, facilitator/network costs,
   refunds, and demand. Listing and SEO work cannot guarantee customers or
   income.

## Primary sources

Sources checked 2026-10-23 against accessible upstream source. Recheck current
requirements before registration or contribution because protocols and catalog
rules can change.

1. [Bankr Skills README: adding a skill and listed providers](https://github.com/BankrBot/skills/blob/main/README.md#adding-a-skill).
2. [ERC-8004 specification: identity, domain association, agent wallet, and feedback](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-8004.md); [published EIP](https://eips.ethereum.org/EIPS/eip-8004).
3. [Official ERC-8004 deployed contracts](https://github.com/erc-8004/erc-8004-contracts#contract-addresses).
4. [8004scan official issue tracker and supported deployments](https://github.com/alt-research/8004scan-issue-tracker).
5. [Official x402 README: ecosystem directories](https://github.com/coinbase/x402#ecosystem).
6. [Official x402 Bazaar extension specification](https://github.com/coinbase/x402/blob/main/specs/extensions/bazaar.md).
7. [Bankr's BlueAgent catalog example](https://github.com/BankrBot/skills/blob/main/blueagent/catalog.json) and [skill instructions](https://github.com/BankrBot/skills/blob/main/blueagent/SKILL.md).

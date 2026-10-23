---
name: phantom-operator
description: >
  Inspect public HTML metadata and HTTP headers, triage authorized public-web
  exposure, and produce evidence-based OPSEC assessments. Three HTTP tools paid
  per successful call through x402 v2 exact in USDC on Base. Use for metadata
  privacy audits or consent-based exposure checks with source links and remediation.
---

# PhantomOperator

Base URL: `https://phantom-operator.onrender.com`

Contribution status: **prepared; not submitted or approved by Bankr**. The catalog's
Bankr install URL is the proposed upstream destination and becomes available only
after an accepted contribution is merged there.

## Choose a tool

| Tool | Method and path | Price | JSON body |
| --- | --- | --- | --- |
| Metadata Audit | `POST /skills/metadata-audit` | 0.05 USDC | `{"url":"https://example.com"}` |
| Threat Scan | `POST /skills/threat-scan` | 0.10 USDC | `{"fullName":"Jane Example","consent":true}` |
| OPSEC Exposure Score | `POST /skills/opsec-score` | 0.25 USDC | `{"handle":"janeexample","consent":true}` |

`opsec-score` accepts one or more of `fullName`, `handle`, and `email`, plus
`consent:true`. `threat-scan` requires `fullName` and `consent:true`. Obtain the
user's confirmation that the subject is themselves or explicitly authorized the
assessment before sending either personal-exposure request. Do not infer consent
from a person's public profile. Use only public pages the user is authorized to
assess and follow the [terms](https://phantom-operator.onrender.com/terms).

Metadata Audit examines static HTML and response headers for metadata exposure,
software fingerprints, third-party references, and missing security headers.
It does not inspect image EXIF or execute page JavaScript. Threat Scan classifies
search-result snippets; name matches do not establish identity. OPSEC scores are
heuristics and include source coverage and remediation. Preserve partial-coverage
warnings when reporting results. None of these tools removes data, performs a paid
email-breach lookup, or guarantees privacy.

## Discover the live contract

Read the public [skill catalog](https://phantom-operator.onrender.com/skills) and
[OpenAPI document](https://phantom-operator.onrender.com/openapi.json) before a
paid call. The [agent instructions](https://phantom-operator.onrender.com/llms.txt)
and [x402 resources](https://phantom-operator.onrender.com/.well-known/x402) are
also public. This integration uses HTTP JSON; it does not provide an MCP server
or an A2A endpoint.

Start with an unpaid challenge. This command does not authorize payment or run
the audit:

```bash
curl -i --max-time 60 \
  -X POST https://phantom-operator.onrender.com/skills/metadata-audit \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://example.com"}'
```

Expected response: HTTP `402`, an x402 v2 JSON challenge, and a base64-encoded
`PAYMENT-REQUIRED` header. An old deployment or unavailable service may return a
different result; stop and inspect that response before paying.

## Pay for one authorized request

Use an existing x402 v2 `exact` client and a wallet capability that the user has
authorized for the quoted amount. This skill does not install or create a wallet.
Never request or include a private key or seed phrase in prompts or HTTP bodies.

1. Send the intended JSON request without a payment header.
2. Inspect the challenge and require `x402Version:2`, `scheme:"exact"`, network
   `eip155:8453` (Base mainnet), USDC asset
   `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, and receiver
   `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6`. The expected six-decimal
   amounts are `50000`, `100000`, and `250000`, respectively. Stop if the quote
   differs from the user's authorization.
3. Let the compatible client construct the payment authorization. Preserve the
   advertised resource and echo the `extensions.bazaar` object into the payment
   payload so a supporting facilitator can catalog the endpoint. Do not fabricate
   a signature, transaction hash, or payment receipt.
4. Retry the same endpoint and body with the client's base64 payment payload in
   `PAYMENT-SIGNATURE`. `X-PAYMENT` is an accepted alternate header, but the
   payload must still use v2. Do not send an arbitrary ERC-20 transfer as a
   substitute for the protocol.
5. A successful call returns `{ "skill": "...", "result": ... }` and a
   `PAYMENT-RESPONSE` settlement receipt. Keep source links, risk reasons,
   observation time, coverage limits, and suggested remediation in the answer.

An unpaid 402 proves a quote is available; it does not prove execution,
settlement, or directory indexing. A `400` means fix the request or consent.
Respect `429` and `Retry-After`. If settlement is pending or a request times out
after payment authorization, inspect the wallet and any returned transaction
before retrying to avoid paying twice. Report an unsupported payment capability
instead of claiming a paid call succeeded.

## Agent identity and claims

[Registration metadata](https://phantom-operator.onrender.com/agent-registration.json)
advertises the service. An empty `registrations` list means no on-chain identity
is declared. A real ERC-8004 identity requires a confirmed registry record and a
matching domain association; verify any advertised identity independently. Do not
claim Bankr approval, registry endorsement, ranking, ratings, unique invention,
complete coverage, or guaranteed earnings from these files.

# Website Privacy Baseline — launch specification

**Status:** internal launch specification. Do not advertise as card-purchasable until Stripe Checkout, webhook crediting, redemption, and delivery are verified in production.

## Customer promise

A fixed-scope review of the information a public website reveals to ordinary visitors and automated clients, with prioritized practical remediation.

This is a public-exposure and privacy-baseline review. It is **not** a penetration test, guarantee of anonymity, compliance certification, malware scan, authenticated application assessment, or a promise that data will disappear from the internet.

## Recommended initial offer

| Field | Launch value |
| --- | --- |
| Name | Website Privacy Baseline |
| Target | One public HTTP/HTTPS website origin, supplied by its owner or an authorized representative |
| Launch price | **$19 USD** fixed price after card credits are live; Base-USDC/x402 may be offered separately to agent clients |
| Delivery | Immediate structured report plus prioritized mitigation checklist |
| Repeat review | A new purchase is required after material changes or a new target URL |

The initial $19 price is a product decision recommendation, not a currently available checkout price.

## Report contents

Only include observations that PhantomOperator can support from the public target at execution time:

1. Target URL, redirect outcome, and report timestamp.
2. Public HTTP response headers that disclose technology or weaken common privacy/security posture.
3. Public HTML metadata such as generator/author markers and exposed comments.
4. Detected third-party trackers and externally loaded resources when observable from the fetched page.
5. Plain-language risk classification with evidence and prioritized remediation actions.
6. Scope and limitations, including inaccessible pages, bot blocks, redirects, and items not assessed.

## Safety and authorization controls

- Accept only a public `http` or `https` URL.
- Customer must confirm they own the target or have authorization to assess it.
- Do not crawl private networks, localhost, link-local addresses, authenticated pages, or arbitrary discovered URLs.
- Do not accept passwords, session cookies, API keys, seed phrases, or payment credentials.
- Do not submit data-removal or takedown requests as part of this product.

## Checkout and fulfillment requirements

Before public card marketing:

1. Stripe Checkout must create a purchase only within configured $0.50–$500 bounds.
2. Stripe must deliver a verified `checkout.session.completed` or `checkout.session.async_payment_succeeded` webhook.
3. Credit fulfillment must be durable and idempotent.
4. The purchaser must be able to check their credit balance.
5. A redeemed audit must atomically debit one fixed product credit and restore it if execution fails.
6. Success/cancel pages and support instructions must be clear about storing the bearer credit token securely.

## Human-facing copy

> See what your public website reveals before someone else does. PhantomOperator checks public metadata, headers, trackers, and exposure signals, then returns a focused remediation checklist. Assess only sites you own or are authorized to review.

## Agent-facing relationship

The human offer is a packaged version of the same public-metadata discipline as `POST /skills/metadata-audit`. Agents should use the canonical OpenAPI/x402 interface and should not infer that the $19 human package changes the existing $0.05 Base-USDC x402 endpoint price.

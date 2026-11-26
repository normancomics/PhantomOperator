# PhantomOperator quickstart

PhantomOperator provides authorized public-exposure and privacy checks for people and agents.

- **Human website check:** [Free Website Privacy Preview](https://freysaai.freysa.dev/free-website-privacy-preview)
- **Human fixed-scope audit:** [$19 Website Privacy Baseline](https://freysaai.freysa.dev/website-privacy-baseline)
- **Agent/API discovery:** [OpenAPI](https://freysaai.freysa.dev/openapi.json), [x402 requirements](https://freysaai.freysa.dev/.well-known/x402), [MCP](https://freysaai.freysa.dev/mcp), and [A2A agent card](https://freysaai.freysa.dev/.well-known/agent-card.json)

Use only on public targets you own or are explicitly authorized to assess. Do not submit secrets, private keys, passwords, or another person’s personal data without permission.

## 1. Run a free website privacy preview

```bash
curl -sS https://freysaai.freysa.dev/preview/metadata-audit \
  -X POST \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com"}'
```

The free, rate-limited preview returns a limited set of public signals from headers, metadata, HTML comments, and tracker discovery.

## 2. Request exact x402 payment terms for the complete API audit

```bash
curl -i https://freysaai.freysa.dev/skills/metadata-audit \
  -X POST \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com"}'
```

The first response returns payment requirements for Base native USDC through x402. Review those exact terms before authorizing a payment. The metadata audit is currently listed at **$0.05 USDC**.

## 3. Use the MCP endpoint

The MCP endpoint is:

```text
https://freysaai.freysa.dev/mcp
```

Discover the current tool list through MCP `tools/list`. API builders can use the OpenAPI document for request and response schemas.

## Human checkout

The Website Privacy Baseline is a one-time **$19** Stripe Checkout offer. It covers one authorized public website and returns a prioritized remediation checklist after payment confirmation. The page stores the receipt token in the browser so the report can run automatically when Stripe’s webhook settles.

## Links

- Website: https://freysaai.freysa.dev
- Free preview: https://freysaai.freysa.dev/free-website-privacy-preview
- $19 baseline: https://freysaai.freysa.dev/website-privacy-baseline
- OpenAPI: https://freysaai.freysa.dev/openapi.json
- x402: https://freysaai.freysa.dev/.well-known/x402
- Agent Card: https://freysaai.freysa.dev/.well-known/agent-card.json
- X: https://x.com/phntmop

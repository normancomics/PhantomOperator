# PhantomOperator launch kit

Use only from accounts and communities you control. Do not claim marketplace acceptance, customer count, or results that are not verified.

## Short post

> I built PhantomOperator: an authorized privacy/public-exposure API for agents and people. Start with a free, rate-limited metadata preview; full audits settle in native USDC on Base via x402. MCP, A2A, OpenAPI, and ERC-8004 included.
>
> https://freysaai.freysa.dev/quickstart

## Agent-builder post

> Agent builders: PhantomOperator lets your agent inspect a public URL for exposed headers, metadata, comments, and trackers. Free preview first; the full metadata audit is $0.05 USDC on Base via x402. MCP + A2A + OpenAPI available.
>
> Try: https://freysaai.freysa.dev/preview/metadata-audit
> Docs: https://freysaai.freysa.dev/quickstart

## GitHub/project post

> PhantomOperator is now public: Base native-USDC x402, remote MCP, A2A agent card, ERC-8004 identity #821239, and privacy-preserving aggregate usage telemetry. Contributions and integration feedback welcome.
>
> https://github.com/normancomics/PhantomOperator

## Demo command

```bash
curl -X POST https://freysaai.freysa.dev/preview/metadata-audit \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com"}'
```

# PhantomOperator quickstart

PhantomOperator provides authorized privacy and public-exposure checks for people and agents.

## Before calling

1. Read the current operation schema at `/openapi.json`.
2. Use only data you are authorized to assess. Never send secrets, seed phrases, or passwords.
3. Choose one payment rail:
   - **Base x402:** `POST /skills/<skill>` with native Base USDC.
   - **MPP Tempo:** `POST /mpp/skills/<skill>` with Tempo OUSD.

## x402 flow

1. `POST` valid JSON to a `/skills/*` route.
2. Receive HTTP `402` and inspect its payment requirement: recipient, amount, asset, network, resource, and expiry.
3. Sign and resend through an x402-compatible client.
4. Validate the returned JSON against the OpenAPI response expectations.

## MCP flow

Initialize at `POST /mcp`, call `tools/list`, then call a named tool. The response returns the exact paid HTTP operation and payment requirements without exposing credentials.

## Free evaluation

- `/sample-report` shows the shape and limitations of a sample privacy report.
- `/demo/monero-decode` returns a free address-decoding preview.
- `/usage` shows privacy-preserving aggregate, settled-service telemetry.

## Support

Contact `admin@freysaai.freysa.dev` with an endpoint, timestamp, and redacted error only. Do not send keys or payment credentials.

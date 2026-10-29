# Test PhantomOperator without spending money

## 1. Human/browser test: free metadata preview

Open [https://freysaai.freysa.dev](https://freysaai.freysa.dev), leave `metadata-audit` selected, replace the example URL with a public URL you control (for example `https://example.com`), and click **Try free metadata preview**.

The preview is rate-limited and intentionally redacts/truncates output. A successful preview exposes a **View full-audit payment terms** button but does not create a payment.

Equivalent API request:

```bash
curl -sS -X POST https://freysaai.freysa.dev/preview/metadata-audit \
  -H 'content-type: application/json' \
  --data '{"url":"https://example.com"}'
```

## 2. Agent/payment integration test: free x402 challenge

This verifies the public discovery and payment requirement without signing, transferring, or spending anything. Use a valid request body and omit payment credentials:

```bash
curl -i -X POST https://freysaai.freysa.dev/skills/metadata-audit \
  -H 'content-type: application/json' \
  --data '{"url":"https://example.com"}'
```

Expected result: **HTTP 402 Payment Required** with the exact Base-USDC x402 requirement. Receiving a 402 is success for this no-cost test.

Also inspect the machine-readable contracts:

```bash
curl -sS https://freysaai.freysa.dev/.well-known/x402
curl -sS https://freysaai.freysa.dev/openapi.json
curl -sS https://freysaai.freysa.dev/status
```

## 3. Local regression test: no real payment or wallet required

Clone the repository, install dependencies, then run:

```bash
npm ci
npm test
```

The test starts a local server and verifies health, OpenAPI, x402 discovery, unpaid 402 behavior, robots/sitemap, and Monero-address decoding. It does not send a Base transaction or require a wallet.

Do **not** set `TEST_RECEIVER_ADDRESS` when running the test unless you intentionally want to run the legacy optional on-chain demo.

## 4. What requires payment

A complete production paid-report settlement requires a compatible x402 client, Base-mainnet USDC, and an exact payment authorization. Do not use a raw ERC-20 transfer as a substitute. The free preview, 402 challenge, and local regression test above are sufficient to validate the public user experience and integration contract without spending funds.

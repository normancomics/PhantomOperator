# PhantomOperator privacy model

PhantomOperator is an **authorized assessment service**, not an anonymity system. This page states what the application is designed to minimize, what it does not protect, and how to use it conservatively.

## Data minimization by feature

- **Website metadata preview/audit:** PhantomOperator requests the public URL supplied by the user. The destination website can observe a request from PhantomOperator's server. Use a URL you are authorized to assess; do not use this service to probe private or internal systems.
- **Breach and OPSEC checks:** Send only data you are authorized to assess. Never submit passwords, seed phrases, private keys, recovery phrases, or a third party's personal data without authorization.
- **Aggregate usage page:** `/usage` publishes aggregate settled-call counts and totals. It does not expose request bodies, raw IP addresses, wallet addresses, credit credentials, or payment credentials.
- **Application results:** skill requests are processed to generate a response. PhantomOperator does not intentionally add request bodies to its aggregate telemetry. Deployment-layer logs, reverse proxies, clients, external target websites, and third-party data sources may have their own logging and retention policies.

## Monero boundaries

The Monero tooling is intentionally constrained.

- Address decoding and OPSEC guidance operate on a supplied public address.
- Optional Monero invoices use a **view-only** `monero-wallet-rpc` to create subaddresses and verify confirmed incoming payments.
- PhantomOperator never asks for, stores, or needs a Monero spend key or seed phrase.
- An invoice store necessarily retains invoice metadata such as route, subaddress, amount, expiry, confirmation state, transaction ID after confirmation, and a hash of the associated request body until an operator deletes or rotates it.
- A Monero address, subaddress, payment, remote node, wallet RPC host, network connection, browser, or server should not be assumed anonymous merely because Monero is used.

## What PhantomOperator does not promise

It does not promise anonymity, invisibility, removal from every data broker, complete breach coverage, legal outcomes, account recovery, transaction unlinkability, or protection against a compromised device, browser, network, remote node, or wallet.

## Safer operating practices

1. Prefer the self-hosted code path for sensitive internal workflows.
2. Review source and deploy with your own reverse-proxy, logging, retention, and network policies.
3. Keep Monero wallet RPC private and view-only; bind it to localhost or an authenticated private network.
4. Use a trusted local Monero node or independently chosen remote node when node privacy matters.
5. Verify payment destination, exact amount, chain, token contract, and response schema before making any payment.
6. Treat any public token airdrop, unknown NFT, unsolicited link, or wallet approval as untrusted.

## Reporting and contact

Report a security issue privately to `admin@freysaai.freysa.dev`. Do not include secrets in email. For general product updates, see [@phntmop](https://x.com/phntmop).

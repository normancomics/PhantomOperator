# PhantomOperator: Terms of Use and Acceptable Use

By calling any PhantomOperator endpoint you agree to these terms.

## Permitted use
- **threat-scan**, **opsec-score**, **breach-check**, **data-removal**, and **full-privacy-sweep** may only be run on **yourself**, or on a person or organization that has **explicitly authorized you** to assess their exposure (for example, a red-team, PERSEC, or client security engagement).
- **metadata-audit**, **monero-opsec-audit**, and **wallet-opsec-audit** may be run on web pages, `$XMR` Monero addresses/transactions, or EVM addresses you own, operate, or are evaluating for legitimate privacy, counterparty hygiene, and security review.

## Prohibited use
- Stalking, harassment, doxxing, or locating, tracking or profiling anyone without their consent.
- Building dossiers on private individuals, or reselling results about third parties.
- Any use that violates applicable law, including privacy and data-protection laws (GDPR, CCPA/CPRA, California Delete Act SB 362) and anti-stalking laws.
- Attempting to probe private networks, overload the service, or evade rate limits.

## What the service does
- Reads **publicly available** web data, public breach intelligence APIs (XposedOrNot + HIBP k-anonymity SHA-1 prefix range checks), public blockchain/Monero explorers, and direct HTTP fetches of URLs you supply.
- Results are heuristic and cryptographic assessments; nothing here constitutes legal or financial advice.
- Requests are processed in memory and are not persisted.

## Payments
- Paid calls use the **x402 protocol** (USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` on Base mainnet `eip155:8453`, settled to `0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6` via `https://api.cdp.coinbase.com/platform/v2/x402`).
- Payment is settled only after a successful response (`HTTP 200`). Invalid input and server errors are not charged.
- All settled payments are final.

Contact: https://github.com/normancomics/PhantomOperator/issues

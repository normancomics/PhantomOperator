#!/usr/bin/env node
/**
 * Verify this merchant's current public Coinbase x402 Bazaar discovery entries.
 *
 * Bazaar discovery is automatic: a resource becomes eligible after a successful
 * CDP-facilitated settlement that includes Bazaar metadata. No CDP secret or
 * listing form is required for this read-only verification.
 *
 * Usage:
 *   node scripts/list-on-bazaar.js
 *   BAZAAR_PAY_TO=0x... node scripts/list-on-bazaar.js
 */
'use strict';

const PAY_TO = process.env.BAZAAR_PAY_TO || '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';
const ENDPOINT = `https://api.cdp.coinbase.com/platform/v2/x402/discovery/merchant?payTo=${encodeURIComponent(PAY_TO)}`;

async function main() {
  const response = await fetch(ENDPOINT, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`Bazaar lookup failed: HTTP ${response.status}`);

  const catalog = await response.json();
  const resources = catalog.resources || [];
  console.log(`Coinbase x402 Bazaar resources for ${catalog.payTo || PAY_TO}: ${resources.length}`);
  for (const item of resources) {
    const accept = item.accepts?.[0] || {};
    const quality = item.quality || {};
    console.log(`\n- ${item.resource}`);
    console.log(`  ${accept.network || 'unknown network'} | ${accept.amount || '?'} base units | ${accept.asset || 'unknown asset'}`);
    console.log(`  ${quality.l30DaysTotalCalls ?? 0} calls / ${quality.l30DaysUniquePayers ?? 0} unique payers in the last 30 days`);
    console.log(`  Last updated: ${item.lastUpdated || 'unknown'}`);
  }

  if (resources.length === 0) {
    console.log('\nNo resources are currently indexed. Confirm a real x402 settlement through the CDP facilitator, then allow up to 10 minutes for discovery caching.');
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});

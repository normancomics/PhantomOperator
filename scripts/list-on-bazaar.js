#!/usr/bin/env node
'use strict';
const base = process.argv[2] || process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || process.env.AGENT_SERVER_URL;
if (!base) {
  console.error('Usage: npm run list-bazaar -- https://YOUR-SERVICE');
  console.error('This command describes discovery metadata; it does not submit a listing or request credentials. See docs/DISCOVERY-LAUNCH.md.');
  process.exitCode = 1;
} else {
  try {
    const origin = new URL(base);
    if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('Use the HTTPS service origin without credentials, path or query');
    console.log(JSON.stringify({ status: 'listing-not-submitted', name: 'PhantomOperator', discovery: origin.origin + '/.well-known/x402', openapi: origin.origin + '/openapi.json', manifest: origin.origin + '/manifest', note: 'Bazaar discovery uses the x402 bazaar extension and an indexing facilitator. A compatible paying client must echo that extension. There is no verified universal POST /bazaar/listings API. Verify actual indexing separately.' }, null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

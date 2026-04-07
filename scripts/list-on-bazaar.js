#!/usr/bin/env node
/**
 * scripts/list-on-bazaar.js
 *
 * Step 6: Submit this agent to the Coinbase CDP x402 Bazaar.
 *
 * The Bazaar is a public directory of x402-compatible agents. Listing here
 * makes your agent discoverable and callable by other agents on the network.
 *
 * Prerequisites:
 *   - Complete Steps 2-5 first (run scripts/register.js, then node server.js)
 *   - Set CDP_API_KEY_NAME and CDP_API_KEY_PRIVATE_KEY in .env
 *     (get these from https://portal.cdp.coinbase.com)
 *   - Set AGENT_SERVER_URL to the public URL of your running server.js
 *     (e.g., https://your-domain.com or a tunneled URL like https://abc123.ngrok.io)
 *
 * Docs: https://docs.cdp.coinbase.com/x402/bazaar
 */
require('dotenv').config();
const axios = require('axios');
const manifest = require('../agent-manifest.json');

const CDP_BAZAAR_API = 'https://api.cdp.coinbase.com/platform/x402/v1/bazaar/listings';
const AGENT_SERVER_URL = process.env.AGENT_SERVER_URL;
const CDP_API_KEY_NAME = process.env.CDP_API_KEY_NAME;
const CDP_API_KEY_PRIVATE_KEY = process.env.CDP_API_KEY_PRIVATE_KEY;

async function main() {
  if (!AGENT_SERVER_URL) {
    console.error('ERROR: AGENT_SERVER_URL is not set.');
    console.error('This should be the public URL where your server.js is running.');
    console.error('Example: https://your-domain.com or https://abc123.ngrok.io');
    process.exit(1);
  }
  if (!CDP_API_KEY_NAME || !CDP_API_KEY_PRIVATE_KEY) {
    console.error('ERROR: CDP_API_KEY_NAME and CDP_API_KEY_PRIVATE_KEY are not set.');
    console.error('Get your CDP API key at https://portal.cdp.coinbase.com');
    process.exit(1);
  }

  const listing = {
    name: manifest.name,
    description: manifest.description,
    url: AGENT_SERVER_URL,
    manifestUrl: `${AGENT_SERVER_URL}/manifest`,
    skills: manifest.skills.map(s => ({
      id: s.id,
      name: s.name,
      description: s.description,
      endpoint: `${AGENT_SERVER_URL}/skills/${s.id}`,
      pricing: s.pricing,
      tags: s.tags,
    })),
    payment: manifest.payment,
    chainId: manifest.chainId,
    author: manifest.author,
    version: manifest.version,
    website: manifest.website,
  };

  console.log('=== Listing on CDP x402 Bazaar ===');
  console.log('Agent URL:', AGENT_SERVER_URL);
  console.log('Submitting listing...');
  console.log('');

  try {
    // CDP uses API key authentication via a signed JWT or API key header.
    // The exact auth scheme depends on your CDP key type.
    // Here we use the API key name + private key pattern from Coinbase CDP docs.
    const { data } = await axios.post(CDP_BAZAAR_API, listing, {
      headers: {
        'Content-Type': 'application/json',
        // CDP API key auth header — adjust if your key type uses a different scheme
        'X-Api-Key': CDP_API_KEY_NAME,
        'X-Api-Secret': CDP_API_KEY_PRIVATE_KEY,
      },
      timeout: 20000,
    });

    console.log('✅ Listed on CDP Bazaar!');
    console.log('  Listing ID:', data.id || data.listingId);
    console.log('  View at: https://docs.cdp.coinbase.com/x402/bazaar');
    console.log('  Direct URL:', data.url || `${CDP_BAZAAR_API}/${data.id}`);
  } catch (err) {
    if (err.response) {
      console.error('❌ CDP Bazaar listing failed.');
      console.error('  Status:', err.response.status);
      console.error('  Body:', JSON.stringify(err.response.data, null, 2));
      console.error('');
      console.error('  Check the CDP Bazaar docs at https://docs.cdp.coinbase.com/x402/bazaar');
      console.error('  and verify your CDP_API_KEY_NAME and CDP_API_KEY_PRIVATE_KEY are correct.');
    } else {
      console.error('❌ Request failed:', err.message);
    }
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

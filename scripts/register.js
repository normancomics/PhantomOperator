#!/usr/bin/env node
/**
 * scripts/register.js
 *
 * End-to-end agent registration script. Run once after deploying:
 *
 *   node scripts/register.js
 *
 * Prerequisites:
 *   1. Copy .env.example to .env and fill in all values.
 *   2. The wallet at PRIVATE_KEY must hold enough ETH on Base mainnet to pay gas
 *      for two transactions (registerAgent + initializeAgent).
 *
 * What this script does:
 *   Step 2 — Registers the agent address in the Base Identity Registry
 *   Step 3 — Initializes the agent in the Base Reputation Registry
 *   Step 4 — Registers the agent profile and all skills on CryptoSkill
 *   Step 7 — Reads back on-chain state to verify registration succeeded
 */
require('dotenv').config();
const { ethers } = require('ethers');
const { registerIdentity, initializeReputation, getReputation, getIdentity } = require('../services/RegistryService');
const { registerAgent: csRegisterAgent, publishSkill } = require('../services/CryptoSkillService');
const manifest = require('../agent-manifest.json');

const AGENT_METADATA_URI = process.env.AGENT_METADATA_URI;

async function main() {
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    console.error('ERROR: PRIVATE_KEY is not set. Add it to your .env file.');
    process.exit(1);
  }
  if (!AGENT_METADATA_URI) {
    console.error(
      'ERROR: AGENT_METADATA_URI is not set.\n' +
      'This should be the public URL (or IPFS CID) of your agent-manifest.json.\n' +
      'Example: https://raw.githubusercontent.com/normancomics/sovereignagent/main/agent-manifest.json\n' +
      'Set AGENT_METADATA_URI in your .env file and re-run.'
    );
    process.exit(1);
  }

  const wallet = new ethers.Wallet(privateKey);
  const agentAddress = wallet.address;
  console.log('=== SovereignAgent Registration ===');
  console.log('Agent wallet:', agentAddress);
  console.log('Metadata URI:', AGENT_METADATA_URI);
  console.log('Chain: Base mainnet (8453)');
  console.log('');

  // ── Step 2: Base Identity Registry ──────────────────────────────────────────
  console.log('── Step 2: Registering with Base Identity Registry ──');
  console.log(`  Contract: ${manifest.registries.identityRegistry}`);
  let identityTxHash;
  try {
    identityTxHash = await registerIdentity(AGENT_METADATA_URI);
    if (identityTxHash) {
      console.log(`  ✅ Identity registered. Tx: https://basescan.org/tx/${identityTxHash}`);
    }
  } catch (err) {
    console.error('  ❌ Identity registration failed:', err.message);
    console.error('  Tip: Ensure RPC_URL points to Base mainnet and your wallet has ETH for gas.');
    process.exit(1);
  }
  console.log('');

  // ── Step 3: Base Reputation Registry ────────────────────────────────────────
  console.log('── Step 3: Initializing Base Reputation Registry ──');
  console.log(`  Contract: ${manifest.registries.reputationRegistry}`);
  try {
    const repTxHash = await initializeReputation();
    if (repTxHash) {
      console.log(`  ✅ Reputation initialized. Tx: https://basescan.org/tx/${repTxHash}`);
    }
  } catch (err) {
    console.error('  ❌ Reputation initialization failed:', err.message);
    process.exit(1);
  }
  console.log('');

  // ── Step 4: CryptoSkill ──────────────────────────────────────────────────────
  if (!process.env.CRYPTOSKILL_API_KEY) {
    console.log('── Step 4: CryptoSkill ── SKIPPED (CRYPTOSKILL_API_KEY not set)');
    console.log('  Get your API key at https://cryptoskill.org, set CRYPTOSKILL_API_KEY in .env, and re-run.');
    console.log('');
  } else {
    console.log('── Step 4: Registering with CryptoSkill ──');
    try {
      const csAgent = await csRegisterAgent(manifest, agentAddress);
      const csAgentId = csAgent.id || csAgent.agentId;
      console.log(`  ✅ Agent registered on CryptoSkill. ID: ${csAgentId}`);

      for (const skill of manifest.skills) {
        const result = await publishSkill(csAgentId, skill);
        console.log(`  ✅ Skill published: ${skill.id} (CryptoSkill ID: ${result.id || result.skillId})`);
      }
    } catch (err) {
      console.error('  ❌ CryptoSkill registration failed:', err.message);
      if (err.response) {
        console.error('  API response:', JSON.stringify(err.response.data, null, 2));
      }
      console.log('  CryptoSkill registration is non-blocking — on-chain registrations above still succeeded.');
    }
    console.log('');
  }

  // ── Step 7: Verify on-chain ──────────────────────────────────────────────────
  console.log('── Step 7: Verifying on-chain registration ──');
  try {
    const identity = await getIdentity(agentAddress);
    console.log('  Identity Registry:');
    console.log(`    metadataURI:  ${identity.metadataURI}`);
    console.log(`    registeredAt: ${identity.registeredAt}`);
    console.log(`    BaseScan:     https://basescan.org/address/${manifest.registries.identityRegistry}#readContract`);

    const reputation = await getReputation(agentAddress);
    console.log('  Reputation Registry:');
    console.log(`    score:      ${reputation.score}`);
    console.log(`    totalJobs:  ${reputation.totalJobs}`);
    console.log(`    updatedAt:  ${reputation.updatedAt}`);
    console.log(`    BaseScan:   https://basescan.org/address/${manifest.registries.reputationRegistry}#readContract`);
  } catch (err) {
    console.error('  ❌ On-chain verification failed:', err.message);
    console.log('  (This may succeed once the transactions confirm — try running again in ~30 seconds.)');
  }

  console.log('');
  console.log('=== Registration complete ===');
  console.log('Next step (Step 5): Run `node server.js` to start your agent with x402 payment middleware.');
  console.log('Next step (Step 6): List on CDP Bazaar by running `node scripts/list-on-bazaar.js`.');
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

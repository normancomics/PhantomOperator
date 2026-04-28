#!/usr/bin/env node
/**
 * scripts/registerAgent.js
 *
 * Full registration pipeline for PhantomOperator sub-agents:
 *
 *   1. On-chain Identity Registry  (0x8004A169FB4a3325136EB29fA0ceB6D2e539a432, Base mainnet)
 *   2. On-chain Reputation/Skill Registry  (0x8004BAa17C55a88189AE136b182e5fdA19dE9b63, Base mainnet)
 *   3. CryptoSkill.org  (https://cryptoskill.org/)
 *   4. Superfluid x402  (https://x402.superfluid.org/)
 *   5. CDP x402 Bazaar  (https://docs.cdp.coinbase.com/x402/bazaar)
 *
 * Usage:
 *   node scripts/registerAgent.js
 *
 * Required .env vars:
 *   PRIVATE_KEY             — wallet private key (agent owner / signer)
 *   PHANTOM_OPERATOR_ADDRESS — deployed agent wallet address
 *   BASE_RPC_URL            — Base mainnet JSON-RPC (default: https://mainnet.base.org)
 *   AGENT_SERVICE_ENDPOINT  — public HTTPS URL clients will call
 *   CRYPTOSKILL_API_KEY     — CryptoSkill.org API key (if required)
 *   CDP_API_KEY             — Coinbase Developer Platform API key (for Bazaar)
 *
 * Optional .env vars:
 *   X402_FACILITATOR_URL    — override Superfluid x402 facilitator URL
 *   X402_BAZAAR_URL         — override CDP Bazaar base URL
 *   AGENT_METADATA_URI      — IPFS/HTTPS URI to the agent metadata JSON
 *   PRICE_PER_REQUEST       — price in USDCx per request (default: "0.001")
 */

require('dotenv').config();

const { registerIdentity, registerSkill: registerOnChainSkill, getIdentity } = require('../services/RegistryService');
const { registerWithCryptoSkill, registerSkillWithCryptoSkill } = require('../services/SkillRegistryService');
const { registerWithSuperfluidX402, listInX402Bazaar } = require('../services/X402Service');

// ─── Agent configuration ──────────────────────────────────────────────────────

const AGENT_ADDRESS = process.env.PHANTOM_OPERATOR_ADDRESS;
const SERVICE_ENDPOINT = process.env.AGENT_SERVICE_ENDPOINT || '';
const METADATA_URI = process.env.AGENT_METADATA_URI || '';
const PRICE_PER_REQUEST = process.env.PRICE_PER_REQUEST || '0.001';

// Agents and their novel skills to register
const AGENTS = [
  {
    name: 'PhantomOperator/SearchAgent',
    description: 'Automated privacy-threat search agent — scans public web sources for PII exposure and returns a prioritised threat list.',
    skills: [
      {
        name: 'ThreatAnalysis',
        description: 'Searches public sources for exposed PII (phone, email, address) and classifies results by threat level.',
        category: 'privacy',
        metadataURI: METADATA_URI,
      },
      {
        name: 'DuckDuckGoSearch',
        description: 'Structured DuckDuckGo HTML-endpoint search with snippet extraction.',
        category: 'search',
        metadataURI: METADATA_URI,
      },
    ],
  },
  {
    name: 'PhantomOperator/BrokerAgent',
    description: 'Data-broker opt-out automation agent — submits opt-out / removal requests to data brokers on behalf of the user.',
    skills: [
      {
        name: 'DataBrokerOptOut',
        description: 'Automates submission of removal/opt-out requests to data-broker websites.',
        category: 'privacy',
        metadataURI: METADATA_URI,
      },
    ],
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function required(name) {
  const val = process.env[name];
  if (!val) {
    console.error(`ERROR: ${name} is not set in .env — please configure it before running this script.`);
    process.exit(1);
  }
  return val;
}

function step(label) {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`  ${label}`);
  console.log('─'.repeat(60));
}

// ─── Main registration flow ───────────────────────────────────────────────────

async function main() {
  required('PRIVATE_KEY');
  required('PHANTOM_OPERATOR_ADDRESS');

  for (const agent of AGENTS) {
    // ── 1. Check / register on-chain identity ────────────────────────────────
    step(`[1/5] On-chain Identity Registry — ${agent.name}`);
    let agentId;
    try {
      const existing = await getIdentity(AGENT_ADDRESS);
      if (existing && existing.active) {
        console.log(`Identity already registered: agentId=${existing.agentId}`);
        agentId = existing.agentId;
      } else {
        const result = await registerIdentity(agent.name, METADATA_URI);
        agentId = result.agentId;
        console.log(`Identity registered: agentId=${agentId}, tx=${result.txHash}`);
      }
    } catch (err) {
      console.error(`Identity registry step failed: ${err.message || err}`);
      console.warn('Continuing with remaining steps (on-chain agentId will be null).');
      agentId = null;
    }

    // ── 2. Register skills in Reputation Registry ─────────────────────────────
    step(`[2/5] On-chain Reputation/Skill Registry — ${agent.name}`);
    const skillIds = {};
    if (agentId !== null) {
      for (const skill of agent.skills) {
        try {
          const result = await registerOnChainSkill(agentId, skill.name, skill.metadataURI || METADATA_URI);
          skillIds[skill.name] = result.skillId;
          console.log(`Skill "${skill.name}" registered: skillId=${result.skillId}, tx=${result.txHash}`);
        } catch (err) {
          console.error(`Skill "${skill.name}" registration failed: ${err.message || err}`);
        }
      }
    } else {
      console.warn('Skipping on-chain skill registration (agentId unknown).');
    }

    // ── 3. CryptoSkill.org ────────────────────────────────────────────────────
    step(`[3/5] CryptoSkill.org — ${agent.name}`);
    try {
      await registerWithCryptoSkill({
        agentName: agent.name,
        agentAddress: AGENT_ADDRESS,
        description: agent.description,
        skills: agent.skills,
        metadataURI: METADATA_URI,
        serviceEndpoint: SERVICE_ENDPOINT,
        onChainRegistryId: agentId || '',
      });
    } catch (err) {
      console.error(`CryptoSkill registration failed: ${err.message || err}`);
    }

    // Register each skill individually as well
    for (const skill of agent.skills) {
      try {
        await registerSkillWithCryptoSkill(AGENT_ADDRESS, skill);
      } catch (err) {
        console.error(`CryptoSkill skill "${skill.name}" failed: ${err.message || err}`);
      }
    }

    // ── 4. Superfluid x402 ───────────────────────────────────────────────────
    step(`[4/5] Superfluid x402 Facilitator — ${agent.name}`);
    const serviceOpts = {
      agentName: agent.name,
      agentAddress: AGENT_ADDRESS,
      serviceEndpoint: SERVICE_ENDPOINT,
      description: agent.description,
      skills: agent.skills.map(s => s.name),
      pricePerRequest: PRICE_PER_REQUEST,
      superToken: 'USDCx',
    };
    try {
      await registerWithSuperfluidX402(serviceOpts);
    } catch (err) {
      console.error(`Superfluid x402 registration failed: ${err.message || err}`);
    }

    // ── 5. CDP x402 Bazaar ───────────────────────────────────────────────────
    step(`[5/5] CDP x402 Bazaar — ${agent.name}`);
    try {
      await listInX402Bazaar(serviceOpts);
    } catch (err) {
      console.error(`CDP Bazaar listing failed: ${err.message || err}`);
    }
  }

  console.log('\n✅  Registration pipeline complete.\n');
}

main().catch(err => {
  console.error('Fatal error in registerAgent.js:', err);
  process.exit(1);
});

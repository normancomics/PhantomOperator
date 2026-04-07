require('dotenv').config();
const axios = require('axios');

const CRYPTOSKILL_API_BASE = 'https://api.cryptoskill.org/v1';
const CRYPTOSKILL_API_KEY = process.env.CRYPTOSKILL_API_KEY;

function _headers() {
  if (!CRYPTOSKILL_API_KEY) {
    throw new Error('CRYPTOSKILL_API_KEY is not set in .env — get your key at https://cryptoskill.org');
  }
  return {
    'Authorization': `Bearer ${CRYPTOSKILL_API_KEY}`,
    'Content-Type': 'application/json',
  };
}

/**
 * Register or update the agent profile on CryptoSkill.
 * @param {object} manifest - parsed agent-manifest.json
 * @param {string} agentAddress - on-chain address of the agent wallet
 * @returns {object} CryptoSkill API response
 */
async function registerAgent(manifest, agentAddress) {
  const payload = {
    name: manifest.name,
    handle: manifest.handle,
    description: manifest.description,
    version: manifest.version,
    website: manifest.website,
    walletAddress: agentAddress,
    chainId: manifest.chainId,
    payment: manifest.payment,
    registries: manifest.registries,
  };

  const { data } = await axios.post(`${CRYPTOSKILL_API_BASE}/agents`, payload, {
    headers: _headers(),
    timeout: 20000,
  });
  return data;
}

/**
 * Publish a single skill to CryptoSkill.
 * @param {string} agentId - CryptoSkill agent ID returned from registerAgent()
 * @param {object} skill - a skill object from agent-manifest.json skills array
 * @returns {object} CryptoSkill API response
 */
async function publishSkill(agentId, skill) {
  const payload = {
    agentId,
    skillId: skill.id,
    name: skill.name,
    description: skill.description,
    version: skill.version,
    inputs: skill.inputs,
    outputs: skill.outputs,
    pricing: skill.pricing,
    tags: skill.tags,
  };

  const { data } = await axios.post(`${CRYPTOSKILL_API_BASE}/skills`, payload, {
    headers: _headers(),
    timeout: 20000,
  });
  return data;
}

/**
 * List all skills published by this agent on CryptoSkill.
 * @param {string} agentId - CryptoSkill agent ID
 * @returns {Array} array of skill objects
 */
async function listSkills(agentId) {
  const { data } = await axios.get(`${CRYPTOSKILL_API_BASE}/agents/${agentId}/skills`, {
    headers: _headers(),
    timeout: 20000,
  });
  return data.skills || data;
}

module.exports = { registerAgent, publishSkill, listSkills };

require('dotenv').config();
const { ethers } = require('ethers');

// ─── Contract addresses (Base mainnet) ───────────────────────────────────────
const IDENTITY_REGISTRY_ADDRESS = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
const REPUTATION_REGISTRY_ADDRESS = '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63';

// Base mainnet
const BASE_CHAIN_ID = 8453;
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const PRIVATE_KEY = process.env.PRIVATE_KEY;

// ─── ABIs ─────────────────────────────────────────────────────────────────────
// Minimal ABI for the 8004scan Identity Registry.
// Functions are derived from the standard agent-identity pattern used by 8004scan.io.
const IDENTITY_REGISTRY_ABI = [
  // Register a new agent identity
  'function registerAgent(string calldata name, string calldata metadataURI) external returns (uint256 agentId)',
  // Update existing agent metadata
  'function updateAgent(uint256 agentId, string calldata name, string calldata metadataURI) external',
  // Read back a registered agent
  'function getAgent(address owner) external view returns (uint256 agentId, string memory name, string memory metadataURI, bool active)',
  // Check if an address has a registered identity
  'function isRegistered(address owner) external view returns (bool)',
  // Event emitted on registration
  'event AgentRegistered(uint256 indexed agentId, address indexed owner, string name)',
];

// Minimal ABI for the 8004scan Reputation / Skill Registry.
const REPUTATION_REGISTRY_ABI = [
  // Register a skill for a given agent
  'function registerSkill(uint256 agentId, string calldata skillName, string calldata skillMetadataURI) external returns (uint256 skillId)',
  // Endorse a skill (other agents or users call this)
  'function endorseSkill(uint256 skillId) external',
  // Read all skills for an agentId
  'function getSkills(uint256 agentId) external view returns (uint256[] memory skillIds, string[] memory skillNames, string[] memory metadataURIs)',
  // Event
  'event SkillRegistered(uint256 indexed skillId, uint256 indexed agentId, string skillName)',
];

// ─── Provider / signer setup ─────────────────────────────────────────────────
function _getSigner() {
  if (!PRIVATE_KEY) throw new Error('PRIVATE_KEY not set in .env — cannot sign transactions.');
  const provider = new ethers.providers.JsonRpcProvider(BASE_RPC_URL);
  return new ethers.Wallet(PRIVATE_KEY, provider);
}

// ─── Identity Registry ────────────────────────────────────────────────────────

/**
 * Register this agent's identity on-chain.
 * @param {string} agentName        Human-readable name, e.g. "PhantomOperator/SearchAgent"
 * @param {string} metadataURI      URI pointing to an agent metadata JSON (IPFS, HTTPS, etc.)
 * @returns {Promise<{txHash: string, agentId: string|null}>}
 */
async function registerIdentity(agentName, metadataURI) {
  const signer = _getSigner();
  const contract = new ethers.Contract(IDENTITY_REGISTRY_ADDRESS, IDENTITY_REGISTRY_ABI, signer);

  console.log(`RegistryService: registering identity for "${agentName}"...`);
  const tx = await contract.registerAgent(agentName, metadataURI);
  const receipt = await tx.wait();

  // Attempt to parse agentId from event log
  let agentId = null;
  try {
    const iface = new ethers.utils.Interface(IDENTITY_REGISTRY_ABI);
    for (const log of receipt.logs) {
      try {
        const parsed = iface.parseLog(log);
        if (parsed.name === 'AgentRegistered') {
          agentId = parsed.args.agentId.toString();
          break;
        }
      } catch (_) { /* skip non-matching logs */ }
    }
  } catch (_) { /* event parsing is best-effort */ }

  console.log(`RegistryService: identity registered. tx=${receipt.transactionHash}, agentId=${agentId}`);
  return { txHash: receipt.transactionHash, agentId };
}

/**
 * Update an already-registered agent identity.
 * @param {string|number} agentId
 * @param {string} agentName
 * @param {string} metadataURI
 * @returns {Promise<string>} txHash
 */
async function updateIdentity(agentId, agentName, metadataURI) {
  const signer = _getSigner();
  const contract = new ethers.Contract(IDENTITY_REGISTRY_ADDRESS, IDENTITY_REGISTRY_ABI, signer);

  console.log(`RegistryService: updating identity agentId=${agentId}...`);
  const tx = await contract.updateAgent(agentId, agentName, metadataURI);
  const receipt = await tx.wait();
  console.log(`RegistryService: identity updated. tx=${receipt.transactionHash}`);
  return receipt.transactionHash;
}

/**
 * Read back the registered identity for a wallet address.
 * @param {string} ownerAddress
 * @returns {Promise<{agentId: string, name: string, metadataURI: string, active: boolean}|null>}
 */
async function getIdentity(ownerAddress) {
  const provider = new ethers.providers.JsonRpcProvider(BASE_RPC_URL);
  const contract = new ethers.Contract(IDENTITY_REGISTRY_ADDRESS, IDENTITY_REGISTRY_ABI, provider);
  const registered = await contract.isRegistered(ownerAddress);
  if (!registered) return null;
  const [agentId, name, metadataURI, active] = await contract.getAgent(ownerAddress);
  return { agentId: agentId.toString(), name, metadataURI, active };
}

// ─── Reputation / Skill Registry ─────────────────────────────────────────────

/**
 * Register a novel skill for a previously-registered agentId.
 * @param {string|number} agentId       Returned from registerIdentity()
 * @param {string} skillName            e.g. "DataBrokerOptOut", "ThreatAnalysis"
 * @param {string} skillMetadataURI     URI to skill manifest JSON
 * @returns {Promise<{txHash: string, skillId: string|null}>}
 */
async function registerSkill(agentId, skillName, skillMetadataURI) {
  const signer = _getSigner();
  const contract = new ethers.Contract(REPUTATION_REGISTRY_ADDRESS, REPUTATION_REGISTRY_ABI, signer);

  console.log(`RegistryService: registering skill "${skillName}" for agentId=${agentId}...`);
  const tx = await contract.registerSkill(agentId, skillName, skillMetadataURI);
  const receipt = await tx.wait();

  let skillId = null;
  try {
    const iface = new ethers.utils.Interface(REPUTATION_REGISTRY_ABI);
    for (const log of receipt.logs) {
      try {
        const parsed = iface.parseLog(log);
        if (parsed.name === 'SkillRegistered') {
          skillId = parsed.args.skillId.toString();
          break;
        }
      } catch (_) { /* skip */ }
    }
  } catch (_) { /* best-effort */ }

  console.log(`RegistryService: skill registered. tx=${receipt.transactionHash}, skillId=${skillId}`);
  return { txHash: receipt.transactionHash, skillId };
}

/**
 * List all skills registered for an agentId.
 * @param {string|number} agentId
 */
async function getSkills(agentId) {
  const provider = new ethers.providers.JsonRpcProvider(BASE_RPC_URL);
  const contract = new ethers.Contract(REPUTATION_REGISTRY_ADDRESS, REPUTATION_REGISTRY_ABI, provider);
  const [skillIds, skillNames, metadataURIs] = await contract.getSkills(agentId);
  return skillIds.map((id, i) => ({
    skillId: id.toString(),
    skillName: skillNames[i],
    metadataURI: metadataURIs[i],
  }));
}

module.exports = {
  registerIdentity,
  updateIdentity,
  getIdentity,
  registerSkill,
  getSkills,
  IDENTITY_REGISTRY_ADDRESS,
  REPUTATION_REGISTRY_ADDRESS,
};

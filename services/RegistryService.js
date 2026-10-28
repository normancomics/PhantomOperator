require('dotenv').config();
const { ethers } = require('ethers');
const IdentityABI = require('../abis/IdentityRegistry.json');
const ReputationABI = require('../abis/ReputationRegistry.json');

const provider = new ethers.JsonRpcProvider(
  process.env.BASE_RPC_URL || 'https://base-rpc.publicnode.com'
);

let wallet = null;
if (process.env.PRIVATE_KEY) {
  wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
}

const IDENTITY_ADDRESS =
  process.env.IDENTITY_REGISTRY_ADDRESS ||
  '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
const REPUTATION_ADDRESS =
  process.env.REPUTATION_REGISTRY_ADDRESS ||
  '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63';

function getIdentityContract() {
  if (!wallet) {
    throw new Error('RegistryService: PRIVATE_KEY must be set in .env before calling contract methods.');
  }
  return new ethers.Contract(IDENTITY_ADDRESS, IdentityABI, wallet);
}

function getReputationContract() {
  const signerOrProvider = wallet || provider;
  return new ethers.Contract(REPUTATION_ADDRESS, ReputationABI, signerOrProvider);
}

/**
 * Register the agent on the ERC-8004 IdentityRegistry (Base Mainnet 8453).
 * Uses standard EIP-8004 `register(string agentURI)`.
 *
 * @param {string} metadataURI - HTTPS URL, IPFS URI, or data:application/json;base64,... URI
 */
async function registerAgent(metadataURI = 'https://freysaai.freysa.dev/.well-known/agent-registration.json') {
  const identityContract = getIdentityContract();
  const tx = await identityContract['register(string)'](metadataURI);
  console.log('ERC-8004 registration transaction submitted:', tx.hash);
  const receipt = await tx.wait();
  console.log('PhantomOperator registered in block', receipt.blockNumber);
  return receipt;
}

async function getReputation(agentAddress) {
  const reputationContract = getReputationContract();
  const rep = await reputationContract.getReputation(agentAddress);
  console.log(`Current reputation for ${agentAddress}:`, rep.toString());
  return rep;
}

module.exports = { registerAgent, getReputation, IDENTITY_ADDRESS, REPUTATION_ADDRESS };

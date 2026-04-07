require('dotenv').config();
const { ethers } = require('ethers');
const identityAbi = require('../abis/IdentityRegistry.json');
const reputationAbi = require('../abis/ReputationRegistry.json');

const IDENTITY_REGISTRY_ADDRESS =
  process.env.IDENTITY_REGISTRY_ADDRESS || '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
const REPUTATION_REGISTRY_ADDRESS =
  process.env.REPUTATION_REGISTRY_ADDRESS || '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63';
const BASE_MAINNET_CHAIN_ID = 8453;

function _createProvider() {
  const rpcUrl = process.env.RPC_URL;
  if (!rpcUrl) throw new Error('RPC_URL is not set in .env');
  return new ethers.providers.JsonRpcProvider(rpcUrl);
}

function _createWallet(provider) {
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) throw new Error('PRIVATE_KEY is not set in .env');
  return new ethers.Wallet(privateKey, provider);
}

async function _assertNetwork(provider) {
  const network = await provider.getNetwork();
  if (network.chainId !== BASE_MAINNET_CHAIN_ID) {
    throw new Error(
      `Wrong network: connected to chainId ${network.chainId}, expected ${BASE_MAINNET_CHAIN_ID} (Base mainnet). ` +
      'Set RPC_URL to a Base mainnet endpoint (e.g. https://mainnet.base.org).'
    );
  }
}

async function _assertContractExists(provider, address, name) {
  const code = await provider.getCode(address);
  if (code === '0x') {
    throw new Error(
      `${name} contract not found at ${address} on Base mainnet. ` +
      'Verify the address on https://basescan.org'
    );
  }
}

/**
 * Register this agent's wallet address in the Base Identity Registry.
 * @param {string} metadataURI - HTTPS or IPFS URI pointing to agent-manifest.json
 * @returns {string} transaction hash
 */
async function registerIdentity(metadataURI) {
  if (!metadataURI) throw new Error('metadataURI is required (set AGENT_METADATA_URI in .env)');

  const provider = _createProvider();
  await _assertNetwork(provider);
  await _assertContractExists(provider, IDENTITY_REGISTRY_ADDRESS, 'IdentityRegistry');

  const wallet = _createWallet(provider);
  const contract = new ethers.Contract(IDENTITY_REGISTRY_ADDRESS, identityAbi, wallet);

  const agentAddress = await wallet.getAddress();

  // Check if already registered
  const alreadyRegistered = await contract.isRegistered(agentAddress).catch(() => false);
  if (alreadyRegistered) {
    console.log(`Agent ${agentAddress} is already registered in the Identity Registry.`);
    console.log('Updating metadata URI instead...');
    const tx = await contract.updateMetadata(metadataURI);
    console.log('updateMetadata tx submitted:', tx.hash);
    await tx.wait();
    console.log('Metadata updated. Block:', (await provider.getTransaction(tx.hash)).blockNumber);
    return tx.hash;
  }

  const tx = await contract.registerAgent(metadataURI);
  console.log('registerAgent tx submitted:', tx.hash);
  const receipt = await tx.wait();
  console.log('Identity registered. Block:', receipt.blockNumber);
  return tx.hash;
}

/**
 * Initialize this agent's reputation record in the Base Reputation Registry.
 * @returns {string} transaction hash
 */
async function initializeReputation() {
  const provider = _createProvider();
  await _assertNetwork(provider);
  await _assertContractExists(provider, REPUTATION_REGISTRY_ADDRESS, 'ReputationRegistry');

  const wallet = _createWallet(provider);
  const contract = new ethers.Contract(REPUTATION_REGISTRY_ADDRESS, reputationAbi, wallet);

  const agentAddress = await wallet.getAddress();

  // Check if already initialized
  const alreadyInitialized = await contract.isInitialized(agentAddress).catch(() => false);
  if (alreadyInitialized) {
    console.log(`Agent ${agentAddress} already has a reputation record.`);
    const rep = await getReputation(agentAddress);
    console.log('Current reputation:', rep);
    return null;
  }

  const tx = await contract.initializeAgent(agentAddress);
  console.log('initializeAgent tx submitted:', tx.hash);
  const receipt = await tx.wait();
  console.log('Reputation initialized. Block:', receipt.blockNumber);
  return tx.hash;
}

/**
 * Read the current reputation for any agent address.
 * @param {string} agentAddress - checksummed Ethereum address
 * @returns {{ score: string, totalJobs: string, updatedAt: string }}
 */
async function getReputation(agentAddress) {
  const provider = _createProvider();
  const contract = new ethers.Contract(REPUTATION_REGISTRY_ADDRESS, reputationAbi, provider);
  const [score, totalJobs, updatedAt] = await contract.getReputation(agentAddress);
  return {
    score: score.toString(),
    totalJobs: totalJobs.toString(),
    updatedAt: new Date(updatedAt.toNumber() * 1000).toISOString(),
  };
}

/**
 * Read the registered identity metadata for any agent address.
 * @param {string} agentAddress - checksummed Ethereum address
 * @returns {{ metadataURI: string, registeredAt: string }}
 */
async function getIdentity(agentAddress) {
  const provider = _createProvider();
  const contract = new ethers.Contract(IDENTITY_REGISTRY_ADDRESS, identityAbi, provider);
  const [metadataURI, registeredAt] = await contract.getAgentMetadata(agentAddress);
  return {
    metadataURI,
    registeredAt: new Date(registeredAt.toNumber() * 1000).toISOString(),
  };
}

module.exports = { registerIdentity, initializeReputation, getReputation, getIdentity };

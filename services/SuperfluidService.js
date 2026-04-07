require('dotenv').config();
const { Framework } = require('@superfluid-finance/sdk-core');
const { ethers } = require('ethers');

// Default to Base mainnet chainId
const DEFAULT_CHAIN_ID = 8453;

const RPC_URL = process.env.RPC_URL || 'https://mainnet.base.org';
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const CHAIN_ID = process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : DEFAULT_CHAIN_ID;
const SUPER_TOKEN = process.env.SUPER_TOKEN || 'USDCx'; // USDCx on Base mainnet

if (!PRIVATE_KEY) {
  console.warn('SuperfluidService: PRIVATE_KEY not set in .env — Superfluid operations will fail until configured.');
}

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = PRIVATE_KEY ? new ethers.Wallet(PRIVATE_KEY, provider) : null;

async function _createFramework() {
  // create Framework bound to the configured chain and provider
  return Framework.create({ chainId: CHAIN_ID, provider });
}

async function startSuperfluidFlow(receiver, flowRate) {
  if (!wallet) throw new Error('Wallet not configured (set PRIVATE_KEY in .env)');
  const sf = await _createFramework();

  // Use loadSuperToken which is compatible with production/testnet symbols
  const token = await sf.loadSuperToken(SUPER_TOKEN);
  const senderAddress = await wallet.getAddress();

  const createFlowOperation = token.createFlow({ sender: senderAddress, receiver, flowRate });
  const result = await createFlowOperation.exec(wallet);

  // Normalize returned tx hash
  return (result && (result.hash || result.transactionHash)) || result;
}

async function stopSuperfluidFlow(receiver) {
  if (!wallet) throw new Error('Wallet not configured (set PRIVATE_KEY in .env)');
  const sf = await _createFramework();
  const token = await sf.loadSuperToken(SUPER_TOKEN);
  const senderAddress = await wallet.getAddress();

  const deleteFlowOperation = token.deleteFlow({ sender: senderAddress, receiver });
  const result = await deleteFlowOperation.exec(wallet);
  return (result && (result.hash || result.transactionHash)) || result;
}

module.exports = { startSuperfluidFlow, stopSuperfluidFlow };

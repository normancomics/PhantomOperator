require('dotenv').config();
const { Framework } = require('@superfluid-finance/sdk-core');
const { ethers } = require('ethers');

const RPC_URL = process.env.RPC_URL;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const CHAIN_ID = process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : 8453; // Default to Base mainnet chainId
const SUPER_TOKEN = process.env.SUPER_TOKEN || 'USDCx';

if (!RPC_URL || !PRIVATE_KEY) {
  console.warn('SuperfluidService: RPC_URL or PRIVATE_KEY not set in .env — Superfluid operations will fail until configured.');
}

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = PRIVATE_KEY ? new ethers.Wallet(PRIVATE_KEY, provider) : null;

async function _createFramework() {
  return Framework.create({ chainId: CHAIN_ID, provider });
}

async function startSuperfluidFlow(receiver, flowRate) {
  if (!wallet) throw new Error('Wallet not configured');
  const sf = await _createFramework();
  const token = await sf.loadSuperToken(SUPER_TOKEN);
  const senderAddress = await wallet.getAddress();

  const createFlowOperation = token.createFlow({ sender: senderAddress, receiver, flowRate });
  const result = await createFlowOperation.exec(wallet);
  return result.hash || result.transactionHash || result;
}

async function stopSuperfluidFlow(receiver) {
  if (!wallet) throw new Error('Wallet not configured');
  const sf = await _createFramework();
  const token = await sf.loadSuperToken(SUPER_TOKEN);
  const senderAddress = await wallet.getAddress();

  const deleteFlowOperation = token.deleteFlow({ sender: senderAddress, receiver });
  const result = await deleteFlowOperation.exec(wallet);
  return result.hash || result.transactionHash || result;
}

module.exports = { startSuperfluidFlow, stopSuperfluidFlow };

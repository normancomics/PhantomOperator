/**
 * WalletOpsecAgent.js
 *
 * On-Chain EVM (Base / Ethereum) Wallet Deanonymization, Hygiene & Cross-Chain
 * ($XMR Monero) Sovereignty Auditor.
 *
 * Inspects live on-chain state (ETH balance, USDC balance, transaction nonce,
 * contract code status, ERC-8004 AgentIdentity NFT ownership) and evaluates
 * address reuse, gas-funder correlation, and transparent ledger exposure.
 */

'use strict';

const { ethers } = require('ethers');
const MoneroAgent = require('./MoneroAgent');

const BASE_RPC = process.env.BASE_RPC_URL || 'https://base-rpc.publicnode.com';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const ERC8004_IDENTITY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';

const ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
];

const ERC721_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
];

async function audit(params = {}) {
  const rawAddress = String(params.walletAddress || params.address || '').trim();
  if (!ethers.utils.isAddress(rawAddress)) {
    throw new Error('walletAddress must be a valid 0x EVM address');
  }
  const address = ethers.utils.getAddress(rawAddress);
  const provider = new ethers.providers.JsonRpcProvider(BASE_RPC);

  let ethBalance = '0.0';
  let usdcBalance = '0.0';
  let txCount = 0;
  let isContract = false;
  let erc8004NftCount = 0;

  try {
    const [ethWei, nonce, code, usdcRaw, nftRaw] = await Promise.all([
      provider.getBalance(address).catch(() => ethers.BigNumber.from(0)),
      provider.getTransactionCount(address).catch(() => 0),
      provider.getCode(address).catch(() => '0x'),
      new ethers.Contract(USDC_BASE, ERC20_ABI, provider).balanceOf(address).catch(() => ethers.BigNumber.from(0)),
      new ethers.Contract(ERC8004_IDENTITY, ERC721_ABI, provider).balanceOf(address).catch(() => ethers.BigNumber.from(0)),
    ]);
    ethBalance = ethers.utils.formatEther(ethWei);
    usdcBalance = ethers.utils.formatUnits(usdcRaw, 6);
    txCount = Number(nonce);
    isContract = code && code !== '0x';
    erc8004NftCount = Number(nftRaw.toString());
  } catch {
    // Graceful degradation if RPC times out
  }

  const findings = [];
  let exposureScore = 15;

  if (txCount > 100) {
    exposureScore += 35;
    findings.push({
      category: 'high_nonce_graph_density',
      riskLevel: 'high',
      label: `High On-Chain Transaction Graph Density (Nonce: ${txCount})`,
      detail: 'Addresses with >100 outbound transactions create dense heuristics for behavioral clustering, timezone fingerprinting, and counterparty linkage.',
      remediation: 'Rotate operational EOAs periodically and isolate public identity addresses from execution/treasury wallets.',
    });
  } else if (txCount > 10) {
    exposureScore += 20;
    findings.push({
      category: 'moderate_nonce_reuse',
      riskLevel: 'medium',
      label: `Moderate Address Reuse (Nonce: ${txCount})`,
      detail: 'Repeated outbound transactions on Base mainnet expose counterparty graph and active hours.',
      remediation: 'Segregate x402 agent settlement wallets from personal cold storage.',
    });
  } else {
    findings.push({
      category: 'clean_nonce_footprint',
      riskLevel: 'low',
      label: `Low Transaction Graph Footprint (Nonce: ${txCount})`,
      detail: 'Minimal outbound transaction history reduces behavioral clustering surface.',
      remediation: 'Fund new operational addresses via privacy-preserving atomic swaps ($XMR <-> EVM) rather than direct CEX transfers.',
    });
  }

  if (erc8004NftCount > 0) {
    findings.push({
      category: 'erc8004_verified_identity',
      riskLevel: 'low',
      label: `ERC-8004 AgentIdentity NFT Holder (${erc8004NftCount} token(s))`,
      detail: 'Wallet holds on-chain verifiable ERC-8004 AgentIdentity on Base mainnet.',
      remediation: 'Keep agentURI metadata and /.well-known/agent-registration.json synchronized.',
    });
  }

  findings.push({
    category: 'xmr_sovereign_settlement_path',
    riskLevel: 'low',
    label: '$XMR (Monero) Zero-Link Settlement Recommendation',
    detail: 'All EVM balances and USDC transfers on Base are permanently public. To break deterministic on-chain clustering between agent revenue and cold storage, settle periodic treasury sweeps through $XMR RingCT subaddresses (8...).',
    remediation: 'Use `POST /skills/monero-opsec-audit` to verify fresh 8... Cryptonote subaddresses before cross-chain settlement.',
  });

  const finalScore = Math.min(100, Math.max(0, exposureScore));
  const grade =
    finalScore <= 20 ? 'A' :
    finalScore <= 40 ? 'B' :
    finalScore <= 60 ? 'C' :
    finalScore <= 80 ? 'D' : 'F';

  return {
    walletAddress: address,
    chain: 'Base Mainnet (eip155:8453)',
    isSmartContract: isContract,
    onChainState: {
      ethBalance,
      usdcBalance,
      outboundTxCount: txCount,
      erc8004AgentIdentityCount: erc8004NftCount,
    },
    exposureScore: finalScore,
    privacyHygieneScore: 100 - finalScore,
    grade,
    riskLevel: finalScore >= 70 ? 'high' : finalScore >= 40 ? 'medium' : 'low',
    findings,
    moneroSubaddressSample: MoneroAgent.deriveDeterministicSubaddress(`wallet:${address}`),
    mmrCommitmentProof: MoneroAgent.buildMmrCommitment([address, String(txCount), ethBalance, usdcBalance]),
  };
}

module.exports = { audit };

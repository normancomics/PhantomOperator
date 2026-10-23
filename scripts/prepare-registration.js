#!/usr/bin/env node
'use strict';

// Prepare an unsigned proposal. This script never loads a wallet, contacts an RPC,
// signs a message, submits a transaction, or asks for a private key.
const fs = require('node:fs/promises');
const path = require('node:path');
const { ethers } = require('ethers');

const REGISTRATION_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
const BASE_CHAIN_ID = 8453;
const registryInterface = new ethers.utils.Interface([
  'function register(string agentURI) external returns (uint256 agentId)',
]);

function address(value, label) {
  if (!value) throw new Error(`${label} is required; use a public address, never a private key.`);
  let result;
  try { result = ethers.utils.getAddress(value); }
  catch { throw new Error(`${label} must be a valid Ethereum address (with a valid checksum when mixed case).`); }
  if (result === ethers.constants.AddressZero) throw new Error(`${label} cannot be the zero address.`);
  return result;
}

function serviceOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('A valid HTTPS service URL is required.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !url.hostname) {
    throw new Error('Service URL must use HTTPS without credentials, query parameters, or fragments.');
  }
  if (url.pathname !== '/' && url.pathname !== '') throw new Error('Service URL must be the service origin, without a path.');
  return url.origin;
}

function prepareRegistration(options = {}) {
  const registry = address(options.registry, '--registry');
  const owner = address(options.owner, '--owner');
  const uri = options.agentUri;
  if (typeof uri !== 'string' || uri.length > 4096 || /[\u0000-\u0020]/.test(uri)) {
    throw new Error('--agent-uri must be a nonempty HTTPS or IPFS URI of at most 4096 characters.');
  }
  let parsed;
  try { parsed = new URL(uri); } catch { throw new Error('--agent-uri must be an HTTPS or IPFS URI.'); }
  if (!['https:', 'ipfs:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.hash) {
    throw new Error('--agent-uri must use HTTPS or IPFS without credentials or fragments.');
  }
  if (parsed.protocol === 'https:' && parsed.search) throw new Error('--agent-uri must not contain query parameters.');
  const base = serviceOrigin(options.serviceUrl || (parsed.protocol === 'https:' ? parsed.origin : ''));

  return {
    status: 'unsigned-proposal-only',
    standard: 'ERC-8004',
    chain: 'Base mainnet',
    method: 'register(string)',
    agentURI: uri,
    transaction: {
      chainId: BASE_CHAIN_ID,
      from: owner,
      to: registry,
      value: '0x0',
      data: registryInterface.encodeFunctionData('register(string)', [uri]),
    },
    registrationFile: {
      type: REGISTRATION_TYPE,
      name: 'PhantomOperator',
      description: 'HTTP/HTML metadata privacy audits and consent-based public-web exposure checks. Evidence-based reports; pay per successful call with USDC on Base through x402.',
      image: `${base}/icon.svg`,
      services: [
        { name: 'web', endpoint: base },
        { name: 'OpenAPI', endpoint: `${base}/openapi.json`, version: '3.1.0' },
      ],
      x402Support: true,
      active: true,
      registrations: [],
    },
    checksRequiredBeforeSigning: [
      'Verify the registry address and its deployed implementation on a Base block explorer. This script does not verify contract code.',
      'Check for an existing PhantomOperator registration before creating another identity.',
      'Publish the registration file at agentURI and verify the production service, pricing, payment receiver, and advertised endpoints.',
      'Review this exact transaction in your wallet on Base. Gas is additional; no gas price or successful registration is implied by this proposal.',
    ],
    afterConfirmedTransaction: [
      'Read the agentId from the confirmed Registered event; this proposal cannot predict that ID.',
      'Add the confirmed agentId and eip155:8453:<registry> to the hosted registration file and /.well-known/agent-registration.json.',
      'The registry initially uses the transaction sender as agentWallet. A different payment wallet requires the standard setAgentWallet ownership proof, not an arbitrary metadata field.',
      'Check the confirmed identity in supported indexers. An unsigned proposal or hosted file alone is not an on-chain registration or directory listing.',
    ],
    sources: [
      'https://eips.ethereum.org/EIPS/eip-8004',
      'https://github.com/ethereum/ERCs/blob/master/ERCS/erc-8004.md',
    ],
  };
}

function parseArgs(argv) {
  const options = {};
  const names = { '--registry': 'registry', '--owner': 'owner', '--agent-uri': 'agentUri', '--service-url': 'serviceUrl', '--output': 'output' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { options.help = true; continue; }
    const name = names[arg];
    if (!name || !argv[i + 1] || argv[i + 1].startsWith('--') || Object.hasOwn(options, name)) {
      throw new Error(`Unknown, duplicate, or incomplete argument: ${arg}`);
    }
    options[name] = argv[++i];
  }
  return options;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write('Usage: node scripts/prepare-registration.js --registry <verified-address> --owner <public-address> --agent-uri <https-or-ipfs-uri> [--service-url https://service.example] [--output proposal.json]\nPrepares public metadata and unsigned Base transaction data only. No RPC, signing, or submission.\n');
    return;
  }
  const proposal = prepareRegistration(options);
  const json = `${JSON.stringify(proposal, null, 2)}\n`;
  if (options.output) {
    if (path.extname(options.output).toLowerCase() !== '.json') throw new Error('--output must name a new .json file.');
    await fs.writeFile(options.output, json, { flag: 'wx', mode: 0o600 });
  }
  process.stdout.write(json);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({ ok: false, error: error.message })}\n`);
    process.exitCode = 2;
  });
}

module.exports = { prepareRegistration, parseArgs, serviceOrigin, REGISTRATION_TYPE, BASE_CHAIN_ID };

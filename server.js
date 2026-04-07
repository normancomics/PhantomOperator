/**
 * server.js
 *
 * Step 5: HTTP server for SovereignAgent with x402 payment middleware.
 *
 * x402 is a payment protocol built on HTTP 402 Payment Required.
 * When a caller hits a paid endpoint without a valid payment proof, the server
 * returns 402 with a JSON body describing how to pay (token, amount, address).
 * The caller attaches a signed EIP-712 payment proof in the X-PAYMENT header
 * and retries. The server validates the proof and serves the response.
 *
 * Endpoints:
 *   GET  /manifest          — public: returns agent-manifest.json
 *   GET  /health            — public: liveness check
 *   POST /skills/threat-scan      — PAID: threat scan skill
 *   POST /skills/data-removal     — PAID: data removal skill
 *   POST /skills/full-privacy-sweep — PAID (streaming): full sweep skill
 *
 * Run: node server.js
 * Docs: https://x402.superfluid.org / https://docs.cdp.coinbase.com/x402/welcome
 */
require('dotenv').config();
const http = require('http');
const { ethers } = require('ethers');
const SearchAgent = require('./agents/SearchAgent');
const BrokerAgent = require('./agents/BrokerAgent');
const SovereignAgent = require('./SovereignAgent');
const manifest = require('./agent-manifest.json');

const PORT = process.env.PORT || 3000;

// ── x402 configuration ───────────────────────────────────────────────────────
// USDCx on Base mainnet
const PAYMENT_TOKEN_ADDRESS = process.env.PAYMENT_TOKEN_ADDRESS || '0xD04383398dD2426297da660F9CCA3d439AF9ce1b';
const PAYMENT_RECEIVER = process.env.PAYMENT_RECEIVER_ADDRESS || process.env.SOVEREIGN_AGENT_ADDRESS;
const CHAIN_ID = process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : 8453;
const MAX_TIMEOUT_SECONDS = 300;

// ── Skill pricing (in token smallest units, 6 decimals for USDC) ─────────────
const SKILL_PRICES = {
  'threat-scan': '1000000',       // 1.00 USDCx
  'data-removal': '5000000',      // 5.00 USDCx
  'full-privacy-sweep': '10000000', // 10.00 USDCx
};

// ── x402 helpers ─────────────────────────────────────────────────────────────

/**
 * Build the 402 Payment Required response body following the x402 spec.
 * https://x402.org / https://eips.ethereum.org/EIPS/eip-4337
 */
function buildPaymentRequired(skillId, resourcePath) {
  if (!PAYMENT_RECEIVER) {
    throw new Error('PAYMENT_RECEIVER_ADDRESS (or SOVEREIGN_AGENT_ADDRESS) must be set in .env');
  }
  return {
    x402Version: 1,
    accepts: [
      {
        scheme: 'exact',
        network: 'base-mainnet',
        maxAmountRequired: SKILL_PRICES[skillId] || '1000000',
        resource: resourcePath,
        description: manifest.skills.find(s => s.id === skillId)?.description || skillId,
        mimeType: 'application/json',
        payTo: PAYMENT_RECEIVER,
        maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
        asset: PAYMENT_TOKEN_ADDRESS,
        extra: {
          name: 'USD Coin',
          version: '2',
        },
      },
    ],
    error: 'Payment required to access this skill.',
  };
}

/**
 * Validate an x402 payment proof from the X-PAYMENT header.
 * The proof is a base64-encoded JSON object containing:
 *   - payload: { x402Version, scheme, network, payload: { resource, amount, asset, payTo, expiresAt } }
 *   - signature: EIP-712 signature over the payload
 *
 * Returns { valid: boolean, error?: string, payerAddress?: string }
 */
async function validatePayment(xPaymentHeader, skillId, resourcePath) {
  if (!xPaymentHeader) return { valid: false, error: 'Missing X-PAYMENT header' };

  let proof;
  try {
    proof = JSON.parse(Buffer.from(xPaymentHeader, 'base64').toString('utf8'));
  } catch {
    return { valid: false, error: 'X-PAYMENT header is not valid base64-encoded JSON' };
  }

  const { payload, signature } = proof;
  if (!payload || !signature) {
    return { valid: false, error: 'X-PAYMENT proof missing payload or signature' };
  }

  const innerPayload = payload.payload || {};

  // Verify the resource matches this endpoint
  if (innerPayload.resource && innerPayload.resource !== resourcePath) {
    return { valid: false, error: `Resource mismatch: expected ${resourcePath}, got ${innerPayload.resource}` };
  }

  // Verify expiry
  if (innerPayload.expiresAt && Date.now() / 1000 > innerPayload.expiresAt) {
    return { valid: false, error: 'Payment proof has expired' };
  }

  // Verify amount meets minimum
  const required = BigInt(SKILL_PRICES[skillId] || '1000000');
  const provided = BigInt(innerPayload.amount || '0');
  if (provided < required) {
    return {
      valid: false,
      error: `Insufficient payment: required ${required.toString()}, provided ${provided.toString()}`,
    };
  }

  // Verify asset token address
  if (
    innerPayload.asset &&
    innerPayload.asset.toLowerCase() !== PAYMENT_TOKEN_ADDRESS.toLowerCase()
  ) {
    return { valid: false, error: `Wrong payment token: expected ${PAYMENT_TOKEN_ADDRESS}` };
  }

  // Recover signer from EIP-712 signature
  // The signed message is a hash of the payload object
  try {
    const messageHash = ethers.utils.hashMessage(
      JSON.stringify(payload)
    );
    const payerAddress = ethers.utils.recoverAddress(messageHash, signature);
    return { valid: true, payerAddress };
  } catch (err) {
    return { valid: false, error: `Signature verification failed: ${err.message}` };
  }
}

// ── Middleware helpers ────────────────────────────────────────────────────────

function sendJson(res, status, body) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')));
    req.on('error', reject);
  });
}

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleManifest(req, res) {
  sendJson(res, 200, manifest);
}

async function handleHealth(req, res) {
  sendJson(res, 200, { status: 'ok', agent: manifest.name, version: manifest.version });
}

async function handlePaidSkill(req, res, skillId) {
  const resourcePath = `/skills/${skillId}`;

  // x402 gate
  const xPayment = req.headers['x-payment'];
  const { valid, error: paymentError } = await validatePayment(xPayment, skillId, resourcePath);

  if (!valid) {
    res.setHeader('X-PAYMENT-RESPONSE', JSON.stringify({ status: 'payment-required' }));
    return sendJson(res, 402, buildPaymentRequired(skillId, resourcePath));
  }

  // Parse request body
  let body;
  try {
    body = await readBody(req);
  } catch {
    return sendJson(res, 400, { error: 'Invalid JSON body' });
  }

  // Execute the skill
  try {
    let result;
    if (skillId === 'threat-scan') {
      if (!body.fullName) return sendJson(res, 400, { error: 'fullName is required' });
      result = await SearchAgent.run({ fullName: body.fullName });
    } else if (skillId === 'data-removal') {
      if (!body.threatUrl) return sendJson(res, 400, { error: 'threatUrl is required' });
      result = await BrokerAgent.removeThreat({ link: body.threatUrl, ...body });
    } else if (skillId === 'full-privacy-sweep') {
      if (!body.fullName) return sendJson(res, 400, { error: 'fullName is required' });
      const agent = new SovereignAgent();
      await agent.startDataRemovalTask({
        fullName: body.fullName,
        walletAddress: body.walletAddress || PAYMENT_RECEIVER,
        flowRate: body.flowRate || process.env.FLOW_RATE || '385802469135802',
      });
      result = { status: 'sweep-complete', message: 'Full privacy sweep finished.' };
    } else {
      return sendJson(res, 404, { error: `Unknown skill: ${skillId}` });
    }

    // Acknowledge payment in response header
    res.setHeader('X-PAYMENT-RESPONSE', JSON.stringify({ status: 'settled' }));
    sendJson(res, 200, { skill: skillId, result });
  } catch (err) {
    console.error(`Skill ${skillId} error:`, err.message);
    sendJson(res, 500, { error: err.message });
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  try {
    if (req.method === 'GET' && url === '/manifest') return await handleManifest(req, res);
    if (req.method === 'GET' && url === '/health') return await handleHealth(req, res);
    if (req.method === 'POST' && url.startsWith('/skills/')) {
      const skillId = url.replace('/skills/', '');
      return await handlePaidSkill(req, res, skillId);
    }
    sendJson(res, 404, { error: 'Not found', hint: 'Available: GET /manifest, GET /health, POST /skills/{skill-id}' });
  } catch (err) {
    console.error('Unhandled error:', err.message);
    sendJson(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`SovereignAgent server running on port ${PORT}`);
  console.log(`  GET  http://localhost:${PORT}/health`);
  console.log(`  GET  http://localhost:${PORT}/manifest`);
  for (const skillId of Object.keys(SKILL_PRICES)) {
    console.log(`  POST http://localhost:${PORT}/skills/${skillId}  (${SKILL_PRICES[skillId]} USDCx)`);
  }
  console.log('');
  console.log('x402 payment token:', PAYMENT_TOKEN_ADDRESS);
  console.log('Payment receiver:', PAYMENT_RECEIVER || '(NOT SET — set PAYMENT_RECEIVER_ADDRESS in .env)');
  console.log('Chain ID:', CHAIN_ID);
});

module.exports = server;

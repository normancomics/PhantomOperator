/**
 * server.js
 *
 * SovereignAgent HTTP server with x402 payment middleware.
 *
 * x402 is a payment protocol built on HTTP 402 Payment Required.
 * When a caller hits a paid endpoint without a valid payment proof the server
 * returns 402 with a JSON body describing how to pay (token, amount, address).
 * The caller attaches a signed payment proof in the X-PAYMENT header and
 * retries.  The server validates the proof and serves the response.
 *
 * Endpoints:
 *   GET  /manifest                     — public: returns agent-manifest.json
 *   GET  /health                       — public: liveness check
 *   POST /skills/threat-scan           — PAID: PII threat scan
 *   POST /skills/data-removal          — PAID: data broker opt-out
 *   POST /skills/full-privacy-sweep    — PAID: full sweep + Superfluid stream
 *   POST /skills/opsec-score           — PAID: multi-vector OPSEC exposure score
 *   POST /skills/breach-check          — PAID: HIBP k-anonymity breach lookup
 *   POST /skills/metadata-audit        — PAID: HTTP/HTML metadata privacy audit
 *
 * Run: node server.js
 */
require('dotenv').config();
const http = require('http');
const { ethers } = require('ethers');

const SearchAgent  = require('./agents/SearchAgent');
const BrokerAgent  = require('./agents/BrokerAgent');
const OpsecAgent   = require('./agents/OpsecAgent');
const BreachAgent  = require('./agents/BreachAgent');
const MetadataAgent = require('./agents/MetadataAgent');
const SovereignAgent = require('./SovereignAgent');
const manifest     = require('./agent-manifest.json');
const {
  checkRateLimit,
  setSecurityHeaders,
  sanitizeString,
  isValidEmail,
  isValidHttpUrl,
  RATE_LIMIT_PUBLIC,
  RATE_LIMIT_PAID,
  MAX_BODY_BYTES,
} = require('./middleware/security');

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ── x402 configuration ───────────────────────────────────────────────────────
const PAYMENT_TOKEN_ADDRESS = process.env.PAYMENT_TOKEN_ADDRESS || '0xD04383398dD2426297da660F9CCA3d439AF9ce1b';
const PAYMENT_RECEIVER      = process.env.PAYMENT_RECEIVER_ADDRESS || process.env.SOVEREIGN_AGENT_ADDRESS;
const CHAIN_ID              = process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : 8453;
const MAX_TIMEOUT_SECONDS   = 300;

// ── Skill pricing (USDCx, 6 decimal places) ──────────────────────────────────
const SKILL_PRICES = {
  'threat-scan':         '1000000',   //  1.00 USDCx
  'data-removal':        '5000000',   //  5.00 USDCx
  'full-privacy-sweep':  '10000000',  // 10.00 USDCx
  'opsec-score':         '5000000',   //  5.00 USDCx
  'breach-check':        '2000000',   //  2.00 USDCx
  'metadata-audit':      '1000000',   //  1.00 USDCx
};

const VALID_SKILL_IDS = new Set(Object.keys(SKILL_PRICES));

// ── x402 helpers ─────────────────────────────────────────────────────────────

function buildPaymentRequired(skillId, resourcePath) {
  if (!PAYMENT_RECEIVER) {
    throw new Error('PAYMENT_RECEIVER_ADDRESS (or SOVEREIGN_AGENT_ADDRESS) must be set in .env');
  }
  return {
    x402Version: 1,
    accepts: [{
      scheme:            'exact',
      network:           'base-mainnet',
      maxAmountRequired: SKILL_PRICES[skillId] || '1000000',
      resource:          resourcePath,
      description:       manifest.skills.find(s => s.id === skillId)?.description || skillId,
      mimeType:          'application/json',
      payTo:             PAYMENT_RECEIVER,
      maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
      asset:             PAYMENT_TOKEN_ADDRESS,
      extra: { name: 'USD Coin', version: '2' },
    }],
    error: 'Payment required to access this skill.',
  };
}

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

  const inner = payload.payload || {};

  if (inner.resource && inner.resource !== resourcePath) {
    return { valid: false, error: `Resource mismatch: expected ${resourcePath}` };
  }
  if (inner.expiresAt && Date.now() / 1000 > inner.expiresAt) {
    return { valid: false, error: 'Payment proof has expired' };
  }

  const required = BigInt(SKILL_PRICES[skillId] || '1000000');
  const provided  = BigInt(inner.amount || '0');
  if (provided < required) {
    return { valid: false, error: `Insufficient payment: required ${required}, provided ${provided}` };
  }

  if (inner.asset && inner.asset.toLowerCase() !== PAYMENT_TOKEN_ADDRESS.toLowerCase()) {
    return { valid: false, error: `Wrong payment token: expected ${PAYMENT_TOKEN_ADDRESS}` };
  }

  try {
    const payerAddress = ethers.utils.verifyMessage(JSON.stringify(payload), signature);
    return { valid: true, payerAddress };
  } catch (err) {
    return { valid: false, error: 'Signature verification failed' };
  }
}

// ── Middleware helpers ────────────────────────────────────────────────────────

function sendJson(res, status, body) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    req.on('data', chunk => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_BODY_BYTES) {
        req.destroy();
        return reject(new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes`));
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
         req.socket.remoteAddress ||
         'unknown';
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
  const { valid, error: paymentError } = await validatePayment(
    req.headers['x-payment'], skillId, resourcePath
  );
  if (!valid) {
    res.setHeader('X-PAYMENT-RESPONSE', JSON.stringify({ status: 'payment-required' }));
    return sendJson(res, 402, buildPaymentRequired(skillId, resourcePath));
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }

  try {
    let result;

    if (skillId === 'threat-scan') {
      const fullName = sanitizeString(body.fullName);
      if (!fullName) return sendJson(res, 400, { error: 'fullName is required' });
      result = await SearchAgent.run({ fullName });

    } else if (skillId === 'data-removal') {
      const threatUrl = sanitizeString(body.threatUrl);
      if (!threatUrl) return sendJson(res, 400, { error: 'threatUrl is required' });
      result = await BrokerAgent.removeThreat({ link: threatUrl, ...body });

    } else if (skillId === 'full-privacy-sweep') {
      const fullName = sanitizeString(body.fullName);
      if (!fullName) return sendJson(res, 400, { error: 'fullName is required' });
      const agent = new SovereignAgent();
      await agent.startDataRemovalTask({
        fullName,
        walletAddress: sanitizeString(body.walletAddress) || PAYMENT_RECEIVER,
        flowRate:      sanitizeString(body.flowRate) || process.env.FLOW_RATE || '385802469135802',
      });
      result = { status: 'sweep-complete', message: 'Full privacy sweep finished.' };

    } else if (skillId === 'opsec-score') {
      const target = {};
      if (body.fullName) target.fullName = sanitizeString(body.fullName);
      if (body.handle)   target.handle   = sanitizeString(body.handle);
      if (body.email)    target.email    = sanitizeString(body.email);
      if (!target.fullName && !target.handle && !target.email) {
        return sendJson(res, 400, { error: 'At least one of fullName, handle, or email is required' });
      }
      result = await OpsecAgent.assess(target);

    } else if (skillId === 'breach-check') {
      const email    = sanitizeString(body.email);
      const password = typeof body.password === 'string' ? body.password : null;
      if (!email && !password) {
        return sendJson(res, 400, { error: 'email or password is required' });
      }
      result = {};
      if (email) {
        if (!isValidEmail(email)) return sendJson(res, 400, { error: 'Invalid email address' });
        result.emailReport = await BreachAgent.getBreachReport(email);
      }
      if (password) {
        result.passwordCheck = await BreachAgent.checkPassword(password);
      }

    } else if (skillId === 'metadata-audit') {
      const url = sanitizeString(body.url, 2048);
      if (!url) return sendJson(res, 400, { error: 'url is required' });
      if (!isValidHttpUrl(url)) return sendJson(res, 400, { error: 'url must be an absolute HTTP/HTTPS URL' });
      result = await MetadataAgent.audit(url);

    } else {
      return sendJson(res, 404, { error: 'Unknown skill' });
    }

    res.setHeader('X-PAYMENT-RESPONSE', JSON.stringify({ status: 'settled' }));
    sendJson(res, 200, { skill: skillId, result });

  } catch (err) {
    console.error(`Skill error [${skillId}]:`, err.message);
    // Never expose internal error details in production
    const message = IS_PRODUCTION ? 'An internal error occurred' : err.message;
    sendJson(res, 500, { error: message });
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  // Security headers on every response
  setSecurityHeaders(res);

  const url      = req.url.split('?')[0];
  const clientIp = getClientIp(req);

  try {
    // Public endpoints — higher rate limit
    if (req.method === 'GET' && (url === '/manifest' || url === '/health')) {
      const rl = checkRateLimit(clientIp, RATE_LIMIT_PUBLIC);
      if (!rl.allowed) {
        res.setHeader('Retry-After', String(rl.retryAfter));
        return sendJson(res, 429, { error: 'Too many requests', retryAfter: rl.retryAfter });
      }
      if (url === '/manifest') return await handleManifest(req, res);
      return await handleHealth(req, res);
    }

    // Paid skill endpoints — stricter rate limit
    if (req.method === 'POST' && url.startsWith('/skills/')) {
      const skillId = url.slice('/skills/'.length);
      if (!VALID_SKILL_IDS.has(skillId)) {
        return sendJson(res, 404, { error: 'Unknown skill' });
      }
      const rl = checkRateLimit(clientIp, RATE_LIMIT_PAID);
      if (!rl.allowed) {
        res.setHeader('Retry-After', String(rl.retryAfter));
        return sendJson(res, 429, { error: 'Too many requests', retryAfter: rl.retryAfter });
      }
      return await handlePaidSkill(req, res, skillId);
    }

    sendJson(res, 404, {
      error: 'Not found',
      hint:  'Available: GET /manifest, GET /health, POST /skills/{skill-id}',
    });
  } catch (err) {
    console.error('Unhandled error:', err.message);
    sendJson(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`SovereignAgent server running on port ${PORT}`);
  console.log(`  GET  http://localhost:${PORT}/health`);
  console.log(`  GET  http://localhost:${PORT}/manifest`);
  for (const [skillId, price] of Object.entries(SKILL_PRICES)) {
    console.log(`  POST http://localhost:${PORT}/skills/${skillId}  (${price} USDCx)`);
  }
  console.log('');
  console.log('x402 payment token:', PAYMENT_TOKEN_ADDRESS);
  console.log('Payment receiver:  ', PAYMENT_RECEIVER || '(NOT SET — set PAYMENT_RECEIVER_ADDRESS in .env)');
  console.log('Chain ID:          ', CHAIN_ID);
});

module.exports = server;


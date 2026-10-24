/**
 * server.js
 *
 * PhantomOperator HTTP server with x402 + (future) Monero payment middleware.
 *
 * x402 is a payment protocol built on HTTP 402 Payment Required.
 * When a caller hits a paid endpoint without a valid payment proof the server
 * returns 402 with a JSON body describing how to pay (token, amount, address).
 * The caller attaches a signed payment proof in the X-PAYMENT header and
 * retries. The server validates the proof and serves the response.
 *
 * Endpoints:
 *   GET  /manifest                     — public: returns agent-manifest.json
 *   GET  /health                       — public: liveness check
 *   POST /skills/threat-scan           — PAID: PII threat scan
 *   POST /skills/data-removal          — PAID: data broker opt-out
 *   POST /skills/full-privacy-sweep    — PAID: full sweep (+ orchestration)
 *   POST /skills/opsec-score           — PAID: multi-vector OPSEC exposure score
 *   POST /skills/breach-check          — PAID: HIBP k-anonymity breach lookup
 *   POST /skills/metadata-audit        — PAID: HTTP/HTML metadata privacy audit
 *
 * Run: node server.js
 */
require('dotenv').config();
const http = require('http');
const fs   = require('fs');
const path = require('path');
const { ethers } = require('ethers');

const SearchAgent      = require('./agents/SearchAgent');
const BrokerAgent      = require('./agents/BrokerAgent');
const OpsecAgent       = require('./agents/OpsecAgent');
const BreachAgent      = require('./agents/BreachAgent');
const MetadataAgent    = require('./agents/MetadataAgent');
const OrchestratorOperator = require('./operators/OrchestratorOperator');
const manifest         = require('./agent-manifest.json');
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
const PAYMENT_TOKEN_ADDRESS =
  process.env.PAYMENT_TOKEN_ADDRESS ||
  '0xD04383398dD2426297da660F9CCA3d439AF9ce1b';

const PAYMENT_RECEIVER =
  process.env.PAYMENT_RECEIVER_ADDRESS ||
  process.env.SOVEREIGN_AGENT_ADDRESS ||
  process.env.PHANTOM_OPERATOR_ADDRESS;

const CHAIN_ID = process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : 8453;
const MAX_TIMEOUT_SECONDS = 300;

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
    throw new Error(
      'PAYMENT_RECEIVER_ADDRESS (or SOVEREIGN_AGENT_ADDRESS/PHANTOM_OPERATOR_ADDRESS) must be set in .env'
    );
  }
  return {
    x402Version: 1,
    accepts: [{
      scheme:            'exact',
      network:           'base-mainnet',
      maxAmountRequired: SKILL_PRICES[skillId] || '1000000',
      resource:          resourcePath,
      description:
        manifest.skills.find(s => s.id === skillId)?.description || skillId,
      mimeType:          'application/json',
      payTo:             PAYMENT_RECEIVER,
      maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
      asset:             PAYMENT_TOKEN_ADDRESS,
      outputSchema: {
        input: {
          type:   'http',
          method: 'POST',
          bodyType: 'json',
          bodyFields: Object.fromEntries(
            (manifest.skills.find(s => s.id === skillId)?.inputs || [])
              .map(i => [i.name, { type: i.type || 'string', description: i.description || '' }])
          ),
        },
      },
      extra: { name: 'USD Coin', version: '2' },
    }],
    error: 'Payment required to access this skill.',
  };
}

/**
 * Legacy x402/EVM payment validation.
 * This is your existing logic extracted under a more explicit name.
 */
async function validatePaymentX402(xPaymentHeader, skillId, resourcePath) {
  if (!xPaymentHeader) {
    return { valid: false, error: 'Missing X-PAYMENT header' };
  }

  let proof;
  try {
    proof = JSON.parse(Buffer.from(xPaymentHeader, 'base64').toString('utf8'));
  } catch {
    return {
      valid: false,
      error: 'X-PAYMENT header is not valid base64-encoded JSON',
    };
  }

  const { payload, signature } = proof;
  if (!payload || !signature) {
    return { valid: false, error: 'X-PAYMENT proof missing payload or signature' };
  }

  const inner = payload.payload || {};

  if (inner.resource && inner.resource !== resourcePath) {
    return {
      valid: false,
      error: `Resource mismatch: expected ${resourcePath}`,
    };
  }
  if (inner.expiresAt && Date.now() / 1000 > inner.expiresAt) {
    return { valid: false, error: 'Payment proof has expired' };
  }

  const required = BigInt(SKILL_PRICES[skillId] || '1000000');
  const provided = BigInt(inner.amount || '0');
  if (provided < required) {
    return {
      valid: false,
      error: `Insufficient payment: required ${required}, provided ${provided}`,
    };
  }

  if (inner.asset && inner.asset.toLowerCase() !== PAYMENT_TOKEN_ADDRESS.toLowerCase()) {
    return {
      valid: false,
      error: `Wrong payment token: expected ${PAYMENT_TOKEN_ADDRESS}`,
    };
  }

  try {
    const payerAddress = ethers.utils.verifyMessage(
      JSON.stringify(payload),
      signature
    );
    return { valid: true, payerAddress };
  } catch (err) {
    return { valid: false, error: 'Signature verification failed' };
  }
}

/**
 * Monero payment validation stub.
 *
 * This is where you will later integrate with a separate Monero bridge service
 * that talks to monerod/monero-wallet-rpc and returns signed payment proofs.
 *
 * Expected header usage:
 *   X-PAYMENT-METHOD: monero
 *   X-PAYMENT: base64-encoded JSON like:
 *     { invoiceId, proof, signature }
 */
async function validatePaymentMonero(xPaymentHeader, skillId, resourcePath) {
  if (!xPaymentHeader) {
    return { valid: false, error: 'Missing X-PAYMENT header for Monero' };
  }

  // TODO: Implement actual integration with your Monero bridge service.
  // For now we always fail with a clear message so callers know this path
  // is not production-ready yet.
  return {
    valid: false,
    error: 'Monero payment method not yet implemented on this deployment',
  };
}

/**
 * Unified payment validator.
 *
 * Chooses between x402 (Base / EVM) and Monero based on the X-PAYMENT-METHOD
 * header. Defaults to x402 for backward compatibility.
 *
 *   X-PAYMENT-METHOD: x402    → validatePaymentX402
 *   X-PAYMENT-METHOD: monero  → validatePaymentMonero
 */
async function validateAnyPayment(req, skillId, resourcePath) {
  const methodHeader = req.headers['x-payment-method'];
  const method = (methodHeader || 'x402').toLowerCase();
  const xPaymentHeader = req.headers['x-payment'];

  if (method === 'x402') {
    return validatePaymentX402(xPaymentHeader, skillId, resourcePath);
  }

  if (method === 'monero') {
    return validatePaymentMonero(xPaymentHeader, skillId, resourcePath);
  }

  return {
    valid: false,
    error: `Unsupported payment method: ${method}`,
  };
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
        return reject(
          new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes`)
        );
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

// ── Route handlers ───────────────────────────────────────────────────────────

async function handleManifest(req, res) {
  const base = getBaseUrl(req);
  sendJson(res, 200, {
    ...manifest,
    url: base,
    endpoints: {
      openapi: `${base}/openapi.json`,
      skill:   `${base}/SKILL.md`,
      llms:    `${base}/llms.txt`,
      x402:    `${base}/.well-known/x402`,
    },
    tags: ['privacy', 'opsec', 'osint', 'x402', 'base', 'usdc', 'data-removal', 'breach-check'],
  });
}

async function handleX402Discovery(req, res) {
  const base = getBaseUrl(req);
  sendJson(res, 200, {
    x402Version: 1,
    name:        manifest.name,
    description: manifest.description,
    payTo:       PAYMENT_RECEIVER || null,
    network:     'base-mainnet',
    chainId:     CHAIN_ID,
    asset:       PAYMENT_TOKEN_ADDRESS,
    resources:   Object.entries(SKILL_PRICES).map(([id, price]) => ({
      resource:          `${base}/skills/${id}`,
      method:            'POST',
      scheme:            'exact',
      maxAmountRequired: price,
    })),
  });
}

function handleRobots(req, res) {
  sendText(res, 200, 'text/plain; charset=utf-8',
    `User-agent: *\nAllow: /\n\nSitemap: ${getBaseUrl(req)}/llms.txt\n`);
}

function sendText(res, status, contentType, text) {
  res.writeHead(status, {
    'Content-Type':   contentType,
    'Content-Length': Buffer.byteLength(text),
  });
  res.end(text);
}

function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
  const host  = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

async function handleIndex(req, res) {
  const base = getBaseUrl(req);
  sendJson(res, 200, {
    name:        manifest.name || 'PhantomOperator',
    version:     manifest.version,
    description: manifest.description,
    links: {
      health:   `${base}/health`,
      manifest: `${base}/manifest`,
      agent:    `${base}/.well-known/agent.json`,
      openapi:  `${base}/openapi.json`,
      skill:    `${base}/SKILL.md`,
      llms:     `${base}/llms.txt`,
      x402:     `${base}/.well-known/x402`,
      source:   manifest.website,
    },
    skills: Object.entries(SKILL_PRICES).map(([id, price]) => ({
      id,
      method:  'POST',
      url:     `${base}/skills/${id}`,
      price,
      payment: 'x402 (USDCx on Base); unpaid calls return HTTP 402',
    })),
  });
}

function sendStaticFile(res, file, contentType) {
  let text;
  try {
    text = fs.readFileSync(path.join(__dirname, file), 'utf8');
  } catch {
    return sendJson(res, 404, { error: 'Not found' });
  }
  sendText(res, 200, contentType, text);
}

function buildOpenApi(req) {
  const paths = {};
  for (const [id, price] of Object.entries(SKILL_PRICES)) {
    const skill = (manifest.skills || []).find(s => s.id === id) || {};
    const properties = {};
    for (const input of skill.inputs || []) {
      properties[input.name] = {
        type:        input.type || 'string',
        description: input.description || '',
      };
    }
    paths[`/skills/${id}`] = {
      post: {
        operationId: id,
        summary:     skill.name || id,
        description: `${skill.description || id} Price: ${price} USDCx base units (6 decimals).`,
        parameters: [
          { name: 'X-PAYMENT', in: 'header', required: false, schema: { type: 'string' },
            description: 'Base64-encoded x402 payment proof' },
          { name: 'X-PAYMENT-METHOD', in: 'header', required: false,
            schema: { type: 'string', enum: ['x402', 'monero'] } },
        ],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', properties } } },
        },
        responses: {
          200: { description: 'Skill result' },
          400: { description: 'Invalid input' },
          402: {
            description: 'Payment required (x402 descriptor)',
            content: { 'application/json': { schema: { type: 'object', properties: {
              x402Version: { type: 'integer' },
              accepts:     { type: 'array', items: { type: 'object' } },
              error:       { type: 'string' },
            } } } },
          },
          503: { description: 'Payment receiver not configured' },
        },
      },
    };
  }
  paths['/health'] = {
    get: { operationId: 'health', summary: 'Liveness check',
           responses: { 200: { description: 'OK' } } },
  };
  paths['/manifest'] = {
    get: { operationId: 'manifest', summary: 'Agent manifest',
           responses: { 200: { description: 'Agent manifest JSON' } } },
  };
  return {
    openapi: '3.1.0',
    info: {
      title:       manifest.name || 'PhantomOperator',
      version:     manifest.version || '0.1.0',
      description: manifest.description,
    },
    servers: [{ url: getBaseUrl(req) }],
    paths,
  };
}

async function handleHealth(req, res) {
  sendJson(res, 200, {
    status:  'ok',
    agent:   manifest.name || 'PhantomOperator',
    version: manifest.version,
  });
}

/**
 * Main handler for all paid skills.
 * Uses validateAnyPayment to support x402 and (future) Monero.
 */
async function handlePaidSkill(req, res, skillId) {
  const resourcePath = `/skills/${skillId}`;

  // x402 / Monero gate
  const { valid, error: paymentError } = await validateAnyPayment(
    req,
    skillId,
    resourcePath
  );
  if (!valid) {
    res.setHeader(
      'X-PAYMENT-RESPONSE',
      JSON.stringify({ status: 'payment-required', error: paymentError })
    );
    let descriptor;
    try {
      descriptor = buildPaymentRequired(skillId, resourcePath);
    } catch (err) {
      console.error(`Payment configuration error [${skillId}]:`, err.message);
      return sendJson(res, 503, {
        error: 'Payment receiver not configured',
        hint:  'Set PAYMENT_RECEIVER_ADDRESS',
      });
    }
    return sendJson(res, 402, descriptor);
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
      if (!fullName) {
        return sendJson(res, 400, { error: 'fullName is required' });
      }
      result = await SearchAgent.run({ fullName });

    } else if (skillId === 'data-removal') {
      const threatUrl = sanitizeString(body.threatUrl);
      if (!threatUrl) {
        return sendJson(res, 400, { error: 'threatUrl is required' });
      }
      result = await BrokerAgent.removeThreat({ link: threatUrl, ...body });

    } else if (skillId === 'full-privacy-sweep') {
      const fullName = sanitizeString(body.fullName);
      if (!fullName) {
        return sendJson(res, 400, { error: 'fullName is required' });
      }

      // Use OrchestratorOperator as the core coordinator for sweeps.
      const operator = new OrchestratorOperator();
      const sweepResult = await operator.startDataRemovalTask({
        fullName,
        walletAddress: sanitizeString(body.walletAddress) || PAYMENT_RECEIVER,
        flowRate:      sanitizeString(body.flowRate) ||
                       process.env.FLOW_RATE ||
                       '385802469135802',
      });

      result = {
        status: 'sweep-complete',
        ...sweepResult,
      };

    } else if (skillId === 'opsec-score') {
      const target = {};
      if (body.fullName) target.fullName = sanitizeString(body.fullName);
      if (body.handle)   target.handle   = sanitizeString(body.handle);
      if (body.email)    target.email    = sanitizeString(body.email);
      if (!target.fullName && !target.handle && !target.email) {
        return sendJson(res, 400, {
          error: 'At least one of fullName, handle, or email is required',
        });
      }
      result = await OpsecAgent.assess(target);

    } else if (skillId === 'breach-check') {
      const email    = sanitizeString(body.email);
      const password = typeof body.password === 'string'
        ? body.password
        : null;

      if (!email && !password) {
        return sendJson(res, 400, {
          error: 'email or password is required',
        });
      }

      result = {};

      if (email) {
        if (!isValidEmail(email)) {
          return sendJson(res, 400, { error: 'Invalid email address' });
        }
        result.emailReport = await BreachAgent.getBreachReport(email);
      }
      if (password) {
        result.passwordCheck = await BreachAgent.checkPassword(password);
      }

    } else if (skillId === 'metadata-audit') {
      const url = sanitizeString(body.url, 2048);
      if (!url) {
        return sendJson(res, 400, { error: 'url is required' });
      }
      if (!isValidHttpUrl(url)) {
        return sendJson(res, 400, {
          error: 'url must be an absolute HTTP/HTTPS URL',
        });
      }
      result = await MetadataAgent.audit(url);

    } else {
      return sendJson(res, 404, { error: 'Unknown skill' });
    }

    res.setHeader(
      'X-PAYMENT-RESPONSE',
      JSON.stringify({ status: 'settled' })
    );
    sendJson(res, 200, { skill: skillId, result });

  } catch (err) {
    console.error(`Skill error [${skillId}]:`, err.message);
    const message = IS_PRODUCTION ? 'An internal error occurred' : err.message;
    sendJson(res, 500, { error: message });
  }
}

// ── HTTP server ──────────────────────────────────────────────────────────────

const PUBLIC_ROUTES = new Set([
  '/', '/health', '/manifest', '/.well-known/agent.json',
  '/SKILL.md', '/llms.txt', '/openapi.json',
  '/.well-known/x402', '/robots.txt',
]);

const server = http.createServer(async (req, res) => {
  // Security headers on every response
  setSecurityHeaders(res);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'X-PAYMENT, X-PAYMENT-METHOD, Content-Type');
  res.setHeader('Access-Control-Expose-Headers', 'X-PAYMENT-RESPONSE');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url      = req.url.split('?')[0];
  const clientIp = getClientIp(req);

  try {
    // Public endpoints — higher rate limit
    if (req.method === 'GET' && PUBLIC_ROUTES.has(url)) {
      const rl = checkRateLimit(clientIp, RATE_LIMIT_PUBLIC);
      if (!rl.allowed) {
        res.setHeader('Retry-After', String(rl.retryAfter));
        return sendJson(res, 429, {
          error:      'Too many requests',
          retryAfter: rl.retryAfter,
        });
      }
      if (url === '/manifest' || url === '/.well-known/agent.json') {
        return await handleManifest(req, res);
      }
      if (url === '/.well-known/x402') return await handleX402Discovery(req, res);
      if (url === '/robots.txt') return handleRobots(req, res);
      if (url === '/') return await handleIndex(req, res);
      if (url === '/SKILL.md') return sendStaticFile(res, 'SKILL.md', 'text/markdown; charset=utf-8');
      if (url === '/llms.txt') return sendStaticFile(res, 'llms.txt', 'text/plain; charset=utf-8');
      if (url === '/openapi.json') return sendJson(res, 200, buildOpenApi(req));
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
        return sendJson(res, 429, {
          error:      'Too many requests',
          retryAfter: rl.retryAfter,
        });
      }
      return await handlePaidSkill(req, res, skillId);
    }

    sendJson(res, 404, {
      error: 'Not found',
      hint:  'Available: GET /, GET /manifest, GET /health, GET /openapi.json, POST /skills/{skill-id}',
    });
  } catch (err) {
    console.error('Unhandled error:', err.message);
    sendJson(res, 500, { error: 'Internal server error' });
  }
});

if (!PAYMENT_RECEIVER) {
  console.warn(
    'WARNING: no payment receiver configured. Set PAYMENT_RECEIVER_ADDRESS; ' +
    'paid skills will return 503 until it is set.'
  );
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`PhantomOperator server running on port ${PORT}`);
  console.log(`  GET  http://localhost:${PORT}/health`);
  console.log(`  GET  http://localhost:${PORT}/manifest`);
  for (const [skillId, price] of Object.entries(SKILL_PRICES)) {
    console.log(
      `  POST http://localhost:${PORT}/skills/${skillId}  (${price} USDCx)`
    );
  }
  console.log('');
  console.log('x402 payment token:', PAYMENT_TOKEN_ADDRESS);
  console.log(
    'Payment receiver:  ',
    PAYMENT_RECEIVER ||
      '(NOT SET — set PAYMENT_RECEIVER_ADDRESS or PHANTOM_OPERATOR_ADDRESS in .env)'
  );
  console.log('Chain ID:          ', CHAIN_ID);
});

module.exports = server;

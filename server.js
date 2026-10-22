/**
 * server.js
 *
 * PhantomOperator HTTP server, Render-ready, with real x402 v2 payments
 * (plain USDC on Base mainnet, keyless PayAI facilitator, payTo normancomics.eth).
 *
 * Only skills that use free data sources are enabled. No paid API keys needed.
 *
 * Free:
 *   GET  /                 service index
 *   GET  /health           liveness
 *   GET  /manifest         agent-manifest.json
 *   GET  /skills           skill catalog with prices
 *   GET  /terms            terms of use / acceptable use
 *   GET  /llms.txt         agent-readable index
 *   GET  /.well-known/x402 x402 resource list
 * Paid (x402, POST JSON):
 *   POST /skills/metadata-audit  $0.05  HTTP/HTML metadata privacy audit of a URL
 *   POST /skills/threat-scan     $0.10  public-web PII exposure scan for a name (self/authorized only)
 *   POST /skills/opsec-score     $0.25  multi-vector OPSEC exposure score (self/authorized only)
 *
 * Disabled on this deployment (see README): breach-check (needs paid HIBP key),
 * data-removal (was a stub that didn't submit anything), full-privacy-sweep
 * (needs a funded wallet private key + Superfluid), Solana and Python tooling.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const SearchAgent   = require('./agents/SearchAgent');
const OpsecAgent    = require('./agents/OpsecAgent');
const MetadataAgent = require('./agents/MetadataAgent');
const manifest      = require('./agent-manifest.json');
const x402          = require('./lib/x402');
const {
  checkRateLimit, setSecurityHeaders, sanitizeString, isValidEmail, isValidHttpUrl,
  RATE_LIMIT_PUBLIC, RATE_LIMIT_PAID, MAX_BODY_BYTES,
} = require('./middleware/security');

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const TERMS = fs.readFileSync(path.join(__dirname, 'TERMS.md'), 'utf8');

const publicBase = (req) => {
  const env = process.env.RENDER_EXTERNAL_URL || process.env.PUBLIC_URL;
  if (env) return env.replace(/\/$/, '');
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return `${proto}://${req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`}`;
};

const CONSENT = { type: 'boolean', description: 'Must be true: you confirm the target is yourself or someone who authorized this scan, and you accept /terms' };

// ── Paid skills ──────────────────────────────────────────────────────────────
const SKILLS = {
  'metadata-audit': {
    path: '/skills/metadata-audit', priceUsd: 0.05,
    description: 'Privacy audit of a web page: leaky HTTP headers, meta tags, HTML comments, third-party trackers and resources, with a risk rating and recommendations.',
    bodySchema: { type: 'object', properties: { url: { type: 'string', description: 'Absolute http(s) URL to audit' } }, required: ['url'] },
    inputExample: { url: 'https://example.com' },
    outputExample: { skill: 'metadata-audit', result: { overallRisk: 'low', findings: [] } },
    async run(body) {
      const url = sanitizeString(body.url, 2048);
      if (!url || !isValidHttpUrl(url)) return { status: 400, body: { error: 'url must be an absolute HTTP/HTTPS URL' } };
      return { status: 200, body: { skill: 'metadata-audit', result: await MetadataAgent.audit(url) } };
    },
  },
  'threat-scan': {
    path: '/skills/threat-scan', priceUsd: 0.10, requiresConsent: true,
    description: "Searches the public web (DuckDuckGo) for a person's name and flags results exposing PII (phone, email, address keywords). For self-assessment or authorized use only.",
    bodySchema: { type: 'object', properties: { fullName: { type: 'string', description: 'Full name to scan' }, consent: CONSENT }, required: ['fullName', 'consent'] },
    inputExample: { fullName: 'Jane Example', consent: true },
    outputExample: { skill: 'threat-scan', result: [{ title: '...', link: 'https://...', threatLevel: 'high', reasons: ['email'] }] },
    async run(body) {
      const fullName = sanitizeString(body.fullName);
      if (!fullName) return { status: 400, body: { error: 'fullName is required' } };
      return { status: 200, body: { skill: 'threat-scan', result: await SearchAgent.run({ fullName }) } };
    },
  },
  'opsec-score': {
    path: '/skills/opsec-score', priceUsd: 0.25, requiresConsent: true,
    description: 'Multi-vector OPSEC exposure score (0-100) for a name, handle and/or email from public web search results, with prioritized recommendations. For self-assessment or authorized use only.',
    bodySchema: { type: 'object', properties: { fullName: { type: 'string' }, handle: { type: 'string' }, email: { type: 'string' }, consent: CONSENT }, required: ['consent'] },
    inputExample: { handle: 'janeexample', consent: true },
    outputExample: { skill: 'opsec-score', result: { score: 42, riskLevel: 'medium', vectors: {} } },
    async run(body) {
      const target = {};
      if (body.fullName) target.fullName = sanitizeString(body.fullName);
      if (body.handle) target.handle = sanitizeString(body.handle);
      if (body.email) {
        const e = sanitizeString(body.email);
        if (!isValidEmail(e)) return { status: 400, body: { error: 'Invalid email address' } };
        target.email = e;
      }
      if (!target.fullName && !target.handle && !target.email) return { status: 400, body: { error: 'At least one of fullName, handle, or email is required' } };
      return { status: 200, body: { skill: 'opsec-score', result: await OpsecAgent.assess(target) } };
    },
  },
};

const DISABLED = {
  'breach-check': 'Disabled: email breach lookup requires a paid HaveIBeenPwned API key.',
  'data-removal': 'Disabled: opt-out submission is not implemented yet (previous version only returned a stub).',
  'full-privacy-sweep': 'Disabled: requires a funded wallet private key and Superfluid streaming.',
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function send(res, status, body, headers = {}) {
  const isText = typeof body === 'string';
  const data = isText ? body : JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': isText ? 'text/plain; charset=utf-8' : 'application/json',
    'Content-Length': Buffer.byteLength(data),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Expose-Headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE',
    ...headers,
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) { req.destroy(); return reject(new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes`)); }
      chunks.push(c);
    });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(new Error('Invalid JSON body')); } });
    req.on('error', reject);
  });
}

const clientIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';

function catalog(base) {
  return {
    paid: Object.entries(SKILLS).map(([id, s]) => ({
      id, method: 'POST', url: base + s.path, priceUsd: s.priceUsd, description: s.description,
      body: s.bodySchema, requiresConsent: !!s.requiresConsent,
    })),
    disabled: DISABLED,
    payment: { protocol: 'x402 v2', scheme: 'exact', network: x402.NETWORK, asset: x402.USDC_BASE, payTo: x402.PAY_TO, facilitator: x402.FACILITATOR },
    terms: base + '/terms',
  };
}

function llms(base) {
  return [
    '# PhantomOperator',
    '',
    '> Privacy and OPSEC agent. Audits web pages for metadata leaks and scores public-web PII exposure for yourself (or someone who authorized you). Pay per call via x402 (USDC on Base mainnet, payTo normancomics.eth). See terms before use.',
    '',
    '## Free',
    `- [Skill catalog](${base}/skills)`,
    `- [Agent manifest](${base}/manifest)`,
    `- [Official logo](${base}/logo.png)`,
    `- [Terms of use](${base}/terms)`,
    `- [x402 resources](${base}/.well-known/x402)`,
    '',
    '## Paid (x402 v2, exact, eip155:8453 USDC; POST JSON)',
    ...Object.values(SKILLS).map((s) => `- [POST ${s.path}](${base}${s.path}) $${s.priceUsd.toFixed(2)}: ${s.description}`),
    '',
    'Unpaid requests return HTTP 402 with a PAYMENT-REQUIRED header. Pay with any x402 client (PAYMENT-SIGNATURE or X-PAYMENT header). Errors and invalid input are not charged. threat-scan and opsec-score require "consent": true.',
    '',
  ].join('\n');
}

async function handlePaid(req, res, id) {
  const skill = SKILLS[id];
  const base = publicBase(req);
  let body;
  try { body = await readBody(req); } catch (e) { return send(res, 400, { error: e.message }); }

  // Validate cheap preconditions before asking for payment so nobody pays for a rejected request.
  if (skill.requiresConsent && body && Object.keys(body).length && body.consent !== true) {
    return send(res, 400, { error: 'consent must be true (target is yourself or authorized you; you accept the terms)', terms: base + '/terms' });
  }

  const v = await x402.verify(req, skill, base);
  if (!v.ok) return send(res, v.status, v.body, v.headers);
  if (skill.requiresConsent && body.consent !== true) {
    return send(res, 400, { error: 'consent must be true', terms: base + '/terms' }); // not charged
  }

  let out;
  try { out = await skill.run(body); }
  catch (err) {
    console.error(`Skill error [${id}]:`, err.message);
    return send(res, 500, { error: IS_PRODUCTION ? 'An internal error occurred' : err.message }); // not charged
  }
  if (out.status >= 400) return send(res, out.status, out.body); // not charged

  const s = await x402.settle(v.payload, skill);
  if (!s.ok) return send(res, s.status, s.body);
  send(res, 200, out.body, s.headers);
}

// ── HTTP server ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);
  const url = req.url.split('?')[0];
  const ip = clientIp(req);
  const base = publicBase(req);

  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' });
      return res.end();
    }
    if (req.method === 'GET') {
      const rl = checkRateLimit(ip, RATE_LIMIT_PUBLIC);
      if (!rl.allowed) return send(res, 429, { error: 'Too many requests', retryAfter: rl.retryAfter }, { 'Retry-After': String(rl.retryAfter) });
      switch (url) {
        case '/': return send(res, 200, { service: 'PhantomOperator', description: manifest.description, ...catalog(base), discovery: { llms: base + '/llms.txt', x402: base + '/.well-known/x402', manifest: base + '/manifest', logo: base + '/logo.png' } });
        case '/health': return send(res, 200, { status: 'ok', agent: manifest.name, version: manifest.version });
        case '/manifest': return send(res, 200, { ...manifest, image: base + '/logo.png', logo: base + '/logo.png', payment: { ...manifest.payment, payTo: x402.PAY_TO } });
        case '/skills': return send(res, 200, { ...catalog(base), logo: base + '/logo.png' });
        case '/logo.png': {
          const image = fs.readFileSync(path.join(__dirname, 'assets', 'phantom-operator-logo.png'));
          res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': image.length, 'Cache-Control': 'public, max-age=3600' });
          return res.end(image);
        }
        case '/terms': return send(res, 200, TERMS);
        case '/llms.txt': return send(res, 200, llms(base));
        case '/.well-known/x402': return send(res, 200, {
          x402Version: 2, facilitator: x402.FACILITATOR, network: x402.NETWORK, asset: x402.USDC_BASE, payTo: x402.PAY_TO,
          resources: Object.values(SKILLS).map((s) => ({ resource: base + s.path, method: 'POST', description: s.description, priceUsd: s.priceUsd, accepts: [x402.requirements(s)] })),
        });
      }
    }

    if (req.method === 'POST' && url.startsWith('/skills/')) {
      const id = url.slice('/skills/'.length);
      if (DISABLED[id]) return send(res, 410, { error: DISABLED[id] });
      if (!SKILLS[id]) return send(res, 404, { error: 'Unknown skill', available: Object.keys(SKILLS) });
      const rl = checkRateLimit(ip, RATE_LIMIT_PAID);
      if (!rl.allowed) return send(res, 429, { error: 'Too many requests', retryAfter: rl.retryAfter }, { 'Retry-After': String(rl.retryAfter) });
      return await handlePaid(req, res, id);
    }

    send(res, 404, { error: 'Not found', hint: 'See GET / for available endpoints' });
  } catch (err) {
    console.error('Unhandled error:', err.message);
    send(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`PhantomOperator listening on :${PORT}`);
  for (const s of Object.values(SKILLS)) console.log(`  POST ${s.path}  $${s.priceUsd.toFixed(2)} USDC (x402, Base)`);
  console.log(`  payTo ${x402.PAY_TO} via ${x402.FACILITATOR}`);
});

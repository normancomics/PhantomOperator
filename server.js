'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const manifest = require('./agent-manifest.json');
const paymentDefault = require('./lib/x402');
const { createDiscovery } = require('./lib/discovery');
const defaultAgents = { SearchAgent: require('./agents/SearchAgent'), OpsecAgent: require('./agents/OpsecAgent'), MetadataAgent: require('./agents/MetadataAgent') };
const { checkRateLimit, setSecurityHeaders, sanitizeString, isValidEmail, isValidHttpUrl, RATE_LIMIT_PUBLIC, RATE_LIMIT_PAID, MAX_BODY_BYTES } = require('./middleware/security');
const TERMS = fs.readFileSync(path.join(__dirname, 'TERMS.md'), 'utf8');
const CONSENT = { type: 'boolean', const: true, description: 'You confirm the target is yourself or explicitly authorized this assessment, and accept /terms.' };
const text = (description, maxLength = 512) => ({ type: 'string', minLength: 1, maxLength, description });
const DISABLED = {
  'breach-check': 'Disabled: paid email-breach data integration is not configured.',
  'data-removal': 'Disabled: automated broker opt-out submission is not implemented.',
  'full-privacy-sweep': 'Disabled: automated removal and funded streaming are not offered by this deployment.',
};

function createSkills(agents) {
  return {
    'metadata-audit': {
      path: '/skills/metadata-audit', priceUsd: 0.05, tags: ['privacy', 'metadata', 'http-headers', 'web-security'],
      description: 'Inspect a public web page for metadata exposure, software fingerprints, third-party resources and missing security headers. Returns evidence and practical remediation; does not inspect image EXIF.',
      bodySchema: { type: 'object', properties: { url: { ...text('Public HTTP/HTTPS page to audit', 2048), format: 'uri' } }, required: ['url'], additionalProperties: false },
      inputExample: { url: 'https://example.com' },
      outputExample: { skill: 'metadata-audit', result: { overallRisk: 'medium', findingCounts: { critical: 0, high: 0, medium: 1, low: 0 }, findings: [{ category: 'missing-security-header', riskLevel: 'medium', label: 'Missing security header', field: 'referrer-policy', value: null }], recommendation: 'Review the observed headers.' } },
      async run(body) { return agents.MetadataAgent.audit(body.url); },
    },
    'threat-scan': {
      path: '/skills/threat-scan', priceUsd: 0.10, requiresConsent: true, tags: ['privacy', 'pii', 'authorized-osint', 'evidence'],
      description: 'Classify public search-result snippets for possible phone, email and sensitive-keyword exposure for yourself or an authorized client. Returns source links and heuristic reasons; name matches are not identity verification.',
      bodySchema: { type: 'object', properties: { fullName: text('Name of yourself or an explicitly authorized subject'), consent: CONSENT }, required: ['fullName', 'consent'], additionalProperties: false },
      inputExample: { fullName: 'Jane Example', consent: true },
      outputExample: { skill: 'threat-scan', result: [{ title: 'Example public page', link: 'https://example.com/profile', description: 'Example snippet', threatLevel: 'high', reasons: ['email'] }] },
      async run(body) { return agents.SearchAgent.run({ fullName: body.fullName }); },
    },
    'opsec-score': {
      path: '/skills/opsec-score', priceUsd: 0.25, requiresConsent: true, tags: ['opsec', 'privacy', 'exposure-assessment', 'authorized-osint'],
      description: 'Assess public search exposure for a consenting name, handle or email, with evidence, heuristic score breakdown, coverage and prioritized remediation. Failed searches are not treated as proof of privacy.',
      bodySchema: { type: 'object', properties: { fullName: text('Authorized subject name'), handle: text('Authorized public handle'), email: { ...text('Authorized email', 254), format: 'email' }, consent: CONSENT }, required: ['consent'], anyOf: [{ required: ['fullName'] }, { required: ['handle'] }, { required: ['email'] }], additionalProperties: false },
      inputExample: { handle: 'janeexample', consent: true },
      outputExample: { skill: 'opsec-score', result: { score: 42, grade: 'C', breakdown: { searchExposure: { score: 40, criticalFindings: 1, highFindings: 1, totalResults: 5 }, dataBrokerExposure: { score: 40, brokerCount: 2, brokers: ['example.com'] }, pasteLeaks: { score: 40, pasteCount: 1, sites: [] }, socialFootprint: { score: 48, platformCount: 4, platforms: [] } }, recommendations: [{ priority: 'HIGH', action: 'Review source evidence', detail: 'Verify the linked result and request correction where appropriate.' }], coverage: { complete: true } } },
      async run(body) { const target = {}; for (const key of ['fullName', 'handle', 'email']) if (body[key]) target[key] = body[key]; return agents.OpsecAgent.assess(target); },
    },
  };
}

function validateBody(id, body, skill) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'Body must be a JSON object';
  const allowed = new Set(Object.keys(skill.bodySchema.properties));
  if (Object.keys(body).some(key => !allowed.has(key))) return 'Body contains an unsupported property';
  if (skill.requiresConsent && body.consent !== true) return 'consent must be true (self-assessment or explicit authorization; see /terms)';
  for (const [key, spec] of Object.entries(skill.bodySchema.properties)) {
    if (spec.type !== 'string' || body[key] === undefined) continue;
    if (typeof body[key] !== 'string' || !body[key].trim() || body[key].length > spec.maxLength || /[\x00-\x1F\x7F]/.test(body[key])) return `${key} must be a nonempty string of at most ${spec.maxLength} characters`;
    body[key] = sanitizeString(body[key], spec.maxLength);
  }
  if (id === 'metadata-audit') {
    if (!body.url || !isValidHttpUrl(body.url)) return 'url must be an absolute HTTP/HTTPS URL';
    const parsed = new URL(body.url);
    if (parsed.username || parsed.password) return 'URLs containing credentials are not supported';
  }
  if (id === 'threat-scan' && !body.fullName) return 'fullName is required';
  if (id === 'opsec-score') {
    if (!body.fullName && !body.handle && !body.email) return 'At least one of fullName, handle, or email is required';
    if (body.email && !isValidEmail(body.email)) return 'Invalid email address';
  }
  return null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let failed = false;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        if (!failed) {
          failed = true;
          chunks.length = 0;
          req.pause();
          reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        }
        return;
      }
      if (!failed) chunks.push(chunk);
    });
    req.on('end', () => { if (failed) return; try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(new Error('Invalid JSON body')); } });
    req.on('error', reject);
  });
}

function canonicalBase(value) {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') throw new Error('PUBLIC_URL must be an HTTP(S) origin, without path, query or credentials');
  return parsed.origin;
}

function createServer({ payment = paymentDefault, agents = defaultAgents, publicUrl = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL, registration = { agentId: process.env.AGENT_ID, agentRegistry: process.env.AGENT_REGISTRY } } = {}) {
  const skills = createSkills(agents);
  const instance = randomUUID();
  const configuredBase = publicUrl ? canonicalBase(publicUrl) : null;
  const trustProxy = process.env.RENDER === 'true' || process.env.TRUST_PROXY === 'true';
  const runtimePayment = { protocol: 'x402', x402Version: 2, scheme: 'exact', network: payment.NETWORK, asset: payment.USDC_BASE, payTo: payment.PAY_TO, facilitator: payment.FACILITATOR };
  const baseFor = req => {
    if (configuredBase) return configuredBase;
    const host = req.headers.host;
    if (!host || !/^[a-zA-Z0-9.\-:[\]]+$/.test(host)) throw new Error('Invalid Host header');
    return canonicalBase(`http://${host}`);
  };
  function catalog(base) {
    return { paid: Object.entries(skills).map(([id, s]) => ({ id, method: 'POST', url: base + s.path, priceUsd: s.priceUsd, description: s.description, body: s.bodySchema, requiresConsent: !!s.requiresConsent, example: s.inputExample })), disabled: DISABLED, payment: runtimePayment, terms: base + '/terms', logo: base + '/icon.svg', openapi: base + '/openapi.json' };
  }
  function runtimeManifest(base) {
    return { ...manifest, image: base + '/icon.svg', logo: base + '/icon.svg', website: base, payment: { ...runtimePayment, terms: base + '/terms' }, skills: Object.entries(skills).map(([id, s]) => {
      const { inputs, outputs, ...identity } = manifest.skills.find(item => item.id === id) || {};
      return { ...identity, id, description: s.description, tags: s.tags, endpoint: base + s.path, method: 'POST', inputSchema: s.bodySchema, example: s.inputExample, outputExample: s.outputExample, requiresConsent: !!s.requiresConsent, pricing: { perCallAmount: payment.requirements(s).amount, token: 'USDC', tokenAddress: payment.USDC_BASE, protocol: 'x402 v2 exact', network: payment.NETWORK } };
    }), discovery: { openapi: base + '/openapi.json', agentRegistration: base + '/agent-registration.json', llms: base + '/llms.txt' } };
  }
  return http.createServer({ requestTimeout: 15000, headersTimeout: 10000, keepAliveTimeout: 5000 }, async (req, res) => {
    setSecurityHeaders(res);
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    const send = (status, body, headers = {}) => {
      const data = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
      res.writeHead(status, { 'Content-Type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data), 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE', ...headers });
      res.end(req.method === 'HEAD' ? undefined : data);
    };
    try {
      const base = baseFor(req);
      const url = new URL(req.url, base).pathname;
      const peer = req.socket.remoteAddress || 'unknown';
      const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map(value => value.trim()).filter(Boolean);
      const ip = trustProxy && forwarded.length ? forwarded[forwarded.length - 1] : peer;
      if (req.method === 'OPTIONS') return send(204, '', { 'Access-Control-Allow-Headers': 'Content-Type, PAYMENT-SIGNATURE, X-PAYMENT', 'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS' });
      if (req.method === 'GET' || req.method === 'HEAD') {
        const rate = checkRateLimit(`${instance}:public:${ip}`, RATE_LIMIT_PUBLIC);
        if (!rate.allowed) return send(429, { error: 'Too many requests', retryAfter: rate.retryAfter }, { 'Retry-After': String(rate.retryAfter) });
        if (url === '/health') return send(200, { status: 'ok', agent: manifest.name, version: manifest.version });
        if (url === '/skills') return send(200, catalog(base));
        if (url === '/manifest') return send(200, runtimeManifest(base));
        if (url === '/terms') return send(200, TERMS);
        if (url === '/logo.png') return send(302, '', { Location: base + '/icon.svg' });
        if (url === '/.well-known/x402') return send(200, { x402Version: 2, ...runtimePayment, resources: Object.values(skills).map(s => ({ resource: base + s.path, method: 'POST', description: s.description, priceUsd: s.priceUsd, accepts: [payment.requirements(s)], extensions: payment.paymentRequired(s, base).extensions })) });
        const route = createDiscovery({ base, manifest: runtimeManifest(base), skills, payment: runtimePayment, registration }).route(url);
        if (route) return send(route.status, route.body, { 'Content-Type': route.contentType });
      }
      if (req.method === 'POST' && url.startsWith('/skills/')) {
        const id = url.slice('/skills/'.length);
        if (DISABLED[id]) return send(410, { error: DISABLED[id] });
        const skill = skills[id];
        if (!skill) return send(404, { error: 'Unknown skill', available: Object.keys(skills) });
        const rate = checkRateLimit(`${instance}:paid:${ip}`, RATE_LIMIT_PAID);
        if (!rate.allowed) return send(429, { error: 'Too many requests', retryAfter: rate.retryAfter }, { 'Retry-After': String(rate.retryAfter) });
        const type = req.headers['content-type'];
        if (type && !/^application\/json(?:\s*;|$)/i.test(type)) return send(415, { error: 'Use Content-Type: application/json' });
        let body;
        try { body = await readBody(req); } catch (error) {
          if (error.statusCode === 413) {
            res.once('finish', () => req.socket.destroySoon());
            return send(413, { error: error.message }, { Connection: 'close' });
          }
          return send(error.statusCode || 400, { error: error.message });
        }
        const invalid = validateBody(id, body, skill);
        if (invalid) return send(400, { error: invalid, terms: base + '/terms' });
        const verified = await payment.verify(req, skill, base);
        if (!verified.ok) return send(verified.status, verified.body, verified.headers);
        let result;
        try { result = await skill.run(body); }
        catch (error) {
          console.error(`Skill failed [${id}] code=${error.code || 'UPSTREAM_FAILED'}`);
          const status = Number.isInteger(error.statusCode) && error.statusCode >= 400 && error.statusCode <= 599 ? error.statusCode : 502;
          return send(status, { error: error.code === 'UNSAFE_TARGET' ? 'The target is not a permitted public web address' : 'The assessment could not be completed; no payment was settled by this request', code: error.code || 'UPSTREAM_FAILED' });
        }
        const settled = await payment.settle(verified.payload, skill);
        if (!settled.ok) return send(settled.status, settled.body);
        console.log(JSON.stringify({ event: 'skill_settled', skill: id, amount: payment.requirements(skill).amount, network: payment.NETWORK, transaction: settled.receipt?.transaction || null }));
        return send(200, { skill: id, result }, settled.headers);
      }
      return send(404, { error: 'Not found', hint: 'See /skills or /openapi.json' });
    } catch (error) {
      console.error('Request failed:', error.code || 'INTERNAL_ERROR');
      if (!res.headersSent) send(500, { error: 'Internal server error' });
      else res.end();
    }
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const server = createServer();
  server.listen(port, () => console.log(`PhantomOperator listening on :${port}\npayTo ${paymentDefault.PAY_TO} via ${paymentDefault.FACILITATOR}`));
}
module.exports = { createServer, createSkills, validateBody };

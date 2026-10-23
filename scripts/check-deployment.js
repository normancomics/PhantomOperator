#!/usr/bin/env node
'use strict';

// Public discovery and unpaid 402 checks only. Never signs or pays for a call.
const { ethers } = require('ethers');

const SKILLS = {
  'metadata-audit': { priceUsd: 0.05, amount: '50000', body: { url: 'https://example.com' } },
  'threat-scan': { priceUsd: 0.10, amount: '100000', body: { fullName: 'Development Fixture', consent: true } },
  'opsec-score': { priceUsd: 0.25, amount: '250000', body: { handle: 'phantom_fixture', consent: true } },
};
const TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
const MAX_BYTES = 1024 * 1024;

function normalizeBase(value, allowHttp = false) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Supply the explicit public HTTPS service URL.'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(allowHttp && local && url.protocol === 'http:')) throw new Error('Service URL must use HTTPS (--allow-http is for loopback development only).');
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) throw new Error('Service URL must be an origin without credentials, path, query, or fragment.');
  return url.origin;
}

function normalizeAddress(value) {
  try {
    const canonical = ethers.utils.getAddress(value);
    return canonical === ethers.constants.AddressZero ? null : canonical;
  } catch { return null; }
}

async function readBounded(response) {
  if (Number(response.headers.get('content-length')) > MAX_BYTES) throw new Error('Response exceeds the 1 MiB verification limit.');
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = []; let bytes = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      bytes += item.value.length;
      if (bytes > MAX_BYTES) throw new Error('Response exceeds the 1 MiB verification limit.');
      chunks.push(Buffer.from(item.value));
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

function isRealImage(response) {
  if (!response?.headers || !Buffer.isBuffer(response.bytes)) return false;
  const type = response.headers.get('content-type') || '';
  if (/image\/png/i.test(type)) return response.bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (/image\/svg\+xml/i.test(type)) return /<svg(?:\s|>)/i.test(response.text) && !/<(?:!doctype\s+html|html)(?:\s|>)/i.test(response.text);
  return false;
}

async function checkDeployment(serviceUrl, options = {}) {
  const base = normalizeBase(serviceUrl, options.allowHttp);
  const expected = options.expectedPayTo ? normalizeAddress(options.expectedPayTo) : null;
  if (options.expectedPayTo && !expected) throw new Error('--expected-pay-to must be a valid Ethereum address.');
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const checks = []; const warnings = [];
  const responses = {};
  const add = (name, ok, detail, pathname) => checks.push({ name, ok: Boolean(ok), ...(pathname ? { path: pathname } : {}), ...(detail ? { detail } : {}) });

  async function request(pathname, { method = 'GET', body, coldStart = false } = {}) {
    const attempts = coldStart ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        const response = await fetchImpl(`${base}${pathname}`, {
          method,
          headers: body ? { 'content-type': 'application/json' } : {},
          ...(body ? { body: JSON.stringify(body) } : {}),
          redirect: 'error',
          signal: AbortSignal.timeout(coldStart ? (options.coldStartTimeoutMs || 55000) : (options.timeoutMs || 12000)),
        });
        if (coldStart && attempt === 0 && [502, 503, 504].includes(response.status)) {
          await response.body?.cancel();
          if (options.wait) await options.wait(1000);
          else await new Promise(resolve => setTimeout(resolve, 1000));
          continue;
        }
        const bytes = await readBounded(response);
        const result = { status: response.status, headers: response.headers, bytes, text: bytes.toString('utf8') };
        if (/application\/(?:[\w.+-]*\+)?json/i.test(response.headers.get('content-type') || '')) {
          try { result.json = JSON.parse(result.text); } catch { result.error = 'Response declared JSON but was not valid JSON.'; }
        }
        return result;
      } catch (error) {
        if (coldStart && attempt === 0 && (error.name === 'TimeoutError' || error.name === 'AbortError')) continue;
        return { error: error.message || 'Network request failed.' };
      }
    }
    return { error: 'Readiness request did not complete.' };
  }

  const health = await request('/health', { coldStart: true });
  add('HTTP health', health.status === 200 && health.json?.status === 'ok' && health.json?.agent === 'PhantomOperator', health.error || (health.status ? `HTTP ${health.status}` : 'No response'), '/health');
  if (!checks[0].ok) return report();

  // These come before the catalog probes for compatibility with old deployments
  // whose public and paid routes accidentally share one rate-limit counter.
  for (const [id, skill] of Object.entries(SKILLS)) {
    responses[`challenge:${id}`] = await request(`/skills/${id}`, { method: 'POST', body: skill.body });
  }
  const paths = ['/skills', '/manifest', '/openapi.json', '/agent-registration.json', '/.well-known/agent-registration.json', '/robots.txt', '/llms.txt', '/sitemap.xml', '/icon.svg'];
  const all = await Promise.all(paths.map(pathname => request(pathname)));
  paths.forEach((pathname, index) => { responses[pathname] = all[index]; });
  for (const pathname of paths) {
    const response = responses[pathname];
    add(`HTTP ${pathname}`, response.status === 200 && !response.error, response.error || `HTTP ${response.status}`, pathname);
  }

  const catalog = responses['/skills'].json;
  const payment = catalog?.payment;
  const actualPayTo = normalizeAddress(payment?.payTo);
  add('Base x402 payment configuration', payment?.network === 'eip155:8453' && payment?.scheme === 'exact' && actualPayTo && normalizeAddress(payment?.asset), undefined, '/skills');
  if (expected) add('Requested payment receiver', actualPayTo === expected, actualPayTo ? `Advertised receiver: ${actualPayTo}` : 'Missing or invalid receiver.', '/skills');
  const paid = Array.isArray(catalog?.paid) ? catalog.paid : [];
  add('Exactly three advertised working skills', paid.length === 3 && Object.keys(SKILLS).every(id => paid.some(skill => skill.id === id)), undefined, '/skills');
  const manifest = responses['/manifest'].json;
  add('Manifest agrees with runtime payment', normalizeAddress(manifest?.payment?.payTo) === actualPayTo && actualPayTo && manifest?.payment?.network === payment?.network && normalizeAddress(manifest?.payment?.asset) === normalizeAddress(payment?.asset), undefined, '/manifest');
  const manifestSkills = Array.isArray(manifest?.skills) ? manifest.skills : [];
  add('Manifest advertises only implemented skills', manifestSkills.length === 3 && Object.keys(SKILLS).every(id => manifestSkills.some(skill => skill.id === id)), undefined, '/manifest');

  for (const [id, skill] of Object.entries(SKILLS)) {
    const advertised = paid.find(item => item.id === id);
    const listed = manifestSkills.find(item => item.id === id);
    add(`${id}: catalog and manifest price`, advertised?.priceUsd === skill.priceUsd && advertised?.method === 'POST' && advertised?.url === `${base}/skills/${id}` && listed?.pricing?.perCallAmount === skill.amount, undefined, '/skills');
    add(`${id}: consent requirement advertised`, advertised?.requiresConsent === (id !== 'metadata-audit'), undefined, '/skills');
    const challenge = responses[`challenge:${id}`];
    const offer = challenge.json?.accepts?.[0];
    let header;
    try { header = JSON.parse(Buffer.from(challenge.headers?.get('payment-required') || '', 'base64').toString('utf8')); } catch { /* reported as a failing check below */ }
    const headerOffer = header?.accepts?.[0];
    add(`${id}: unpaid x402 v2 challenge`, challenge.status === 402 && challenge.json?.x402Version === 2 && header?.x402Version === 2 && offer?.amount === skill.amount && offer?.network === 'eip155:8453' && offer?.scheme === 'exact' && normalizeAddress(offer?.payTo) === actualPayTo && actualPayTo && normalizeAddress(offer?.asset) === normalizeAddress(payment?.asset) && JSON.stringify(headerOffer) === JSON.stringify(offer), challenge.error || (challenge.status !== 402 ? `Expected HTTP 402; received ${challenge.status}.` : undefined), `/skills/${id}`);
  }

  const openapi = responses['/openapi.json'].json;
  add('OpenAPI 3.1 and complete paid operations', /^3\.1\./.test(openapi?.openapi || '') && Object.keys(SKILLS).every(id => {
    const post = openapi?.paths?.[`/skills/${id}`]?.post;
    return post?.requestBody?.content?.['application/json']?.schema && post?.responses?.['200'] && post?.responses?.['402'];
  }), undefined, '/openapi.json');
  const registration = responses['/agent-registration.json'].json;
  const services = Array.isArray(registration?.services) ? registration.services : [];
  add('ERC-8004 registration file and real services', registration?.type === TYPE && registration?.name === 'PhantomOperator' && registration?.active === true && registration?.x402Support === true && Array.isArray(registration?.registrations) && services.some(service => service?.name === 'web' && [base, `${base}/`].includes(service.endpoint)) && services.some(service => service?.name === 'OpenAPI' && service.endpoint === `${base}/openapi.json`), undefined, '/agent-registration.json');
  const association = responses['/.well-known/agent-registration.json'].json;
  const validRegistration = (entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const parts = typeof entry.agentRegistry === 'string' && entry.agentRegistry.match(/^eip155:([1-9]\d*):(0x[0-9a-fA-F]{40})$/);
    if (!parts || !normalizeAddress(parts[2])) return false;
    if (typeof entry.agentId === 'number' && (!Number.isSafeInteger(entry.agentId) || entry.agentId < 0)) return false;
    if (!['string', 'number'].includes(typeof entry.agentId) || !/^(?:0|[1-9]\d*)$/.test(String(entry.agentId))) return false;
    try { return BigInt(entry.agentId) < 2n ** 256n; } catch { return false; }
  };
  const normalizeRegistrations = (entries) => Array.isArray(entries) && entries.every(validRegistration) ? entries.map(entry => `${entry.agentRegistry.toLowerCase()}:${entry.agentId}`).sort() : null;
  const registrations = registration?.registrations;
  const canonicalRegistrations = normalizeRegistrations(registrations);
  add('Domain association matches registration file', canonicalRegistrations && JSON.stringify(normalizeRegistrations(association?.registrations)) === JSON.stringify(canonicalRegistrations), undefined, '/.well-known/agent-registration.json');
  if (Array.isArray(registrations) && registrations.length === 0) warnings.push('No ERC-8004 registration is declared. Hosted metadata alone does not create an identity or directory listing.');
  else if (Array.isArray(registrations)) warnings.push('ERC-8004 identities are declared but were not checked against a blockchain RPC or indexer.');
  add('Crawlable robots and canonical sitemap', responses['/robots.txt'].text?.includes(`${base}/sitemap.xml`) && /<urlset(?:\s|>)/.test(responses['/sitemap.xml'].text || '') && responses['/sitemap.xml'].text?.includes(`<loc>${base}/`), undefined, '/sitemap.xml');
  add('Agent instructions link working skills and API schema', responses['/llms.txt'].text?.includes(`${base}/openapi.json`) && Object.keys(SKILLS).every(id => responses['/llms.txt'].text?.includes(`/skills/${id}`)), undefined, '/llms.txt');
  add('Discoverable icon is an actual image', isRealImage(responses['/icon.svg']), undefined, '/icon.svg');
  add('Registration image uses verified icon', registration?.image === `${base}/icon.svg`, undefined, '/agent-registration.json');
  return report();

  function report() {
    return {
      ok: checks.length > 0 && checks.every(check => check.ok),
      baseUrl: base,
      checkedAt: new Date().toISOString(),
      scope: 'Public HTTP discovery and unpaid payment challenges. No signing, payment, registration, or deployment is performed.',
      paidSkillExecutionVerified: false,
      paymentSettlementVerified: false,
      onchainRegistrationVerified: false,
      checks,
      warnings,
    };
  }
}

function parseArgs(argv) {
  const options = {}; let serviceUrl;
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--allow-http') options.allowHttp = true;
    else if (arg === '--expected-pay-to' && argv[index + 1] && !options.expectedPayTo) options.expectedPayTo = argv[++index];
    else if (!arg.startsWith('-') && !serviceUrl) serviceUrl = arg;
    else throw new Error(`Unknown, duplicate, or incomplete argument: ${arg}`);
  }
  if (!options.help && !serviceUrl) throw new Error('Supply the explicit public HTTPS service URL; this tool will not guess the deployment URL.');
  return { serviceUrl, options };
}

async function main(argv = process.argv.slice(2)) {
  const { serviceUrl, options } = parseArgs(argv);
  if (options.help) {
    process.stdout.write('Usage: node scripts/check-deployment.js https://service.example [--expected-pay-to 0x...] [--allow-http]\nRead-only public discovery and unpaid HTTP 402 checks. --allow-http permits loopback development only.\n');
    return;
  }
  const report = await checkDeployment(serviceUrl, options);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.ok) process.exitCode = 1;
}

if (require.main === module) {
  main().catch(error => {
    process.stderr.write(`${JSON.stringify({ ok: false, error: error.message })}\n`);
    process.exitCode = 2;
  });
}

module.exports = { checkDeployment, normalizeBase, isRealImage, parseArgs, SKILLS };

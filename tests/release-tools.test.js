'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const { ethers } = require('ethers');
const { checkDeployment, normalizeBase, isRealImage, parseArgs, SKILLS } = require('../scripts/check-deployment');
const { prepareRegistration, parseArgs: parseRegistrationArgs } = require('../scripts/prepare-registration');

const PAY_TO = '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';
// Synthetic test addresses; these are not deployment contract addresses.
const ASSET = '0x1111111111111111111111111111111111111111';
const REGISTRY = '0x2222222222222222222222222222222222222222';
const TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';

function fixtures(base) {
  const payment = { protocol: 'x402 v2', scheme: 'exact', network: 'eip155:8453', asset: ASSET, payTo: PAY_TO, facilitator: 'https://facilitator.example' };
  const operations = Object.fromEntries(Object.keys(SKILLS).map(id => [`/skills/${id}`, {
    post: { requestBody: { content: { 'application/json': { schema: { type: 'object' } } } }, responses: { 200: { description: 'Success' }, 402: { description: 'Payment required' } } },
  }]));
  const registration = { type: TYPE, name: 'PhantomOperator', active: true, x402Support: true, image: `${base}/icon.svg`, registrations: [], services: [{ name: 'web', endpoint: base }, { name: 'OpenAPI', endpoint: `${base}/openapi.json` }] };
  return {
    '/health': { status: 'ok', agent: 'PhantomOperator' },
    '/skills': { payment, paid: Object.entries(SKILLS).map(([id, skill]) => ({ id, method: 'POST', url: `${base}/skills/${id}`, priceUsd: skill.priceUsd, requiresConsent: id !== 'metadata-audit' })) },
    '/manifest': { name: 'PhantomOperator', payment, skills: Object.entries(SKILLS).map(([id, skill]) => ({ id, pricing: { perCallAmount: skill.amount } })) },
    '/openapi.json': { openapi: '3.1.0', paths: operations },
    '/agent-registration.json': registration,
    '/.well-known/agent-registration.json': { registrations: [] },
    '/robots.txt': `User-agent: *\nAllow: /\nSitemap: ${base}/sitemap.xml\n`,
    '/llms.txt': `${base}/openapi.json\n${Object.keys(SKILLS).map(id => `/skills/${id}`).join('\n')}`,
    '/sitemap.xml': `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${base}/</loc></url></urlset>`,
    '/icon.svg': '<svg xmlns="http://www.w3.org/2000/svg"><text>PO</text></svg>',
  };
}

function createFetch(base, adjust) {
  const data = fixtures(base);
  if (adjust) adjust(data);
  const requests = [];
  async function fetchImpl(url, options = {}) {
    requests.push({ url, ...options });
    const pathname = new URL(url).pathname;
    if (options.method === 'POST') {
      const id = pathname.slice('/skills/'.length);
      const offer = { scheme: 'exact', network: 'eip155:8453', asset: ASSET, payTo: PAY_TO, amount: SKILLS[id].amount };
      const body = { x402Version: 2, accepts: [offer] };
      return new Response(JSON.stringify(body), { status: 402, headers: { 'content-type': 'application/json', 'payment-required': Buffer.from(JSON.stringify(body)).toString('base64') } });
    }
    const value = data[pathname];
    if (value === undefined) return new Response('Not found', { status: 404 });
    const contentType = pathname === '/icon.svg' ? 'image/svg+xml' : typeof value === 'string' ? 'text/plain' : 'application/json';
    return new Response(typeof value === 'string' ? value : JSON.stringify(value), { headers: { 'content-type': contentType } });
  }
  return { fetchImpl, requests, data };
}

test('deployment verifier checks genuine public documents and unpaid offers without paying', async () => {
  const base = 'https://phantom.example';
  const { fetchImpl, requests } = createFetch(base);
  const report = await checkDeployment(base, { fetchImpl, expectedPayTo: PAY_TO });
  assert.equal(report.ok, true, JSON.stringify(report.checks.filter(check => !check.ok)));
  assert.ok(report.checks.length >= 20);
  assert.equal(requests.length, 13);
  assert.equal(requests.filter(request => request.method === 'POST').length, 3);
  for (const request of requests) {
    assert.equal(request.headers['payment-signature'], undefined);
    assert.equal(request.headers['x-payment'], undefined);
    assert.equal(new URL(request.url).origin, base);
  }
  assert.equal(report.paymentSettlementVerified, false);
  assert.equal(report.paidSkillExecutionVerified, false);
  assert.equal(report.onchainRegistrationVerified, false);
  assert.match(report.warnings.join(' '), /No ERC-8004 registration/);
});

test('runtime and manifest receiver mismatch fails the verifier', async () => {
  const base = 'https://phantom.example';
  const { fetchImpl } = createFetch(base, data => { data['/manifest'].payment = { ...data['/manifest'].payment, payTo: REGISTRY }; });
  const report = await checkDeployment(base, { fetchImpl, expectedPayTo: PAY_TO });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find(check => check.name === 'Manifest agrees with runtime payment').ok, false);
});

test('price mismatch and missing OpenAPI response are real failures', async () => {
  const base = 'https://phantom.example';
  const { fetchImpl } = createFetch(base, data => {
    data['/skills'].paid.find(skill => skill.id === 'metadata-audit').priceUsd = 0.5;
    delete data['/openapi.json'].paths['/skills/threat-scan'].post.responses['402'];
  });
  const report = await checkDeployment(base, { fetchImpl });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find(check => check.name === 'metadata-audit: catalog and manifest price').ok, false);
  assert.equal(report.checks.find(check => check.name === 'OpenAPI 3.1 and complete paid operations').ok, false);
});

test('declared registrations must match the domain association without implying on-chain verification', async () => {
  const base = 'https://phantom.example';
  const pair = { agentId: '9007199254740993', agentRegistry: `eip155:8453:${REGISTRY}` };
  const { fetchImpl } = createFetch(base, data => {
    data['/agent-registration.json'].registrations = [pair];
    data['/.well-known/agent-registration.json'].registrations = [{ ...pair, agentId: '1' }];
  });
  const report = await checkDeployment(base, { fetchImpl });
  assert.equal(report.ok, false);
  assert.equal(report.onchainRegistrationVerified, false);
  assert.equal(report.checks.find(check => check.name === 'Domain association matches registration file').ok, false);
  assert.match(report.warnings.join(' '), /not checked against a blockchain/);
});

test('malformed registration metadata fails checks rather than crashing or accepting matching garbage', async () => {
  const base = 'https://phantom.example';
  const { fetchImpl } = createFetch(base, data => {
    data['/agent-registration.json'].services = 'not a services array';
    data['/agent-registration.json'].registrations = [{}];
    data['/.well-known/agent-registration.json'].registrations = [{}];
  });
  const report = await checkDeployment(base, { fetchImpl });
  assert.equal(report.ok, false);
  assert.equal(report.checks.find(check => check.name === 'ERC-8004 registration file and real services').ok, false);
  assert.equal(report.checks.find(check => check.name === 'Domain association matches registration file').ok, false);
});

test('PNG content type cannot hide an HTML file; SVG must really be SVG', () => {
  const fake = { headers: new Headers({ 'content-type': 'image/png' }), bytes: Buffer.from('<html><img src="logo.png"></html>'), text: '<html><img src="logo.png"></html>' };
  assert.equal(isRealImage(fake), false);
  const real = { headers: new Headers({ 'content-type': 'image/png' }), bytes: Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), text: '' };
  assert.equal(isRealImage(real), true);
  assert.equal(isRealImage({ error: 'Network blocked' }), false);
  assert.equal(isRealImage({ headers: new Headers({ 'content-type': 'image/svg+xml' }), bytes: Buffer.from('<html><svg></svg></html>'), text: '<html><svg></svg></html>' }), false);
});

test('network denial is reported as failure and stops unnecessary downstream probes', async () => {
  let count = 0;
  const report = await checkDeployment('https://phantom.example', { fetchImpl: async () => { count++; throw Error('Network denied'); } });
  assert.equal(report.ok, false);
  assert.equal(count, 1);
  assert.match(report.checks[0].detail, /Network denied/);
});

test('Render cold start gets one bounded retry, not an endless loop', async () => {
  const base = 'https://phantom.example';
  const fake = createFetch(base); let count = 0;
  const report = await checkDeployment(base, {
    fetchImpl: async (url, options) => {
      if (url.endsWith('/health') && count++ === 0) return new Response('Waking up', { status: 503 });
      return fake.fetchImpl(url, options);
    },
    wait: async () => {},
  });
  assert.equal(count, 2);
  assert.equal(report.ok, true);
});

test('real HTTP fixture exercises local fetch and JSON output validation', async () => {
  let base; let data;
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      const id = req.url.slice('/skills/'.length);
      const body = { x402Version: 2, accepts: [{ scheme: 'exact', network: 'eip155:8453', asset: ASSET, payTo: PAY_TO, amount: SKILLS[id].amount }] };
      res.writeHead(402, { 'content-type': 'application/json', 'payment-required': Buffer.from(JSON.stringify(body)).toString('base64') });
      res.end(JSON.stringify(body));
      return;
    }
    const body = data[req.url];
    const type = req.url === '/icon.svg' ? 'image/svg+xml' : typeof body === 'string' ? 'text/plain' : 'application/json';
    res.writeHead(200, { 'content-type': type });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  data = fixtures(base);
  try {
    const report = await checkDeployment(base, { allowHttp: true, expectedPayTo: PAY_TO });
    assert.equal(report.ok, true, JSON.stringify(report.checks.filter(check => !check.ok)));
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('CLI requires an explicit origin and never treats an arbitrary HTTP host as local', () => {
  assert.throws(() => parseArgs([]), /explicit public HTTPS/);
  assert.throws(() => normalizeBase('https://name:password@example.com'), /credentials/);
  assert.throws(() => normalizeBase('https://example.com/path'), /origin/);
  assert.throws(() => normalizeBase('http://example.com', true), /HTTPS/);
  assert.equal(normalizeBase('http://127.0.0.1:3000/', true), 'http://127.0.0.1:3000');
});

test('zero address cannot be passed off as the requested payment receiver', async () => {
  await assert.rejects(checkDeployment('https://phantom.example', { expectedPayTo: ethers.constants.AddressZero }), /valid Ethereum address/);
});

test('registration proposal uses exact register(string) ABI, zero value, and explicit ownership', () => {
  const uri = 'https://phantom.example/agent-registration.json';
  const proposal = prepareRegistration({ registry: REGISTRY, owner: PAY_TO, agentUri: uri });
  const iface = new ethers.utils.Interface(['function register(string agentURI) returns (uint256 agentId)']);
  assert.equal(proposal.status, 'unsigned-proposal-only');
  assert.equal(proposal.transaction.chainId, 8453);
  assert.equal(proposal.transaction.from, PAY_TO);
  assert.equal(proposal.transaction.to, REGISTRY);
  assert.equal(proposal.transaction.value, '0x0');
  assert.equal(iface.decodeFunctionData('register(string)', proposal.transaction.data)[0], uri);
  assert.equal(proposal.registrationFile.type, TYPE);
  assert.deepEqual(proposal.registrationFile.registrations, []);
  assert.equal(proposal.registrationFile.services.some(service => ['MCP', 'A2A'].includes(service.name)), false);
  assert.match(proposal.checksRequiredBeforeSigning.join(' '), /does not verify contract code/);
  assert.match(proposal.afterConfirmedTransaction.join(' '), /setAgentWallet/);
});

test('registration refuses missing identity, zero address, broken checksum, or URI secrets', () => {
  const valid = { registry: REGISTRY, owner: PAY_TO, agentUri: 'https://phantom.example/agent-registration.json' };
  assert.throws(() => prepareRegistration({ ...valid, registry: undefined }), /--registry is required/);
  assert.throws(() => prepareRegistration({ ...valid, owner: undefined }), /--owner is required/);
  assert.throws(() => prepareRegistration({ ...valid, registry: ethers.constants.AddressZero }), /zero address/);
  assert.throws(() => prepareRegistration({ ...valid, owner: PAY_TO.replace('C5f', 'c5f') }), /checksum/);
  assert.throws(() => prepareRegistration({ ...valid, agentUri: 'https://user:secret@phantom.example/agent-registration.json' }), /credentials/);
  assert.throws(() => prepareRegistration({ ...valid, agentUri: 'https://phantom.example/agent-registration.json?api_key=secret' }), /query/);
  assert.throws(() => prepareRegistration({ ...valid, agentUri: 'file:///etc/passwd' }), /HTTPS or IPFS/);
});

test('IPFS registration requires an explicit working HTTPS service and does not invent endpoints', () => {
  const options = { registry: REGISTRY, owner: PAY_TO, agentUri: 'ipfs://examplecid/registration.json' };
  assert.throws(() => prepareRegistration(options), /HTTPS service URL/);
  const proposal = prepareRegistration({ ...options, serviceUrl: 'https://phantom.example' });
  assert.equal(proposal.agentURI, options.agentUri);
  assert.equal(proposal.registrationFile.services[0].endpoint, 'https://phantom.example');
  assert.throws(() => parseRegistrationArgs(['--owner', PAY_TO, '--owner', PAY_TO]), /duplicate/);
});

test('registration CLI emits only an unsigned public proposal and works without environment credentials', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, '../scripts/prepare-registration.js'), '--registry', REGISTRY, '--owner', PAY_TO, '--agent-uri', 'https://phantom.example/agent-registration.json'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(result.status, 0, result.stderr);
  const proposal = JSON.parse(result.stdout);
  assert.equal(proposal.status, 'unsigned-proposal-only');
  assert.equal(proposal.transaction.from, PAY_TO);
  assert.equal(result.stderr, '');
});

test('registration CLI preserves an existing proposal instead of overwriting it', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-registration-'));
  const output = path.join(directory, 'proposal.json');
  try {
    await fs.writeFile(output, 'existing public proposal');
    const result = spawnSync(process.execPath, [path.join(__dirname, '../scripts/prepare-registration.js'), '--registry', REGISTRY, '--owner', PAY_TO, '--agent-uri', 'https://phantom.example/agent-registration.json', '--output', output], { encoding: 'utf8', env: { PATH: process.env.PATH } });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /EEXIST/);
    assert.equal(result.stdout, '');
    assert.equal(await fs.readFile(output, 'utf8'), 'existing public proposal');
  } finally {
    await fs.rm(directory, { recursive: true });
  }
});

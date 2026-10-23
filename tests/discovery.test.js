'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const cheerio = require('cheerio');
const { createDiscovery } = require('../lib/discovery');
const MetadataAgent = require('../agents/MetadataAgent');
const SearchAgent = require('../agents/SearchAgent');

const base = 'https://operator.example';
const payment = { payTo: '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6', network: 'eip155:8453', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', facilitator: 'https://facilitator.payai.network' };
const skills = {
  'metadata-audit': { path: '/skills/metadata-audit', priceUsd: 0.05, description: 'Audit public page metadata.', bodySchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] }, inputExample: { url: 'https://example.com' }, outputExample: { skill: 'metadata-audit', result: { overallRisk: 'none', findings: [] } } },
  'threat-scan': { path: '/skills/threat-scan', priceUsd: 0.10, description: 'Search public web exposure signals.', requiresConsent: true, bodySchema: { type: 'object', properties: { fullName: { type: 'string' }, consent: { type: 'boolean' } }, required: ['fullName', 'consent'] }, inputExample: { fullName: 'Jane Example', consent: true }, outputExample: { skill: 'threat-scan', result: [] } },
  'opsec-score': { path: '/skills/opsec-score', priceUsd: 0.25, description: 'Score public exposure signals.', requiresConsent: true, bodySchema: { type: 'object', properties: { handle: { type: 'string' }, consent: { type: 'boolean' } }, required: ['consent'] }, inputExample: { handle: 'janeexample', consent: true }, outputExample: { skill: 'opsec-score', result: { score: 0, grade: 'A', breakdown: {} } } },
};
const manifest = { name: 'PhantomOperator', version: '0.1.0', image: 'https://obsolete.example/broken.png', skills: [{ id: 'metadata-audit', name: 'Metadata Privacy Audit' }, { id: 'threat-scan', name: 'Threat Scan' }, { id: 'opsec-score', name: 'OPSEC Exposure Score' }] };
const discovery = overrides => createDiscovery({ base, manifest, skills, payment, ...overrides });

test('homepage offers working skill documents, honest examples, and runtime canonical metadata', () => {
  const app = discovery();
  const response = app.route('/');
  assert.equal(response.status, 200);
  assert.match(response.contentType, /^text\/html/);
  const $ = cheerio.load(response.body);
  assert.equal($('h1').text(), 'PhantomOperator');
  assert.equal($('link[rel=canonical]').attr('href'), `${base}/`);
  assert.equal($('meta[property="og:image"]').attr('content'), `${base}/icon.svg`);
  assert.equal($('[itemscope][itemtype="https://schema.org/SoftwareApplication"]').length, 1);
  assert.equal($('[itemtype="https://schema.org/Offer"]').length, 3);
  assert.equal($('link[rel=stylesheet]').attr('href'), `${base}/styles.css`);
  assert.equal($('script, [onclick], [style]').length, 0);
  assert.match($('body').text(), /documentation example, not a scan result/);
  assert.match($('body').text(), /Onchain agent registration is not configured/);
  assert.doesNotMatch(response.body, /aggregateRating|ratingValue|obsolete\.example/);
  for (const skill of Object.values(skills)) {
    assert.ok($(`a[href="${base}${skill.path}"]`).length);
    const detail = app.route(skill.path);
    assert.equal(detail.status, 200);
    const page = cheerio.load(detail.body);
    assert.equal(page('link[rel=canonical]').attr('href'), `${base}${skill.path}`);
    assert.match(page('body').text(), new RegExp(`${skill.priceUsd.toFixed(2)} USDC`));
    assert.ok(page('pre').toArray().some(element => page(element).text().includes(JSON.stringify(skill.inputExample))));
  }
});

test('dynamic input is escaped in HTML without creating tags or active attributes', () => {
  const hostile = '"><img src=x onerror="alert(1)"><script>alert(1)</script>&';
  const customManifest = { ...manifest, name: hostile, skills: [{ id: 'metadata-audit', name: hostile }] };
  const customSkills = { ...skills, 'metadata-audit': { ...skills['metadata-audit'], description: hostile, inputExample: { url: hostile } } };
  const app = discovery({ manifest: customManifest, skills: customSkills, payment: { ...payment, payTo: hostile } });
  for (const pathname of ['/', '/skills/metadata-audit']) {
    const markup = app.route(pathname).body;
    const $ = cheerio.load(markup);
    assert.equal($('script, img[onerror], [onclick]').length, 0);
    assert.ok($('body').text().includes(hostile));
    assert.ok(markup.includes('&lt;script&gt;'));
    assert.equal($('link[rel=canonical]').length, 1);
  }
});

test('base URL normalization preserves deployment prefix and rejects credential or scheme injection', () => {
  const app = discovery({ base: 'https://operator.example/deploy///' });
  assert.equal(app.route('/openapi.json').body.servers[0].url, `${base}/deploy`);
  assert.equal(app.route('/agent-registration.json').body.image, `${base}/deploy/icon.svg`);
  for (const unsafe of ['javascript:alert(1)', 'ftp://example.com', 'https://name:password@example.com', 'https://example.com?x=1', 'https://example.com/#fragment']) {
    assert.throws(() => discovery({ base: unsafe }), /URL|base/i);
  }
});

test('OpenAPI exposes only the three active POST operations with consistent payment and consent details', () => {
  const spec = discovery().route('/openapi.json').body;
  assert.equal(spec.openapi, '3.1.0');
  assert.deepEqual(Object.keys(spec.paths).sort(), Object.values(skills).map(skill => skill.path).sort());
  assert.equal(new Set(Object.values(spec.paths).map(value => value.post.operationId)).size, 3);
  for (const [id, skill] of Object.entries(skills)) {
    const operation = spec.paths[skill.path].post;
    assert.deepEqual(operation.requestBody.content['application/json'].schema, skill.bodySchema);
    assert.deepEqual(operation.requestBody.content['application/json'].example, skill.inputExample);
    assert.equal(operation['x-x402'].requirements.payTo, payment.payTo);
    assert.equal(operation['x-x402'].requirements.amount, String(Math.round(skill.priceUsd * 1e6)));
    assert.equal(operation.responses['402'].content['application/json'].example.accepts[0].asset, payment.asset);
    assert.ok(operation.responses['200']);
    assert.ok(operation.responses['400']);
    assert.ok(operation.responses['413']);
    assert.ok(operation.responses['415']);
    assert.ok(operation.responses['422']);
    assert.ok(operation.responses['429']);
    assert.ok(operation.responses['502']);
    assert.ok(operation.responses['503']);
    assert.ok(operation.responses['504']);
    assert.equal(operation.parameters[0].name, 'PAYMENT-SIGNATURE');
    assert.equal(operation.responses['200'].content['application/json'].schema.properties.skill.const, id);
  }
  const opsec = spec.components.schemas.OpsecScoreResult;
  assert.ok(opsec.properties.grade);
  assert.ok(opsec.properties.breakdown.properties.searchExposure);
  assert.equal(opsec.properties.riskLevel, undefined);
  assert.equal(opsec.properties.vectors, undefined);
});

test('metadata response documentation represents absent headers and observed source evidence', async () => {
  const report = await MetadataAgent.audit('https://public.example.org/', {
    proxyEnvironment: {},
    lookup: async () => [{ address: '93.184.215.14', family: 4 }],
    transport: async () => ({ statusCode: 200, headers: { 'content-type': 'text/html' }, body: '<html><head><meta name="author" content="Example Author"></head></html>' }),
  });
  const spec = discovery().route('/openapi.json').body;
  const documented = spec.components.schemas.MetadataAuditResult.properties;
  const valueTypes = documented.findings.items.properties.value.type;
  assert.ok(report.findings.some(finding => finding.value === null));
  assert.ok(report.findings.some(finding => typeof finding.value === 'string'));
  assert.ok(valueTypes.includes('null'), 'Missing headers serialize as null, not the string "missing"');
  assert.ok(valueTypes.includes('string'));
  assert.ok(documented.status.enum.includes(report.status));
  assert.equal(documented.scope.const, report.scope);
  assert.equal(documented.provenance.properties.transport.const, report.provenance.transport);
  const evidenceSchema = documented.findings.items.properties.evidence.properties;
  for (const finding of report.findings) {
    assert.equal(evidenceSchema.sourceUrl.format, 'uri');
    assert.equal(finding.evidence.sourceUrl, report.url);
    assert.equal(evidenceSchema.observedAt.format, 'date-time');
    assert.equal(finding.evidence.observedAt, report.timestamp);
  }
  assert.ok(documented.limitations);
  const coverage = spec.components.schemas.OpsecScoreResult.properties.coverage.properties;
  assert.equal(coverage.scope.const, 'public-search-snippets');
  assert.equal(coverage.maxResultsPerSearch.const, 15);
});

test('search response documentation includes medium heuristic signals and source provenance', async () => {
  const [report] = await SearchAgent.run({ fullName: 'Jane Example' }, {
    request: async () => ({ status: 200, headers: { 'content-type': 'text/html' }, data: '<div class="result"><a class="result__a" href="https://public.example.org/profile">Jane Example</a><p class="result__snippet">A profile with an email contact field.</p></div>' }),
  });
  assert.equal(report.threatLevel, 'medium');
  const spec = discovery().route('/openapi.json').body;
  const documented = spec.components.schemas.ThreatScanResult.items.properties;
  assert.ok(documented.threatLevel.enum.includes(report.threatLevel));
  assert.equal(documented.evidence.properties.kind.const, report.evidence.kind);
  const provenance = spec.components.schemas.PublicSearchProvenance.properties;
  assert.equal(provenance.provider.const, report.provenance.provider);
  assert.equal(provenance.method.const, report.provenance.method);
  assert.equal(provenance.fetchedPage.const, report.provenance.fetchedPage);
  assert.equal(report.provenance.sourceUrl, report.link);
  assert.ok(documented.limitations);
});

test('registration metadata stays unregistered until a complete, well formed reference is configured', () => {
  const registry = 'eip155:8453:0x1234567890123456789012345678901234567890';
  for (const registration of [{}, { agentId: '42' }, { agentRegistry: registry }, { agentId: 'oops', agentRegistry: registry }, { agentId: '42', agentRegistry: 'https://registry.invalid' }, { agentId: String(1n << 256n), agentRegistry: registry }, { agentId: Number.MAX_SAFE_INTEGER + 1, agentRegistry: registry }]) {
    const app = discovery({ registration });
    assert.deepEqual(app.route('/agent-registration.json').body.registrations, []);
    assert.deepEqual(app.route('/.well-known/agent-registration.json').body, { registrations: [] });
  }
  const agentId = '90071992547409931234567890';
  const app = discovery({ registration: { agentId, agentRegistry: registry } });
  const document = app.route('/agent-registration.json').body;
  assert.equal(document.type, 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1');
  assert.deepEqual(document.registrations, [{ agentId, agentRegistry: registry }]);
  assert.deepEqual(app.route('/.well-known/agent-registration.json').body, { registrations: [{ agentId, agentRegistry: registry }] });
  assert.equal(document.image, `${base}/icon.svg`);
  assert.deepEqual(document.services.map(service => service.name), ['web', 'OpenAPI']);
  assert.equal(document.x402Support, true);
  assert.deepEqual(discovery({ registration: { agentId: '0', agentRegistry: registry } }).route('/agent-registration.json').body.registrations, [{ agentId: '0', agentRegistry: registry }]);
});

test('crawler documents use the deployment URL and publish only real skill pages', () => {
  const app = discovery();
  const robots = app.route('/robots.txt');
  assert.match(robots.contentType, /^text\/plain/);
  assert.ok(robots.body.includes(`Sitemap: ${base}/sitemap.xml`));
  const xml = cheerio.load(app.route('/sitemap.xml').body, { xmlMode: true });
  assert.deepEqual(xml('loc').toArray().map(node => xml(node).text()), [`${base}/`, ...Object.values(skills).map(skill => `${base}${skill.path}`)]);
  const llms = app.route('/llms.txt').body;
  assert.ok(llms.includes(payment.payTo));
  assert.ok(llms.includes(`${base}/openapi.json`));
  assert.ok(llms.includes('Requires consent:true.'));
  assert.ok(llms.includes('No onchain registration is configured'));
  assert.doesNotMatch(llms, /\]\([^)]*\/mcp\)|\]\([^)]*agent-card/);
});

test('static assets have correct MIME types and unknown routes are left to the server', () => {
  const app = discovery();
  const icon = app.route('/icon.svg');
  assert.match(icon.contentType, /^image\/svg\+xml/);
  const svg = cheerio.load(icon.body, { xmlMode: true });
  assert.equal(svg('svg').attr('xmlns'), 'http://www.w3.org/2000/svg');
  assert.equal(svg('title').text(), 'PhantomOperator');
  assert.equal(svg('script').length, 0);
  assert.match(app.route('/styles.css').contentType, /^text\/css/);
  assert.equal(app.route('/skills/disabled-skill'), null);
  assert.equal(app.route('/constructor'), null);
  assert.equal(app.route('/__proto__'), null);
});

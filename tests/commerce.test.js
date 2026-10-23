'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const { spawnSync } = require('node:child_process');
const { setImmediate: nextTurn } = require('node:timers/promises');
const test = require('node:test');
const { createServer } = require('../server');

const REQUESTED_RECEIVER = '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';
const FIXTURE_RECEIVER = '0x1111111111111111111111111111111111111111';
const PUBLIC_URL = 'https://phantom.example';
const FIXTURE_SIGNATURE = 'fixture-authorization-not-a-real-payment';
const ROUTES = {
  'metadata-audit': { body: { url: 'https://example.com/' }, amount: '50000' },
  'threat-scan': { body: { fullName: 'Development Fixture', consent: true }, amount: '100000' },
  'opsec-score': { body: { handle: 'development-fixture', consent: true }, amount: '250000' },
};

function fakePayment(events, overrides = {}) {
  const payment = {
    PAY_TO: FIXTURE_RECEIVER,
    FACILITATOR: 'https://facilitator.example',
    USDC_BASE: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    NETWORK: 'eip155:8453',
    requirements(route) {
      return {
        scheme: 'exact', network: payment.NETWORK,
        amount: String(Math.round(route.priceUsd * 1e6)),
        asset: payment.USDC_BASE, payTo: payment.PAY_TO,
        maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' },
      };
    },
    paymentRequired(route, base, error = 'Payment required') {
      return {
        x402Version: 2,
        error,
        resource: { url: base + route.path, description: route.description, mimeType: 'application/json' },
        accepts: [payment.requirements(route)],
      };
    },
    async verify(req, route, base) {
      events.push('verify');
      if (req.headers['payment-signature'] !== FIXTURE_SIGNATURE) {
        const body = payment.paymentRequired(route, base);
        return {
          ok: false, status: 402, body,
          headers: { 'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(body)).toString('base64') },
        };
      }
      return { ok: true, payload: { x402Version: 2, accepted: payment.requirements(route), payload: { fixtureAuthorization: true } } };
    },
    async settle() {
      events.push('settle');
      return {
        ok: true,
        headers: { 'PAYMENT-RESPONSE': Buffer.from(JSON.stringify({ success: true, fixture: true })).toString('base64') },
      };
    },
    ...overrides,
  };
  return payment;
}

async function fixture(t, options = {}) {
  const events = [];
  const results = {
    metadata: { url: 'https://example.com/', overallRisk: 'none', findingCounts: {}, findings: [] },
    search: [{ title: 'Fixture evidence', link: 'https://example.com/evidence', description: 'Contact fixture@example.com', threatLevel: 'high', reasons: ['email'] }],
    opsec: { score: 20, grade: 'B', breakdown: { searchExposure: 20 }, coverage: { complete: true }, recommendations: [] },
  };
  const agents = {
    MetadataAgent: { async audit(url) { events.push('run:metadata'); assert.equal(url, 'https://example.com/'); return results.metadata; } },
    SearchAgent: { async run(target) { events.push('run:search'); assert.equal(target.fullName, 'Development Fixture'); return results.search; } },
    OpsecAgent: { async assess(target) { events.push('run:opsec'); assert.equal(target.handle, 'development-fixture'); return results.opsec; } },
    ...options.agents,
  };
  const payment = fakePayment(events, options.payment);
  const server = createServer({ payment, agents, publicUrl: PUBLIC_URL });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(pathname, { body, rawBody, paid = false, method = 'GET', headers = {} } = {}) {
    return fetch(base + pathname, {
      method,
      headers: {
        Connection: 'close',
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
        ...(paid ? { 'PAYMENT-SIGNATURE': FIXTURE_SIGNATURE } : {}),
        ...headers,
      },
      ...(rawBody !== undefined ? { body: rawBody } : body !== undefined ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(5000),
    });
  }
  return { request, events, results, payment };
}

function dereference(document, schema) {
  if (!schema?.$ref) return schema;
  assert.match(schema.$ref, /^#\//);
  return schema.$ref.slice(2).split('/').reduce((value, key) => value[key.replace(/~1/g, '/').replace(/~0/g, '~')], document);
}

test('the configured default receiver is the user-requested public address', () => {
  const result = spawnSync(process.execPath, ['-e', 'console.log(require("./lib/x402").PAY_TO)'], {
    cwd: require('node:path').resolve(__dirname, '..'),
    env: { ...process.env, PAY_TO: '', PAYMENT_RECEIVER_ADDRESS: '' },
    encoding: 'utf8', timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), REQUESTED_RECEIVER);
});

test('public documents advertise one runtime receiver and the same three working skill prices', async t => {
  const { request, payment } = await fixture(t);
  const healthResponse = await request('/health');
  assert.equal(healthResponse.status, 200);
  assert.equal((await healthResponse.json()).status, 'ok');

  const catalogResponse = await request('/skills');
  assert.equal(catalogResponse.status, 200);
  const catalog = await catalogResponse.json();
  assert.equal(catalog.payment.payTo, FIXTURE_RECEIVER);
  assert.equal(catalog.payment.network, payment.NETWORK);
  assert.deepEqual(catalog.paid.map(skill => skill.id).sort(), Object.keys(ROUTES).sort());
  for (const skill of catalog.paid) {
    assert.equal(skill.url, `${PUBLIC_URL}/skills/${skill.id}`);
    assert.equal(String(Math.round(skill.priceUsd * 1e6)), ROUTES[skill.id].amount);
  }

  const manifestResponse = await request('/manifest');
  assert.equal(manifestResponse.status, 200);
  const manifest = await manifestResponse.json();
  assert.equal(manifest.payment.payTo, FIXTURE_RECEIVER);
  assert.equal(manifest.payment.asset, payment.USDC_BASE);

  const discoveryResponse = await request('/.well-known/x402');
  assert.equal(discoveryResponse.status, 200);
  const discovery = await discoveryResponse.json();
  assert.equal(discovery.payTo, FIXTURE_RECEIVER);
  assert.equal(discovery.resources.length, 3);
  for (const resource of discovery.resources) {
    assert.equal(resource.accepts[0].payTo, FIXTURE_RECEIVER);
    assert.equal(resource.accepts[0].asset, payment.USDC_BASE);
  }
});

test('HTML and OpenAPI are indexable, link to the canonical service, and express consent constraints', async t => {
  const { request } = await fixture(t);
  const homepage = await request('/');
  assert.equal(homepage.status, 200);
  assert.match(homepage.headers.get('content-type'), /^text\/html/);
  const html = await homepage.text();
  assert.match(html, /PhantomOperator/);
  assert.match(html, /rel=["']canonical["']/i);
  assert.ok(html.includes(PUBLIC_URL));
  assert.ok(html.includes('/openapi.json'));
  assert.equal(homepage.headers.get('x-content-type-options'), 'nosniff');

  const apiResponse = await request('/openapi.json');
  assert.equal(apiResponse.status, 200);
  const api = await apiResponse.json();
  assert.match(api.openapi, /^3\./);
  assert.equal(api.servers[0].url, PUBLIC_URL);
  for (const id of Object.keys(ROUTES)) {
    const post = api.paths[`/skills/${id}`].post;
    assert.ok(post);
    assert.ok(post.responses['402']);
    const schema = dereference(api, post.requestBody.content['application/json'].schema);
    assert.equal(schema.type, 'object');
    if (id !== 'metadata-audit') {
      assert.ok(schema.required.includes('consent'));
      const consent = dereference(api, schema.properties.consent);
      assert.ok(consent.const === true || consent.enum?.length === 1 && consent.enum[0] === true,
        `${id} consent must be represented as true, not any boolean`);
    }
  }
});

const invalidInputs = [
  ['metadata-audit', null, 'null is not an object'],
  ['metadata-audit', [], 'arrays are not request objects'],
  ['metadata-audit', 'https://example.com/', 'strings are not request objects'],
  ['metadata-audit', 7, 'numbers are not request objects'],
  ['metadata-audit', {}, 'URL is required'],
  ['metadata-audit', { url: 'ftp://example.com/file' }, 'non-HTTP protocols are rejected'],
  ['metadata-audit', { url: { value: 'https://example.com/' } }, 'URL must be a string'],
  ['metadata-audit', { url: 'https://fixture:password@example.com/' }, 'embedded URL credentials are rejected'],
  ['threat-scan', {}, 'name and consent are required'],
  ['threat-scan', { fullName: 'Development Fixture' }, 'consent is required'],
  ['threat-scan', { fullName: 'Development Fixture', consent: false }, 'false consent is rejected'],
  ['threat-scan', { fullName: 'Development Fixture', consent: 'true' }, 'string consent is rejected'],
  ['threat-scan', { fullName: 42, consent: true }, 'numeric names are rejected'],
  ['threat-scan', { fullName: '   ', consent: true }, 'empty names are rejected'],
  ['opsec-score', { consent: true }, 'at least one target is required'],
  ['opsec-score', { email: 'invalid-email', consent: true }, 'malformed emails are rejected'],
  ['opsec-score', { email: 42, consent: true }, 'email must be a string'],
  ['opsec-score', { handle: ['development-fixture'], consent: true }, 'handle must be a string'],
  ['opsec-score', { handle: 'development-fixture', consent: false }, 'OPSEC consent is required'],
];
for (const [id, body, reason] of invalidInputs) {
  test(`validation happens before payment: ${id}: ${reason}`, async t => {
    const { request, events } = await fixture(t);
    const response = await request(`/skills/${id}`, { method: 'POST', body, paid: true });
    assert.equal(response.status, 400);
    const result = await response.json();
    assert.equal(typeof result.error, 'string');
    assert.deepEqual(events, [], 'invalid input must not verify payment, run a skill, or settle');
  });
}

test('malformed JSON is rejected before a payment authorization is inspected', async t => {
  const { request, events } = await fixture(t);
  const response = await request('/skills/metadata-audit', { method: 'POST', rawBody: '{"url":', paid: true });
  assert.equal(response.status, 400);
  assert.deepEqual(events, []);
});

for (const [id, route] of Object.entries(ROUTES)) {
  test(`unpaid ${id} returns its exact fixed-price challenge without executing or settling`, async t => {
    const { request, events, payment } = await fixture(t);
    const response = await request(`/skills/${id}`, { method: 'POST', body: route.body });
    assert.equal(response.status, 402);
    const challenge = await response.json();
    assert.equal(challenge.x402Version, 2);
    assert.equal(challenge.resource.url, `${PUBLIC_URL}/skills/${id}`);
    assert.equal(challenge.accepts[0].amount, route.amount);
    assert.equal(challenge.accepts[0].payTo, FIXTURE_RECEIVER);
    assert.equal(challenge.accepts[0].asset, payment.USDC_BASE);
    const headerChallenge = JSON.parse(Buffer.from(response.headers.get('payment-required'), 'base64').toString('utf8'));
    assert.deepEqual(headerChallenge, challenge);
    assert.deepEqual(events, ['verify']);
  });
}

for (const [id, route] of Object.entries(ROUTES)) {
  test(`authorized ${id} executes its real handler with injected dependencies then settles`, async t => {
    const { request, events, results } = await fixture(t);
    const response = await request(`/skills/${id}`, { method: 'POST', body: route.body, paid: true });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.skill, id);
    const kind = { 'metadata-audit': 'metadata', 'threat-scan': 'search', 'opsec-score': 'opsec' }[id];
    assert.deepEqual(result.result, results[kind]);
    assert.deepEqual(events, ['verify', `run:${kind}`, 'settle']);
    const settlement = JSON.parse(Buffer.from(response.headers.get('payment-response'), 'base64').toString('utf8'));
    assert.equal(settlement.success, true);
  });
}

test('successful result is withheld until the facilitator confirms settlement', async t => {
  let reachedSettlement;
  let finishSettlement;
  const reached = new Promise(resolve => { reachedSettlement = resolve; });
  const release = new Promise(resolve => { finishSettlement = resolve; });
  const { request } = await fixture(t, {
    payment: {
      async settle() {
        reachedSettlement();
        await release;
        return { ok: true, headers: {} };
      },
    },
  });
  let responded = false;
  const pendingResponse = request('/skills/metadata-audit', {
    method: 'POST', body: ROUTES['metadata-audit'].body, paid: true,
  }).then(response => { responded = true; return response; });
  try {
    await Promise.race([reached, new Promise((_, reject) => setTimeout(() => reject(new Error('settlement was not reached')), 2000).unref())]);
    await nextTurn();
    assert.equal(responded, false, 'HTTP response must not precede settlement confirmation');
  } finally {
    finishSettlement();
  }
  const response = await pendingResponse;
  assert.equal(response.status, 200);
});

test('failed skill requests return an upstream error and never settle', async t => {
  const { request, events } = await fixture(t, {
    agents: { MetadataAgent: { async audit() { throw new Error('fixture upstream unavailable'); } } },
  });
  const response = await request('/skills/metadata-audit', { method: 'POST', body: ROUTES['metadata-audit'].body, paid: true });
  assert.equal(response.status, 502);
  assert.deepEqual(events, ['verify']);
  assert.equal(response.headers.has('payment-response'), false);
});

test('failed settlement cannot expose a successful skill response or a success receipt', async t => {
  const { request, events } = await fixture(t, {
    payment: { async settle() { events.push('settle-failed'); return { ok: false, status: 502, body: { error: 'Fixture settlement unavailable' } }; } },
  });
  const response = await request('/skills/metadata-audit', { method: 'POST', body: ROUTES['metadata-audit'].body, paid: true });
  assert.equal(response.status, 502);
  const result = await response.json();
  assert.equal(result.result, undefined);
  assert.equal(typeof result.error, 'string');
  assert.equal(response.headers.has('payment-response'), false);
  assert.deepEqual(events, ['verify', 'run:metadata', 'settle-failed']);
});

test('disabled placeholder services are never sold as working paid skills', async t => {
  const { request, events } = await fixture(t);
  for (const id of ['breach-check', 'data-removal', 'full-privacy-sweep']) {
    const response = await request(`/skills/${id}`, { method: 'POST', body: {}, paid: true });
    assert.equal(response.status, 410);
  }
  assert.deepEqual(events, []);
});

test('oversized request bodies are rejected before verification or settlement', async t => {
  const { request, events } = await fixture(t);
  const response = await request('/skills/metadata-audit', {
    method: 'POST', rawBody: JSON.stringify({ url: `https://example.com/${'x'.repeat(128 * 1024)}` }), paid: true,
  });
  assert.equal(response.status, 413);
  assert.deepEqual(events, []);
});

test('unsupported content types cannot invoke a skill or payment verification', async t => {
  const { request, events } = await fixture(t);
  const response = await request('/skills/metadata-audit', {
    method: 'POST', body: ROUTES['metadata-audit'].body, paid: true,
    headers: { 'Content-Type': 'text/plain' },
  });
  assert.equal(response.status, 415);
  assert.deepEqual(events, []);
});

test('browser preflight permits the payment header and POST without executing a skill', async t => {
  const { request, events } = await fixture(t);
  const response = await request('/skills/metadata-audit', { method: 'OPTIONS' });
  assert.equal(response.status, 204);
  assert.match(response.headers.get('access-control-allow-methods'), /POST/);
  assert.match(response.headers.get('access-control-allow-headers'), /PAYMENT-SIGNATURE/i);
  assert.equal(response.headers.get('access-control-allow-origin'), '*');
  assert.deepEqual(events, []);
});

test('a blocked metadata target returns an actionable rejection and is never settled', async t => {
  const { request, events } = await fixture(t, {
    agents: {
      MetadataAgent: {
        async audit() {
          throw Object.assign(new Error('fixture private upstream details'), { code: 'UNSAFE_TARGET', statusCode: 422 });
        },
      },
    },
  });
  const response = await request('/skills/metadata-audit', { method: 'POST', body: ROUTES['metadata-audit'].body, paid: true });
  assert.equal(response.status, 422);
  const body = await response.json();
  assert.equal(body.code, 'UNSAFE_TARGET');
  assert.ok(!JSON.stringify(body).includes('fixture private upstream details'));
  assert.deepEqual(events, ['verify']);
});

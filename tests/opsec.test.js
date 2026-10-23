'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const SearchAgent = require('../agents/SearchAgent');
const OpsecAgent = require('../agents/OpsecAgent');
const { createServer } = require('../server');

const fullName = 'Public Assessment Fixture';
const emptyPage = '<div class="no-results"><h1>No results found for this query.</h1></div>';
const escapeHtml = value => String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const page = results => `<html><body>${results.map((result, index) =>
  `<div class="result"><h2><a class="result__a" href="${escapeHtml(result.link)}">${escapeHtml(result.title || `${fullName} ${index}`)}</a></h2><p class="result__snippet">${escapeHtml(result.description || 'Fixture public portfolio.')}</p></div>`
).join('')}</body></html>`;
const response = data => ({ status: 200, headers: { 'content-type': 'text/html' }, data });
const requestFor = results => async () => response(page(results));
const evidence = [
  { link: 'https://profiles.spokeo.com/fixture', description: 'Fixture SSN 123-45-6789.' },
  { link: 'https://github.com/public-fixture', description: 'Public contact fixture@example.com.' },
  { link: 'https://pastebin.com/public-fixture', description: 'Possible leaked fixture record.' },
];
const codeIs = code => error => error.code === code && error.statusCode === 503;

test('real OPSEC assessment searches every supplied identifier and returns integer scoring, evidence and honest coverage', async () => {
  const queries = [];
  const report = await OpsecAgent.assess({ fullName, handle: 'fixture-handle', email: 'fixture@example.com' }, {
    request: async config => {
      queries.push(new URLSearchParams(config.data).get('q'));
      return response(page(evidence));
    },
  });
  assert.deepEqual(queries, [fullName, '"fixture-handle"', 'fixture@example.com']);
  assert.equal(report.score, 33);
  assert.equal(report.grade, 'B');
  assert.deepEqual(report.breakdown.searchExposure, { score: 48, criticalFindings: 1, highFindings: 2, totalResults: 3 });
  assert.deepEqual(report.breakdown.dataBrokerExposure, { score: 20, brokerCount: 1, brokers: ['profiles.spokeo.com'] });
  assert.equal(report.breakdown.pasteLeaks.score, 40);
  assert.equal(report.breakdown.socialFootprint.score, 12);
  for (const category of Object.values(report.breakdown)) {
    assert.ok(Number.isInteger(category.score) && category.score >= 0 && category.score <= 100);
  }
  assert.equal(report.provider, 'DuckDuckGo HTML');
  assert.deepEqual(report.coverage, {
    complete: true, identifiersSearched: 3, searchesCompleted: 3, searchesWithResults: 3,
    resultsRetrieved: 9, uniqueResults: 3, maxResultsPerSearch: 15, scope: 'public-search-snippets',
  });
  assert.ok(report.topThreats.some(threat => threat.threatLevel === 'critical'));
  assert.ok(report.topThreats.every(threat => threat.provenance.sourceUrl === threat.source && threat.provenance.fetchedPage === false));
  assert.ok(report.limitations.some(text => /unverified/.test(text)));
  assert.ok(report.limitations.some(text => /fixed weights/.test(text)));
  assert.ok(report.limitations.some(text => /each requested identifier search completed/.test(text)));
  assert.ok(Number.isFinite(Date.parse(report.timestamp)));
  const recommendations = JSON.stringify(report.recommendations);
  assert.doesNotMatch(recommendations, /full-privacy-sweep|data-removal|automated removal|automated opt-out/i);
  assert.match(recommendations, /official.*opt-out|official process/);
  assert.match(recommendations, /Verify/);
});

test('any failed identifier search invalidates scoring rather than silently dropping coverage', async () => {
  const calls = [];
  await assert.rejects(OpsecAgent.assess({ fullName, handle: 'fixture-handle', email: 'fixture@example.com' }, {
    request: async config => {
      const query = new URLSearchParams(config.data).get('q');
      calls.push(query);
      if (query === '"fixture-handle"') throw new Error('Sensitive upstream identifier and internal proxy details');
      return response(page(evidence));
    },
  }), error => {
    assert.equal(error.code, 'SEARCH_INCOMPLETE');
    assert.equal(error.statusCode, 503);
    assert.doesNotMatch(error.message + JSON.stringify(error), /Sensitive|fixture-handle|internal proxy/);
    return true;
  });
  assert.equal(calls.length, 3);
});

test('all failed searches are incomplete and all genuine empty searches have no evidence', async () => {
  await assert.rejects(OpsecAgent.assess({ fullName }, {
    request: async () => { throw new Error('Fixture provider unavailable'); },
  }), codeIs('SEARCH_INCOMPLETE'));
  await assert.rejects(OpsecAgent.assess({ fullName, handle: 'fixture' }, {
    request: async () => response(emptyPage),
  }), codeIs('SEARCH_NO_EVIDENCE'));
});

test('a genuine empty identifier search is represented in coverage when another search has evidence', async () => {
  const report = await OpsecAgent.assess({ fullName, handle: 'fixture' }, {
    request: async config => response(new URLSearchParams(config.data).get('q') === fullName ? emptyPage : page([evidence[1]])),
  });
  assert.equal(report.coverage.complete, true);
  assert.equal(report.coverage.identifiersSearched, 2);
  assert.equal(report.coverage.searchesCompleted, 2);
  assert.equal(report.coverage.searchesWithResults, 1);
  assert.equal(report.coverage.uniqueResults, 1);
});

test('domain categories recognize subdomains while ignoring deceptive suffixes and path names', async () => {
  const report = await OpsecAgent.assess({ fullName }, { request: requestFor([
    { link: 'https://profiles.spokeo.com/fixture' },
    { link: 'https://spokeo.com.evil.org/fixture' },
    { link: 'https://example.com/whitepages.com' },
    { link: 'https://github.com.evil.org/fixture' },
    { link: 'https://gist.github.com/fixture' },
    { link: 'https://pastebin.com.evil.org/fixture' },
    { link: 'https://pastebin.com/fixture' },
  ]) });
  assert.equal(report.breakdown.dataBrokerExposure.brokerCount, 1);
  assert.equal(report.breakdown.socialFootprint.platformCount, 1);
  assert.equal(report.breakdown.pasteLeaks.pasteCount, 1);
});

test('multiple results on one social platform do not invent additional platforms or verified account activity', async () => {
  const report = await OpsecAgent.assess({ fullName }, { request: requestFor([
    { link: 'https://github.com/fixture-one' }, { link: 'https://github.com/fixture-two' },
    { link: 'https://gist.github.com/fixture-three' }, { link: 'https://github.com/fixture-four' },
  ]) });
  assert.equal(report.breakdown.socialFootprint.platformCount, 1);
  assert.deepEqual(report.breakdown.socialFootprint.platforms, ['github.com']);
  assert.doesNotMatch(JSON.stringify(report.recommendations), /Active across|4 platforms/);
});

const critical = (domain, count) => Array.from({ length: count }, (_, index) => ({
  link: `https://${domain}/fixture-${index}`, description: 'Fixture phone 212-555-0101.',
}));
for (const [grade, score, results] of [
  ['A', 0, [{ link: 'https://example.com/portfolio' }]],
  ['B', 33, evidence],
  ['C', 47, critical('pastebin.com', 3)],
  ['D', 65, critical('spokeo.com', 5)],
  ['F', 98, [...critical('spokeo.com', 5), ...critical('pastebin.com', 3), ...critical('github.com', 7)]],
]) {
  test(`grade ${grade} reflects deterministic weighted exposure score ${score} with real source evidence`, async () => {
    const report = await OpsecAgent.assess({ fullName }, { request: requestFor(results) });
    assert.equal(report.score, score);
    assert.equal(report.grade, grade);
    assert.ok(report.coverage.uniqueResults > 0);
    if (grade === 'A') {
      assert.match(JSON.stringify(report.recommendations), /retrieved snippets/);
      assert.doesNotMatch(JSON.stringify(report.recommendations), /Excellent score|proof of privacy/);
    }
  });
}

test('invalid targets fail before public-search transport is invoked', async () => {
  for (const target of [undefined, null, [], {}, { fullName: '' }, { email: 7 }, { handle: 'x'.repeat(513) }, { fullName: 'fixture\nname' }]) {
    await assert.rejects(OpsecAgent.assess(target, {
      request: () => assert.fail('Invalid target must not invoke transport'),
    }), error => error.code === 'INVALID_TARGET' && error.statusCode === 400);
  }
  const report = await OpsecAgent.assess({ handle: 'x'.repeat(512) }, { request: requestFor([evidence[1]]) });
  assert.equal(report.coverage.identifiersSearched, 1);
});

// Local HTTP integration exercises the actual paid handlers and real agents,
// using fixture HTML and an in-memory payment adapter. No wallet/network calls.
async function serve(t, request) {
  const events = [];
  const payment = {
    PAY_TO: '0x1111111111111111111111111111111111111111',
    NETWORK: 'eip155:8453', USDC_BASE: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    FACILITATOR: 'https://facilitator.example',
    requirements: route => ({ scheme: 'exact', network: 'eip155:8453', amount: String(Math.round(route.priceUsd * 1e6)) }),
    async verify() { events.push('verify'); return { ok: true, payload: { fixture: true } }; },
    async settle() { events.push('settle'); return { ok: true, headers: {} }; },
  };
  const server = createServer({
    payment, publicUrl: 'https://phantom.example',
    agents: {
      SearchAgent: { run: target => SearchAgent.run(target, { request }) },
      OpsecAgent: { assess: target => OpsecAgent.assess(target, { request }) },
    },
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  return {
    events,
    call: async (skill, body) => {
      const result = await fetch(`http://127.0.0.1:${server.address().port}/skills/${skill}`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'payment-signature': 'fixture-only' },
        body: JSON.stringify({ ...body, consent: true }),
      });
      return { status: result.status, body: await result.json() };
    },
  };
}

for (const [skill, body] of [['threat-scan', { fullName }], ['opsec-score', { fullName }]]) {
  test(`actual ${skill} handler returns search evidence before fixture settlement succeeds`, async t => {
    const { events, call } = await serve(t, requestFor(evidence));
    const result = await call(skill, body);
    assert.equal(result.status, 200);
    assert.equal(result.body.skill, skill);
    if (skill === 'threat-scan') assert.equal(result.body.result[0].provenance.provider, 'DuckDuckGo HTML');
    else assert.equal(result.body.result.coverage.complete, true);
    assert.deepEqual(events, ['verify', 'settle']);
  });
  test(`actual ${skill} no-evidence error returns 503 and never settles a payment`, async t => {
    const { events, call } = await serve(t, async () => response(emptyPage));
    const result = await call(skill, body);
    assert.equal(result.status, 503);
    assert.equal(result.body.code, 'SEARCH_NO_EVIDENCE');
    assert.deepEqual(events, ['verify']);
    assert.equal(result.body.result, undefined);
  });
}

test('actual OPSEC partial-search failure never settles and never leaks provider details', async t => {
  const { events, call } = await serve(t, async config => {
    if (new URLSearchParams(config.data).get('q') === fullName) return response(page(evidence));
    throw new Error('Secret fixture proxy password and personal search query');
  });
  const result = await call('opsec-score', { fullName, handle: 'fixture-failed-search' });
  assert.equal(result.status, 503);
  assert.equal(result.body.code, 'SEARCH_INCOMPLETE');
  assert.doesNotMatch(JSON.stringify(result.body), /Secret|password|fixture-failed-search/);
  assert.deepEqual(events, ['verify']);
});

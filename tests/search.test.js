'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const SearchAgent = require('../agents/SearchAgent');
const RagService = require('../services/RagService');

const QUERY = 'Public Search Fixture';
const emptyPage = '<html><body><div class="no-results"><div class="no-results__message">No results found for the supplied query.</div></div></body></html>';
const escapeHtml = value => String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const resultHtml = ({ title = QUERY, link = 'https://example.com/profile', description = 'A public fixture page.', extraClass = '' } = {}) =>
  `<div class="result ${extraClass}"><h2 class="result__title"><a class="result__a" href="${escapeHtml(link)}">${escapeHtml(title)}</a></h2><a class="result__snippet">${escapeHtml(description)}</a></div>`;
const page = results => `<html><body>${results.map(resultHtml).join('')}</body></html>`;
const requestFor = (data, overrides = {}) => async () => ({ status: 200, headers: { 'content-type': 'text/html; charset=UTF-8' }, data, ...overrides });
const codeIs = expected => error => error.code === expected && error.statusCode === 503;

test('real Search.run uses a fixed bounded Axios request, retains sibling snippets and returns source evidence', async t => {
  let calls = 0;
  t.mock.method(console, 'log', () => assert.fail('Search targets must never be logged'));
  t.mock.method(axios, 'request', async config => {
    calls++;
    assert.equal(config.method, 'POST');
    assert.equal(config.url, 'https://html.duckduckgo.com/html');
    assert.equal(new URLSearchParams(config.data).get('q'), QUERY);
    assert.equal(config.timeout, 15000);
    assert.equal(config.maxContentLength, 2 * 1024 * 1024);
    assert.equal(config.maxRedirects, 0);
    return { status: 200, data: page([{ description: 'Fixture contact: fixture@example.com; phone 212-555-0101.' }]) };
  });
  const threats = await SearchAgent.run({ fullName: QUERY });
  assert.ok(Array.isArray(threats));
  assert.equal(calls, 1);
  assert.equal(threats.length, 1);
  const finding = threats[0];
  assert.equal(finding.threatLevel, 'critical');
  assert.deepEqual(finding.reasons, ['phone', 'email']);
  assert.match(finding.description, /fixture@example\.com/);
  assert.equal(finding.evidence.kind, 'search-result-snippet');
  assert.match(finding.evidence.text, /212-555-0101/);
  assert.equal(finding.provenance.provider, 'DuckDuckGo HTML');
  assert.equal(finding.provenance.sourceUrl, finding.link);
  assert.equal(finding.provenance.method, 'public-search-snippet');
  assert.equal(finding.provenance.fetchedPage, false);
  assert.ok(Number.isFinite(Date.parse(finding.provenance.observedAt)));
  assert.ok(finding.limitations.some(text => /unverified/.test(text)));
});

test('DDG absolute, protocol-relative and relative uddg wrappers normalize to public source URLs and deduplicate', async () => {
  const source = 'https://example.com/profile?item=1&fixture=2';
  const html = page([
    { link: `//duckduckgo.com/l/?uddg=${encodeURIComponent(source)}` },
    { link: `https://duckduckgo.com/l/?uddg=${encodeURIComponent(source)}&rut=tracking` },
    { link: `/l/?uddg=${encodeURIComponent('http://example.org/person#fragment')}` },
    { link: '//www.wikipedia.org/wiki/Example' },
  ]);
  const results = await SearchAgent.performDuckDuckGoSearch(QUERY, 10, { request: requestFor(html) });
  assert.deepEqual(results.map(result => result.link), [source, 'http://example.org/person', 'https://www.wikipedia.org/wiki/Example']);
});

test('unsafe URLs, navigation, ads, missing titles and duplicate sources never become search evidence', async () => {
  const links = [
    'javascript:alert(1)', 'file:///etc/passwd', 'ftp://example.com/', '#fragment', '/about',
    'https://duckduckgo.com/about', 'http://127.1/', 'http://2130706433/', 'http://[::1]/',
    'http://metadata.google.internal/', 'http://name.localhost/', 'http://intranet/',
    'https://user:secret@example.com/', 'https://@example.com/',
    '/l/?uddg=javascript%3Aalert(1)', '/l/?uddg=%2Fsomewhere', '/l/?other=value',
    'https://example.com/' + 'x'.repeat(8192),
  ];
  const html = page([
    ...links.map(link => ({ link })),
    { title: '', link: 'https://example.org/empty-title' },
    { link: 'https://example.org/advert', extraClass: 'result--ad' },
    { link: 'https://example.org/public' },
    { link: 'https://example.org/public#duplicate' },
  ]);
  const results = await SearchAgent.performDuckDuckGoSearch(QUERY, 10, { request: requestFor(html) });
  assert.deepEqual(results.map(result => result.link), ['https://example.org/public']);
});

test('bounded result count and text cannot inflate the report', async () => {
  const html = page(Array.from({ length: 40 }, (_, index) => ({
    title: 'x'.repeat(1000), description: 'z'.repeat(4000), link: `https://example.com/${index}`,
  })));
  const results = await SearchAgent.performDuckDuckGoSearch(QUERY, 1000000, { request: requestFor(html) });
  assert.equal(results.length, 20);
  assert.ok(results.every(result => result.title.length === 300 && result.description.length === 2000));
  const short = await SearchAgent.performDuckDuckGoSearch(QUERY, 2, { request: requestFor(html) });
  assert.equal(short.length, 2);
});

for (const [label, html] of [
  ['DDG challenge form', '<form id="challenge-form"><a href="https://example.com/">Help</a></form>'],
  ['DDG bot text', '<p>Unfortunately, bots use DuckDuckGo too. Please complete the following challenge.</p><a href="https://example.com/">Help</a>'],
  ['CAPTCHA', '<h1>CAPTCHA</h1><a href="https://example.com/">Privacy policy</a>'],
  ['challenge plus misleading no-results', '<form action="/anomaly.js"></form><div class="no-results">No results found</div>'],
]) {
  test(`${label} rejects as a blocked provider rather than benign search results`, async () => {
    await assert.rejects(SearchAgent.run({ fullName: QUERY }, { request: requestFor(html) }), codeIs('SEARCH_BLOCKED'));
  });
}

for (const [label, html] of [
  ['generic navigation', '<a href="https://example.com/">About DuckDuckGo</a>'],
  ['unstructured result anchor', '<a class="result__a" href="https://example.com/">Unrecognized provider markup</a>'],
  ['unrecognized empty page', '<html><body></body></html>'],
  ['unmarked no-results text', '<p>No results found</p>'],
  ['structured unusable results', page([{ link: 'javascript:alert(1)' }])],
]) {
  test(`${label} rejects as unusable provider evidence`, async () => {
    await assert.rejects(SearchAgent.performDuckDuckGoSearch(QUERY, 10, { request: requestFor(html) }), codeIs('SEARCH_INVALID_RESPONSE'));
  });
}

test('recognized genuine no-results page is empty at provider level and not sold as a completed threat scan', async () => {
  const options = { request: requestFor(emptyPage) };
  assert.deepEqual(await SearchAgent.performDuckDuckGoSearch(QUERY, 10, options), []);
  await assert.rejects(SearchAgent.run({ fullName: QUERY }, options), codeIs('SEARCH_NO_EVIDENCE'));
});

test('legitimate structured results discussing CAPTCHAs or automated requests remain usable evidence', async () => {
  const results = await SearchAgent.performDuckDuckGoSearch(QUERY, 10, { request: requestFor(page([
    { description: 'A public article about unusual traffic, automated requests, and CAPTCHA verification.' },
  ])) });
  assert.equal(results.length, 1);
  assert.match(results[0].description, /automated requests/);
});

test('upstream errors, HTTP failures and invalid responses return sanitized service errors', async () => {
  const upstreamDetail = 'Private Fixture query, secret proxy password, axios config';
  await assert.rejects(SearchAgent.run({ fullName: QUERY }, {
    request: async () => { throw Object.assign(new Error(upstreamDetail), { config: { data: QUERY } }); },
  }), error => {
    assert.equal(error.code, 'SEARCH_UNAVAILABLE');
    assert.equal(error.statusCode, 503);
    assert.doesNotMatch(error.message + JSON.stringify(error), /Private Fixture|secret proxy|Public Search Fixture/);
    assert.equal(error.cause, undefined);
    return true;
  });
  await assert.rejects(SearchAgent.performDuckDuckGoSearch(QUERY, 10, {
    request: async () => { throw Object.assign(new Error(upstreamDetail), { response: { status: 429 } }); },
  }), codeIs('SEARCH_BLOCKED'));
  for (const status of [202, 403, 429]) {
    await assert.rejects(SearchAgent.performDuckDuckGoSearch(QUERY, 10, { request: requestFor(page([{}]), { status }) }), codeIs('SEARCH_BLOCKED'));
  }
  for (const overrides of [
    { status: 500 }, { data: {} }, { data: '' }, { data: 'x'.repeat(2 * 1024 * 1024 + 1) },
    { headers: { 'content-type': 'application/json' } },
  ]) {
    await assert.rejects(SearchAgent.performDuckDuckGoSearch(QUERY, 10, { request: requestFor(page([{}]), overrides) }), codeIs('SEARCH_INVALID_RESPONSE'));
  }
});

test('invalid query inputs fail before contacting the provider', async () => {
  for (const query of [undefined, null, {}, '', '   ', 'x'.repeat(1025), 'fixture\nname']) {
    await assert.rejects(SearchAgent.performDuckDuckGoSearch(query, 10, {
      request: () => assert.fail('Invalid input must not invoke Axios'),
    }), error => error.code === 'INVALID_SEARCH_QUERY' && error.statusCode === 400);
  }
});

test('Search and RAG use the same severity rules, including numeric SSNs', () => {
  const cases = [
    ['Fixture SSN 123-45-6789.', 'critical', 'ssn'],
    ['Fixture phone 212.555.0101.', 'critical', 'phone'],
    ['Contact fixture@example.com.', 'high', 'email'],
    ['Fixture home address.', 'high', 'keyword:address'],
    ['Fixture email preferences.', 'medium', 'keyword:email'],
    ['Fixture public writing portfolio.', 'benign', undefined],
  ];
  for (const [description, level, reason] of cases) {
    const result = SearchAgent.analyzeThreats([{ title: 'Fixture', link: 'https://example.com/', description }])[0];
    assert.equal(result.threatLevel, level);
    assert.equal(RagService.classifyThreatLevel(description), level);
    if (reason) assert.ok(result.reasons.includes(reason));
  }
});

test('RAG retains short sensitive sentences, ranks query evidence, bounds topK and builds source context', () => {
  const documents = [
    { title: QUERY, description: '123-45-6789. A longer public fixture passage follows this short sensitive sentence.', link: 'https://example.com/evidence' },
    { title: 'Fiction novel', description: 'A historical character in a movie book song.', link: 'https://example.org/unrelated' },
  ];
  const passages = RagService.retrieveRelevantPassages(documents, QUERY, { topK: 20 });
  assert.ok(passages.some(passage => passage.threatLevel === 'critical' && passage.text.includes('123-45-6789')));
  assert.equal(passages[0].source, documents[0].link);
  assert.ok(passages.every(passage => passage.score >= 0 && passage.score <= 1));
  assert.match(RagService.buildContext(passages), /\[1\].*https:\/\/example\.com\/evidence/);
  assert.ok(RagService.scoreThreatRelevance('phone email leak breach background check') > 0);
  assert.equal(RagService.scoreThreatRelevance('fiction novel character movie book song'), 0);
  assert.equal(RagService.retrieveRelevantPassages(documents, QUERY, { topK: 1 }).length, 1);
  assert.deepEqual(RagService.retrieveRelevantPassages(documents, QUERY, { topK: 0 }), []);
  assert.deepEqual(RagService.retrieveRelevantPassages([], QUERY), []);
});

test('legacy SearchAgent.scan demo workflow remains usable without network access', async () => {
  const result = await new SearchAgent({ demo: true }).scan({ name: 'Fixture', country: 'Fixture Country' });
  assert.equal(result.exposures.length, 1);
  assert.equal(result.exposures[0].source, 'ExampleBroker');
  assert.match(result.exposures[0].details, /Demo exposure/);
});

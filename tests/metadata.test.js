'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const MetadataAgent = require('../agents/MetadataAgent');
const { safeFetch, isPublicAddress, requestPinned } = require('../lib/safe-fetch');

const PUBLIC = { address: '93.184.215.14', family: 4 };
const fixtureOptions = overrides => ({
  proxyEnvironment: {},
  lookup: async () => [PUBLIC],
  transport: async () => ({ statusCode: 200, headers: { 'content-type': 'text/html' }, body: '<html></html>' }),
  ...overrides,
});
const errorCode = code => error => error.code === code && Number.isInteger(error.statusCode);

test('rejects private and special-purpose IPv4 and IPv6 addresses', () => {
  for (const address of [
    '0.0.0.0', '10.1.2.3', '100.64.0.1', '100.127.255.254', '127.0.0.1',
    '169.254.169.254', '172.16.0.1', '172.31.255.254', '192.0.0.9', '192.0.2.4',
    '192.168.2.1', '198.18.0.1', '198.19.0.1', '198.51.100.1', '203.0.113.5',
    '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255', '168.63.129.16',
    '::', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:8.8.8.8',
    '::127.0.0.1', 'fc00::1', 'fd12::1', 'fe80::1', 'fe80::1%eth0',
    'fec0::1', 'ff02::1', '64:ff9b::a00:1', '64:ff9b:1::1',
    '2001::1', '2001:2::1', '2001:10::1', '2001:20::1', '2001:db8::1',
    '2002:7f00:1::', '3fff::1', '4000::1', 'not-an-address',
  ]) assert.equal(isPublicAddress(address), false, address);
  for (const address of ['8.8.8.8', '1.1.1.1', PUBLIC.address, '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPublicAddress(address), true, address);
  }
});

test('URL normalization cannot hide loopback, mapped IPv4, credentials or forbidden schemes', async () => {
  for (const url of [
    'http://127.1/', 'http://0177.0.0.1/', 'http://0x7f000001/', 'http://2130706433/',
    'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[::ffff:7f00:1]/',
    'http://LOCALHOST./', 'http://name.localhost/', 'http://name.local/',
    'http://metadata.google.internal/', 'http://home.arpa/', 'http://name.invalid/',
    'file:///etc/passwd', 'ftp://public.example.org/', 'https://user:secret@public.example.org/',
    'https://@public.example.org/', 'https://public.example.org/\npath',
  ]) {
    await assert.rejects(safeFetch(url, fixtureOptions({
      lookup: () => assert.fail('Unsafe URL must not reach DNS'),
      transport: () => assert.fail('Unsafe URL must not reach transport'),
    })), errorCode('UNSAFE_TARGET'), url);
  }
});

test('rejects any private or invalid DNS answer before opening a connection', async () => {
  for (const answers of [
    [{ address: '127.0.0.1', family: 4 }],
    [PUBLIC, { address: '10.0.0.1', family: 4 }],
    [{ address: '::ffff:169.254.169.254', family: 6 }],
    [{ address: PUBLIC.address, family: 6 }],
  ]) {
    await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
      lookup: async () => answers,
      transport: () => assert.fail('Unsafe DNS must not reach transport'),
    })), errorCode('UNSAFE_TARGET'));
  }
});

test('pins a validated address rather than letting transport resolve a hostname again', async () => {
  let lookups = 0;
  const fetched = await safeFetch('https://public.example.org/page', fixtureOptions({
    lookup: async hostname => {
      assert.equal(hostname, 'public.example.org');
      lookups++;
      return lookups === 1 ? [PUBLIC] : [{ address: '127.0.0.1', family: 4 }];
    },
    transport: async (target, options) => {
      assert.equal(target.address, PUBLIC.address);
      assert.equal(target.family, 4);
      assert.equal(target.url.hostname, 'public.example.org');
      assert.equal(options.maxBytes, 2 * 1024 * 1024);
      assert.ok(options.signal instanceof AbortSignal);
      return { statusCode: 200, headers: {}, body: 'ok' };
    },
  }));
  assert.equal(lookups, 1);
  assert.equal(fetched.resolvedAddress, PUBLIC.address);
  assert.equal(fetched.byteLength, 2);
});

test('literal public IPv6 addresses are accepted and normalized without DNS', async () => {
  const fetched = await safeFetch('https://[2606:4700:4700::1111]/', fixtureOptions({
    lookup: () => assert.fail('Literal IP must not use DNS'),
    transport: async target => {
      assert.equal(target.address, '2606:4700:4700::1111');
      assert.equal(target.family, 6);
      return { statusCode: 200, headers: {}, body: '' };
    },
  }));
  assert.equal(fetched.finalUrl, 'https://[2606:4700:4700::1111]/');
});

test('each redirect is validated, resolved again and bounded', async () => {
  let requests = 0;
  await assert.rejects(safeFetch('https://public.example.org/start', fixtureOptions({
    lookup: async () => ++requests === 1 ? [PUBLIC] : [{ address: '169.254.169.254', family: 4 }],
    transport: async () => ({ statusCode: 302, headers: { location: '/next' }, body: '' }),
  })), errorCode('UNSAFE_TARGET'));
  assert.equal(requests, 2, 'Same-host redirects must recheck DNS to prevent rebinding');

  for (const location of ['http://127.0.0.1/', 'http://[::1]/', 'https://user:secret@public.example.org/', 'file:///etc/passwd']) {
    let calls = 0;
    await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
      transport: async () => {
        calls++;
        return { statusCode: 302, headers: { location }, body: '' };
      },
    })), errorCode('UNSAFE_TARGET'));
    assert.equal(calls, 1);
  }

  let calls = 0;
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    maxRedirects: 1,
    transport: async () => {
      calls++;
      return { statusCode: 307, headers: { location: '/again' }, body: '' };
    },
  })), errorCode('TOO_MANY_REDIRECTS'));
  assert.equal(calls, 2);
});

test('records a validated public redirect chain and final response', async () => {
  const hosts = [];
  const result = await safeFetch('https://first.example.org/start', fixtureOptions({
    lookup: async host => { hosts.push(host); return [PUBLIC]; },
    transport: async target => target.hostname === 'first.example.org'
      ? { statusCode: 301, headers: { Location: 'https://second.example.org/final' }, body: '' }
      : { statusCode: 200, headers: { 'Content-Type': 'text/html' }, body: 'page' },
  }));
  assert.deepEqual(hosts, ['first.example.org', 'second.example.org']);
  assert.equal(result.finalUrl, 'https://second.example.org/final');
  assert.deepEqual(result.redirects, [{
    url: 'https://first.example.org/start', statusCode: 301, location: 'https://second.example.org/final',
  }]);
  assert.equal(result.responseHeaders['content-type'], 'text/html');
});

test('configured proxies fail closed instead of bypassing egress policy or remote DNS', async () => {
  for (const proxyEnvironment of [
    { HTTPS_PROXY: 'http://proxy.invalid:8080' },
    { all_proxy: 'socks5://proxy.invalid:1080' },
  ]) {
    await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
      proxyEnvironment,
      lookup: () => assert.fail('Proxy limitation should be detected before DNS'),
      transport: () => assert.fail('Proxy policy must not be bypassed'),
    })), error => error.code === 'PROXY_PINNING_UNSUPPORTED' && error.statusCode === 503);
  }
  const fetched = await safeFetch('https://public.example.org/', fixtureOptions({
    proxyEnvironment: { HTTPS_PROXY: 'http://proxy.invalid:8080', NO_PROXY: '.example.org' },
  }));
  assert.equal(fetched.statusCode, 200, 'An explicitly configured NO_PROXY bypass is respected');
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    proxyEnvironment: { HTTPS_PROXY: 'http://proxy.invalid:8080', NO_PROXY: 'public.example.org:80' },
  })), errorCode('PROXY_PINNING_UNSUPPORTED'));
});

test('DNS and transport failures have actionable codes without leaking original errors', async () => {
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({ lookup: async () => [] })), errorCode('DNS_FAILED'));
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    lookup: async () => { throw new Error('private diagnostic'); },
  })), error => error.code === 'DNS_FAILED' && !error.message.includes('private diagnostic'));
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    transport: async () => { throw new Error('private diagnostic'); },
  })), error => error.code === 'UPSTREAM_FAILED' && !error.message.includes('private diagnostic'));
  const personal = 'private-person@example.org';
  const apiSecret = 'fixture-secret-value';
  for (const options of [
    { lookup: async () => { throw new Error(`${personal} ${apiSecret}`); } },
    { transport: async () => { throw new Error(`${personal} ${apiSecret}`); } },
    { proxyEnvironment: { HTTPS_PROXY: `http://user:${apiSecret}@proxy.invalid` } },
  ]) {
    await assert.rejects(safeFetch(`https://public.example.org/?person=${personal}`, fixtureOptions(options)), error => {
      for (const text of [String(error), error.stack, JSON.stringify(error)]) {
        assert.ok(!text.includes(personal));
        assert.ok(!text.includes(apiSecret));
      }
      return true;
    });
  }
});

test('one deadline bounds DNS, redirects and body retrieval; limits cannot be disabled', async () => {
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    timeoutMs: 15, lookup: () => new Promise(() => {}),
  })), errorCode('FETCH_TIMEOUT'));
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    timeoutMs: 15, transport: () => new Promise(() => {}),
  })), errorCode('FETCH_TIMEOUT'));
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    timeoutMs: 25,
    transport: async () => {
      await new Promise(resolve => setTimeout(resolve, 15));
      return { statusCode: 302, headers: { location: '/again' }, body: '' };
    },
  })), errorCode('FETCH_TIMEOUT'));
  await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
    maxBytes: 4, transport: async () => ({ statusCode: 200, headers: {}, body: '12345' }),
  })), errorCode('RESPONSE_TOO_LARGE'));
  for (const limits of [{ timeoutMs: 0 }, { maxBytes: Infinity }, { maxRedirects: -1 }]) {
    await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions(limits)), TypeError);
  }
});

function fakeNativeRequest({ statusCode = 200, headers = {}, chunks = [], inspect = () => {} }) {
  return (url, options, onResponse) => {
    inspect(url, options);
    const req = new EventEmitter();
    req.end = () => queueMicrotask(() => {
      const response = new PassThrough();
      response.statusCode = statusCode;
      response.headers = headers;
      onResponse(response);
      queueMicrotask(() => {
        for (const chunk of chunks) if (!response.destroyed) response.write(chunk);
        if (!response.destroyed) response.end();
      });
    });
    return req;
  };
}

test('native HTTPS transport keeps TLS hostname verification and uses the pinned DNS callback', async () => {
  const result = await safeFetch('https://public.example.org/page', fixtureOptions({
    transport: (target, options) => requestPinned(target, options, {
      httpsRequest: fakeNativeRequest({
        headers: { 'content-type': 'text/html' }, chunks: [Buffer.from('hello')],
        inspect: (url, options) => {
          assert.equal(url.hostname, 'public.example.org');
          assert.equal(options.agent, false);
          assert.equal(options.autoSelectFamily, false);
          assert.notEqual(options.rejectUnauthorized, false);
          assert.equal(options.headers['Accept-Encoding'], 'identity');
          options.lookup('public.example.org', {}, (error, address, family) => {
            assert.equal(error, null); assert.equal(address, PUBLIC.address); assert.equal(family, 4);
          });
          options.lookup('public.example.org', { all: true }, (error, answers) => {
            assert.equal(error, null); assert.deepEqual(answers, [PUBLIC]);
          });
        },
      }),
    }),
  }));
  assert.equal(result.body, 'hello');
});

test('native transport enforces both streamed and advertised byte limits and refuses unexpected compression', async () => {
  for (const fixture of [
    { headers: { 'content-length': '20' }, chunks: [], code: 'RESPONSE_TOO_LARGE' },
    { headers: {}, chunks: ['123', '456'], code: 'RESPONSE_TOO_LARGE' },
    { headers: { 'content-encoding': 'gzip' }, chunks: [], code: 'UNSUPPORTED_CONTENT_ENCODING' },
  ]) {
    await assert.rejects(safeFetch('https://public.example.org/', fixtureOptions({
      maxBytes: 5,
      transport: (target, options) => requestPinned(target, options, {
        httpsRequest: fakeNativeRequest(fixture),
      }),
    })), errorCode(fixture.code));
  }
});

test('audit findings include their observed source and scope without fetching linked resources', async () => {
  let calls = 0;
  const report = await MetadataAgent.audit('https://public.example.org/', fixtureOptions({
    transport: async () => {
      calls++;
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', server: 'Fixture/1.0' },
        body: '<html><meta name="author" content="Fixture Author"><!-- Contact auditor@example.org -->' +
          '<script src="https://cdn.example.org/tracker.js"></script></html>',
      };
    },
  }));
  assert.equal(calls, 1);
  assert.equal(report.status, 'complete');
  assert.equal(report.scope, 'http-headers-and-static-html');
  assert.equal(report.overallRisk, 'critical');
  assert.ok(report.findings.some(f => f.field === 'author' && f.value === 'Fixture Author'));
  assert.ok(report.findings.some(f => f.category === 'third-party-resources'));
  for (const finding of report.findings) {
    assert.equal(finding.evidence.sourceUrl, 'https://public.example.org/');
    assert.equal(finding.evidence.observedAt, report.timestamp);
    assert.equal(typeof finding.evidence.observation, 'string');
  }
  assert.equal(report.provenance.transport, 'dns-pinned-direct');
  assert.equal(report.provenance.inspectedHtml, true);
  assert.equal(report.provenance.httpStatus, 200);
  assert.ok(report.provenance.bytesReceived > 0);
  assert.ok(report.limitations.some(text => text.includes('does not inspect image EXIF')));
  assert.ok(!report.limitations.some(text => text.includes('non-UTF-8')));
});

test('blocked, unsuccessful, empty and non-HTML responses cannot masquerade as clean assessments', async () => {
  for (const fixture of [
    { statusCode: 403, headers: { 'content-type': 'text/html' }, body: '<h1>Access denied</h1>', code: 'UPSTREAM_FAILED', status: 502 },
    { statusCode: 500, headers: { 'content-type': 'text/html' }, body: '<h1>Upstream unavailable</h1>', code: 'UPSTREAM_FAILED', status: 502 },
    { statusCode: 200, headers: { 'content-type': 'text/html' }, body: '   ', code: 'EMPTY_RESPONSE', status: 502 },
    { statusCode: 200, headers: { 'content-type': 'image/jpeg' }, body: '<meta name="email" content="auditor@example.org">', code: 'UNSUPPORTED_CONTENT_TYPE', status: 422 },
    { statusCode: 200, headers: {}, body: '<html>Undeclared</html>', code: 'UNSUPPORTED_CONTENT_TYPE', status: 422 },
  ]) {
    await assert.rejects(MetadataAgent.audit('https://public.example.org/', fixtureOptions({
      transport: async () => fixture,
    })), error => error.code === fixture.code && error.statusCode === fixture.status);
  }
});

test('HTTP pages are not incorrectly flagged for missing HTTPS-only HSTS and charset limits are explicit', async () => {
  const report = await MetadataAgent.audit('http://public.example.org/', fixtureOptions({
    transport: async () => ({
      statusCode: 200, headers: { 'content-type': 'text/html; charset=iso-8859-1' }, body: '<html>A page</html>',
    }),
  }));
  assert.equal(report.status, 'partial');
  assert.ok(!report.findings.some(f => f.field === 'strict-transport-security'));
  assert.ok(report.limitations.some(text => text.includes('non-UTF-8')));
});

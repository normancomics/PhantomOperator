'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');
const { createPaymentClient } = require('../lib/x402');

const PAY_TO = '0x1111111111111111111111111111111111111111';
const FACILITATOR_URL = 'https://facilitator.example';
const BASE_URL = 'https://phantom.example';
const NETWORK = 'eip155:8453';
const TX_HASH = `0x${'a'.repeat(64)}`;
const ROUTE = {
  path: '/skills/metadata-audit', priceUsd: 0.05,
  description: 'HTTP/HTML privacy audit',
  bodySchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
  inputExample: { url: 'https://example.com/' },
  outputExample: { skill: 'metadata-audit', result: { findings: [] } },
};
const ACCEPTED = {
  scheme: 'exact', network: NETWORK, amount: '50000',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: PAY_TO,
  maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' },
};
const PAYLOAD = { x402Version: 2, accepted: ACCEPTED, payload: { signature: 'fixture-not-a-real-authorization' } };

function requestWith(payload) {
  return { headers: { 'payment-signature': Buffer.from(JSON.stringify(payload)).toString('base64') } };
}

function clientReturning(body, options = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (options.error) throw options.error;
    return new Response(options.rawBody ?? JSON.stringify(body), {
      status: options.status ?? 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  const client = createPaymentClient({ fetchImpl, payTo: PAY_TO, facilitatorUrl: FACILITATOR_URL });
  return { client, calls };
}

test('the zero address cannot be configured as the payment receiver', () => {
  let calls = 0;
  assert.throws(() => createPaymentClient({
    payTo: `0x${'0'.repeat(40)}`,
    facilitatorUrl: FACILITATOR_URL,
    fetchImpl: async () => { calls++; },
  }), /nonzero Ethereum address/);
  assert.equal(calls, 0);
});

for (const variable of ['PAY_TO', 'PAYMENT_RECEIVER_ADDRESS']) {
  test(`startup rejects a zero receiver configured through ${variable}`, () => {
    const result = spawnSync(process.execPath, ['-e', 'require("./lib/x402")'], {
      cwd: path.resolve(__dirname, '..'),
      env: { ...process.env, PAY_TO: '', PAYMENT_RECEIVER_ADDRESS: '', [variable]: `0x${'0'.repeat(40)}` },
      encoding: 'utf8', timeout: 5000,
    });
    assert.notEqual(result.status, 0, 'invalid receiver must prevent startup');
    assert.match(result.stderr, /nonzero Ethereum address/);
  });
}

test('unpaid requests challenge without contacting the facilitator', async () => {
  const { client, calls } = clientReturning({ isValid: true });
  const result = await client.verify({ headers: {} }, ROUTE, BASE_URL);
  assert.equal(result.ok, false);
  assert.equal(result.status, 402);
  assert.equal(calls.length, 0);
  assert.equal(result.body.accepts[0].payTo, PAY_TO);
  assert.equal(result.body.accepts[0].amount, '50000');
  const header = JSON.parse(Buffer.from(result.headers['PAYMENT-REQUIRED'], 'base64').toString('utf8'));
  assert.deepEqual(header, result.body);
});

for (const invalidPayload of [null, [], 'authorization', 7, {}, { x402Version: 1, payload: {} }, { x402Version: 2, payload: null }, { x402Version: 2, payload: [] }]) {
  test(`invalid payment envelope ${JSON.stringify(invalidPayload)} is rejected without forwarding`, async () => {
    const { client, calls } = clientReturning({ isValid: true });
    const result = await client.verify(requestWith(invalidPayload), ROUTE, BASE_URL);
    assert.equal(result.ok, false);
    assert.equal(result.status, 402);
    assert.equal(calls.length, 0);
  });
}

test('malformed payment header cannot reach facilitator verification', async () => {
  const { client, calls } = clientReturning({ isValid: true });
  const result = await client.verify({ headers: { 'payment-signature': '%%%not-base64-json%%%' } }, ROUTE, BASE_URL);
  assert.equal(result.status, 402);
  assert.equal(calls.length, 0);
});

test('verification forwards the exact route price, receiver, and received envelope', async () => {
  const { client, calls } = clientReturning({ isValid: true, payer: PAY_TO });
  const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
  assert.equal(result.ok, true);
  assert.deepEqual(result.payload, PAYLOAD);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${FACILITATOR_URL}/verify`);
  assert.equal(calls[0].init.method, 'POST');
  const forwarded = JSON.parse(calls[0].init.body);
  assert.equal(forwarded.x402Version, 2);
  assert.deepEqual(forwarded.paymentPayload, PAYLOAD);
  assert.equal(forwarded.paymentRequirements.payTo, PAY_TO);
  assert.equal(forwarded.paymentRequirements.amount, '50000');
  assert.equal(forwarded.paymentRequirements.network, NETWORK);
  assert.ok(calls[0].init.signal instanceof AbortSignal, 'facilitator requests must have a bounded deadline');
});

test('an explicit invalid authorization produces a new payment challenge', async () => {
  const { client } = clientReturning({ isValid: false, invalidReason: 'fixture authorization expired' });
  const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
  assert.equal(result.ok, false);
  assert.equal(result.status, 402);
  assert.equal(result.body.error, 'fixture authorization expired');
});

for (const badBody of [{ isValid: 'true' }, { isValid: 1 }, {}, null, [], 'verified']) {
  test(`malformed facilitator verification ${JSON.stringify(badBody)} fails closed`, async () => {
    const { client } = clientReturning(badBody);
    const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
    assert.equal(result.ok, false);
    assert.equal(result.status, 502);
  });
}

test('an HTTP error cannot be treated as authorization even with an isValid:true JSON body', async () => {
  const { client } = clientReturning({ isValid: true }, { status: 503 });
  const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
});

test('facilitator network failures do not authorize payments', async () => {
  const { client } = clientReturning(null, { error: new Error('fixture network failure') });
  const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
});

test('non-JSON facilitator responses cannot authorize payments', async () => {
  const { client } = clientReturning(null, { rawBody: '<html>gateway unavailable</html>' });
  const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
});

test('successful settlement requires a Base transaction hash and exposes a verifiable receipt', async () => {
  const receipt = { success: true, transaction: TX_HASH, network: NETWORK, payer: PAY_TO };
  const { client, calls } = clientReturning(receipt);
  const result = await client.settle(PAYLOAD, ROUTE);
  assert.equal(result.ok, true);
  assert.equal(calls[0].url, `${FACILITATOR_URL}/settle`);
  const forwarded = JSON.parse(calls[0].init.body);
  assert.deepEqual(forwarded.paymentPayload, PAYLOAD);
  assert.equal(forwarded.paymentRequirements.amount, '50000');
  const decoded = JSON.parse(Buffer.from(result.headers['PAYMENT-RESPONSE'], 'base64').toString('utf8'));
  assert.deepEqual(decoded, receipt);
});

test('an explicit failed settlement does not produce a success receipt', async () => {
  const { client } = clientReturning({ success: false, errorReason: 'fixture insufficient balance', network: NETWORK, transaction: '' });
  const result = await client.settle(PAYLOAD, ROUTE);
  assert.equal(result.ok, false);
  assert.equal(result.status, 402);
  assert.ok(!result.headers?.['PAYMENT-RESPONSE']);
});

for (const badBody of [
  { success: 'true', transaction: TX_HASH, network: NETWORK },
  { success: 1, transaction: TX_HASH, network: NETWORK },
  { success: true, network: NETWORK },
  { success: true, transaction: 'not-a-transaction', network: NETWORK },
  { success: true, transaction: TX_HASH, network: 'eip155:1' },
  { success: true, transaction: TX_HASH },
  {}, null, [],
]) {
  test(`malformed settlement ${JSON.stringify(badBody)} cannot produce HTTP success`, async () => {
    const { client } = clientReturning(badBody);
    const result = await client.settle(PAYLOAD, ROUTE);
    assert.equal(result.ok, false);
    assert.equal(result.status, 502);
    assert.ok(!result.headers?.['PAYMENT-RESPONSE']);
  });
}

test('non-success HTTP status prevents settlement success even with a valid-looking receipt', async () => {
  const { client } = clientReturning({ success: true, transaction: TX_HASH, network: NETWORK }, { status: 503 });
  const result = await client.settle(PAYLOAD, ROUTE);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
});

test('settlement network and JSON failures fail closed', async t => {
  for (const options of [{ error: new Error('fixture network failure') }, { rawBody: '<html>unavailable</html>' }]) {
    await t.test(options.error ? 'network' : 'JSON', async () => {
      const { client } = clientReturning(null, options);
      const result = await client.settle(PAYLOAD, ROUTE);
      assert.equal(result.ok, false);
      assert.equal(result.status, 502);
    });
  }
});

test('USDC route prices must be positive, finite, safely representable whole micro-units', () => {
  const { client } = clientReturning({ isValid: true });
  assert.equal(client.atomic(0.05), '50000');
  assert.equal(client.atomic(0.10), '100000');
  assert.equal(client.atomic(0.25), '250000');
  assert.equal(client.atomic(0.000001), '1');
  for (const invalid of [0, -1, NaN, Infinity, '0.05', 0.0000001, 0.1234567, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => client.atomic(invalid), undefined, `invalid USDC price ${String(invalid)}`);
  }
});

test('oversized facilitator bodies fail closed even without a Content-Length header', async () => {
  const { client } = clientReturning({ isValid: true, padding: 'x'.repeat(262144) });
  const result = await client.verify(requestWith(PAYLOAD), ROUTE, BASE_URL);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
});

test('oversized chunked settlement bodies cannot produce oversized success receipt headers', async () => {
  const { client } = clientReturning({ success: true, transaction: TX_HASH, network: NETWORK, padding: 'x'.repeat(262144) });
  const result = await client.settle(PAYLOAD, ROUTE);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
  assert.ok(!result.headers?.['PAYMENT-RESPONSE']);
});

const invalidAcceptedOffers = [
  ['missing accepted offer', undefined],
  ['null accepted offer', null],
  ['array accepted offer', []],
  ['string accepted offer', 'exact'],
  ['empty accepted offer', {}],
  ['wrong scheme', { ...ACCEPTED, scheme: 'upto' }],
  ['wrong network', { ...ACCEPTED, network: 'eip155:1' }],
  ['wrong token', { ...ACCEPTED, asset: '0x2222222222222222222222222222222222222222' }],
  ['wrong receiving wallet', { ...ACCEPTED, payTo: '0x2222222222222222222222222222222222222222' }],
  ['underpayment', { ...ACCEPTED, amount: '1' }],
  ['different amount', { ...ACCEPTED, amount: '50001' }],
  ['non-string amount', { ...ACCEPTED, amount: 50000 }],
];
for (const field of ['scheme', 'network', 'asset', 'payTo', 'amount']) {
  const offer = { ...ACCEPTED };
  delete offer[field];
  invalidAcceptedOffers.push([`missing ${field}`, offer]);
}
for (const [reason, accepted] of invalidAcceptedOffers) {
  test(`a payment with ${reason} is rejected before forwarding to the facilitator`, async () => {
    const { client, calls } = clientReturning({ isValid: true });
    const result = await client.verify(requestWith({ ...PAYLOAD, accepted }), ROUTE, BASE_URL);
    assert.equal(result.ok, false);
    assert.equal(result.status, 402);
    assert.equal(calls.length, 0, 'a different resource offer must not be submitted for verification');
  });
}

test('settlement receipt headers contain only bounded standard fields', async () => {
  const receipt = { success: true, transaction: TX_HASH, network: NETWORK, payer: PAY_TO };
  const { client } = clientReturning({ ...receipt, debug: 'x'.repeat(16000), arbitrary: { nested: 'ignored' } });
  const result = await client.settle(PAYLOAD, ROUTE);
  assert.equal(result.ok, true);
  const header = result.headers['PAYMENT-RESPONSE'];
  assert.ok(Buffer.byteLength(header) < 2048, 'receipt must fit comfortably within ordinary HTTP header limits');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64').toString('utf8')), receipt);
  assert.equal(result.headers['X-PAYMENT-RESPONSE'], header);
});

test('pending settlement preserves its transaction without asking the client to pay again', async () => {
  const { client } = clientReturning({
    success: false, errorReason: 'settlement_pending', transaction: TX_HASH, network: NETWORK,
  });
  const result = await client.settle(PAYLOAD, ROUTE);
  assert.equal(result.ok, false);
  assert.equal(result.status, 502);
  assert.equal(result.body.transaction, TX_HASH);
  assert.equal(result.body.network, NETWORK);
  assert.match(result.body.error, /wallet/i);
  assert.ok(!result.headers?.['PAYMENT-REQUIRED']);
  assert.ok(!result.headers?.['PAYMENT-RESPONSE']);
});

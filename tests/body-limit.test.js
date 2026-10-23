'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const net = require('node:net');
const test = require('node:test');
const { createServer } = require('../server');
const { MAX_BODY_BYTES } = require('../middleware/security');

for (const framing of ['content-length', 'chunked']) {
  test(`an oversized unfinished ${framing} body gets a complete 413 and its connection closes`, { timeout: 5000 }, async t => {
    const events = [];
    const payment = {
      PAY_TO: '0x1111111111111111111111111111111111111111',
      FACILITATOR: 'https://facilitator.example',
      USDC_BASE: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      NETWORK: 'eip155:8453',
      async verify() { events.push('verify'); return { ok: false, status: 402, body: {} }; },
      async settle() { events.push('settle'); return { ok: false, status: 502, body: {} }; },
    };
    const agents = { MetadataAgent: { async audit() { events.push('run'); return {}; } } };
    const server = createServer({ payment, agents, publicUrl: 'https://phantom.example' });
    t.after(async () => {
      server.closeAllConnections();
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');

    const connected = once(server, 'connection');
    // Keep the client's writable side open after a FIN, so a server-side close
    // cannot be caused by the client finishing the request or closing its socket.
    const client = net.connect({ host: '127.0.0.1', port: server.address().port, allowHalfOpen: true });
    t.after(() => client.destroy());
    const [serverSocket] = await connected;
    await once(client, 'connect');
    const responseChunks = [];
    client.on('data', chunk => responseChunks.push(chunk));
    const signal = AbortSignal.timeout(2000);
    const responseEnded = once(client, 'end', { signal });
    const serverClosed = once(serverSocket, 'close', { signal });
    const body = 'x'.repeat(MAX_BODY_BYTES + 1);
    const framingHeader = framing === 'chunked'
      ? 'Transfer-Encoding: chunked'
      : `Content-Length: ${body.length + 1024}`;
    client.write(`POST /skills/metadata-audit HTTP/1.1\r\nHost: phantom.example\r\nContent-Type: application/json\r\nPayment-Signature: fixture-not-a-real-payment\r\nConnection: keep-alive\r\n${framingHeader}\r\n\r\n`);
    client.write(framing === 'chunked' ? `${body.length.toString(16)}\r\n${body}\r\n` : body);
    // Deliberately send neither the remaining Content-Length bytes nor the final
    // zero-size chunk. The response and connection close must happen anyway.
    await Promise.all([responseEnded, serverClosed]);

    const response = Buffer.concat(responseChunks).toString('utf8');
    const [headers, responseBody] = response.split('\r\n\r\n');
    assert.match(headers, /^HTTP\/1\.1 413 /);
    assert.match(headers, /\r\nConnection: close(?:\r\n|$)/i);
    const length = headers.match(/\r\nContent-Length: (\d+)(?:\r\n|$)/i);
    assert.ok(length, 'the error response must declare its body length');
    assert.equal(Buffer.byteLength(responseBody), Number(length[1]), 'the 413 body must flush before the socket closes');
    assert.deepEqual(JSON.parse(responseBody), { error: 'Request body too large' });
    assert.equal(serverSocket.destroyed, true);
    assert.equal(client.writableEnded, false, 'the client must never finish its request');
    assert.deepEqual(events, [], 'oversized input must never reach payment or skill execution');
  });
}

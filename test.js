const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const PhantomOperatorCore = require('./PhantomOperatorCore');

function request(port, method, path, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json', 'X-PhantomOperator-Test': '1' } },
      res => {
        let data = '';
        res.on('data', c => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.on('error', reject);
    req.end(body);
  });
}

async function withServer(port, receiver, fn) {
  const env = { ...process.env, PORT: String(port) };
  for (const k of ['PAYMENT_RECEIVER_ADDRESS', 'SOVEREIGN_AGENT_ADDRESS', 'PHANTOM_OPERATOR_ADDRESS']) {
    delete env[k];
  }
  if (receiver) env.PAYMENT_RECEIVER_ADDRESS = receiver;
  const child = spawn(process.execPath, ['server.js'], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  try {
    await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('exit', code => reject(new Error(`server exited early (${code})`)));
      child.stdout.on('data', d => d.toString().includes('running on port') && resolve());
    });
    await fn();
  } finally {
    child.removeAllListeners('exit');
    child.kill();
  }
}

async function runServerTests() {
  const RECEIVER = '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';

  await withServer(34567, RECEIVER, async () => {
    assert.strictEqual((await request(34567, 'GET', '/health')).status, 200);
    const unpaid = await request(34567, 'POST', '/skills/opsec-score', '{}');
    if (unpaid.status !== 402) console.error("UNPAID BODY:", unpaid.body); assert.strictEqual(unpaid.status, 402);
    assert.ok(Array.isArray(JSON.parse(unpaid.body).accepts));
    const spec = JSON.parse((await request(34567, 'GET', '/openapi.json')).body);
    assert.ok(spec.openapi && spec.paths['/skills/opsec-score']);
    const disc = JSON.parse((await request(34567, 'GET', '/.well-known/x402')).body);
    assert.ok(disc.resources.length > 0 && disc.payTo === RECEIVER);
    assert.strictEqual((await request(34567, 'GET', '/robots.txt')).status, 200);
    assert.strictEqual((await request(34567, 'GET', '/sitemap.xml')).status, 200);
    const alias = await request(34567, 'GET', '/.well-known/agent.json');
    assert.strictEqual(alias.status, 308);
    const llms = (await request(34567, 'GET', '/llms.txt')).body;
    assert.ok(llms.includes('USDC on Base') && !llms.includes('USDCx on Base') && !llms.includes('MPP equivalents are available'));
    assert.ok(JSON.parse(unpaid.body).accepts[0].outputSchema);
    assert.strictEqual((await request(34567, 'OPTIONS', '/skills/opsec-score')).status, 204);

    // Phase 1 Elysium USDC billing endpoint tests
    const elyInfoRes = await request(34567, 'GET', '/billing/elysium-usdc/info');
    assert.strictEqual(elyInfoRes.status, 200);
    const elyInfo = JSON.parse(elyInfoRes.body);
    assert.strictEqual(elyInfo.chainId, 99901);
    assert.strictEqual(elyInfo.network, 'eip155:99901');
    assert.strictEqual(elyInfo.asset, '0xb47c4C8F73F009CC0C0d3f92B388d13E293F0B65');
    assert.strictEqual(elyInfo.payTo, RECEIVER);
    assert.strictEqual(elyInfo.decimals, 6);

    const { ethers } = require('ethers');
    const os = require('os');
    const path = require('path');
    const fs = require('fs');
    const {
      ElysiumUsdcBilling,
      ELYSIUM_USDC,
      buildSigningMessage,
      requestHash,
    } = require('./lib/elysium-billing');

    const testWallet = ethers.Wallet.createRandom();
    const quoteRes = await request(
      34567,
      'POST',
      '/billing/elysium-usdc/quote',
      JSON.stringify({
        skillId: 'opsec-score',
        input: { handle: 'satoshi' },
        payer: testWallet.address,
      })
    );
    assert.strictEqual(quoteRes.status, 201);
    const quoteObj = JSON.parse(quoteRes.body);
    assert.strictEqual(quoteObj.payer, testWallet.address);
    assert.strictEqual(quoteObj.payTo, RECEIVER);
    assert.strictEqual(quoteObj.amountAtomic, '250000');

    const statusRes = await request(34567, 'GET', `/billing/elysium-usdc/quote/${quoteObj.quoteId}`);
    assert.strictEqual(statusRes.status, 200);
    assert.strictEqual(JSON.parse(statusRes.body).status, 'pending');

    // Unit test ElysiumUsdcBilling receipt verification + replay protection
    const tmpDb = path.join(os.tmpdir(), `elysium-billing-test-${process.pid}-${Date.now()}.sqlite`);
    const transferIface = new ethers.Interface([
      'event Transfer(address indexed from, address indexed to, uint256 value)',
    ]);
    const fakeTxHash = '0x' + 'ab'.repeat(32);
    const encodedLog = transferIface.encodeEventLog('Transfer', [
      testWallet.address,
      RECEIVER,
      50000n,
    ]);
    const mockProvider = {
      getTransactionReceipt: async (hash) => {
        if (hash !== fakeTxHash) return null;
        return {
          status: 1,
          blockNumber: 123450,
          logs: [
            {
              address: ELYSIUM_USDC,
              topics: encodedLog.topics,
              data: encodedLog.data,
              index: 0,
            },
          ],
        };
      },
      getBlock: async () => ({ timestamp: Math.floor(Date.now() / 1000) }),
      getBlockNumber: async () => 123452,
    };

    const billing = new ElysiumUsdcBilling({ filename: tmpDb, provider: mockProvider });
    const mockRoute = { id: 'opsec-score', path: '/skills/opsec-score', priceUsd: 0.05 };
    const bodyInput = { handle: 'satoshi' };
    const localQuote = billing.createQuote({
      route: mockRoute,
      body: bodyInput,
      payer: testWallet.address,
      baseUrl: 'http://127.0.0.1:34567',
    });

    const msg = buildSigningMessage({
      quoteId: localQuote.quoteId,
      txHash: fakeTxHash,
      routeId: mockRoute.id,
      reqHash: requestHash(bodyInput),
    });
    const sig = await testWallet.signMessage(msg);
    const headerPayload = Buffer.from(
      JSON.stringify({ quoteId: localQuote.quoteId, txHash: fakeTxHash, signature: sig })
    ).toString('base64');

    // 1. Tampered request body must be rejected (402)
    const tampered = await billing.verifyForRequest(headerPayload, mockRoute, { handle: 'mallory' });
    assert.strictEqual(tampered.ok, false);
    assert.strictEqual(tampered.status, 402);

    // 2. Valid proof succeeds
    const verified = await billing.verifyForRequest(headerPayload, mockRoute, bodyInput);
    assert.strictEqual(verified.ok, true);
    assert.strictEqual(verified.settlement.txHash, fakeTxHash);
    assert.strictEqual(verified.settlement.amountAtomic, '50000');

    // 3. Replaying the same quote fails with 409
    const replayQuote = await billing.verifyForRequest(headerPayload, mockRoute, bodyInput);
    assert.strictEqual(replayQuote.ok, false);
    assert.strictEqual(replayQuote.status, 409);

    // 4. Replaying the same on-chain txHash on a brand-new quote also fails with 409
    const secondQuote = billing.createQuote({
      route: mockRoute,
      body: bodyInput,
      payer: testWallet.address,
      baseUrl: 'http://127.0.0.1:34567',
    });
    const secondMsg = buildSigningMessage({
      quoteId: secondQuote.quoteId,
      txHash: fakeTxHash,
      routeId: mockRoute.id,
      reqHash: requestHash(bodyInput),
    });
    const secondSig = await testWallet.signMessage(secondMsg);
    const secondHeader = Buffer.from(
      JSON.stringify({ quoteId: secondQuote.quoteId, txHash: fakeTxHash, signature: secondSig })
    ).toString('base64');
    const replayTx = await billing.verifyForRequest(secondHeader, mockRoute, bodyInput);
    assert.strictEqual(replayTx.ok, false);
    assert.strictEqual(replayTx.status, 409);

    for (const suffix of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(tmpDb + suffix); } catch { /* ignore */ }
    }
  });


  const MoneroAgent = require("./agents/MoneroAgent");
  const monero = new MoneroAgent();
  const xmrAudit = await monero.audit({
    xmrAddress: "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    nodeMode: "remote-tor",
  });
  assert.strictEqual(xmrAudit.addressAnalysis.valid, true);
  assert.ok(xmrAudit.mmrCommitmentProof.mmrRoot);
  console.log("Server + Monero ($XMR) Cryptonote & MMR tests passed.");

}


(async () => {
  try {
    await runServerTests();

    const agent = new PhantomOperatorCore();

    const user = {
      email: 'user@example.com',
      name: 'Jane Doe',
      country: 'US',
    };

    console.log('Running privacy workflow...');
    const workflowResult = await agent.runPrivacyWorkflow(user);
    console.log('Workflow result:\n', JSON.stringify(workflowResult, null, 2));

    const receiver = process.env.TEST_RECEIVER_ADDRESS;
    const flowRate = process.env.TEST_FLOW_RATE || '1000000000000';

    if (receiver) {
      console.log(`Opening Superfluid stream to ${receiver} with flowRate=${flowRate}...`);
      const txStart = await agent.openRewardStream(receiver, flowRate);
      console.log('Stream opened, tx hash:', txStart);

      console.log('Stopping Superfluid stream...');
      const txStop = await agent.stopRewardStream(receiver);
      console.log('Stream stopped, tx hash:', txStop);
    } else {
      console.log('No TEST_RECEIVER_ADDRESS set; skipping Superfluid demo.');
    }
  } catch (err) {
    console.error('Error running PhantomOperator test:', err);
    process.exit(1);
  }
})();

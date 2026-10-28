const assert = require('assert');
const http = require('http');
const { spawn } = require('child_process');
const PhantomOperatorCore = require('./PhantomOperatorCore');

function request(port, method, path, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, method, path, headers: { 'Content-Type': 'application/json' } },
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
    assert.ok(llms.includes('native USDC on Base') && !llms.includes('USDCx on Base'));
    assert.ok(JSON.parse(unpaid.body).accepts[0].outputSchema);
    assert.strictEqual((await request(34567, 'OPTIONS', '/skills/opsec-score')).status, 204);
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

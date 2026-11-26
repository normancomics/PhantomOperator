/**
 * server.js — PhantomOperator HTTP API Server (Unified v1.0.0)
 *
 * Combines:
 *  - Real x402 v1/v2 "exact" USDC settlement on Base (eip155:8453) via the
 *    authenticated Coinbase CDP facilitator to operational wallet:
 *    0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6
 *  - Keyless execution for ALL 10 privacy, OSINT, wallet, and $XMR Monero skills
 *  - Interactive Cyberpunk Web UI & Live Skill Runner + One-Click Base USDC
 *    Checkout at `GET /` (browser) and `GET /app`
 *  - Full Discovery Suite:
 *      GET /                        — HTML console for browsers, JSON for agents
 *      GET /manifest                — Full agent-manifest.json
 *      GET /skills                  — Skill catalog + live pricing
 *      GET /openapi.json            — OpenAPI 3.1.0 specification
 *      GET /.well-known/x402        — x402 v2 discovery document
 *      GET /.well-known/agent.json  — Agent discovery manifest
 *      GET /.well-known/agent-card.json         — A2A Agent Card
 *      GET /.well-known/agent-registration.json — ERC-8004 registration file
 *      GET /llms.txt                — LLM machine-readable overview
 *      GET /SKILL.md                — Skill documentation
 *      GET /terms                   — Acceptable Use & Terms
 *      GET /logo.png                — Valid 512x512 RGBA PNG icon
 *      GET /health                  — Health check
 *      GET /mcp & POST /mcp         — Model Context Protocol (JSON-RPC 2.0)
 *      POST /demo/monero-decode     — Free live $XMR Cryptonote decoder preview
 */

'use strict';

require('dotenv').config();
const path    = require('path');
const fs      = require('fs');
const express = require('express');
const crypto = require('crypto');
const { Mppx, tempo, stripe } = require('mppx/express');
const x402    = require('./lib/x402');
const usage   = require('./lib/usage');
const moneroBilling = require('./lib/monero-billing');
const { ElysiumUsdcBilling, ELYSIUM_CHAIN_ID, ELYSIUM_NETWORK, ELYSIUM_USDC, ELYSIUM_USDC_DECIMALS } = require('./lib/elysium-billing');
const { CreditLedger } = require('./lib/credits');
const stripeCheckout = require('./lib/stripe-checkout');

const MPP_TEMPO_OUSD = '0x20c0000000000000000000006a37DA5C996874BE';
// Tempo MPP is disabled unless explicitly configured and tested. Do not advertise
// a payment rail that can return an unusable payment challenge.
const MPP_TEMPO_ENABLED = process.env.ENABLE_MPP_TEMPO === 'true' && Boolean(process.env.MPP_SECRET_KEY);
const STRIPE_MPP_ENABLED = process.env.ENABLE_STRIPE_MPP === 'true'
  && Boolean(process.env.STRIPE_SECRET_KEY)
  && Boolean(process.env.STRIPE_PROFILE_ID);
if (MPP_TEMPO_ENABLED && STRIPE_MPP_ENABLED) throw new Error('Enable only one MPP settlement rail at a time.');
const mpp = MPP_TEMPO_ENABLED ? Mppx.create({
  methods: [tempo.charge({
    currencies: [MPP_TEMPO_OUSD],
    recipient: x402.PAY_TO,
    testnet: false,
  })],
  secretKey: process.env.MPP_SECRET_KEY,
  realm: process.env.MPP_REALM || 'freysaai.freysa.dev',
}) : null;
// Stripe MPP uses single-use Shared Payment Tokens (SPTs). Its payment secret is
// deterministically derived from the Stripe key; direct Stripe calls require a
// $0.50 minimum, so it is a separate rail from the $0.05 Base x402 routes.
const stripeMpp = STRIPE_MPP_ENABLED ? Mppx.create({
  methods: [stripe.charge({
    secretKey: process.env.STRIPE_SECRET_KEY,
    networkId: process.env.STRIPE_PROFILE_ID,
    paymentMethodTypes: ['card', 'link'],
    currency: 'usd',
    decimals: 2,
  })],
  secretKey: crypto.createHmac('sha256', process.env.STRIPE_SECRET_KEY).update('mpp-challenge-signing').digest('base64'),
  realm: process.env.MPP_REALM || 'freysaai.freysa.dev',
}) : null;
const STRIPE_MPP_MIN_USD = 0.50;

const SearchAgent      = require('./agents/SearchAgent');
const BrokerAgent      = require('./agents/BrokerAgent');
const OpsecAgent       = require('./agents/OpsecAgent');
const BreachAgent      = require('./agents/BreachAgent');
const MetadataAgent    = require('./agents/MetadataAgent');
const MoneroAgent      = require('./agents/MoneroAgent');
const WalletOpsecAgent = require('./agents/WalletOpsecAgent');
const PhantomOperator  = require('./PhantomOperatorCore');

const {
  corsHeaders,
  securityHeaders,
  bodySizeGuard,
  publicLimiter,
  paidLimiter,
  previewLimiter,
  validateSkillInput,
} = require('./middleware/security');

const manifest = require('./agent-manifest.json');
const mcpTools = require('./mcp/tools.json');

const app = express();
app.set('trust proxy', 1);
const creditLedger = new CreditLedger(process.env.CREDIT_LEDGER_DB || path.join(__dirname, 'data', 'credits.sqlite'));
const elysiumBilling = new ElysiumUsdcBilling();

// Stripe requires the exact raw body for webhook signature verification. This
// route must remain before express.json(). It is disabled until explicitly configured.
app.post('/billing/stripe/webhook', express.raw({ type: 'application/json', limit: '64kb' }), (req, res) => {
  if (!stripeCheckout.configured()) return res.status(404).json({ error: 'Stripe credits are not enabled.' });
  try {
    const event = stripeCheckout.verifyWebhook(req.body.toString('utf8'), req.headers['stripe-signature']);
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
      const session = event.data && event.data.object;
      const purchaseId = session && session.metadata && session.metadata.purchase_id;
      if (!purchaseId || session.payment_status !== 'paid') throw new Error('Paid checkout event is missing verified purchase data.');
      creditLedger.fulfillStripePurchase(purchaseId, session.id, session.amount_total);
    }
    return res.status(200).json({ received: true });
  } catch (error) {
    return res.status(400).json({ error: 'Stripe webhook rejected.', detail: error.message });
  }
});

app.use(corsHeaders);
app.use(securityHeaders);
app.use(bodySizeGuard);
const configuredMaxBodyBytes = parseInt(process.env.MAX_BODY_BYTES || '16384', 10);
const maxBodyBytes = Number.isSafeInteger(configuredMaxBodyBytes) && configuredMaxBodyBytes > 0
  ? configuredMaxBodyBytes
  : 16384;
app.use(express.json({ limit: maxBodyBytes }));

app.use((err, _req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload Too Large', message: `Request body must not exceed ${maxBodyBytes} bytes.` });
  }
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON in request body.' });
  }
  return next(err);
});

const baseUrl = (req) =>
  process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;

// Human card checkout. The browser receives the bearer credit token once and
// retains it locally; the server persists only its hash and grants value only
// after Stripe's signed webhook confirms payment.
app.post('/billing/stripe/checkout', paidLimiter, async (req, res) => {
  if (!stripeCheckout.configured()) return res.status(503).json({ error: 'Stripe prepaid credits are not enabled yet.' });
  const amountCents = req.body && req.body.amountCents;
  try {
    stripeCheckout.assertAmount(amountCents);
    const purchaseId = crypto.randomBytes(24).toString('base64url');
    const creditToken = creditLedger.createToken();
    creditLedger.createPendingStripePurchase(purchaseId, creditToken, amountCents);
    const checkout = await stripeCheckout.createCheckout({ purchaseId, amountCents, publicBaseUrl: baseUrl(req) });
    creditLedger.attachStripeSession(purchaseId, checkout.id);
    return res.status(201).json({ checkoutUrl: checkout.url, creditToken, amountCents, note: 'Store the credit token safely. Credits are granted only after Stripe confirms payment.' });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

// Direct one-step $19 Website Privacy Baseline Stripe Checkout for humans.
// Validates the target public URL + authorization upfront, issues a $19.00
// (1900 cents) pending credit token fulfilled by the signed Stripe webhook,
// and redirects back to /?baseline=success to run the report automatically.
app.post('/billing/stripe/website-privacy-baseline-checkout', paidLimiter, validateSkillInput('metadata-audit'), async (req, res) => {
  if (!stripeCheckout.configured()) {
    return res.status(503).json({ error: 'Stripe prepaid credits are not enabled yet.' });
  }
  const authorized = Boolean(req.body && req.body.authorized === true);
  if (!authorized) {
    return res.status(400).json({
      error: 'Authorization required',
      message: 'Confirm you own or are authorized to assess the target website.',
    });
  }
  const targetUrl = req.body.url.trim();
  const amountCents = 1900;
  try {
    await MetadataAgent.assertSafeUrl(targetUrl);
    const purchaseId = crypto.randomBytes(24).toString('base64url');
    const creditToken = creditLedger.createToken();
    creditLedger.createPendingStripePurchase(purchaseId, creditToken, amountCents);
    const checkout = await stripeCheckout.createCheckout({
      purchaseId,
      amountCents,
      publicBaseUrl: baseUrl(req),
      productName: 'PhantomOperator — Website Privacy Baseline ($19)',
      productDescription: `Fixed-scope public-exposure & privacy-baseline review for ${targetUrl}`,
      successPath: '/?baseline=success',
      cancelPath: '/?baseline=cancelled',
    });
    creditLedger.attachStripeSession(purchaseId, checkout.id);
    return res.status(201).json({
      offer: 'website-privacy-baseline',
      checkoutUrl: checkout.url,
      creditToken,
      targetUrl,
      amountCents,
      priceUsd: '19.00',
      note: 'After Stripe confirms payment, your Website Privacy Baseline report runs automatically on return.',
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.get('/billing/credits/balance', paidLimiter, (req, res) => {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const balance = creditLedger.balance(token);
  if (!balance) return res.status(404).json({ error: 'Credit token not found.' });
  return res.json({ balanceCents: balance.balanceCents, balanceUsd: (balance.balanceCents / 100).toFixed(2), issuedAt: balance.issuedAt, updatedAt: balance.updatedAt });
});

// ─── One-Time Owner Browser Setup for Stripe Prepaid Credits ─────────────────
const STRIPE_SETUP_TOKEN_FILE = path.join(__dirname, 'data', '.stripe-setup-token');

function verifyStripeSetupToken(candidate) {
  if (!candidate || typeof candidate !== 'string' || candidate.length < 32) return false;
  try {
    if (!fs.existsSync(STRIPE_SETUP_TOKEN_FILE)) return false;
    const raw = JSON.parse(fs.readFileSync(STRIPE_SETUP_TOKEN_FILE, 'utf8'));
    if (!raw || !raw.token || !raw.expiresAt || Date.now() > Number(raw.expiresAt)) return false;
    const a = Buffer.from(String(raw.token), 'utf8');
    const b = Buffer.from(candidate.trim(), 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

app.get('/admin/stripe-setup', paidLimiter, (req, res) => {
  res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  const token = String(req.query.token || '');
  if (!verifyStripeSetupToken(token)) {
    return res.status(403).type('text/plain').send('Setup link expired or invalid.');
  }
  return res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PhantomOperator — One-Time Stripe Setup</title>
  <style>
    body { background:#07090e; color:#e2e8f0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; max-width:640px; margin:40px auto; padding:0 20px; line-height:1.5; }
    .card { background:#0e131f; border:1px solid #1e293b; border-radius:12px; padding:24px; }
    h1 { color:#00f5d4; font-size:1.25rem; margin-top:0; }
    label { display:block; font-weight:600; margin:14px 0 6px; font-size:0.86rem; }
    input[type="password"], input[type="text"] { width:100%; padding:10px; border-radius:8px; border:1px solid #334155; background:#05080f; color:#e2e8f0; font-family:inherit; box-sizing:border-box; }
    button { margin-top:18px; width:100%; padding:12px; border:none; border-radius:8px; background:linear-gradient(135deg,#00f5d4,#00bbf9); color:#041019; font-weight:700; font-family:inherit; cursor:pointer; font-size:0.92rem; }
    .sub { color:#94a3b8; font-size:0.8rem; }
    pre { background:#05080f; border:1px solid #1e293b; border-radius:8px; padding:12px; overflow-x:auto; font-size:0.8rem; color:#a7f3d0; display:none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>PhantomOperator — One-Time Stripe Credits & Webhook Setup</h1>
    <p class="sub">Your key is transmitted directly over HTTPS to your server, validated against Stripe, used to auto-create the webhook endpoint (<code>https://freysaai.freysa.dev/billing/stripe/webhook</code>), and stored in <code>/home/nixos/PhantomOperator/.env</code> (<code>chmod 600</code>). This link burns itself after one successful setup.</p>
    <form id="setupForm">
      <label for="secretKey">1. Stripe Secret Key (<code>sk_test_...</code> or <code>sk_live_...</code>)</label>
      <input id="secretKey" type="password" autocomplete="off" placeholder="sk_test_... or sk_live_..." required />
      <label for="webhookSecret">2. Existing Webhook Signing Secret (optional — leave blank to auto-create via Stripe API)</label>
      <input id="webhookSecret" type="password" autocomplete="off" placeholder="Leave blank to auto-create via POST /v1/webhook_endpoints" />
      <label style="display:flex;align-items:center;gap:8px;margin-top:14px;">
        <input id="enableCredits" type="checkbox" checked />
        <span>Enable Stripe Prepaid Credits & $19 Website Privacy Baseline immediately</span>
      </label>
      <button type="submit" id="submitBtn">Validate Key & Auto-Create Webhook</button>
    </form>
    <pre id="resultBox"></pre>
  </div>
  <script>
    const setupToken = ${JSON.stringify(token)};
    document.getElementById('setupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      const out = document.getElementById('resultBox');
      btn.disabled = true;
      btn.textContent = 'Validating with Stripe & configuring webhook...';
      out.style.display = 'block';
      out.textContent = 'Working...';
      try {
        const res = await fetch('/admin/stripe-setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: setupToken,
            secretKey: document.getElementById('secretKey').value,
            webhookSecret: document.getElementById('webhookSecret').value,
            enableCredits: document.getElementById('enableCredits').checked
          })
        });
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
        btn.textContent = res.ok ? 'Setup Complete (Link Burned)' : 'Retry Setup';
        if (!res.ok) btn.disabled = false;
      } catch (err) {
        out.textContent = 'Error: ' + err.message;
        btn.disabled = false;
        btn.textContent = 'Retry Setup';
      }
    });
  </script>
</body>
</html>`);
});

app.post('/admin/stripe-setup', paidLimiter, async (req, res) => {
  res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  const token = req.body && req.body.token;
  if (!verifyStripeSetupToken(token)) {
    return res.status(403).json({ error: 'Setup token expired or invalid.' });
  }
  try {
    const result = await stripeCheckout.provisionStripeCredits({
      secretKey: req.body && req.body.secretKey,
      webhookSecret: req.body && req.body.webhookSecret,
      enableCredits: req.body ? Boolean(req.body.enableCredits) : true,
      webhookUrl: `${baseUrl(req)}/billing/stripe/webhook`,
    });
    try { fs.unlinkSync(STRIPE_SETUP_TOKEN_FILE); } catch { /* ignore */ }
    return res.status(200).json({
      ok: true,
      message: 'Stripe prepaid credits & webhook configured and live. One-time setup token burned.',
      ...result,
    });
  } catch (error) {
    return res.status(400).json({ ok: false, error: error.message });
  }
});

// ─── Complete Route & Skill Registry (x402 v2 + Bazaar Metadata) ─────────────

const ROUTES = {
  'metadata-audit': {
    id: 'metadata-audit',
    path: '/skills/metadata-audit',
    priceUsd: 0.05,
    description: 'Audit an HTTP/HTTPS URL for metadata leaks: server/framework headers, author/generator meta tags, HTML comments, and third-party trackers.',
    bodySchema: {
      type: 'object',
      required: ['url'],
      properties: { url: { type: 'string', description: 'Public HTTP/HTTPS URL to audit' } },
    },
    inputExample: { url: 'https://example.com' },
    outputExample: { skill: 'metadata-audit', url: 'https://example.com', overallRisk: 'low', findingCounts: { critical: 0, high: 0, medium: 0, low: 1 }, findings: [], recommendation: 'Clean.' },
    run: (b) => MetadataAgent.audit(b.url.trim()),
  },
  'threat-scan': {
    id: 'threat-scan',
    path: '/skills/threat-scan',
    priceUsd: 0.10,
    description: 'Scan public web search results for PII exposure (phone numbers, emails, SSN patterns, physical addresses) linked to a full name.',
    bodySchema: {
      type: 'object',
      required: ['fullName'],
      properties: { fullName: { type: 'string', description: 'Full name to scan (self or authorized target)' } },
    },
    inputExample: { fullName: 'Jane Doe' },
    outputExample: { skill: 'threat-scan', fullName: 'Jane Doe', threatsFound: 1, threats: [{ title: 'Result', link: 'https://example.com', threatLevel: 'high', reasons: ['Phone number'] }] },
    run: async (b) => {
      const threats = await SearchAgent.run({ fullName: b.fullName.trim() });
      return { fullName: b.fullName.trim(), threatsFound: threats.length, threats };
    },
  },
  'breach-check': {
    id: 'breach-check',
    path: '/skills/breach-check',
    priceUsd: 0.10,
    description: 'Keyless email breach intelligence lookup (XposedOrNot + HIBP) and optional k-anonymity SHA-1 password exposure check.',
    bodySchema: {
      type: 'object',
      required: ['email'],
      properties: {
        email: { type: 'string', description: 'Email address to check' },
        password: { type: 'string', description: 'Optional password checked via 5-char SHA-1 k-anonymity range' },
      },
    },
    inputExample: { email: 'test@example.com' },
    outputExample: { skill: 'breach-check', email: 'test@example.com', breachCount: 2, breaches: [], riskLevel: 'medium', recommendation: 'Rotate credentials.' },
    run: (b) => BreachAgent.getBreachReport(b.email.trim(), b.password),
  },
  'opsec-score': {
    id: 'opsec-score',
    path: '/skills/opsec-score',
    priceUsd: 0.25,
    description: 'Multi-vector OPSEC exposure score (0-100, grade A-F) across web search, data brokers, paste sites, and social profiles, with prioritised remediation.',
    bodySchema: {
      type: 'object',
      properties: {
        fullName: { type: 'string', description: 'Full name (provide at least one of fullName, handle, email)' },
        handle: { type: 'string', description: 'Username / handle without @' },
        email: { type: 'string', description: 'Email address' },
      },
    },
    inputExample: { handle: 'satoshi' },
    outputExample: { skill: 'opsec-score', score: 25, grade: 'B', riskLevel: 'low', breakdown: {}, topThreats: [], recommendations: [] },
    run: (b) => OpsecAgent.assess({ fullName: b.fullName, handle: b.handle, email: b.email }),
  },
  'monero-opsec-audit': {
    id: 'monero-opsec-audit',
    path: '/skills/monero-opsec-audit',
    priceUsd: 0.25,
    description: 'Cryptonote Base58 + Keccak-256 Monero ($XMR) address/subaddress decoder (Spend Key, View Key, network byte, checksum), live $XMR RingCT network telemetry, EVM <-> $XMR swap correlation check, and Merkle Mountain Range (MMR) commitment proof.',
    bodySchema: {
      type: 'object',
      properties: {
        xmrAddress: { type: 'string', description: 'Monero Standard (4...), Subaddress (8...), or Integrated address' },
        txHash: { type: 'string', description: 'Optional 64-hex Monero transaction hash' },
        evmAddress: { type: 'string', description: 'Optional 0x EVM address to evaluate cross-chain correlation' },
        swapAmountXmr: { type: 'number', description: 'Optional XMR swap amount' },
        nodeMode: { type: 'string', description: 'local | remote-tor | remote-clearnet' },
      },
    },
    inputExample: { xmrAddress: '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A', nodeMode: 'remote-tor' },
    outputExample: { skill: 'monero-opsec-audit', sovereigntyScore: 85, grade: 'B', riskLevel: 'low', addressAnalysis: { valid: true, type: 'mainnet_standard' }, mmrCommitmentProof: {} },
    run: (b) => MoneroAgent.audit(b),
  },
  'data-removal': {
    id: 'data-removal',
    path: '/skills/data-removal',
    priceUsd: 0.50,
    description: 'Automated data-broker opt-out matcher (24+ brokers) + statutory CCPA § 1798.105 / GDPR Art. 17 / CA Delete Act legal erasure demand generator.',
    bodySchema: {
      type: 'object',
      required: ['link'],
      properties: {
        link: { type: 'string', description: 'URL of the data broker listing to remove' },
        fullName: { type: 'string', description: 'Full name of the data subject (optional)' },
      },
    },
    inputExample: { link: 'https://www.spokeo.com/Jane-Doe', fullName: 'Jane Doe' },
    outputExample: { skill: 'data-removal', broker: 'Spokeo', status: 'submitted', optOutUrl: 'https://www.spokeo.com/optout', estimatedCompletionDays: 3 },
    run: (b) => BrokerAgent.removeThreat({ link: b.link.trim(), fullName: b.fullName ? b.fullName.trim() : undefined }),
  },
  'spam-caller-removal': {
    id: 'spam-caller-removal',
    path: '/skills/spam-caller-removal',
    priceUsd: 0.10,
    description: 'Prepare official caller-ID unlisting and spam-label dispute steps for an authorized phone number across Truecaller, Hiya, RoboKiller, and Whitepages. Does not submit requests.',
    bodySchema: {
      type: 'object',
      required: ['phoneNumber', 'authorized'],
      properties: {
        phoneNumber: { type: 'string', description: 'Authorized phone number in international format, e.g. +15551234567' },
        provider: { type: 'string', enum: ['truecaller', 'hiya', 'robokiller', 'whitepages'], description: 'Optional provider; omit to receive all supported official paths' },
        authorized: { type: 'boolean', description: 'Must be true to confirm authority to request this guidance' },
      },
    },
    inputExample: { phoneNumber: '+15551234567', authorized: true },
    outputExample: { skill: 'spam-caller-removal', status: 'prepared', providers: [{ id: 'truecaller', removalUrl: 'https://www.truecaller.com/unlisting' }] },
    run: (b) => BrokerAgent.prepareCallerIdRemoval({ phoneNumber: b.phoneNumber, provider: b.provider, authorized: b.authorized }),
  },
  'wallet-opsec-audit': {
    id: 'wallet-opsec-audit',
    path: '/skills/wallet-opsec-audit',
    priceUsd: 0.50,
    description: 'On-chain Base/EVM wallet deanonymization & hygiene audit (nonce graph density, balance fingerprint, ERC-8004 identity check, and deterministic $XMR settlement subaddress).',
    bodySchema: {
      type: 'object',
      required: ['walletAddress'],
      properties: {
        walletAddress: { type: 'string', description: '0x EVM wallet address to audit' },
      },
    },
    inputExample: { walletAddress: '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6' },
    outputExample: { skill: 'wallet-opsec-audit', walletAddress: '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6', privacyHygieneScore: 85, grade: 'A', riskLevel: 'low' },
    run: (b) => WalletOpsecAgent.audit(b),
  },
  'full-privacy-sweep': {
    id: 'full-privacy-sweep',
    path: '/skills/full-privacy-sweep',
    priceUsd: 1.00,
    description: 'End-to-end multi-operator privacy sweep: runs Threat Scan, OPSEC Exposure Score, Data Broker Removal dossier generation, and $XMR sovereign subaddress derivation.',
    bodySchema: {
      type: 'object',
      required: ['fullName'],
      properties: {
        fullName: { type: 'string', description: 'Full name of the person to protect' },
        email: { type: 'string', description: 'Optional email address' },
        handle: { type: 'string', description: 'Optional handle/username' },
        walletAddress: { type: 'string', description: 'Optional 0x wallet address' },
      },
    },
    inputExample: { fullName: 'Jane Doe', handle: 'janedoe' },
    outputExample: { skill: 'full-privacy-sweep', threatsFound: 2, removalAttempts: 1, removalResults: [], opsecScore: 30, opsecGrade: 'B' },
    run: async (b) => {
      const op = new PhantomOperator();
      return op.startDataRemovalTask({
        fullName: b.fullName.trim(),
        email: b.email,
        handle: b.handle,
        walletAddress: b.walletAddress,
        flowRate: b.flowRate,
      });
    },
  },
  'cypherpunk-redteam-dossier': {
    id: 'cypherpunk-redteam-dossier',
    path: '/skills/cypherpunk-redteam-dossier',
    priceUsd: 5.00,
    description: 'Comprehensive 6-operator Cypherpunk Red-Team Dossier: Web Metadata Audit + OSINT Threat Scan + Breach Check + OPSEC Score + EVM Wallet Hygiene + $XMR Monero Cryptonote Audit + MMR Cryptographic Attestation.',
    bodySchema: {
      type: 'object',
      properties: {
        fullName: { type: 'string', description: 'Target full name or organization' },
        email: { type: 'string', description: 'Email for breach & OSINT correlation' },
        handle: { type: 'string', description: 'Handle or username' },
        url: { type: 'string', description: 'HTTP/HTTPS URL to audit' },
        walletAddress: { type: 'string', description: '0x EVM wallet address' },
        xmrAddress: { type: 'string', description: '$XMR Monero address/subaddress' },
      },
    },
    inputExample: { fullName: 'Satoshi Nakamoto', email: 'satoshi@gmx.com', url: 'https://example.com', walletAddress: '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6' },
    outputExample: { skill: 'cypherpunk-redteam-dossier', executiveSummary: { compositeSovereigntyScore: 82, grade: 'B' }, modules: {}, mmrAttestation: {} },
    run: async (b) => {
      const [meta, breach, opsec, wallet, monero] = await Promise.all([
        b.url ? MetadataAgent.audit(b.url.trim()).catch((e) => ({ error: e.message })) : Promise.resolve(null),
        b.email ? BreachAgent.getBreachReport(b.email.trim()).catch((e) => ({ error: e.message })) : Promise.resolve(null),
        (b.fullName || b.handle || b.email) ? OpsecAgent.assess({ fullName: b.fullName, handle: b.handle, email: b.email }).catch((e) => ({ error: e.message })) : Promise.resolve(null),
        b.walletAddress ? WalletOpsecAgent.audit({ walletAddress: b.walletAddress }).catch((e) => ({ error: e.message })) : Promise.resolve(null),
        MoneroAgent.audit({ xmrAddress: b.xmrAddress, evmAddress: b.walletAddress, nodeMode: 'remote-tor' }).catch((e) => ({ error: e.message })),
      ]);
      const mmrAttestation = MoneroAgent.buildMmrCommitment([
        JSON.stringify(meta || {}),
        JSON.stringify(breach || {}),
        JSON.stringify(opsec || {}),
        JSON.stringify(wallet || {}),
        JSON.stringify(monero || {}),
      ]);
      return {
        executiveSummary: {
          target: b.fullName || b.handle || b.email || b.url || b.walletAddress || 'Sovereign Principal',
          compositeSovereigntyScore: monero && monero.sovereigntyScore ? monero.sovereigntyScore : 84,
          opsecGrade: (opsec && opsec.grade) || 'A',
          breachRisk: (breach && breach.riskLevel) || 'none',
          metadataRisk: (meta && meta.overallRisk) || 'none',
        },
        modules: { metadataAudit: meta, breachReport: breach, opsecAssessment: opsec, walletOpsec: wallet, moneroOpsec: monero },
        mmrAttestation,
      };
    },
  },
  'sovereign-opsec-retainer': {
    id: 'sovereign-opsec-retainer',
    path: '/skills/sovereign-opsec-retainer',
    priceUsd: 25.00,
    description: 'Full-spectrum Enterprise & DAO Zero-Trace OPSEC Retainer Package: Multi-vector OSINT + Web Metadata + Credential Breach + Treasury EVM Clustering + $XMR Atomic-Swap Treasury Isolation Blueprint + Statutory CCPA/GDPR Takedown Binder.',
    bodySchema: {
      type: 'object',
      properties: {
        organization: { type: 'string', description: 'Organization, DAO, or principal name' },
        fullName: { type: 'string', description: 'Principal full name' },
        email: { type: 'string', description: 'Primary security contact email' },
        url: { type: 'string', description: 'Primary domain URL' },
        walletAddress: { type: 'string', description: 'Primary 0x treasury/operational wallet' },
        xmrAddress: { type: 'string', description: 'Optional $XMR subaddress' },
      },
    },
    inputExample: { organization: 'Phantom DAO', url: 'https://example.com', walletAddress: '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6' },
    outputExample: { skill: 'sovereign-opsec-retainer', retainerId: 'RET-8004-XMR', architectureBlueprint: {}, fullAudit: {} },
    run: async (b) => {
      const targetName = b.organization || b.fullName || 'Sovereign Organization';
      const dossier = await ROUTES['cypherpunk-redteam-dossier'].run({
        fullName: targetName,
        email: b.email,
        url: b.url,
        walletAddress: b.walletAddress,
        xmrAddress: b.xmrAddress,
      });
      const subaddress = MoneroAgent.deriveDeterministicSubaddress(`retainer:${targetName}`);
      return {
        retainerId: 'RET-' + dossier.mmrAttestation.root.slice(2, 14).toUpperCase(),
        issuedAt: new Date().toISOString(),
        principal: targetName,
        architectureBlueprint: {
          treasuryIsolation: 'EVM (Base USDC x402 ingress) -> Atomic Swap -> $XMR RingCT Subaddress (8...) -> Cold Multisig',
          dedicatedMoneroSubaddress: subaddress,
          ringSignatureDecoys: 16,
          networkTransport: 'Local monerod + Tor Hidden Service (.onion) + Dandelion++ stem phase',
        },
        fullAudit: dossier,
      };
    },
  },
};

// ─── Interactive Cyberpunk Landing Page (`GET /` for browsers & `GET /app`) ───

function renderLandingHtml(base) {
  const payTo = x402.PAY_TO;
  const skillsRows = Object.values(ROUTES).map((r) => `
    <tr><td><code>POST ${r.path}</code></td><td><span class="badge">$${r.priceUsd.toFixed(2)} USDC</span></td><td>${r.description}</td><td><button class="btn-sm" onclick='selectSkill(${JSON.stringify(r.id)}, ${JSON.stringify(r.inputExample)}, ${r.priceUsd})'>Load in Console</button></td></tr>
  `).join('');
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhantomOperator — Free Website Privacy Preview & $19 Baseline</title>
<meta name="description" content="Check what your public website reveals. Run a free metadata preview or buy a $19 Website Privacy Baseline with an evidence-based remediation checklist. Authorized targets only.">
<link rel="canonical" href="${base}/">
<meta property="og:type" content="website">
<meta property="og:site_name" content="PhantomOperator">
<meta property="og:title" content="PhantomOperator — Free Website Privacy Preview">
<meta property="og:description" content="See public headers, metadata, HTML comments, and tracker signals. Free preview first; $19 fixed-scope Website Privacy Baseline available.">
<meta property="og:url" content="${base}/">
<meta property="og:image" content="${base}/phantomoperator-share-card.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:site" content="@phntmop">
<meta name="twitter:title" content="PhantomOperator — Free Website Privacy Preview">
<meta name="twitter:description" content="Authorized public website privacy checks for people and agents.">
<meta name="twitter:image" content="${base}/phantomoperator-share-card.png">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"PhantomOperator","applicationCategory":"SecurityApplication","operatingSystem":"Web","url":"${base}/","description":"Authorized public website privacy and metadata checks with a free preview and a fixed-scope Website Privacy Baseline.","offers":{"@type":"Offer","price":"19.00","priceCurrency":"USD","description":"Website Privacy Baseline"}}</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Arimo:ital,wght@0,700;1,700&display=swap" rel="stylesheet">
<style>
:root{--ink:#ecdc8f;--shade:#0d0a16;--cyan:#00f5d4;--orange:#ff6600;--text:#e2e8f0;--muted:#94a3b8;--panel:#0e131f;--border:#1e293b;--noise:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='240' height='240'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 15% 15%,#16213a 0%,#07090e 55%);color:var(--text);font-family:'JetBrains Mono',ui-monospace,monospace;line-height:1.55}.wrap{max-width:1180px;margin:0 auto;padding:22px 20px 64px}header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:20px}.brand{display:flex;align-items:center;gap:14px}.brand img{width:56px;height:56px;border-radius:12px;border:1px solid var(--cyan)}h1{margin:0;color:var(--cyan);font-size:1.55rem}.sub{color:var(--muted);font-size:.88rem;margin-top:4px}.pill-row{display:flex;gap:8px;flex-wrap:wrap}.pill,.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-size:.76rem;font-weight:700;background:rgba(0,245,212,.08);border:1px solid rgba(0,245,212,.35);color:var(--cyan)}.badge{background:rgba(255,102,0,.16);border:0;color:var(--orange)}.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:20px;margin-bottom:24px}@media(max-width:900px){.grid{grid-template-columns:1fr}}.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.35);margin-bottom:20px}.card h2{margin-top:0;font-size:1.05rem;color:var(--cyan);display:flex;align-items:center;justify-content:space-between;gap:8px}table{width:100%;border-collapse:collapse;font-size:.84rem}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);vertical-align:top}th{color:var(--muted)}.btn,.btn-sm{background:linear-gradient(135deg,var(--cyan),#00bbf9);color:#041019;border:0;border-radius:7px;padding:10px 16px;font-family:inherit;font-weight:700;cursor:pointer;font-size:.84rem}.btn-sm{padding:5px 10px;font-size:.75rem}.btn-xmr{background:linear-gradient(135deg,var(--orange),#ff9e00);color:#09090b}textarea,input,select{width:100%;background:#060a12;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:10px;font-family:inherit;font-size:.84rem;margin-bottom:10px}pre{background:#05080f;border:1px solid var(--border);border-radius:8px;padding:12px;overflow-x:auto;font-size:.8rem;max-height:360px;color:#a7f3d0}a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}.addr-box,.preview-result{background:#060a12;border:1px solid rgba(0,245,212,.3);border-radius:8px;padding:12px;margin:10px 0;font-size:.8rem;word-break:break-word}.preview-result h3{color:var(--cyan);font-size:.92rem;margin:0 0 8px}.finding{border-top:1px solid var(--border);padding:8px 0;font-size:.82rem}.risk{display:inline-block;border-radius:5px;padding:1px 6px;background:rgba(255,102,0,.16);color:var(--orange);font-weight:700;margin-right:7px}
/* 1990s CRT / VHS commercial */.commercial{margin:0 auto 26px;max-width:900px}.screen{position:relative;width:min(100%,760px);aspect-ratio:4/3;margin:auto;overflow:hidden;clip-path:url(#tube);background:#000;box-shadow:0 0 0 3px #111,0 0 40px rgba(0,245,212,.2)}.screen:before,.screen:after{content:"";position:absolute;inset:0;z-index:7;pointer-events:none}.screen:before{background:radial-gradient(ellipse 50% 32% at 30% 16%,rgb(255 255 255/.1),transparent),radial-gradient(ellipse at center,transparent 55%,rgb(0 0 0/.68))}.screen:after{background:repeating-linear-gradient(rgb(0 0 0/.2) 0 .25%,transparent .25% .52%)}.tv{position:absolute;width:400px;height:300px;overflow:hidden;transform-origin:0 0;font-family:Arimo,Arial,sans-serif;font-weight:700;color:var(--ink);cursor:pointer}.picture{position:absolute;inset:0;filter:url(#vhs) saturate(1.35) contrast(.92) brightness(1.06);animation:jitter 3.3s steps(1) infinite}.tv p,.tv li{text-shadow:.06em .07em 0 var(--shade)}.offer,.order{position:absolute;inset:0}.offer{z-index:2;background:radial-gradient(ellipse 70% 62% at 50% 38%,#275368,#063c71 42%,#042452 72%,#010d29)}.order{display:none;text-align:center;background:linear-gradient(#0b5371,#073e6e 60%,#021e53)}.kicker{position:absolute;top:14px;left:24px;z-index:3;font-size:14px;text-transform:uppercase}.kicker span{display:none}[data-phase=offer] .k-offer,[data-phase=wait] .k-offer,[data-phase=more] .k-more,[data-phase=wait2] .k-more,[data-phase=double] .k-double{display:block}.price{position:absolute;top:186px;width:100%;z-index:3;text-align:center;font-size:30px}.row{position:absolute;top:176px;left:200px;z-index:2}.po-card{position:absolute;bottom:20px;width:58px;height:76px;translate:-50% 0;transform-origin:50% calc(100% + 20px);rotate:calc(var(--from-middle)*min(24deg,150deg/max(var(--count),1)));z-index:var(--z);border:1px solid #6affbc;border-radius:7px;background:linear-gradient(145deg,#061c1b,#13393a);box-shadow:0 0 9px #00f5d4;transition:rotate .7s cubic-bezier(.25,1.35,.4,1);animation:deal .5s calc(abs(var(--from-middle))*120ms) both;text-align:center;overflow:hidden}.po-card img{width:38px;height:38px;object-fit:contain;margin-top:4px;filter:drop-shadow(0 0 4px #00f5d4)}.po-card span{display:block;font-size:7px;line-height:1;padding:1px 2px;color:#d8ffe8;text-transform:uppercase}.each{position:absolute;top:50px;translate:-50% 0;white-space:nowrap;font-size:14px}.each b{display:inline-block;margin:0 .1em}.burst{position:absolute;top:28px;left:264px;z-index:5;display:none;place-items:center;width:108px;aspect-ratio:1;rotate:-12deg;font-size:21px;font-style:italic;line-height:.95;text-align:center;text-transform:uppercase}.burst:before{content:"";position:absolute;inset:0;z-index:-1;background:radial-gradient(#ff3b22,#d8150f 70%);clip-path:polygon(50% 0%,58% 15%,72% 5%,72% 22%,89% 19%,82% 34%,99% 39%,86% 50%,99% 61%,82% 66%,89% 81%,72% 78%,72% 95%,58% 85%,50% 100%,42% 85%,28% 95%,28% 78%,11% 81%,18% 66%,1% 61%,14% 50%,1% 39%,18% 34%,11% 19%,28% 22%,28% 5%,42% 15%)}[data-phase=wait] .burst,[data-phase=wait2] .burst{display:grid;animation:burst .45s cubic-bezier(.3,1.6,.5,1),throb .5s .45s ease-in-out infinite alternate}.call{position:absolute;bottom:14px;width:100%;z-index:5;padding:4px 0 5px;text-align:center;text-transform:uppercase;font-size:11px;background:linear-gradient(90deg,transparent,rgb(0 0 0/.55) 18% 82%,transparent)}.call b{margin-left:.4em;font-size:1.25em}.call a{color:#fff36e}.box{position:absolute;top:28px;left:40px;display:none;width:88px;aspect-ratio:1;border:2px solid #efeee6;background:#071c25 url('/logo.png') center/70px no-repeat;box-shadow:inset 0 0 20px #00f5d4}.pay{position:absolute;top:30px;left:135px;right:10px;display:flex;gap:3px;justify-content:space-between;list-style:none;font-size:5.5px;text-transform:uppercase}.pay li{padding:2px 3px;border:1px solid;border-radius:2px;background:rgb(0 0 0/.3)}.order p{position:absolute;width:100%}.order .delivery,.order .send{left:136px;width:auto;right:10px}.delivery{top:52px;font-size:12px;line-height:1.15;text-transform:uppercase}.send{top:85px;font-size:9px;line-height:1.3}.name{top:122px;font-size:19px;text-transform:uppercase}.address{top:146px;font-size:11px;line-height:1.22}.phone{top:182px;font-size:29px;letter-spacing:-.02em}.stores{top:219px;font-size:11px}.fine{top:238px;font-size:6.4px;line-height:1.4}.fine a{color:inherit}.order a{color:#fff36e}[data-phase=order] .offer{background:none}[data-phase=order] .offer>:not(.row,.box),[data-phase=order] .each{display:none}[data-phase=order] .box,[data-phase=order] .order{display:block}[data-phase=order] .row{top:106px;left:84px;scale:.3}.grain,.chroma,.drop,.track,.head{position:absolute;inset:0;z-index:6;pointer-events:none}.grain{background:var(--noise) 0 0/220px;opacity:.26;mix-blend-mode:hard-light;animation:grain .48s steps(6) infinite}.chroma{background:var(--noise) 0 0/680px 200px;opacity:.18;mix-blend-mode:hard-light;animation:grain .4s steps(5) infinite reverse}.drop{background:linear-gradient(90deg,transparent,#fff 30% 70%,transparent) 0 0/36px 1.4px no-repeat;mix-blend-mode:screen;animation:drop 1.7s steps(1) infinite}.track{bottom:auto;height:12px;background:linear-gradient(transparent,rgb(255 255 255/.55) 35%,rgb(0 245 212/.45) 55%,transparent),var(--noise) 0 0/56px;mix-blend-mode:screen;opacity:0;animation:track 8.4s linear infinite}.head{top:auto;height:6px;background:linear-gradient(transparent,rgb(255 255 255/.2) 40%,rgb(0 0 0/.5)),var(--noise) 0 0/48px;mix-blend-mode:screen;animation:head .24s steps(3) infinite}.tv-controls{display:flex;justify-content:center;flex-wrap:wrap;gap:8px;padding:14px 4px}.tv-controls button,.tv-controls a{font:700 .76rem 'JetBrains Mono',monospace;border-radius:6px;padding:8px 10px;border:1px solid #34505e;background:#101a25;color:#c9fef6;cursor:pointer}.tv-controls a{color:#fff36e;border-color:#8b7330}.tv-caption{text-align:center;color:var(--muted);font-size:.8rem;margin-top:-6px}@keyframes deal{from{scale:.15;opacity:0}55%{scale:1.08;opacity:1}}@keyframes burst{from{scale:0;rotate:-60deg}}@keyframes throb{to{scale:1.06}}@keyframes grain{to{background-position:560px 360px}}@keyframes drop{0%{background-position:48px 36px}15%,50%,83%{background-position:-80px 0}42%{background-position:332px 48px}77%{background-position:324px 176px}}@keyframes track{0%,84%{translate:0 304px;opacity:0}85%,97%{opacity:.9}100%{translate:0 -16px;opacity:0}}@keyframes head{to{background-position:0 0,160px 12px}}@keyframes jitter{12%{translate:0 1px}13%,30%{translate:0 0}31%{translate:.5px 0}33%,71%{translate:0 0}72%{translate:-.4px .2px}73%{translate:0 0}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body><div class="wrap">
<header><div class="brand"><img src="/logo.png" alt="PhantomOperator logo"><div><h1>PhantomOperator</h1><div class="sub">Practical privacy, public-exposure, metadata, and wallet-hygiene checks for authorized users and agents.</div></div></div><div class="pill-row"><span class="pill">x402 Base USDC</span><span class="pill">MCP + A2A</span><a class="pill" href="https://x.com/phntmop" target="_blank" rel="noopener noreferrer">𝕏 @phntmop</a></div></header>
<section class="commercial" aria-label="PhantomOperator 1990s TV commercial"><div class="screen" id="tvScreen"><main class="tv" data-phase="offer" aria-label="PhantomOperator commercial"><div class="picture"><section class="offer"><p class="kicker"><span class="k-offer">3-Vector Website Privacy Audit</span><span class="k-more">Plus 4 Breach &amp; Wallet Scans!</span><span class="k-double">Act Now: All 11 x402 + MCP Privacy Skills!</span></p><p class="price">Baseline Only $19.00</p><div class="box"></div><div class="row"><p class="each">That's just <b id="vectorPrice">$6.33</b> a privacy check!</p></div><p class="burst">But<br>Wait!</p><p class="call">Scan Free or Order Now <b>FREYSAAI.FREYSA.DEV</b> · <a href="https://x.com/phntmop" target="_blank" rel="noopener noreferrer">𝕏 @PHNTMOP</a></p></section><section class="order"><ul class="pay"><li>Stripe Card</li><li>Base USDC x402</li><li>Elysium USDC</li><li>MCP + A2A</li></ul><p class="delivery">Instant Automated<br>Delivery On-Screen</p><p class="send">Get The $19.00 Website Privacy Baseline<br>Or $0.05–$25 USDC Per x402 API Call:</p><p class="name">PhantomOperator</p><p class="address">ERC-8004 Agent #821239 · Base Mainnet<br>freysaai.freysa.dev · 𝕏 @phntmop</p><p class="phone">PHNTM-OP</p><p class="stores">Free Website Metadata Preview Below</p><p class="fine">Authorized Targets Only · Evidence-Based Public Exposure Signals<br>PhantomOperator Privacy &amp; OPSEC Suite · <a href="https://x.com/phntmop" target="_blank" rel="noopener noreferrer">Follow @phntmop on X</a></p></section></div><div class="grain"></div><div class="chroma"></div><div class="drop"></div><div class="track"></div><div class="head"></div></main></div><div class="tv-controls"><button id="soundOn" type="button" aria-pressed="true">Sound: On</button><button id="soundOff" type="button" aria-pressed="false">Silent</button><button type="button" onclick="jumpToPreview()">🔍 Free Preview</button><button type="button" onclick="document.getElementById('baselineOfferCard').scrollIntoView({behavior:'smooth'})">💳 Order $19 Baseline</button><button type="button" onclick="showTvPhase('order')">⏭ Order Screen</button><a href="https://x.com/phntmop" target="_blank" rel="noopener noreferrer">𝕏 @PHNTMOP</a></div><p class="tv-caption">PhantomOperator public-exposure checks for authorized targets.</p></section>
<div class="card" id="freePreviewCard" style="border-color:rgba(0,245,212,.55)"><h2><span>Check what your website publicly reveals</span></h2><p class="sub">Paste a website URL for a free limited privacy preview. It checks public headers, metadata, HTML comments, and tracker signals.</p><div style="display:flex;gap:10px;flex-wrap:wrap"><input id="quickUrl" inputmode="url" autocomplete="url" placeholder="https://your-site.example" style="flex:1;min-width:240px;margin:0"><button class="btn" onclick="runQuickPreview()">Run free preview</button><a class="btn-sm" style="background:#1e293b;color:#e2e8f0;padding:10px 16px" href="/sample-report">View sample report</a></div><p class="sub">Free preview: up to 5 per client per hour. Complete human report: <strong>$19 Website Privacy Baseline</strong>; agent/API preview: $0.05 USDC Base x402.</p></div>
<div class="card" id="baselineOfferCard" style="border-color:rgba(255,102,0,.55)"><h2><span>Website Privacy Baseline — Fixed-Scope Human Audit</span><span class="badge">$19.00 Card / Link</span></h2><p class="sub">One-time Stripe checkout for one public website you own or are authorized to assess. Includes HTTP/security headers, server fingerprinting, metadata leaks, HTML comments, tracker disclosure, and a prioritized remediation checklist.</p><div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center"><input id="baselineUrl" inputmode="url" autocomplete="url" placeholder="https://your-site.example" style="flex:1;min-width:240px;margin:0"><button class="btn btn-xmr" id="baselineCheckoutBtn" onclick="startBaselineStripeCheckout()">Buy $19 Website Privacy Baseline</button></div><label style="display:flex;gap:8px;align-items:center;font-size:.82rem;cursor:pointer;margin:10px 0"><input type="checkbox" id="baselineAuthorized" style="width:auto;margin:0">I confirm I own or am authorized to assess this public website.</label><details><summary style="cursor:pointer;color:var(--cyan)">Already have a prepaid credit token? Run or top up credits</summary><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px"><input id="existingCreditToken" type="password" autocomplete="off" placeholder="po_credit_..." style="flex:1;min-width:220px;margin:0"><button class="btn-sm" onclick="runBaselineWithExistingToken()">Run Baseline with Token</button></div></details><div id="baselineStatusBox" class="addr-box" hidden aria-live="polite"></div><div id="baselineReportBox" class="preview-result" hidden aria-live="polite"></div></div>
<div class="grid"><div class="card"><h2><span>Choose a privacy check</span><span style="color:var(--orange)">Pay only after review</span></h2><label>Select Skill Endpoint</label><select id="skillSelect" onchange="onSkillDropdown()">${Object.values(ROUTES).map((r)=>`<option value="${r.id}">${r.id} — $${r.priceUsd.toFixed(2)} USDC (${r.path})</option>`).join('')}</select><label>JSON Request Payload</label><textarea id="payloadBox" rows="5">{"url":"https://example.com"}</textarea><div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px"><button class="btn" onclick="invokeSkill()">View payment terms</button><button class="btn-sm" style="background:#1e293b;color:#e2e8f0" onclick="runFreeMetadataPreview()">Try free metadata preview</button><button class="btn-sm" style="background:#1e293b;color:#e2e8f0" onclick="runFreeMoneroDemo()">View a free sample report</button></div><div id="previewHumanResult" class="preview-result" hidden aria-live="polite"></div><div id="previewUpgrade" class="addr-box" hidden><strong style="color:var(--cyan)">Free preview complete.</strong> Upgrade to unlock every finding and prioritized remediation steps.<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:9px"><button class="btn-sm btn-xmr" onclick="prefillBaselineFromPreview()">Get $19 Website Privacy Baseline</button><button class="btn-sm" onclick="upgradePreviewToFullAudit()">Agent/API: $0.05 USDC Base x402</button></div></div><p class="sub">Only submit targets you are authorized to assess. Do not submit passwords, seed phrases, private keys, or another person's data without permission. <a href="/privacy">Privacy model</a> · <a href="/terms">terms</a>.</p><pre id="consoleOut">// Select a check, inspect exact terms, or run a free preview.</pre></div><div class="card"><h2><span>For agent builders</span><span>ERC-8004 #821239</span></h2><p class="sub">Use standard discovery documents or MCP. Paid calls use USDC on Base via x402; each request returns payment terms first.</p><ul style="font-size:.84rem;padding-left:18px"><li><a href="/.well-known/x402">/.well-known/x402</a> — payment requirements</li><li><a href="/.well-known/agent-card.json">Agent Card</a> — A2A</li><li><a href="/openapi.json">OpenAPI 3.1</a></li><li><a href="/mcp">/mcp</a> — MCP JSON-RPC</li><li><a href="/skills">/skills</a> — skill manifest</li><li><a href="https://x.com/phntmop" target="_blank" rel="noopener noreferrer">@phntmop on X</a></li></ul><div class="addr-box" style="border-color:rgba(255,102,0,.4)"><strong style="color:var(--orange)">Scope</strong><br>Public-source signals may be incomplete or stale. Data-broker workflows prepare guidance; they do not guarantee removal.</div></div></div>
<div class="card"><h2><span>Complete x402 Skill Catalog (USDC on Base)</span><span>${Object.values(ROUTES).length} Active Skills</span></h2><table><thead><tr><th>Endpoint</th><th>Price</th><th>Capabilities</th><th>Action</th></tr></thead><tbody>${skillsRows}</tbody></table></div></div>
<svg width="0" height="0" aria-hidden="true"><clipPath id="tube" clipPathUnits="objectBoundingBox"><path d="M.075 .026Q.5 -.016 .925 .026Q.968 .03 .972 .085Q1.018 .5 .972 .915Q.968 .97 .925 .974Q.5 1.016 .075 .974Q.032 .97 .028 .915Q-.018 .5 .028 .085Q.032 .03 .075 .026Z"/></clipPath><filter id="vhs" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB"><feImage id="bulge" x="0" y="0" width="400" height="300" preserveAspectRatio="none"/><feDisplacementMap in="SourceGraphic" scale="40" xChannelSelector="R" yChannelSelector="G" result="curved"/><feTurbulence type="fractalNoise" baseFrequency="0 .32" seed="1" result="jitter"><animate attributeName="seed" values="1;2;3;4;5;6;7;8;9;10;11;12" dur=".96s" calcMode="discrete" repeatCount="indefinite"/></feTurbulence><feDisplacementMap in="curved" in2="jitter" scale="5" xChannelSelector="R" yChannelSelector="G" result="soft"/><feGaussianBlur in="soft" stdDeviation=".55 .1"/></filter></svg>
<script>
const EXAMPLES=${JSON.stringify(Object.fromEntries(Object.values(ROUTES).map(r=>[r.id,{example:r.inputExample,price:r.priceUsd}])))};
const tv=document.querySelector('.tv'),row=document.querySelector('.row'),each=document.querySelector('.each'),screen=document.getElementById('tvScreen');
function fitTv(){const r=screen.getBoundingClientRect();tv.style.transform='scale('+(r.width/400)+')'}new ResizeObserver(fitTv).observe(screen);fitTv();
function bulge(){const c=document.createElement('canvas');c.width=40;c.height=30;const x=c.getContext('2d'),m=x.createImageData(40,30);for(let y=0;y<30;y++)for(let q=0;q<40;q++){const u=q/39*2-1,v=y/29*2-1,i=(y*40+q)*4;m.data[i]=128+u*v*v*80;m.data[i+1]=128+v*u*u*80;m.data[i+3]=255}x.putImageData(m,0,0);document.getElementById('bulge').setAttribute('href',c.toDataURL())}
const labels=['HEADERS','METADATA','TRACKERS','BREACH','THREATS','OPSEC','WALLET','MONERO','BROKERS','CALLERS','DOSSIER'];
function add(count){const before=row.querySelectorAll('.po-card').length;for(let i=0;i<count;i++){const n=before+i,e=document.createElement('div');e.className='po-card';e.style.setProperty('--z',n+1);e.innerHTML='<img src="/logo.png" alt=""><span>'+labels[n%labels.length]+'</span>';row.append(e);setTimeout(()=>TvAudio.deal(),i*120)}}
function arrange(){const cards=[...row.querySelectorAll('.po-card')],n=cards.length;cards.forEach((e,i)=>e.style.setProperty('--from-middle',i-(n-1)/2));cards.forEach(e=>e.style.setProperty('--count',Math.max(n-1,1)));const cost=(19/n).toFixed(2);document.getElementById('vectorPrice').textContent='$'+cost}
function showTvPhase(phase){tv.dataset.phase=phase;if(phase==='wait'||phase==='wait2')TvAudio.sting();if(phase==='more'||phase==='double')TvAudio.tally();if(phase==='order')TvAudio.order();}
let timer=[];function playTv(){timer.forEach(clearTimeout);row.querySelectorAll('.po-card').forEach(x=>x.remove());add(3);arrange();showTvPhase('offer');timer=[setTimeout(()=>showTvPhase('wait'),3400),setTimeout(()=>{showTvPhase('more');add(4);arrange()},4700),setTimeout(()=>showTvPhase('wait2'),8800),setTimeout(()=>{showTvPhase('double');add(4);arrange()},10100),setTimeout(()=>showTvPhase('order'),14600),setTimeout(playTv,22000)]}bulge();playTv();
const TvAudio=(()=>{let c,on=false,hum;function ctx(){if(!c)c=new(window.AudioContext||window.webkitAudioContext)();return c}function osc(f,t,d,g=.06,type='sine'){if(!on)return;const a=ctx(),o=a.createOscillator(),v=a.createGain();o.type=type;o.frequency.setValueAtTime(f,a.currentTime);v.gain.setValueAtTime(g,a.currentTime);v.gain.exponentialRampToValueAtTime(.001,a.currentTime+d);o.connect(v).connect(a.destination);o.start();o.stop(a.currentTime+d)}function noise(d=.08,g=.04){if(!on)return;const a=ctx(),b=a.createBuffer(1,a.sampleRate*d,a.sampleRate),s=b.getChannelData(0);for(let i=0;i<s.length;i++)s[i]=Math.random()*2-1;const n=a.createBufferSource(),v=a.createGain(),f=a.createBiquadFilter();f.type='bandpass';f.frequency.value=1100;v.gain.value=g;n.buffer=b;n.connect(f).connect(v).connect(a.destination);n.start()}return{start(){if(on)return true;on=true;const a=ctx();a.resume();osc(70,.25,.14,'sine');noise(.18,.09);hum=a.createOscillator();const g=a.createGain();hum.frequency.value=60;g.gain.value=.012;hum.connect(g).connect(a.destination);hum.start();return true},stop(){on=false;if(hum){hum.stop();hum=null}return false},deal(){noise(.06,.035);osc(260,.07,.035,'square')},sting(){noise(.13,.08);osc(165,.32,.1,'sawtooth');osc(246,.33,.075,'sawtooth')},tally(){[660,880,1100].forEach((f,i)=>setTimeout(()=>osc(f,.1,.06,'square'),i*75))},order(){[523,659,784,1047].forEach((f,i)=>setTimeout(()=>osc(f,.25,.06,'sine'),i*90));noise(.09,.04)}}})();
const soundOn=document.getElementById('soundOn'),soundOff=document.getElementById('soundOff');function setSound(enabled){if(enabled)TvAudio.start();else TvAudio.stop();soundOn.setAttribute('aria-pressed',String(enabled));soundOff.setAttribute('aria-pressed',String(!enabled));soundOn.style.opacity=enabled?'1':'.55';soundOff.style.opacity=enabled?'.55':'1'}soundOn.onclick=()=>setSound(true);soundOff.onclick=()=>setSound(false);setSound(true);document.addEventListener('pointerdown',()=>{if(soundOn.getAttribute('aria-pressed')==='true')TvAudio.start()},{once:true});function jumpToPreview(){document.getElementById('freePreviewCard').scrollIntoView({behavior:'smooth'})}
function runQuickPreview(){const url=document.getElementById('quickUrl').value.trim();if(!url){document.getElementById('consoleOut').textContent='Enter a public HTTPS URL first.';return}document.getElementById('baselineUrl').value=url;selectSkill('metadata-audit',{url},.05);runFreeMetadataPreview()}
function selectSkill(id,example){document.getElementById('skillSelect').value=id;document.getElementById('payloadBox').value=JSON.stringify(example,null,2)}function onSkillDropdown(){const id=document.getElementById('skillSelect').value;if(EXAMPLES[id])document.getElementById('payloadBox').value=JSON.stringify(EXAMPLES[id].example,null,2)}
async function invokeSkill(){const id=document.getElementById('skillSelect').value,out=document.getElementById('consoleOut');out.textContent='Requesting x402 payment terms…';try{const r=await fetch('/skills/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:document.getElementById('payloadBox').value});out.textContent='HTTP '+r.status+'\\n'+JSON.stringify(await r.json(),null,2)}catch(e){out.textContent='Error: '+e.message}}
function renderPreviewSummary(d){const b=document.getElementById('previewHumanResult');if(!d||!d.preview){b.hidden=true;return}b.replaceChildren();const h=document.createElement('h3');h.textContent='Free preview for '+d.url;const p=document.createElement('p');p.className='sub';p.textContent='Exposure signal: '+String(d.overallRisk||'unknown').toUpperCase()+'. Showing '+d.findings.length+' limited finding(s).';b.append(h,p);for(const f of d.findings){const r=document.createElement('div');r.className='finding';r.textContent=String(f.riskLevel||'review').toUpperCase()+' — '+(f.label||f.category||'Public exposure signal');b.append(r)}b.hidden=false}
async function runFreeMetadataPreview(){const out=document.getElementById('consoleOut');let p;try{p=JSON.parse(document.getElementById('payloadBox').value)}catch{out.textContent='Enter valid JSON with a public URL first.';return}if(!p.url){out.textContent='Enter a public URL first.';return}out.textContent='Running free metadata preview…';try{const r=await fetch('/preview/metadata-audit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:p.url})}),d=await r.json();out.textContent='HTTP '+r.status+' (Free Preview)\\n'+JSON.stringify(d,null,2);renderPreviewSummary(r.ok?d:null);document.getElementById('previewUpgrade').hidden=!r.ok}catch(e){out.textContent='Error: '+e.message;document.getElementById('previewUpgrade').hidden=true}}
function upgradePreviewToFullAudit(){let p;try{p=JSON.parse(document.getElementById('payloadBox').value)}catch{return}if(p.url){selectSkill('metadata-audit',{url:p.url});invokeSkill()}}function prefillBaselineFromPreview(){const u=document.getElementById('quickUrl').value.trim()||(()=>{try{return JSON.parse(document.getElementById('payloadBox').value).url||''}catch{return''}})();if(u)document.getElementById('baselineUrl').value=u;document.getElementById('baselineOfferCard').scrollIntoView({behavior:'smooth'})}
function setBaselineStatus(m,e){const b=document.getElementById('baselineStatusBox');b.hidden=false;b.style.borderColor=e?'rgba(255,102,0,.6)':'rgba(0,245,212,.4)';b.textContent=m}function renderBaselineReport(r){const b=document.getElementById('baselineReportBox');b.replaceChildren();const h=document.createElement('h3');h.textContent='Website Privacy Baseline Report — '+r.targetUrl;const p=document.createElement('p');p.className='sub';p.textContent='Overall exposure risk: '+String(r.overallRisk||'unknown').toUpperCase()+' | HTTP '+r.statusCode+' | '+r.assessedAt;b.append(h,p);for(const i of r.prioritizedRemediationChecklist||[]){const x=document.createElement('div');x.className='finding';x.textContent='#'+i.priority+' '+String(i.riskLevel||'review').toUpperCase()+' — '+i.finding+' Fix: '+(i.action||'Review and minimize exposure.');b.append(x)}const d=document.createElement('button');d.className='btn-sm';d.textContent='Download Full Report JSON';d.onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(r,null,2)],{type:'application/json'}));a.download='phantomoperator-website-privacy-baseline.json';a.click()};b.append(d);b.hidden=false;setBaselineStatus('Baseline report complete. Paid credit receipt redeemed.',false)}
async function executeBaselineWithToken(t,u){setBaselineStatus('Running your $19 Website Privacy Baseline…',false);const r=await fetch('/credits/offers/website-privacy-baseline',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({url:u,authorized:true})}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.message||d.error||'Baseline execution failed');try{localStorage.removeItem('po_pending_baseline')}catch{}renderBaselineReport(d)}
async function startBaselineStripeCheckout(){const u=document.getElementById('baselineUrl').value.trim()||document.getElementById('quickUrl').value.trim(),a=document.getElementById('baselineAuthorized').checked;if(!u){setBaselineStatus('Enter the public website URL first.',true);return}if(!a){setBaselineStatus('Confirm authorization first.',true);return}const b=document.getElementById('baselineCheckoutBtn');b.disabled=true;setBaselineStatus('Creating secure $19 Stripe Checkout…',false);try{const r=await fetch('/billing/stripe/website-privacy-baseline-checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,authorized:true})}),d=await r.json().catch(()=>({}));if(!r.ok||!d.checkoutUrl)throw Error(d.message||d.error||'Could not start Checkout.');localStorage.setItem('po_pending_baseline',JSON.stringify({creditToken:d.creditToken,targetUrl:d.targetUrl,createdAt:Date.now()}));localStorage.setItem('po_credit_token',d.creditToken);window.location.assign(d.checkoutUrl)}catch(e){b.disabled=false;setBaselineStatus('Error: '+e.message,true)}}
async function runBaselineWithExistingToken(){const t=document.getElementById('existingCreditToken').value.trim(),u=document.getElementById('baselineUrl').value.trim()||document.getElementById('quickUrl').value.trim();if(!t||!u||!document.getElementById('baselineAuthorized').checked){setBaselineStatus('Enter a token, target URL, and authorization confirmation.',true);return}try{await executeBaselineWithToken(t,u)}catch(e){setBaselineStatus('Error: '+e.message,true)}}
(async()=>{const q=new URLSearchParams(location.search),s=q.get('baseline');let p;try{p=JSON.parse(localStorage.getItem('po_pending_baseline')||'null')}catch{}if(p?.targetUrl){document.getElementById('baselineUrl').value=p.targetUrl;document.getElementById('baselineAuthorized').checked=true;document.getElementById('existingCreditToken').value=p.creditToken||''}if(s==='cancelled'){setBaselineStatus('Stripe Checkout was cancelled. No charge was made.',true);return}if(s==='success'&&p?.creditToken&&p?.targetUrl){setBaselineStatus('Payment received. Waiting for Stripe webhook confirmation…',false);for(let i=0;i<15;i++){try{const r=await fetch('/billing/credits/balance',{headers:{Authorization:'Bearer '+p.creditToken}});if(r.ok&&(await r.json()).balanceCents>=1900){await executeBaselineWithToken(p.creditToken,p.targetUrl);return}}catch{}await new Promise(r=>setTimeout(r,1500))}setBaselineStatus('Payment still confirming. Your receipt token is pre-filled below; try again shortly.',false)}})();
async function runFreeMoneroDemo(){const o=document.getElementById('consoleOut');o.textContent='Loading a free sample privacy report…';try{const r=await fetch('/demo/monero-decode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({xmrAddress:'44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A'})});o.textContent='HTTP '+r.status+' (Free Live Preview)\\n'+JSON.stringify(await r.json(),null,2)}catch(e){o.textContent='Error: '+e.message}}
</script></body></html>`;
}

// ─── Public Discovery & Health Endpoints ─────────────────────────────────────

app.get('/', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  const accept = String(req.headers.accept || '');
  if (accept.includes('text/html') && !accept.includes('application/json') && req.query.format !== 'json') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(renderLandingHtml(b));
  }
  res.json({
    name: manifest.name,
    version: manifest.version,
    description: manifest.description,
    agentWallet: x402.PAY_TO,
    payment: {
      protocol: 'x402',
      x402Version: 2,
      network: x402.NETWORK,
      asset: x402.USDC_BASE,
      token: 'USDC',
      payTo: x402.PAY_TO,
      facilitator: x402.FACILITATOR,
      secondaryRails: [
        {
          paymentMethod: 'elysium-usdc',
          network: ELYSIUM_NETWORK,
          chainId: ELYSIUM_CHAIN_ID,
          asset: ELYSIUM_USDC,
          token: 'USDC',
          decimals: ELYSIUM_USDC_DECIMALS,
          payTo: x402.PAY_TO,
          quoteEndpoint: `${b}/billing/elysium-usdc/quote`,
        },
      ],
    },
    skills: Object.values(ROUTES).map((r) => ({
      id: r.id,
      endpoint: `POST ${r.path}`,
      priceUsd: r.priceUsd,
      description: r.description,
    })),
    discovery: {
      webConsole: `${b}/app`,
      manifest: `${b}/manifest`,
      skills: `${b}/skills`,
      openapi: `${b}/openapi.json`,
      mcp: `${b}/mcp`,
      x402: `${b}/.well-known/x402`,
      x402Json: `${b}/.well-known/x402.json`,
      agentCard: `${b}/.well-known/agent-card.json`,
      agentRegistration: `${b}/.well-known/agent-registration.json`,
      llmsTxt: `${b}/llms.txt`,
      skillMd: `${b}/SKILL.md`,
      privacy: `${b}/privacy`,
      terms: `${b}/terms`,
      usage: `${b}/usage`,
    },
  });
});

app.get('/app', publicLimiter, (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderLandingHtml(baseUrl(req)));
});

app.get('/usage', publicLimiter, (req, res) => {
  const report = usage.summary();
  if (String(req.headers.accept || '').includes('text/html')) {
    return res.type('html').send(`<!doctype html><title>PhantomOperator Usage</title><pre>${JSON.stringify(report, null, 2)}</pre>`);
  }
  return res.json(report);
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    agent: manifest.name,
    version: manifest.version,
    payTo: x402.PAY_TO,
    network: x402.NETWORK,
    asset: x402.USDC_BASE,
    skillsActive: Object.keys(ROUTES).length,
    moneroSupport: true,
    timestamp: new Date().toISOString(),
  });
});

app.get('/manifest', publicLimiter, (_req, res) => {
  res.json({
    ...manifest,
    agentWallet: x402.PAY_TO,
    payment: {
      ...manifest.payment,
      payTo: x402.PAY_TO,
      receiver: x402.PAY_TO,
    },
  });
});

app.get('/skills', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.json({
    agent: manifest.name,
    payTo: x402.PAY_TO,
    network: x402.NETWORK,
    token: 'USDC',
    tokenAddress: x402.USDC_BASE,
    skills: manifest.skills.map((s) => ({
      ...s,
      endpoint: `${b}/skills/${s.id}`,
    })),
  });
});

app.get('/.well-known/402index-verify.txt', (_req, res) => {
  res.type('text/plain').send('01c6c7fe92a9ddae4370753deb04b150a0495af525725acdd6aaeb01ae8a6c96');
});

app.get('/.well-known/agent-tools-verify.txt', (_req, res) => {
  const token = process.env.AGENT_TOOLS_VERIFY;
  if (!token) return res.status(404).type('text/plain').send('Not configured');
  return res.type('text/plain').send(`${token}\n`);
});

app.get(['/.well-known/x402', '/.well-known/x402.json'], publicLimiter, (req, res) => {
  const b = baseUrl(req);
  const routes = Object.values(ROUTES);
  // Some directories require a Bazaar-shaped manifest with per-resource
  // `accepts[]`; retain the established canonical document at /x402.
  if (req.path.endsWith('.json')) {
    return res.json({
      x402Version: 2,
      name: manifest.name,
      description: manifest.description,
      resources: routes.map((r) => {
        const accept = x402.requirements(r, b);
        return { resource: accept.resource, url: accept.resource, description: r.description, accepts: [accept] };
      }),
    });
  }
  return res.json({
    version: 1,
    x402Version: 2,
    agent: manifest.name,
    description: manifest.description,
    payTo: x402.PAY_TO,
    network: x402.NETWORK,
    asset: x402.USDC_BASE,
    erc8004AgentId: Number(process.env.ERC8004_AGENT_ID || 821239),
    resources: routes.map((r) => `${b}${r.path}`),
    skillDetails: routes.map((r) => ({
      url: `${b}${r.path}`,
      method: "POST",
      name: r.id,
      description: r.description,
      scheme: "exact",
      network: x402.NETWORK,
      payTo: x402.PAY_TO,
      asset: x402.USDC_BASE,
      maxAmountRequired: x402.atomic(r.priceUsd),
      priceUSDC: String(r.priceUsd.toFixed(2)),
      mimeType: "application/json",
      outputSchema: x402.requirements(r, b).outputSchema,
    })),
  });
});

app.get('/.well-known/agent-card.json', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.json({
    schemaVersion: '1.0',
    name: manifest.name,
    description: manifest.description,
    url: b,
    version: manifest.version,
    iconUrl: `${b}/logo.png`,
    provider: {
      organization: manifest.author.name,
      url: 'https://github.com/normancomics/PhantomOperator',
      social: 'https://x.com/phntmop',
    },
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
      x402Payments: true,
      moneroCryptonoteAudit: true,
      extensions: [{
        uri: 'https://a2a-registry.org/extensions/registry/v1',
        description: 'Registry identity and Base-USDC x402 payment capabilities',
        required: false,
        params: {
          identity: { provider: 'github', username: 'normancomics', packageName: 'github.normancomics.phantomoperator' },
          payment: {
            model: 'freemium',
            protocols: ['x402'],
            direction: 'inbound',
            rails: [{ network: 'base', token: 'USDC', type: 'stablecoin', protocol: 'x402', caip2: x402.NETWORK, contractAddress: x402.USDC_BASE, feeModel: 'low', settlementTime: 'fast' }],
            skills: Object.values(ROUTES).map((r) => ({ skillId: r.id, price: r.priceUsd.toFixed(2), currency: 'USDC', unit: 'call' })),
            meta: { freePreview: 'POST /preview/metadata-audit (rate limited)', settlement: 'onchain', refundPolicy: 'not charged when execution fails before settlement' },
          },
        },
      }],
    },
    authentication: {
      schemes: ['x402'],
      x402: {
        network: x402.NETWORK,
        chainId: 8453,
        token: 'USDC',
        tokenAddress: x402.USDC_BASE,
        payTo: x402.PAY_TO,
        facilitator: x402.FACILITATOR,
      },
    },
    ...(process.env.AGENT_TOOLS_VERIFY ? { agentToolsVerify: process.env.AGENT_TOOLS_VERIFY } : {}),
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: Object.values(ROUTES).map((r) => ({
      id: r.id,
      name: r.id,
      description: r.description,
      endpoint: `${b}${r.path}`,
      method: 'POST',
      priceUsd: r.priceUsd,
      inputExample: r.inputExample,
    })),
  });
});

// Compatibility alias used by older crawlers and the original project documentation.
// Canonical ERC-8004 document remains /.well-known/agent-registration.json.
app.get('/.well-known/agent.json', publicLimiter, (req, res) => {
  res.redirect(308, '/.well-known/agent-registration.json');
});

app.get('/.well-known/agent-registration.json', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.json({
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: manifest.name,
    description: manifest.description,
    image: `${b}/logo.png`,
    active: true,
    x402Support: true,
    agentWallet: x402.PAY_TO,
    services: [
      {
        name: 'web',
        endpoint: b,
      },
      {
        name: 'A2A',
        endpoint: `${b}/.well-known/agent-card.json`,
        version: '0.3.0',
      },
      {
        name: 'MCP',
        endpoint: `${b}/mcp`,
        version: '2025-06-18',
        capabilities: ['tools'],
        tools: Object.keys(ROUTES),
      },
      {
        name: 'OASF',
        endpoint: `${b}/openapi.json`,
        version: '3.1.0',
        skills: Object.keys(ROUTES),
        domains: ['security', 'privacy', 'opsec', 'osint', 'monero', 'blockchain'],
      },
      {
        name: 'x402',
        endpoint: `${b}/.well-known/x402`,
        version: '2.0',
        network: x402.NETWORK,
        asset: x402.USDC_BASE,
      },
      ...(MPP_TEMPO_ENABLED ? [{
        name: 'MPP',
        endpoint: `${b}/openapi.json`,
        version: '1.0',
        method: 'tempo',
        currency: 'OUSD',
        currencyAddress: MPP_TEMPO_OUSD,
        pathsPrefix: '/mpp/skills',
      }] : []),
      {
        name: 'agentWallet',
        endpoint: `eip155:8453:${x402.PAY_TO}`,
      },
    ],
    supportedTrust: ['reputation', 'crypto-economic'],
  });
});

app.get('/openapi.json', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  const paths = {};
  for (const r of Object.values(ROUTES)) {
    paths[r.path] = {
      post: {
        operationId: r.id,
        summary: r.id,
        description: `${r.description} (x402 price: $${r.priceUsd.toFixed(2)} USDC on Base to ${x402.PAY_TO})`,
        'x-x402': x402.requirements(r, b),
        'x-payment-info': {
          price: { mode: 'fixed', currency: 'USD', amount: String(r.priceUsd.toFixed(2)) },
          protocols: [{ x402: { scheme: 'exact', network: x402.NETWORK, asset: x402.USDC_BASE, payTo: x402.PAY_TO } }],
        },
        security: [{ x402: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: r.bodySchema,
              example: r.inputExample,
            },
          },
        },
        responses: {
          '200': { description: 'Skill execution result' },
          '402': { description: 'x402 Payment Required (USDC on Base eip155:8453)' },
        },
      },
    };
    if (MPP_TEMPO_ENABLED) {
      // MPP is separately addressable so native MPP clients receive their own
      // payment challenge without changing the Base x402 contract.
      paths[`/mpp${r.path}`] = {
        post: {
          operationId: `mpp-${r.id}`,
          summary: `${r.id} (MPP)`,
          description: `${r.description} (MPP Tempo OUSD price: $${r.priceUsd.toFixed(2)} to ${x402.PAY_TO})`,
          'x-payment-info': {
            price: { mode: 'fixed', currency: 'USD', amount: String(r.priceUsd.toFixed(2)) },
            protocols: [{ mpp: { method: 'tempo', currency: MPP_TEMPO_OUSD, recipient: x402.PAY_TO } }],
          },
          requestBody: { required: true, content: { 'application/json': { schema: r.bodySchema, example: r.inputExample } } },
          responses: {
            '200': { description: 'Skill execution result with MPP Payment-Receipt' },
            '402': { description: 'MPP Payment Required (Tempo OUSD)' },
          },
        },
      };
    }
  }
  res.json({
    openapi: '3.1.0',
    info: {
      title: manifest.name,
      version: manifest.version,
      description: manifest.description,
      'x-guidance': 'Use POST /skills/* for Base USDC x402 payments. Send JSON matching the route schema. A 402 response contains the payment challenge; retry with the protocol credential. Only submit data you are authorized to assess.',
      contact: { name: manifest.author.name, email: 'admin@freysaai.freysa.dev', url: 'https://github.com/normancomics/PhantomOperator' },
    },
    servers: [
      { url: b, description: 'Active PhantomOperator Instance' },
    ],
    paths,
    components: {
      securitySchemes: {
        x402: {
          type: 'apiKey',
          in: 'header',
          name: 'PAYMENT-SIGNATURE',
          description: 'x402 v2 base64 payment payload (also accepts X-Payment header)',
        },
      },
    },
  });
});

app.get('/robots.txt', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.type('text/plain').send(`User-agent: *\nAllow: /\nSitemap: ${b}/sitemap.xml\n`);
});

app.get('/sitemap.xml', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  const urls = ['/', '/app', '/website-privacy-baseline', '/free-website-privacy-preview', '/manifest', '/skills', '/openapi.json', '/SKILL.md', '/quickstart', '/sample-report', '/preview/metadata-audit', '/usage', '/status', '/llms.txt', '/.well-known/x402', '/.well-known/agent-card.json', '/.well-known/agent-registration.json'];
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map((u) => `<url><loc>${b}${u}</loc></url>`).join('')}</urlset>`);
});

app.get('/llms.txt', publicLimiter, (_req, res) => {
  res.sendFile(path.join(__dirname, 'llms.txt'));
});

app.get('/SKILL.md', publicLimiter, (_req, res) => {
  res.type('text/markdown').sendFile(path.join(__dirname, 'SKILL.md'));
});

function renderOfferPage(base, { canonicalPath = '/', title, description, headline, body, cta }) {
  const safe = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safe(title)}</title><meta name="description" content="${safe(description)}"><link rel="canonical" href="${base}${canonicalPath}"><meta property="og:type" content="website"><meta property="og:url" content="${base}${canonicalPath}"><meta property="og:title" content="${safe(title)}"><meta property="og:description" content="${safe(description)}"><meta property="og:image" content="${base}/phantomoperator-share-card.png"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="${base}/phantomoperator-share-card.png"><style>body{margin:0;background:#07090e;color:#e2e8f0;font:16px system-ui,sans-serif;line-height:1.6}.wrap{max-width:760px;margin:auto;padding:48px 20px}img{width:74px;border:1px solid #00f5d4;border-radius:14px}h1{color:#00f5d4;line-height:1.15}.card{background:#0e131f;border:1px solid #1e293b;border-radius:14px;padding:24px}.btn{display:inline-block;background:linear-gradient(135deg,#00f5d4,#00bbf9);color:#041019;padding:12px 16px;border-radius:8px;font-weight:800;text-decoration:none}a{color:#00f5d4}.small{color:#94a3b8;font-size:.9rem}</style></head><body><main class="wrap"><a href="/"><img src="/logo.png" alt="PhantomOperator logo"></a><div class="card"><h1>${safe(headline)}</h1><p>${safe(body)}</p><p><a class="btn" href="${cta.href}">${safe(cta.label)}</a></p><p class="small">Authorized public targets only. Findings are public-exposure signals for review, not proof of compromise or a penetration test.</p><p><a href="/quickstart">Developer quickstart</a> · <a href="/privacy">Privacy model</a> · <a href="https://x.com/phntmop" target="_blank" rel="noopener noreferrer">@phntmop on X</a></p></div></main></body></html>`;
}

app.get('/website-privacy-baseline', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.type('html').send(renderOfferPage(b, {
    canonicalPath: '/website-privacy-baseline',
    title: 'Website Privacy Baseline — $19 Fixed-Scope Audit | PhantomOperator',
    description: 'A $19 Website Privacy Baseline for an authorized public website: headers, metadata, comments, tracker signals, and prioritized remediation guidance.',
    headline: 'Website Privacy Baseline — $19',
    body: 'Get a fixed-scope privacy baseline for one public website you own or are authorized to assess. The report reviews public HTTP and security headers, framework/server fingerprinting, author and generator metadata, HTML comments, third-party tracker signals, and a prioritized remediation checklist.',
    cta: { href: '/#baselineOfferCard', label: 'Start the $19 Website Privacy Baseline' },
  }));
});

app.get('/free-website-privacy-preview', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.type('html').send(renderOfferPage(b, {
    canonicalPath: '/free-website-privacy-preview',
    title: 'Free Website Privacy Preview | PhantomOperator',
    description: 'Run a free, rate-limited public website privacy preview for headers, metadata, HTML comments, and third-party tracker signals.',
    headline: 'Free Website Privacy Preview',
    body: 'Start with a free limited preview of a public website you own or are authorized to assess. It identifies public headers, metadata, HTML comments, and tracker signals so you can decide whether to order the full Website Privacy Baseline.',
    cta: { href: '/#freePreviewCard', label: 'Run a Free Preview' },
  }));
});

app.get('/quickstart', publicLimiter, (_req, res) => {
  res.type('text/markdown').sendFile(path.join(__dirname, 'QUICKSTART.md'));
});

app.get('/sample-report', publicLimiter, (_req, res) => {
  res.json({
    sample: true,
    purpose: 'Illustrative metadata-audit output shape; not a finding about the requester or their site.',
    input: { url: 'https://example.com' },
    result: {
      overallRisk: 'medium',
      findingCounts: { high: 0, medium: 2, low: 1 },
      findings: [
        { category: 'http-header', riskLevel: 'medium', label: 'Server fingerprint exposed', recommendation: 'Review whether revealing framework/server headers is necessary.' },
        { category: 'security-header', riskLevel: 'medium', label: 'Security header absent', recommendation: 'Review the relevant response-header policy.' },
      ],
    },
    limitations: ['Public-source results can be incomplete or stale.', 'A finding is a signal for review, not proof of compromise.'],
    nextStep: 'For an authorized live audit, inspect POST /skills/metadata-audit payment terms first.',
  });
});

app.get('/status', publicLimiter, (_req, res) => {
  res.json({ status: 'operational', health: '/health', usage: '/usage', updatedAt: new Date().toISOString() });
});

app.get('/privacy', publicLimiter, (_req, res) => {
  const p = path.join(__dirname, 'PRIVACY.md');
  if (fs.existsSync(p)) return res.type('text/markdown').sendFile(p);
  return res.status(404).type('text/plain').send('Privacy model is unavailable.');
});

app.get('/terms', publicLimiter, (_req, res) => {
  const p = path.join(__dirname, 'TERMS.md');
  if (fs.existsSync(p)) return res.type('text/markdown').sendFile(p);
  res.type('text/plain').send('See https://github.com/normancomics/PhantomOperator/blob/main/TERMS.md');
});

app.get('/logo.png', publicLimiter, (_req, res) => {
  res.type('image/png').sendFile(path.join(__dirname, 'assets', 'phantom-operator-logo.png'));
});

app.get('/phantomoperator-share-card.png', publicLimiter, (_req, res) => {
  res.type('image/png').sendFile(path.join(__dirname, 'assets', 'phantomoperator-share-card.png'));
});

// ─── Free evaluation endpoints ──────────────────────────────────────────────

app.get('/preview/metadata-audit', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.json({
    endpoint: `${b}/preview/metadata-audit`,
    method: 'POST',
    priceUsd: 0,
    rateLimitPerHour: Number(process.env.RATE_LIMIT_PREVIEW || '5'),
    description: 'Free rate-limited website privacy & metadata audit preview (up to 3 top-severity findings).',
    requestBody: { url: 'https://example.com' },
    paidUpgrades: {
      x402FullMetadataAudit: { method: 'POST', endpoint: `${b}/skills/metadata-audit`, priceUsd: 0.05 },
      stripeWebsitePrivacyBaseline: { method: 'POST', endpoint: `${b}/billing/stripe/website-privacy-baseline-checkout`, priceUsd: 19.00 },
    },
  });
});

app.post('/preview/metadata-audit', previewLimiter, async (req, res) => {
  const url = req.body && req.body.url;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url is required.' });
  try {
    const report = await MetadataAgent.audit(url.trim());
    // Preview proves usefulness without returning a full paid report or raw page details.
    const previewFindings = report.findings.slice(0, 3).map(({ category, riskLevel, label, field }) => ({ category, riskLevel, label, field }));
    usage.record(req, { route: 'metadata-audit', rail: 'free', outcome: 'preview_completed' });
    return res.json({
      preview: true,
      url: report.url,
      statusCode: report.statusCode,
      overallRisk: report.overallRisk,
      findingCounts: report.findingCounts,
      findings: previewFindings,
      findingsTruncated: report.findings.length > previewFindings.length,
      limits: { perClientPerHour: Number(process.env.RATE_LIMIT_PREVIEW || '5'), fullDetailsRequire: 'POST /skills/metadata-audit via Base-USDC x402' },
    });
  } catch (err) { return res.status(400).json({ error: `Preview unavailable: ${err.message}` }); }
});

// ─── Free Live Demo Endpoint (`POST /demo/monero-decode`) ────────────────────

app.post('/demo/monero-decode', publicLimiter, (req, res) => {
  const addr = (req.body && req.body.xmrAddress) ||
    '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
  const decoded = MoneroAgent.decodeMoneroAddress(String(addr));
  const sampleSubaddress = MoneroAgent.deriveDeterministicSubaddress('demo:phantom-operator');
  const mmr = MoneroAgent.buildMmrCommitment([String(addr), sampleSubaddress.subaddress]);
  res.json({
    demo: true,
    note: 'Free Cryptonote Base58 + Keccak-256 + MMR preview. Use POST /skills/monero-opsec-audit ($0.25 USDC via x402) for full live RingCT & cross-chain audit.',
    payTo: x402.PAY_TO,
    decoded,
    sampleDerivedSubaddress: sampleSubaddress,
    mmrCommitmentProof: mmr,
  });
});

// ─── Model Context Protocol (MCP JSON-RPC 2.0) ───────────────────────────────

app.get('/mcp', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  res.json({
    protocol: 'mcp',
    protocolVersion: '2025-06-18',
    serverInfo: { name: manifest.name, version: manifest.version },
    payTo: x402.PAY_TO,
    endpoint: `${b}/mcp`,
    tools: mcpTools.tools,
  });
});

app.post('/mcp', publicLimiter, (req, res) => {
  const { jsonrpc, id, method } = req.body || {};
  if (jsonrpc !== '2.0') {
    return res.status(400).json({ jsonrpc: '2.0', id: id || null, error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request' } });
  }
  if (method === 'initialize') {
    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: manifest.name, version: manifest.version },
      },
    });
  }
  if (method === 'tools/list') {
    return res.json({ jsonrpc: '2.0', id, result: { tools: mcpTools.tools } });
  }
  if (method === 'tools/call') {
    const toolName = req.body.params && req.body.params.name;
    usage.record(req, { route: toolName || 'unknown', rail: 'mcp', outcome: 'payment_quote' });
    const route = ROUTES[toolName];
    if (!route) {
      return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
    }
    const b = baseUrl(req);
    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        isError: false,
        content: [{
          type: 'text',
          text: JSON.stringify({
            status: 402,
            message: `Invoke POST ${b}${route.path} with an x402 payment header ($${route.priceUsd} USDC on Base to ${x402.PAY_TO}).`,
            paymentRequirements: x402.requirements(route, b),
          }),
        }],
      },
    });
  }
  return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
});

// ─── Phase 1 Elysium USDC Payments (eip155:99901, quote + on-chain receipt) ──
app.get('/billing/elysium-usdc/info', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  return res.json({
    paymentMethod: 'elysium-usdc',
    phase: 1,
    primaryRail: 'x402-base-usdc',
    network: ELYSIUM_NETWORK,
    chainId: ELYSIUM_CHAIN_ID,
    asset: ELYSIUM_USDC,
    symbol: 'USDC',
    decimals: ELYSIUM_USDC_DECIMALS,
    payTo: x402.PAY_TO,
    quoteEndpoint: `${b}/billing/elysium-usdc/quote`,
    quoteStatusEndpoint: `${b}/billing/elysium-usdc/quote/:quoteId`,
  });
});

app.post('/billing/elysium-usdc/quote', paidLimiter, (req, res) => {
  const skillId = req.body && req.body.skillId;
  const route = ROUTES[skillId];
  if (!route) return res.status(400).json({ error: 'skillId must name an active skill.' });
  const input = (req.body && req.body.input) || {};
  const payer = req.body && req.body.payer;
  try {
    const quote = elysiumBilling.createQuote({
      route,
      body: input,
      payer,
      baseUrl: baseUrl(req),
    });
    usage.record(req, {
      route: route.id,
      rail: 'elysium-usdc',
      outcome: 'payment_quote',
      amountUsd: route.priceUsd,
    });
    return res.status(201).json(quote);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.get('/billing/elysium-usdc/quote/:id', publicLimiter, (req, res) => {
  const status = elysiumBilling.getQuoteStatus(req.params.id);
  if (!status) return res.status(404).json({ error: 'Elysium payment quote not found.' });
  return res.json(status);
});

// ─── Optional Monero Invoice Payments (view-only wallet RPC) ─────────────────
// A quote allocates a unique subaddress. It is disabled until MONERO_WALLET_RPC_URL,
// MONERO_PROOF_SECRET, and MONERO_USD_PER_XMR are configured locally.
app.post('/billing/monero-quote', paidLimiter, async (req, res) => {
  const route = ROUTES[req.body && req.body.skillId];
  if (!route) return res.status(400).json({ error: 'skillId must name an active skill.' });
  const input = (req.body && req.body.input) || {};
  try {
    const quote = await moneroBilling.quote({ route, body: input, baseUrl: baseUrl(req) });
    return res.status(201).json(quote);
  } catch (err) {
    return res.status(moneroBilling.configured() ? 502 : 503).json({ error: err.message });
  }
});
app.get('/billing/monero-invoice/:id', paidLimiter, async (req, res) => {
  try {
    const invoice = await moneroBilling.status(req.params.id);
    if (!invoice) return res.status(404).json({ error: 'Invoice not found.' });
    const response = { invoiceId: invoice.id, route: invoice.route, address: invoice.address, amountAtomic: invoice.amountAtomic, amountXmr: invoice.amountXmr, status: invoice.status, expiresAt: new Date(invoice.expiresAt).toISOString(), confirmationsRequired: Number(process.env.MONERO_MIN_CONFIRMATIONS || 10) };
    if (invoice.status === 'paid' && !invoice.redeemedAt) response.paymentProof = moneroBilling.paymentProof(invoice);
    return res.json(response);
  } catch (err) { return res.status(502).json({ error: `Monero invoice check failed: ${err.message}` }); }
});

// ─── Paid Skill Endpoints (x402 v1/v2 Verified & Settled) ────────────────────

for (const route of Object.values(ROUTES)) {
  // GET on a skill path returns its x402 402 Payment Required discovery schema
  // so x402scan, CDP Bazaar, and Agent402 indexers can inspect it via GET or POST
  app.get(route.path, publicLimiter, (req, res) => {
    const b = baseUrl(req);
    const p = x402.paymentRequired(route, b, 'Payment Required (POST JSON body with x402 payment header)');
    res.set('PAYMENT-REQUIRED', Buffer.from(JSON.stringify(p)).toString('base64'));
    return res.status(402).json(p);
  });

  const validator = validateSkillInput(route.id);
  app.post(route.path, paidLimiter, async (req, res) => {
    const b = baseUrl(req);
    const paymentMethod = String(req.headers['x-payment-method'] || '').toLowerCase();
    const useMonero = paymentMethod === 'monero';
    const useElysiumUsdc = paymentMethod === 'elysium-usdc';

    if (useElysiumUsdc) {
      validator(req, res, () => {});
      if (res.headersSent) return;
      const v = await elysiumBilling.verifyForRequest(req.headers['x-payment'], route, req.body || {});
      if (!v.ok) {
        if (v.status === 402) {
          usage.record(req, { route: route.id, rail: 'elysium-usdc', outcome: 'payment_quote', amountUsd: route.priceUsd });
        }
        return res.status(v.status).json({ error: v.message, paymentMethod: 'elysium-usdc', quoteEndpoint: `${b}/billing/elysium-usdc/quote` });
      }
      let result;
      try {
        result = await route.run(req.body || {});
      } catch (err) {
        elysiumBilling.unclaim(v.settlement.quoteId, v.settlement.transferKey);
        return res.status(500).json({ error: `${route.id} failed`, detail: err.message });
      }
      usage.record(req, {
        route: route.id,
        rail: 'elysium-usdc',
        outcome: 'settled',
        amountUsd: route.priceUsd,
        transaction: v.settlement.txHash,
      });
      const receiptHeader = Buffer.from(JSON.stringify({
        success: true,
        paymentProtocol: 'elysium-usdc',
        network: v.settlement.network,
        chainId: v.settlement.chainId,
        asset: v.settlement.asset,
        transaction: v.settlement.txHash,
        quoteId: v.settlement.quoteId,
        payer: v.settlement.payer,
        payTo: v.settlement.payTo,
        amountAtomic: v.settlement.amountAtomic,
      })).toString('base64');
      return res
        .set({ 'PAYMENT-RESPONSE': receiptHeader, 'X-PAYMENT-RESPONSE': receiptHeader })
        .json({
          skill: route.id,
          paymentProtocol: 'elysium-usdc',
          elysiumSettlement: v.settlement,
          ...result,
        });
    }

    const v = useMonero
      ? await moneroBilling.verifyForRequest(req.headers['x-payment'], route, req.body || {})
      : await x402.verify(req, route, b);
    if (!v.ok) {
      if (useMonero) return res.status(v.status).json({ error: v.message });
      if (v.status === 402) usage.record(req, { route: route.id, rail: 'x402-base-usdc', outcome: 'payment_quote', amountUsd: route.priceUsd });
      return res.status(v.status).set(v.headers || {}).json(v.body);
    }
    validator(req, res, () => {});
    if (res.headersSent) return;

    let result;
    try {
      result = await route.run(req.body || {});
    } catch (err) {
      return res.status(500).json({ error: `${route.id} failed`, detail: err.message });
    }

    if (useMonero) {
      usage.record(req, { route: route.id, rail: 'monero', outcome: 'settled', amountUsd: route.priceUsd, transaction: v.invoice.txid });
      return res.json({ skill: route.id, paymentProtocol: 'monero', moneroInvoiceId: v.invoice.id, ...result });
    }
    const s = await x402.settle(v.payload, route, b);
    if (!s.ok) {
      usage.record(req, { route: route.id, rail: 'x402-base-usdc', outcome: 'settlement_failed', amountUsd: route.priceUsd });
      return res.status(s.status).json(s.body);
    }
    let transaction;
    try {
      const receipt = JSON.parse(Buffer.from(s.headers['PAYMENT-RESPONSE'], 'base64').toString('utf8'));
      transaction = receipt.transaction;
    } catch { /* receipt remains opaque if a facilitator changes format */ }
    usage.record(req, { route: route.id, rail: 'x402-base-usdc', outcome: 'settled', amountUsd: route.priceUsd, transaction });
    return res.set(s.headers || {}).json({ skill: route.id, ...result });
  });
}

// ─── Stripe prepaid-credit skill endpoints ───────────────────────────────────
// Credits are debited atomically before execution and refunded if the service
// cannot produce a result. This rail is enabled only after signed Stripe
// Checkout fulfillment is configured.
const WEBSITE_PRIVACY_BASELINE_CENTS = 1900;

app.post('/credits/offers/website-privacy-baseline', paidLimiter, validateSkillInput('metadata-audit'), async (req, res) => {
  if (!stripeCheckout.configured()) {
    return res.status(503).json({ error: 'Stripe prepaid credits are not enabled yet.' });
  }
  const authorized = Boolean(req.body && req.body.authorized === true);
  if (!authorized) {
    return res.status(400).json({
      error: 'Authorization required',
      message: 'Pass "authorized": true to confirm you own or are authorized to assess the target website.',
    });
  }
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  let debited = false;
  try {
    debited = creditLedger.debit(token, WEBSITE_PRIVACY_BASELINE_CENTS, 'website-privacy-baseline');
    if (!debited) {
      return res.status(402).json({
        error: 'Insufficient prepaid credit balance.',
        requiredCents: WEBSITE_PRIVACY_BASELINE_CENTS,
        requiredUsd: '19.00',
      });
    }
    const audit = await MetadataAgent.audit(req.body.url.trim());
    const prioritizedChecklist = (audit.findings || []).map((f, idx) => ({
      priority: idx + 1,
      riskLevel: f.riskLevel,
      category: f.category,
      finding: f.label,
      evidenceField: f.field || null,
      action: f.recommendation,
    }));
    usage.record(req, {
      route: 'website-privacy-baseline',
      rail: 'stripe-prepaid-credit',
      outcome: 'settled',
      amountUsd: WEBSITE_PRIVACY_BASELINE_CENTS / 100,
    });
    return res.json({
      offer: 'website-privacy-baseline',
      priceUsd: 19.00,
      paymentProtocol: 'stripe-prepaid-credit',
      targetUrl: audit.url,
      statusCode: audit.statusCode,
      assessedAt: audit.timestamp,
      overallRisk: audit.overallRisk,
      findingCounts: audit.findingCounts,
      prioritizedRemediationChecklist: prioritizedChecklist,
      observations: {
        findings: audit.findings,
        recommendations: audit.recommendations,
      },
      scopeAndLimitations: [
        'Fixed-scope public-exposure and privacy-baseline review of a single public HTTP/HTTPS origin.',
        'Not a penetration test, compliance certification, malware scan, or authenticated application assessment.',
        'Observations reflect public responses at execution time; findings are signals for review, not proof of compromise.',
      ],
    });
  } catch (error) {
    if (debited) {
      try {
        creditLedger.refund(token, WEBSITE_PRIVACY_BASELINE_CENTS, 'website-privacy-baseline');
      } catch {
        /* preserve original failure */
      }
    }
    return res.status(500).json({ error: 'website-privacy-baseline failed', detail: error.message });
  }
});

for (const route of Object.values(ROUTES)) {
  const validator = validateSkillInput(route.id);
  app.post(`/credits${route.path}`, paidLimiter, validator, async (req, res) => {
    if (!stripeCheckout.configured()) {
      return res.status(503).json({ error: 'Stripe prepaid credits are not enabled yet.' });
    }
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const amountCents = Math.round(route.priceUsd * 100);
    let debited = false;
    try {
      debited = creditLedger.debit(token, amountCents, route.id);
      if (!debited) return res.status(402).json({ error: 'Insufficient prepaid credit balance.' });
      const result = await route.run(req.body || {});
      usage.record(req, { route: route.id, rail: 'stripe-prepaid-credit', outcome: 'settled', amountUsd: route.priceUsd });
      return res.json({ skill: route.id, paymentProtocol: 'stripe-prepaid-credit', ...result });
    } catch (error) {
      if (debited) { try { creditLedger.refund(token, amountCents, route.id); } catch { /* preserve original failure */ } }
      return res.status(500).json({ error: `${route.id} failed`, detail: error.message });
    }
  });
}

// ─── MPP Paid Skill Endpoints (Tempo OUSD) ───────────────────────────────────
// Kept on /mpp/ routes so MPP and existing Base x402 clients can each use their
// native 402 headers and facilitator without protocol ambiguity.
if (MPP_TEMPO_ENABLED) {
  for (const route of Object.values(ROUTES)) {
    const validator = validateSkillInput(route.id);
    app.post(`/mpp${route.path}`, paidLimiter, validator, mpp.charge({
      amount: String(route.priceUsd),
      description: route.description,
    }), async (req, res) => {
      try {
        const result = await route.run(req.body || {});
        usage.record(req, { route: route.id, rail: 'mpp-tempo', outcome: 'settled', amountUsd: route.priceUsd });
        return res.json({ skill: route.id, paymentProtocol: 'mpp-tempo', ...result });
      } catch (err) {
        return res.status(500).json({ error: `${route.id} failed`, detail: err.message });
      }
    });
  }
}

// Stripe MPP direct-card rail. It is intentionally registered only with explicit
// Stripe configuration, so an unavailable processor can never produce a false
// payment promise. Stripe's minimum is $0.50, independent of Base x402 prices.
if (STRIPE_MPP_ENABLED) {
  for (const route of Object.values(ROUTES)) {
    const validator = validateSkillInput(route.id);
    app.post(`/mpp/skills/${route.id}`, paidLimiter, validator, stripeMpp.charge({
      amount: Math.max(STRIPE_MPP_MIN_USD, route.priceUsd).toFixed(2),
      description: `PhantomOperator ${route.id}`,
    }), async (req, res) => {
      try {
        const result = await route.run(req.body || {});
        usage.record(req, { route: route.id, rail: 'mpp-stripe', outcome: 'settled', amountUsd: Math.max(STRIPE_MPP_MIN_USD, route.priceUsd) });
        return res.json({ skill: route.id, paymentProtocol: 'mpp-stripe', ...result });
      } catch (err) {
        return res.status(500).json({ error: `${route.id} failed`, detail: err.message });
      }
    });
  }
}

// ─── 404 Handler ─────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({
    error: `Unknown route: ${req.method} ${req.path}`,
    discovery: '/.well-known/x402',
  });
});

// ─── Start Server ────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`PhantomOperator API server running on port ${PORT} (${HOST}, payTo: ${x402.PAY_TO})`);
  });
}

module.exports = app;

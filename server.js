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
const { Mppx, tempo } = require('mppx/express');
const x402    = require('./lib/x402');
const usage   = require('./lib/usage');
const moneroBilling = require('./lib/monero-billing');

const MPP_TEMPO_OUSD = '0x20c0000000000000000000006a37DA5C996874BE';
const mpp = Mppx.create({
  methods: [tempo.charge({
    currencies: [MPP_TEMPO_OUSD],
    recipient: x402.PAY_TO,
    testnet: false,
  })],
  secretKey: process.env.MPP_SECRET_KEY,
  realm: process.env.MPP_REALM || 'freysaai.freysa.dev',
});

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

app.use(corsHeaders);
app.use(securityHeaders);
app.use(bodySizeGuard);
app.use(express.json({ limit: '16kb' }));

app.use((err, _req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload Too Large', message: 'Request body must not exceed 16 KB.' });
  }
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON in request body.' });
  }
  return next(err);
});

const baseUrl = (req) =>
  process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;

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
    <tr>
      <td><code>POST ${r.path}</code></td>
      <td><span class="badge">$${r.priceUsd.toFixed(2)} USDC</span></td>
      <td>${r.description}</td>
      <td><button class="btn-sm" onclick='selectSkill(${JSON.stringify(r.id)}, ${JSON.stringify(r.inputExample)}, ${r.priceUsd})'>Load in Console</button></td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PhantomOperator — Privacy and Public-Exposure Checks</title>
  <style>
    :root {
      --bg: #07090e;
      --panel: #0e131f;
      --border: #1e293b;
      --cyan: #00f5d4;
      --orange: #ff6600;
      --text: #e2e8f0;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at 15% 15%, #0f1b2d 0%, var(--bg) 60%);
      color: var(--text);
      font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      line-height: 1.55;
    }
    .wrap { max-width: 1180px; margin: 0 auto; padding: 28px 20px 64px; }
    header {
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap;
      gap: 16px; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px;
    }
    .brand { display: flex; align-items: center; gap: 16px; }
    .brand img { width: 60px; height: 60px; border-radius: 12px; border: 1px solid var(--cyan); }
    h1 { margin: 0; font-size: 1.55rem; color: var(--cyan); letter-spacing: 0.5px; }
    .sub { color: var(--muted); font-size: 0.88rem; margin-top: 4px; }
    .pill-row { display: flex; gap: 8px; flex-wrap: wrap; }
    .pill {
      padding: 5px 11px; border-radius: 999px; font-size: 0.76rem; font-weight: 600;
      background: rgba(0,245,212,0.08); border: 1px solid rgba(0,245,212,0.35); color: var(--cyan);
    }
    .pill.xmr { background: rgba(255,102,0,0.12); border-color: rgba(255,102,0,0.45); color: var(--orange); }
    .grid { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 20px; margin-bottom: 24px; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .card {
      background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
    }
    .card h2 { margin-top: 0; font-size: 1.05rem; color: var(--cyan); display: flex; align-items: center; justify-content: space-between; }
    table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; }
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 6px;
      background: rgba(255,102,0,0.16); color: var(--orange); font-weight: 700; white-space: nowrap;
    }
    .btn, .btn-sm {
      background: linear-gradient(135deg, var(--cyan), #00bbf9);
      color: #041019; border: none; border-radius: 7px; padding: 10px 16px;
      font-family: inherit; font-weight: 700; cursor: pointer; font-size: 0.84rem;
    }
    .btn-sm { padding: 5px 10px; font-size: 0.75rem; }
    .btn-xmr { background: linear-gradient(135deg, var(--orange), #ff9e00); color: #09090b; }
    textarea, input, select {
      width: 100%; background: #060a12; color: var(--text); border: 1px solid var(--border);
      border-radius: 8px; padding: 10px; font-family: inherit; font-size: 0.84rem; margin-bottom: 10px;
    }
    pre {
      background: #05080f; border: 1px solid var(--border); border-radius: 8px; padding: 12px;
      overflow-x: auto; font-size: 0.8rem; max-height: 360px; color: #a7f3d0;
    }
    a { color: var(--cyan); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .addr-box {
      background: #060a12; border: 1px solid rgba(0,245,212,0.3); border-radius: 8px;
      padding: 10px 12px; font-size: 0.8rem; margin: 10px 0; word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <img src="/logo.png" alt="PhantomOperator Logo" />
        <div>
          <h1>PhantomOperator</h1>
          <div class="sub">Practical privacy, public-exposure, metadata, and wallet-hygiene checks for authorized users and agents.</div>
        </div>
      </div>
      <div class="pill-row">
        <span class="pill">x402 v2 Exact (USDC)</span>
        <span class="pill">Base (eip155:8453)</span>
        <span class="pill">MPP Tempo</span>
        <span class="pill">MCP + A2A</span>
      </div>
    </header>

    <div class="card" style="margin-bottom:20px;">
      <h2><span>Understand your public exposure before it becomes a problem</span></h2>
      <p style="margin-top:0; color:var(--muted);">Start with a transparent payment quote, then run an authorized privacy, metadata, breach, or wallet-hygiene check. Results identify observable risks and recommended next steps; they do not replace legal, security, or identity-verification advice.</p>
      <div class="grid" style="margin:0;">
        <div><strong>For people</strong><br/><span class="sub">Check public metadata, known breach exposure, data-broker listing matches, and wallet-hygiene signals.</span></div>
        <div><strong>For agents</strong><br/><span class="sub">Use OpenAPI, MCP, A2A, x402 Base USDC, or MPP Tempo routes with machine-readable terms.</span></div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2><span>Choose a privacy check</span> <span style="color:var(--orange)">Pay only after review</span></h2>
        <label>Select Skill Endpoint</label>
        <select id="skillSelect" onchange="onSkillDropdown()">
          ${Object.values(ROUTES).map((r) => `<option value="${r.id}">${r.id} — $${r.priceUsd.toFixed(2)} USDC (${r.path})</option>`).join('')}
        </select>
        <label>JSON Request Payload</label>
        <textarea id="payloadBox" rows="5">{"url": "https://example.com"}</textarea>
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px;">
          <button class="btn" onclick="invokeSkill()">View payment terms</button>
          <button class="btn-sm" style="background:#1e293b;color:#e2e8f0;" onclick="runFreeMoneroDemo()">View a free sample report</button>
        </div>
        <p class="sub">Only submit information you are authorized to assess. Do not submit passwords, seed phrases, private keys, or another person's personal data without permission. <a href="/terms">Terms and data-handling limits</a>.</p>
        <pre id="consoleOut">// Select a check, inspect its exact terms, or view a free sample report.</pre>
      </div>

      <div class="card">
        <h2><span>For agent builders</span> <span>ERC-8004 #821239</span></h2>
        <p style="font-size:0.84rem; color:var(--muted); margin-top:0;">Use a standard discovery document or the MCP endpoint. Base x402 uses native USDC; MPP uses Tempo OUSD. Each paid request first returns verifiable payment terms.</p>
        <ul style="font-size:0.84rem; padding-left:18px;">
          <li><a href="/.well-known/x402">/.well-known/x402</a> — x402 v2 payment requirements &amp; Bazaar schemas</li>
          <li><a href="/.well-known/agent-card.json">/.well-known/agent-card.json</a> — A2A Agent Card</li>
          <li><a href="/.well-known/agent-registration.json">/.well-known/agent-registration.json</a> — ERC-8004 Registration JSON</li>
          <li><a href="/openapi.json">/openapi.json</a> — OpenAPI 3.1.0 Specification</li>
          <li><a href="/mcp">/mcp</a> — Model Context Protocol (MCP JSON-RPC 2.0)</li>
          <li><a href="/manifest">/manifest</a> &amp; <a href="/skills">/skills</a> — Full Agent &amp; Skill Manifest</li>
          <li><a href="/llms.txt">/llms.txt</a> &amp; <a href="/SKILL.md">/SKILL.md</a> — LLM Documentation</li>
          <li><a href="/health">/health</a> — Real-time Health &amp; Telemetry</li>
          <li><a href="/usage">/usage</a> — Privacy-preserving live settlement totals</li>
          <li><a href="https://x.com/phntmop" rel="noopener noreferrer">@phntmop on X</a> — Product updates and examples</li>
        </ul>
        <div class="addr-box" style="border-color:rgba(255,102,0,0.4);">
          <strong style="color:var(--orange)">Scope and limitations</strong><br/>
          Public-source findings can be incomplete or stale. Data-broker outputs provide an opt-out workflow and draft materials; they do not guarantee removal. Review all results before acting.
        </div>
      </div>
    </div>

    <div class="card">
      <h2><span>Complete x402 Skill Catalog (Base Mainnet USDC)</span> <span>10 Active Skills</span></h2>
      <table>
        <thead>
          <tr><th>Endpoint</th><th>Price</th><th>Capabilities</th><th>Action</th></tr>
        </thead>
        <tbody>
          ${skillsRows}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    const EXAMPLES = ${JSON.stringify(Object.fromEntries(Object.values(ROUTES).map((r) => [r.id, { example: r.inputExample, price: r.priceUsd }])))};

    function selectSkill(id, example, price) {
      document.getElementById('skillSelect').value = id;
      document.getElementById('payloadBox').value = JSON.stringify(example, null, 2);
    }
    function onSkillDropdown() {
      const id = document.getElementById('skillSelect').value;
      if (EXAMPLES[id]) {
        document.getElementById('payloadBox').value = JSON.stringify(EXAMPLES[id].example, null, 2);
      }
    }
    async function invokeSkill() {
      const id = document.getElementById('skillSelect').value;
      const out = document.getElementById('consoleOut');
      out.textContent = "Requesting exact x402 payment terms for POST /skills/" + id + " ...";
      try {
        const res = await fetch("/skills/" + id, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: document.getElementById('payloadBox').value
        });
        const data = await res.json();
        out.textContent = "HTTP " + res.status + "\\n" + JSON.stringify(data, null, 2);
      } catch (e) {
        out.textContent = "Error: " + e.message;
      }
    }
    async function runFreeMoneroDemo() {
      const out = document.getElementById('consoleOut');
      out.textContent = "Loading a free sample privacy report...";
      try {
        const res = await fetch("/demo/monero-decode", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            xmrAddress: "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
          })
        });
        const data = await res.json();
        out.textContent = "HTTP " + res.status + " (Free Live Preview)\\n" + JSON.stringify(data, null, 2);
      } catch (e) {
        out.textContent = "Error: " + e.message;
      }
    }
  </script>
</body>
</html>`;
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
      agentCard: `${b}/.well-known/agent-card.json`,
      agentRegistration: `${b}/.well-known/agent-registration.json`,
      llmsTxt: `${b}/llms.txt`,
      skillMd: `${b}/SKILL.md`,
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

app.get('/.well-known/x402', publicLimiter, (req, res) => {
  const b = baseUrl(req);
  const routes = Object.values(ROUTES);
  res.json({
    version: 1,
    x402Version: 2,
    agent: manifest.name,
    description: manifest.description,
    payTo: x402.PAY_TO,
    network: x402.NETWORK,
    asset: x402.USDC_BASE,
    erc8004AgentId: Number(process.env.ERC8004_AGENT_ID || 821239),
    ...(process.env.AGENT_TOOLS_VERIFY ? { agentToolsVerify: process.env.AGENT_TOOLS_VERIFY } : {}),
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
      {
        name: 'MPP',
        endpoint: `${b}/openapi.json`,
        version: '1.0',
        method: 'tempo',
        currency: 'OUSD',
        currencyAddress: MPP_TEMPO_OUSD,
        pathsPrefix: '/mpp/skills',
      },
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
    // MPP is an additional, separately-addressable rail so native MPP clients
    // receive a standard WWW-Authenticate: Payment challenge without changing
    // the existing Base x402 endpoint contract.
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
  res.json({
    openapi: '3.1.0',
    info: {
      title: manifest.name,
      version: manifest.version,
      description: manifest.description,
      'x-guidance': 'Use POST /skills/* for Base USDC x402 payments, or POST /mpp/skills/* for MPP Tempo OUSD payments. Send JSON matching the route schema. A 402 response contains the payment challenge; retry with the protocol credential. Only submit data you are authorized to assess.',
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
  const urls = ['/', '/app', '/manifest', '/skills', '/openapi.json', '/SKILL.md', '/quickstart', '/sample-report', '/preview/metadata-audit', '/usage', '/status', '/llms.txt', '/.well-known/x402', '/.well-known/agent-card.json', '/.well-known/agent-registration.json'];
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map((u) => `<url><loc>${b}${u}</loc></url>`).join('')}</urlset>`);
});

app.get('/llms.txt', publicLimiter, (_req, res) => {
  res.sendFile(path.join(__dirname, 'llms.txt'));
});

app.get('/SKILL.md', publicLimiter, (_req, res) => {
  res.type('text/markdown').sendFile(path.join(__dirname, 'SKILL.md'));
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

app.get('/terms', publicLimiter, (_req, res) => {
  const p = path.join(__dirname, 'TERMS.md');
  if (fs.existsSync(p)) return res.type('text/markdown').sendFile(p);
  res.type('text/plain').send('See https://github.com/normancomics/PhantomOperator/blob/main/TERMS.md');
});

app.get('/logo.png', publicLimiter, (_req, res) => {
  res.type('image/png').sendFile(path.join(__dirname, 'assets', 'phantom-operator-logo.png'));
});

// ─── Free evaluation endpoints ──────────────────────────────────────────────

app.post('/preview/metadata-audit', previewLimiter, async (req, res) => {
  const url = req.body && req.body.url;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url is required.' });
  try {
    const report = await MetadataAgent.audit(url.trim());
    // Preview proves usefulness without returning a full paid report or raw page details.
    const previewFindings = report.findings.slice(0, 3).map(({ category, riskLevel, label, field }) => ({ category, riskLevel, label, field }));
    return res.json({
      preview: true,
      url: report.url,
      statusCode: report.statusCode,
      overallRisk: report.overallRisk,
      findingCounts: report.findingCounts,
      findings: previewFindings,
      findingsTruncated: report.findings.length > previewFindings.length,
      limits: { perClientPerHour: Number(process.env.RATE_LIMIT_PREVIEW || '5'), fullDetailsRequire: 'POST /skills/metadata-audit via Base USDC x402 or POST /mpp/skills/metadata-audit via MPP Tempo' },
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
    const useMonero = String(req.headers['x-payment-method'] || '').toLowerCase() === 'monero';
    const v = useMonero
      ? await moneroBilling.verifyForRequest(req.headers['x-payment'], route, req.body || {})
      : await x402.verify(req, route, b);
    if (!v.ok) {
      if (useMonero) return res.status(v.status).json({ error: v.message });
      return res.status(v.status).set(v.headers || {}).json(v.body);
    }
    let validationFailed = false;
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

// ─── MPP Paid Skill Endpoints (Tempo OUSD) ───────────────────────────────────
// Kept on /mpp/ routes so MPP and existing Base x402 clients can each use their
// native 402 headers and facilitator without protocol ambiguity.
for (const route of Object.values(ROUTES)) {
  const validator = validateSkillInput(route.id);
  app.post(`/mpp${route.path}`, paidLimiter, mpp.charge({
    amount: String(route.priceUsd),
    description: route.description,
  }), async (req, res) => {
    validator(req, res, () => {});
    if (res.headersSent) return;
    try {
      const result = await route.run(req.body || {});
      usage.record(req, { route: route.id, rail: 'mpp-tempo', outcome: 'settled', amountUsd: route.priceUsd });
      return res.json({ skill: route.id, paymentProtocol: 'mpp-tempo', ...result });
    } catch (err) {
      return res.status(500).json({ error: `${route.id} failed`, detail: err.message });
    }
  });
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

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`PhantomOperator API server running on port ${PORT} (payTo: ${x402.PAY_TO})`);
  });
}

module.exports = app;

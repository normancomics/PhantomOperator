'use strict';

// Privacy-preserving service telemetry. It records delivery facts, not request
// bodies, credentials, full IP addresses, or raw payment headers.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(DATA_DIR, 'usage-events.jsonl');
const salt = process.env.USAGE_LOG_SALT || 'local-development-only-change-me';

function clientId(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? String(forwarded).split(',')[0].trim() : (req.ip || 'unknown');
  const ua = String(req.headers['user-agent'] || 'unknown').slice(0, 512);
  return crypto.createHash('sha256').update(`${salt}|${ip}|${ua}`).digest('hex').slice(0, 16);
}

function record(req, event) {
  const safe = {
    at: new Date().toISOString(),
    client: clientId(req),
    route: String(event.route || 'unknown').slice(0, 120),
    rail: String(event.rail || 'unknown').slice(0, 48),
    outcome: String(event.outcome || 'unknown').slice(0, 48),
    amountUsd: Number.isFinite(event.amountUsd) ? event.amountUsd : undefined,
    transaction: event.transaction && /^0x[0-9a-fA-F]{64}$/.test(event.transaction) ? event.transaction : undefined,
  };
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    fs.appendFileSync(LOG_FILE, `${JSON.stringify(safe)}\n`, { mode: 0o600 });
  } catch (error) {
    // Telemetry must never prevent payment delivery.
    console.error('usage telemetry write failed:', error.message);
  }
}

function events() {
  try {
    return fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean)
      .slice(-5000).flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

function summary() {
  const now = Date.now();
  const all = events();
  const paid = all.filter((e) => e.outcome === 'settled');
  const since24h = paid.filter((e) => now - Date.parse(e.at) <= 86_400_000);
  const byRoute = {};
  const byRail = {};
  for (const e of paid) {
    byRoute[e.route] = (byRoute[e.route] || 0) + 1;
    byRail[e.rail] = (byRail[e.rail] || 0) + 1;
  }
  return {
    generatedAt: new Date().toISOString(),
    privacy: 'Aggregated service telemetry; no request bodies, wallet addresses, IP addresses, or payment credentials are exposed.',
    settledCalls: paid.length,
    settledCallsLast24Hours: since24h.length,
    distinctAnonymizedClients: new Set(paid.map((e) => e.client)).size,
    byRail,
    byRoute,
    latestSettlementAt: paid.length ? paid[paid.length - 1].at : null,
  };
}

module.exports = { record, summary, LOG_FILE };

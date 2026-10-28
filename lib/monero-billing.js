'use strict';

// View-only Monero invoice verifier. No spend key is needed or accepted.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ATOMIC_UNITS = 1000000000000n;
const storePath = process.env.MONERO_INVOICE_STORE || path.join(__dirname, '..', 'data', 'monero-invoices.json');

function configured() {
  return Boolean(process.env.MONERO_WALLET_RPC_URL && process.env.MONERO_PROOF_SECRET && Number(process.env.MONERO_USD_PER_XMR) > 0);
}
function load() { try { return JSON.parse(fs.readFileSync(storePath, 'utf8')); } catch { return { invoices: {} }; } }
function save(data) {
  fs.mkdirSync(path.dirname(storePath), { recursive: true });
  const tmp = `${storePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, storePath);
}
function requestHash(body) { return crypto.createHash('sha256').update(JSON.stringify(body || {})).digest('hex'); }
function sign(payload) { return crypto.createHmac('sha256', process.env.MONERO_PROOF_SECRET).update(payload).digest('base64url'); }
function encodeProof(payload) { const raw = Buffer.from(JSON.stringify(payload)).toString('base64url'); return `${raw}.${sign(raw)}`; }
function decodeProof(token) {
  if (typeof token !== 'string' || token.length > 4096) return null;
  const [raw, signature] = token.split('.');
  const expected = raw ? sign(raw) : '';
  if (!raw || !signature || signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return null;
  try { return JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')); } catch { return null; }
}
async function rpc(method, params = {}) {
  const endpoint = new URL(process.env.MONERO_WALLET_RPC_URL);
  const headers = { 'content-type': 'application/json' };
  if (endpoint.username) headers.authorization = `Basic ${Buffer.from(`${decodeURIComponent(endpoint.username)}:${decodeURIComponent(endpoint.password)}`).toString('base64')}`;
  endpoint.username = ''; endpoint.password = '';
  const response = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 'phantomoperator', method, params }), signal: AbortSignal.timeout(15000) });
  const json = await response.json().catch(() => ({}));
  if (!response.ok || json.error) throw new Error((json.error && json.error.message) || `Monero wallet RPC HTTP ${response.status}`);
  return json.result;
}
async function quote({ route, body, baseUrl }) {
  if (!configured()) throw new Error('Monero payments are not configured. Use Base USDC x402 instead.');
  const price = Number(process.env.MONERO_USD_PER_XMR);
  const amount = (BigInt(Math.ceil(route.priceUsd * 100000000)) * ATOMIC_UNITS) / BigInt(Math.round(price * 100000000));
  const address = await rpc('create_address', { account_index: Number(process.env.MONERO_ACCOUNT_INDEX || 0), label: `po:${route.id}` });
  if (!address.address || !Number.isInteger(address.address_index)) throw new Error('Monero wallet RPC did not return a subaddress.');
  const id = crypto.randomUUID();
  const now = Date.now();
  const invoice = { id, route: route.id, requestHash: requestHash(body), address: address.address, addressIndex: address.address_index, amountAtomic: amount.toString(), amountXmr: (Number(amount) / 1e12).toFixed(12), createdAt: now, expiresAt: now + 30 * 60 * 1000, status: 'pending' };
  const data = load(); data.invoices[id] = invoice; save(data);
  return { invoiceId: id, paymentMethod: 'monero', address: invoice.address, amountAtomic: invoice.amountAtomic, amountXmr: invoice.amountXmr, expiresAt: new Date(invoice.expiresAt).toISOString(), statusUrl: `${baseUrl}/billing/monero-invoice/${id}` };
}
async function status(id) {
  const data = load(); const invoice = data.invoices[id];
  if (!invoice) return null;
  if (invoice.status === 'paid') return invoice;
  if (Date.now() > invoice.expiresAt) { invoice.status = 'expired'; save(data); return invoice; }
  const txs = await rpc('get_transfers', { in: true, account_index: Number(process.env.MONERO_ACCOUNT_INDEX || 0), min_height: 0 });
  const received = (txs.in || []).filter((tx) => tx.subaddr_index && tx.subaddr_index.minor === invoice.addressIndex && BigInt(tx.amount || 0) >= BigInt(invoice.amountAtomic) && Number(tx.confirmations || 0) >= Number(process.env.MONERO_MIN_CONFIRMATIONS || 10));
  if (received.length) { invoice.status = 'paid'; invoice.paidAt = Date.now(); invoice.txid = received[0].txid; save(data); }
  return invoice;
}
async function verifyForRequest(token, route, body) {
  if (!configured()) return { ok: false, status: 503, message: 'Monero payments are not configured.' };
  const proof = decodeProof(token);
  if (!proof || proof.route !== route.id || proof.requestHash !== requestHash(body) || !proof.invoiceId) return { ok: false, status: 402, message: 'Invalid Monero payment proof.' };
  const invoice = await status(proof.invoiceId);
  if (!invoice || invoice.status !== 'paid' || invoice.route !== route.id || invoice.requestHash !== requestHash(body)) return { ok: false, status: 402, message: 'Monero invoice is not yet paid and confirmed.' };
  if (invoice.redeemedAt) return { ok: false, status: 409, message: 'Monero invoice already redeemed.' };
  invoice.redeemedAt = Date.now(); const data = load(); data.invoices[invoice.id] = invoice; save(data);
  return { ok: true, invoice };
}
function paymentProof(invoice) { return encodeProof({ invoiceId: invoice.id, route: invoice.route, requestHash: invoice.requestHash, issuedAt: Date.now() }); }
module.exports = { configured, quote, status, verifyForRequest, paymentProof };

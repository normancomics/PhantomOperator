'use strict';

// Durable bearer-credit ledger. Tokens are shown only at issuance and only a
// SHA-256 digest is persisted. This is a single-host SQLite ledger; migrate to
// a managed database before horizontal scaling.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

function hash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

class CreditLedger {
  constructor(filename) {
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(filename);
    try { fs.chmodSync(filename, 0o600); } catch { /* platform dependent */ }
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    this.db.exec(`CREATE TABLE IF NOT EXISTS credits (
      token_hash TEXT PRIMARY KEY,
      balance_cents INTEGER NOT NULL CHECK(balance_cents >= 0),
      issued_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS credit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL,
      kind TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      route TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS stripe_purchases (
      purchase_id TEXT PRIMARY KEY,
      checkout_session_id TEXT UNIQUE,
      token_hash TEXT NOT NULL,
      amount_cents INTEGER NOT NULL CHECK(amount_cents >= 50),
      fulfilled_at INTEGER
    );`);
    this.issueStmt = this.db.prepare('INSERT INTO credits (token_hash, balance_cents, issued_at, updated_at) VALUES (?, ?, ?, ?)');
    this.balanceStmt = this.db.prepare('SELECT balance_cents, issued_at, updated_at FROM credits WHERE token_hash = ?');
    this.debitStmt = this.db.prepare('UPDATE credits SET balance_cents = balance_cents - ?, updated_at = ? WHERE token_hash = ? AND balance_cents >= ?');
    this.creditStmt = this.db.prepare('UPDATE credits SET balance_cents = balance_cents + ?, updated_at = ? WHERE token_hash = ?');
    this.eventStmt = this.db.prepare('INSERT INTO credit_events (token_hash, kind, amount_cents, route, created_at) VALUES (?, ?, ?, ?, ?)');
    this.pendingPurchaseStmt = this.db.prepare('INSERT INTO stripe_purchases (purchase_id, token_hash, amount_cents) VALUES (?, ?, ?)');
    this.attachSessionStmt = this.db.prepare('UPDATE stripe_purchases SET checkout_session_id = ? WHERE purchase_id = ? AND checkout_session_id IS NULL');
    this.purchaseStmt = this.db.prepare('SELECT purchase_id, checkout_session_id, token_hash, amount_cents, fulfilled_at FROM stripe_purchases WHERE purchase_id = ?');
    this.fulfillStmt = this.db.prepare('UPDATE stripe_purchases SET fulfilled_at = ? WHERE purchase_id = ? AND fulfilled_at IS NULL');
  }

  createToken() {
    return `po_credit_${crypto.randomBytes(32).toString('base64url')}`;
  }

  createPendingStripePurchase(purchaseId, token, amountCents) {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(purchaseId)) throw new Error('Invalid purchase ID.');
    if (!Number.isSafeInteger(amountCents) || amountCents < 50) throw new Error('Credit purchase must be at least 50 cents.');
    this.pendingPurchaseStmt.run(purchaseId, hash(token), amountCents);
  }

  attachStripeSession(purchaseId, sessionId) {
    if (!/^cs_[A-Za-z0-9_]+$/.test(sessionId)) throw new Error('Invalid Stripe checkout session.');
    const result = this.attachSessionStmt.run(sessionId, purchaseId);
    if (result.changes !== 1) throw new Error('Checkout session cannot be attached to this purchase.');
  }

  fulfillStripePurchase(purchaseId, sessionId, amountCents) {
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const purchase = this.purchaseStmt.get(purchaseId);
      if (!purchase || purchase.checkout_session_id !== sessionId || purchase.amount_cents !== amountCents) throw new Error('Stripe purchase does not match the pending order.');
      if (purchase.fulfilled_at) { this.db.exec('COMMIT'); return false; }
      this.issueStmt.run(purchase.token_hash, amountCents, now, now);
      this.eventStmt.run(purchase.token_hash, 'purchase', amountCents, 'stripe-checkout', now);
      this.fulfillStmt.run(now, purchaseId);
      this.db.exec('COMMIT');
      return true;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }

  issue(amountCents) {
    if (!Number.isSafeInteger(amountCents) || amountCents < 50) throw new Error('Credit purchase must be at least 50 cents.');
    const token = `po_credit_${crypto.randomBytes(32).toString('base64url')}`;
    const tokenHash = hash(token);
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.issueStmt.run(tokenHash, amountCents, now, now);
      this.eventStmt.run(tokenHash, 'purchase', amountCents, 'stripe-mpp', now);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return { token, balanceCents: amountCents };
  }

  balance(token) {
    if (typeof token !== 'string' || !token.startsWith('po_credit_')) return null;
    const row = this.balanceStmt.get(hash(token));
    return row ? { balanceCents: row.balance_cents, issuedAt: new Date(row.issued_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString() } : null;
  }

  debit(token, amountCents, route) {
    if (!Number.isSafeInteger(amountCents) || amountCents < 1) throw new Error('Invalid credit amount.');
    const tokenHash = hash(token || '');
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = this.debitStmt.run(amountCents, now, tokenHash, amountCents);
      if (result.changes !== 1) { this.db.exec('ROLLBACK'); return false; }
      this.eventStmt.run(tokenHash, 'debit', -amountCents, route, now);
      this.db.exec('COMMIT');
      return true;
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch { /* transaction already closed */ }
      throw error;
    }
  }

  refund(token, amountCents, route) {
    const tokenHash = hash(token || '');
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = this.creditStmt.run(amountCents, now, tokenHash);
      if (result.changes !== 1) throw new Error('Cannot refund an unknown credit token.');
      this.eventStmt.run(tokenHash, 'refund', amountCents, route, now);
      this.db.exec('COMMIT');
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch { /* transaction already closed */ }
      throw error;
    }
  }
}

module.exports = { CreditLedger };

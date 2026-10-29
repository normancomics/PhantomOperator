'use strict';

// Durable single-host atomic store for MPP replay protection. SQLite WAL keeps
// state across restarts; use a managed shared store before multi-host scaling.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

class SqliteAtomicStore {
  constructor(filename) {
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(filename);
    try { fs.chmodSync(filename, 0o600); } catch { /* file permissions are platform dependent */ }
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    this.db.exec('CREATE TABLE IF NOT EXISTS mpp_store (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER)');
    this.getStmt = this.db.prepare('SELECT value FROM mpp_store WHERE key = ?');
    this.putStmt = this.db.prepare('INSERT INTO mpp_store (key, value, expires_at) VALUES (?, ?, NULL) ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = NULL');
    this.deleteStmt = this.db.prepare('DELETE FROM mpp_store WHERE key = ?');
    this.claimStmt = this.db.prepare('INSERT OR IGNORE INTO mpp_store (key, value, expires_at) VALUES (?, ?, ?)');
    this.expiredStmt = this.db.prepare('DELETE FROM mpp_store WHERE key = ? AND expires_at IS NOT NULL AND expires_at <= ?');
  }

  get(key) {
    const row = this.getStmt.get(String(key));
    return row ? JSON.parse(row.value) : null;
  }

  put(key, value) {
    this.putStmt.run(String(key), JSON.stringify(value));
  }

  delete(key) {
    this.deleteStmt.run(String(key));
  }

  update(key, fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.get(key);
      const change = fn(current);
      if (!change || !['noop', 'set', 'delete'].includes(change.op)) throw new Error('Invalid atomic-store change.');
      if (change.op === 'set') this.put(key, change.value);
      if (change.op === 'delete') this.delete(key);
      this.db.exec('COMMIT');
      return change.result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  tryClaim(key, expires) {
    if (!Number.isSafeInteger(expires) || expires <= Date.now()) return false;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.expiredStmt.run(String(key), Date.now());
      const result = this.claimStmt.run(String(key), JSON.stringify({ expires, type: 'mppx:replay' }), expires);
      this.db.exec('COMMIT');
      return result.changes === 1;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
}

module.exports = { SqliteAtomicStore };

/**
 * middleware/security.js
 *
 * Security middleware for SovereignAgent HTTP server.
 *
 *  - Sliding-window rate limiter (per IP, configurable limits)
 *  - Hardened HTTP security headers (CSP, X-Content-Type-Options, etc.)
 *  - Request body size cap
 *  - Input sanitization helpers (string scrubbing, email/URL validation)
 */

'use strict';

// ── Rate Limiter ──────────────────────────────────────────────────────────────
// Sliding window per IP stored in an in-memory Map.
// Safe for single-process deployments; swap to Redis for multi-instance.

const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute

/** Max requests per window for public (unauthenticated) endpoints. */
const RATE_LIMIT_PUBLIC = parseInt(process.env.RATE_LIMIT_PUBLIC || '60', 10);
/** Max requests per window for paid skill endpoints. */
const RATE_LIMIT_PAID   = parseInt(process.env.RATE_LIMIT_PAID   || '20', 10);

// ip → array of hit timestamps (within the current window)
const _windows = new Map();

// Sweep stale entries every 5 minutes to prevent unbounded memory growth
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS;
  for (const [ip, timestamps] of _windows) {
    const fresh = timestamps.filter(t => t > cutoff);
    if (fresh.length === 0) _windows.delete(ip);
    else _windows.set(ip, fresh);
  }
}, 5 * 60 * 1000).unref(); // .unref() so the timer doesn't block process exit

/**
 * Check and record a rate-limit hit for an IP address.
 *
 * @param {string} ip - caller IP address
 * @param {number} limit - max requests allowed in the window
 * @returns {{ allowed: boolean, remaining: number, retryAfter: number }}
 */
function checkRateLimit(ip, limit) {
  const now    = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;

  const timestamps = (_windows.get(ip) || []).filter(t => t > cutoff);

  if (timestamps.length >= limit) {
    const retryAfter = Math.ceil((timestamps[0] + RATE_LIMIT_WINDOW_MS - now) / 1000);
    return { allowed: false, remaining: 0, retryAfter };
  }

  timestamps.push(now);
  _windows.set(ip, timestamps);
  return { allowed: true, remaining: limit - timestamps.length, retryAfter: 0 };
}

// ── Security Headers ──────────────────────────────────────────────────────────

/**
 * Apply hardened HTTP security headers to every response.
 * @param {import('http').ServerResponse} res
 */
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
}

// ── Body Size Cap ─────────────────────────────────────────────────────────────

/** Maximum allowed request body size in bytes (default 64 KB). */
const MAX_BODY_BYTES = parseInt(process.env.MAX_BODY_BYTES || String(64 * 1024), 10);

// ── Input Sanitizers ──────────────────────────────────────────────────────────

const MAX_STRING_LEN = 512;

/**
 * Sanitize a free-text string: strip null bytes, non-printable control
 * characters, trim whitespace, and enforce a max length.
 *
 * @param {string} value
 * @param {number} [maxLen=512]
 * @returns {string}
 */
function sanitizeString(value, maxLen = MAX_STRING_LEN) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\0/g, '')                               // null bytes
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // non-printable controls
    .trim()
    .slice(0, maxLen);
}

/**
 * Validate that a value is a well-formed email address (structural check only —
 * no network calls are made).
 * @param {string} value
 * @returns {boolean}
 */
function isValidEmail(value) {
  return (
    typeof value === 'string' &&
    value.length <= 254 &&
    /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(value)
  );
}

/**
 * Validate that a value is an absolute HTTP or HTTPS URL.
 * @param {string} value
 * @returns {boolean}
 */
function isValidHttpUrl(value) {
  if (typeof value !== 'string') return false;
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

module.exports = {
  checkRateLimit,
  setSecurityHeaders,
  sanitizeString,
  isValidEmail,
  isValidHttpUrl,
  RATE_LIMIT_PUBLIC,
  RATE_LIMIT_PAID,
  MAX_BODY_BYTES,
};

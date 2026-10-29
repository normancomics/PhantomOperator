/**
 * middleware/security.js
 *
 * Security hardening middleware for the PhantomOperator HTTP server:
 *  - CORS headers
 *  - Security response headers (CSP, HSTS, X-Frame-Options, etc.)
 *  - Request body size limit guard
 *  - In-memory sliding-window rate limiter (no external Redis dependency)
 *  - Input validation / sanitisation helpers for each skill endpoint
 */

'use strict';

// ─── CORS ────────────────────────────────────────────────────────────────────

const ALLOWED_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map((o) => o.trim())
  : []; // Same-origin by default; explicitly opt in to browser cross-origin callers.

function corsHeaders(req, res, next) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, Payment-Authorization, X-Payment, X-Payment-Method, Payment-Signature, X-Payment-Response, X-Requested-With'
  );
  res.setHeader(
    'Access-Control-Expose-Headers',
    'WWW-Authenticate, Payment-Receipt, PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset'
  );
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  return next();
}

// ─── Security Headers ────────────────────────────────────────────────────────

function securityHeaders(_req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'"
  );
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  res.removeHeader('X-Powered-By');
  return next();
}

// ─── Sliding-Window Rate Limiter ─────────────────────────────────────────────

function createRateLimiter({ windowMs = 60_000, max = 60 } = {}) {
  const hits = new Map();

  const cleanup = setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [ip, timestamps] of hits.entries()) {
      const fresh = timestamps.filter((t) => t > cutoff);
      if (fresh.length === 0) {
        hits.delete(ip);
      } else {
        hits.set(ip, fresh);
      }
    }
  }, windowMs);
  if (cleanup.unref) cleanup.unref();

  return function rateLimiter(req, res, next) {
    if (process.env.RATE_LIMIT_DISABLED === 'true') return next();

    const forwarded = req.headers['x-forwarded-for'];
    const ip = (forwarded ? String(forwarded).split(',')[0].trim() : req.ip) || 'unknown';
    const now = Date.now();
    const cutoff = now - windowMs;

    const prev = (hits.get(ip) || []).filter((t) => t > cutoff);
    prev.push(now);
    hits.set(ip, prev);

    const remaining = Math.max(0, max - prev.length);
    const resetSec = Math.ceil((prev[0] + windowMs - now) / 1000);

    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(resetSec));

    if (prev.length > max) {
      res.setHeader('Retry-After', String(resetSec));
      return res.status(429).json({
        error: 'Too Many Requests',
        retryAfterSeconds: resetSec,
      });
    }
    return next();
  };
}

const publicLimiter = createRateLimiter({
  windowMs: 60_000,
  max: parseInt(process.env.RATE_LIMIT_PUBLIC || '60', 10),
});

const paidLimiter = createRateLimiter({
  windowMs: 60_000,
  max: parseInt(process.env.RATE_LIMIT_PAID || '20', 10),
});

// Free previews trigger outbound URL fetches, so keep their per-client budget low.
const previewLimiter = createRateLimiter({
  windowMs: 60 * 60_000,
  max: parseInt(process.env.RATE_LIMIT_PREVIEW || '5', 10),
});

// ─── Input Validation Helpers ────────────────────────────────────────────────

const EMAIL_RE       = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/;
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HANDLE_RE      = /^@?[a-zA-Z0-9._-]{1,64}$/;
const MAX_STR_LEN    = 512;

function isNonEmptyString(val, maxLen = MAX_STR_LEN) {
  return typeof val === 'string' && val.trim().length > 0 && val.trim().length <= maxLen;
}

function isValidHttpUrl(val) {
  if (!isNonEmptyString(val, 2048)) return false;
  try {
    const parsed = new URL(val.trim());
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function validateSkillInput(skillId) {
  return function validator(req, res, next) {
    const body = req.body || {};

    switch (skillId) {
      case 'threat-scan': {
        if (!isNonEmptyString(body.fullName, 128)) {
          return res.status(400).json({
            error: 'fullName is required and must be a non-empty string (max 128 chars).',
          });
        }
        break;
      }

      case 'data-removal': {
        if (!isValidHttpUrl(body.link)) {
          return res.status(400).json({
            error: 'link is required and must be a valid http:// or https:// URL.',
          });
        }
        if (body.fullName !== undefined && !isNonEmptyString(body.fullName, 128)) {
          return res.status(400).json({
            error: 'fullName, when provided, must be a non-empty string (max 128 chars).',
          });
        }
        break;
      }

      case 'full-privacy-sweep': {
        if (!isNonEmptyString(body.fullName, 128)) {
          return res.status(400).json({
            error: 'fullName is required and must be a non-empty string (max 128 chars).',
          });
        }
        if (body.walletAddress !== undefined && !EVM_ADDRESS_RE.test(String(body.walletAddress))) {
          return res.status(400).json({
            error: 'walletAddress, when provided, must be a valid 0x-prefixed 40-hex-char EVM address.',
          });
        }
        break;
      }

      case 'opsec-score': {
        const hasName   = isNonEmptyString(body.fullName, 128);
        const hasHandle = isNonEmptyString(body.handle, 64);
        const hasEmail  = isNonEmptyString(body.email, 320);

        if (!hasName && !hasHandle && !hasEmail) {
          return res.status(400).json({
            error: 'At least one of fullName, handle, or email is required.',
          });
        }
        if (hasEmail && !EMAIL_RE.test(body.email.trim())) {
          return res.status(400).json({ error: 'email must be a valid email address.' });
        }
        if (hasHandle && !HANDLE_RE.test(body.handle.trim())) {
          return res.status(400).json({
            error: 'handle may only contain letters, digits, dots, underscores, or hyphens (max 64 chars).',
          });
        }
        break;
      }

      case 'breach-check': {
        if (!isNonEmptyString(body.email, 320) || !EMAIL_RE.test(body.email.trim())) {
          return res.status(400).json({
            error: 'email is required and must be a valid email address.',
          });
        }
        if (body.password !== undefined && (typeof body.password !== 'string' || body.password.length > 256)) {
          return res.status(400).json({
            error: 'password, when provided, must be a string (max 256 chars).',
          });
        }
        break;
      }

      case 'metadata-audit': {
        if (!isValidHttpUrl(body.url)) {
          return res.status(400).json({
            error: 'url is required and must be a valid http:// or https:// URL.',
          });
        }
        break;
      }

      case 'monero-opsec-audit': {
        if (body.xmrAddress !== undefined && !isNonEmptyString(body.xmrAddress, 256)) {
          return res.status(400).json({
            error: 'xmrAddress, when provided, must be a non-empty string.',
          });
        }
        break;
      }

      case 'spam-caller-removal': {
        const phone = String(body.phoneNumber || '').replace(/[\s().-]/g, '');
        if (!/^\+?[1-9]\d{6,14}$/.test(phone)) {
          return res.status(400).json({ error: 'phoneNumber is required and must be in international format.' });
        }
        if (body.authorized !== true) {
          return res.status(400).json({ error: 'authorized must be true; only request guidance for your own number or an authorized client.' });
        }
        if (body.provider !== undefined && !['truecaller', 'hiya', 'robokiller', 'whitepages'].includes(body.provider)) {
          return res.status(400).json({ error: 'provider must be truecaller, hiya, robokiller, or whitepages.' });
        }
        break;
      }

      case 'wallet-opsec-audit': {
        if (!isNonEmptyString(body.walletAddress, 64) || !EVM_ADDRESS_RE.test(body.walletAddress.trim())) {
          return res.status(400).json({
            error: 'walletAddress is required and must be a valid 0x-prefixed 40-hex-char EVM address.',
          });
        }
        break;
      }

      case 'cypherpunk-redteam-dossier':
      case 'sovereign-opsec-retainer': {
        if (body.url !== undefined && !isValidHttpUrl(body.url)) {
          return res.status(400).json({ error: 'url, when provided, must be a valid http:// or https:// URL.' });
        }
        break;
      }

      default:
        break;
    }

    return next();
  };
}

// ─── Body Size Guard ─────────────────────────────────────────────────────────

const configuredMaxBodyBytes = parseInt(process.env.MAX_BODY_BYTES || '16384', 10);
const MAX_BODY_BYTES = Number.isSafeInteger(configuredMaxBodyBytes) && configuredMaxBodyBytes > 0
  ? configuredMaxBodyBytes
  : 16384;

function bodySizeGuard(req, res, next) {
  const len = parseInt(req.headers['content-length'] || '0', 10);
  if (len > MAX_BODY_BYTES) {
    return res.status(413).json({
      error: 'Payload Too Large',
      maxBytes: MAX_BODY_BYTES,
    });
  }
  return next();
}

module.exports = {
  corsHeaders,
  securityHeaders,
  bodySizeGuard,
  createRateLimiter,
  publicLimiter,
  paidLimiter,
  previewLimiter,
  validateSkillInput,
  isValidHttpUrl,
  EMAIL_RE,
  EVM_ADDRESS_RE,
};

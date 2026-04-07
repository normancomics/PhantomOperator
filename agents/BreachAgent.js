/**
 * BreachAgent.js
 *
 * Checks email addresses and passwords against known breach datasets using the
 * HaveIBeenPwned (HIBP) APIs with privacy-preserving k-anonymity.
 *
 *  Password check   — uses the HIBP k-anonymity range API.  No API key required.
 *                     Only the first 5 hex characters of the SHA-1 hash are ever
 *                     sent to the server; the full hash never leaves this process.
 *
 *  Email breach check — uses the HIBP v3 breachedaccount API.  Requires
 *                       HIBP_API_KEY in .env.  If the key is absent the function
 *                       returns a graceful "key required" entry so callers can
 *                       still surface a partial result.
 *
 * k-anonymity reference: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
 */

'use strict';

require('dotenv').config();
const crypto = require('crypto');
const axios  = require('axios');

const HIBP_API_BASE            = 'https://haveibeenpwned.com/api/v3';
const HIBP_PWNED_PASSWORDS_BASE = 'https://api.pwnedpasswords.com';
const HIBP_API_KEY             = process.env.HIBP_API_KEY;
const USER_AGENT               = 'SovereignAgent-BreachCheck/1.0 (https://github.com/normancomics/sovereignagent)';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** SHA-1 hash a string and return uppercase hex.
 *
 * NOTE: SHA-1 is used here solely because the HaveIBeenPwned k-anonymity
 * range API requires SHA-1 hashes per its documented specification:
 * https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
 * This is NOT a password storage hash — no hash is ever persisted.
 * Only the first 5 hex characters are transmitted to the remote API.
 */
function sha1(input) {
  return crypto.createHash('sha1').update(input).digest('hex').toUpperCase();
}

// ── Password check (k-anonymity, no API key) ──────────────────────────────────

/**
 * Check whether a plaintext password has appeared in any known data breach.
 *
 * Uses the HIBP k-anonymity range API: only the first 5 hex characters of the
 * SHA-1 hash are transmitted.  The server returns all matching hash suffixes;
 * local matching is performed in-process.
 *
 * @param {string} password - plaintext password to check
 * @returns {Promise<{ pwned: boolean, count: number }>}
 */
async function checkPassword(password) {
  const hash   = sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const { data } = await axios.get(`${HIBP_PWNED_PASSWORDS_BASE}/range/${prefix}`, {
    headers: { 'User-Agent': USER_AGENT, 'Add-Padding': 'true' },
    timeout: 10000,
  });

  for (const line of data.split('\r\n')) {
    const [lineSuffix, count] = line.split(':');
    if (lineSuffix && lineSuffix.trim().toUpperCase() === suffix) {
      return { pwned: true, count: parseInt(count, 10) };
    }
  }
  return { pwned: false, count: 0 };
}

// ── Email breach check (HIBP API v3) ─────────────────────────────────────────

/**
 * Look up all known data breaches for an email address.
 *
 * Requires HIBP_API_KEY in .env (see https://haveibeenpwned.com/API/Key).
 * When the key is not configured, returns a single sentinel entry so callers
 * can detect the missing-key case without throwing.
 *
 * @param {string} email - email address to check
 * @returns {Promise<Array<{name,title,domain,breachDate,dataClasses,isVerified}>>}
 */
async function checkEmail(email) {
  if (!HIBP_API_KEY) {
    return [{
      name:        'KEY_REQUIRED',
      title:       'HIBP API Key Required',
      domain:      null,
      breachDate:  null,
      dataClasses: [],
      isVerified:  false,
      note:        'Set HIBP_API_KEY in .env to enable email breach lookup. ' +
                   'Get a key at https://haveibeenpwned.com/API/Key',
    }];
  }

  try {
    const { data } = await axios.get(
      `${HIBP_API_BASE}/breachedaccount/${encodeURIComponent(email)}`,
      {
        headers: {
          'hibp-api-key': HIBP_API_KEY,
          'User-Agent':   USER_AGENT,
        },
        params:  { truncateResponse: false },
        timeout: 15000,
      }
    );

    return (data || []).map(b => ({
      name:        b.Name,
      title:       b.Title,
      domain:      b.Domain,
      breachDate:  b.BreachDate,
      dataClasses: b.DataClasses,
      isVerified:  b.IsVerified,
    }));
  } catch (err) {
    // 404 = address not found in any breach (normal / good outcome)
    if (err.response && err.response.status === 404) return [];
    throw err;
  }
}

// ── Full breach report ────────────────────────────────────────────────────────

// Data classes that indicate especially serious credential or financial exposure
const CRITICAL_DATA_CLASSES = new Set([
  'Passwords', 'Credit cards', 'Social security numbers',
  'Bank account numbers', 'Private messages', 'Auth tokens',
]);

/**
 * Build a structured breach report for an email address.
 *
 * @param {string} email
 * @returns {Promise<{
 *   email: string,
 *   breachCount: number,
 *   breaches: Array,
 *   riskLevel: 'none'|'unknown'|'medium'|'high'|'critical',
 *   criticalDataClasses: string[],
 *   recommendation: string
 * }>}
 */
async function getBreachReport(email) {
  const breaches      = await checkEmail(email);
  const hasKeyError   = breaches.some(b => b.name === 'KEY_REQUIRED');
  const realBreaches  = breaches.filter(b => b.name !== 'KEY_REQUIRED');

  let riskLevel = 'none';
  if (hasKeyError)             riskLevel = 'unknown';
  else if (realBreaches.length > 5) riskLevel = 'critical';
  else if (realBreaches.length > 2) riskLevel = 'high';
  else if (realBreaches.length > 0) riskLevel = 'medium';

  const criticalDataClasses = [...new Set(
    realBreaches
      .flatMap(b => b.dataClasses || [])
      .filter(dc => CRITICAL_DATA_CLASSES.has(dc))
  )];

  // Escalate risk level if critical data classes are present
  if (criticalDataClasses.length > 0 && riskLevel === 'medium') riskLevel = 'high';

  const recommendation =
    hasKeyError
      ? 'Set HIBP_API_KEY to enable full breach lookup.'
      : riskLevel === 'none'
        ? 'No known breaches found. Stay vigilant and use unique passwords per service.'
        : `Found in ${realBreaches.length} breach(es). Change all reused passwords immediately, enable 2FA, and monitor your accounts.`;

  return {
    email,
    breachCount: realBreaches.length,
    breaches: hasKeyError ? breaches : realBreaches,
    riskLevel,
    criticalDataClasses,
    recommendation,
  };
}

module.exports = { checkPassword, checkEmail, getBreachReport };

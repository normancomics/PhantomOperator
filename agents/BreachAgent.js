/**
 * BreachAgent.js
 *
 * Checks email addresses and passwords against known breach datasets:
 *  1. Password check — HIBP k-anonymity range API (no API key required; only
 *     5-char SHA-1 prefix transmitted).
 *  2. Email breach check — Uses HIBP v3 if HIBP_API_KEY is set, and falls back
 *     automatically to the keyless XposedOrNot public breach intelligence API
 *     (https://api.xposedornot.com/v1/check-email/{email}) so email breach
 *     checks work out-of-the-box in production without requiring a paid key.
 */

'use strict';

require('dotenv').config();
const crypto = require('crypto');
const axios  = require('axios');

const HIBP_API_BASE             = 'https://haveibeenpwned.com/api/v3';
const HIBP_PWNED_PASSWORDS_BASE = 'https://api.pwnedpasswords.com';
const XPOSED_API_BASE           = 'https://api.xposedornot.com/v1';
const USER_AGENT                = 'PhantomOperator-BreachCheck/1.0 (https://github.com/normancomics/PhantomOperator)';

function sha1(input) {
  return crypto.createHash('sha1').update(input).digest('hex').toUpperCase();
}

async function checkPassword(password) {
  const hash   = sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const { data } = await axios.get(`${HIBP_PWNED_PASSWORDS_BASE}/range/${prefix}`, {
    headers: { 'User-Agent': USER_AGENT, 'Add-Padding': 'true' },
    timeout: 10000,
  });

  for (const line of String(data).split(/\r?\n/)) {
    const [lineSuffix, count] = line.split(':');
    if (lineSuffix && lineSuffix.trim().toUpperCase() === suffix) {
      return { pwned: true, count: parseInt(count, 10) };
    }
  }
  return { pwned: false, count: 0 };
}

async function checkEmail(email) {
  const hibpKey = process.env.HIBP_API_KEY;
  if (hibpKey) {
    try {
      const { data } = await axios.get(
        `${HIBP_API_BASE}/breachedaccount/${encodeURIComponent(email)}`,
        {
          headers: { 'hibp-api-key': hibpKey, 'User-Agent': USER_AGENT },
          params:  { truncateResponse: false },
          timeout: 12000,
        }
      );
      return (data || []).map((b) => ({
        name:        b.Name,
        title:       b.Title,
        domain:      b.Domain,
        breachDate:  b.BreachDate,
        dataClasses: b.DataClasses || ['Email addresses', 'Passwords'],
        isVerified:  b.IsVerified,
        source:      'HIBP',
      }));
    } catch (err) {
      if (err.response && err.response.status === 404) return [];
    }
  }

  // Keyless fallback via XposedOrNot public API
  try {
    const { data } = await axios.get(
      `${XPOSED_API_BASE}/check-email/${encodeURIComponent(email)}`,
      { headers: { 'User-Agent': USER_AGENT }, timeout: 10000 }
    );
    const list = (data && Array.isArray(data.breaches) && Array.isArray(data.breaches[0]))
      ? data.breaches[0]
      : (data && Array.isArray(data.breaches) ? data.breaches : []);

    return list.map((name) => ({
      name:        String(name),
      title:       String(name),
      domain:      null,
      breachDate:  null,
      dataClasses: ['Email addresses', 'Passwords'],
      isVerified:  true,
      source:      'XposedOrNot',
    }));
  } catch (err) {
    if (err.response && err.response.status === 404) return [];
    return [{
      name:        'KEY_REQUIRED',
      title:       'Breach Lookup Unavailable',
      domain:      null,
      breachDate:  null,
      dataClasses: [],
      isVerified:  false,
      note:        `Public breach API unreachable (${err.message}).`,
    }];
  }
}

const CRITICAL_DATA_CLASSES = new Set([
  'Passwords', 'Credit cards', 'Social security numbers',
  'Bank account numbers', 'Private messages', 'Auth tokens',
]);

async function getBreachReport(email, password) {
  const breaches     = await checkEmail(email);
  const hasKeyError  = breaches.some((b) => b.name === 'KEY_REQUIRED');
  const realBreaches = breaches.filter((b) => b.name !== 'KEY_REQUIRED');

  let passwordResult = null;
  if (password && typeof password === 'string') {
    try {
      passwordResult = await checkPassword(password);
    } catch {
      passwordResult = null;
    }
  }

  let riskLevel = 'none';
  if (hasKeyError)               riskLevel = 'unknown';
  else if (realBreaches.length > 5) riskLevel = 'critical';
  else if (realBreaches.length > 2) riskLevel = 'high';
  else if (realBreaches.length > 0) riskLevel = 'medium';

  if (passwordResult && passwordResult.pwned) {
    riskLevel = passwordResult.count > 100 ? 'critical' : 'high';
  }

  const criticalDataClasses = [...new Set(
    realBreaches
      .flatMap((b) => b.dataClasses || [])
      .filter((dc) => CRITICAL_DATA_CLASSES.has(dc))
  )];

  if (criticalDataClasses.length > 0 && riskLevel === 'medium') riskLevel = 'high';

  const recommendation =
    hasKeyError
      ? 'Set HIBP_API_KEY or retry keyless XposedOrNot breach intelligence.'
      : riskLevel === 'none'
        ? 'No known breaches found. Stay vigilant, use unique passwords per service, and rotate credentials regularly.'
        : `Found in ${realBreaches.length} breach(es). Rotate compromised credentials immediately, enable hardware/TOTP 2FA, and isolate email aliases per service.`;

  return {
    email,
    breachCount: realBreaches.length,
    breaches: hasKeyError ? breaches : realBreaches,
    passwordCheck: passwordResult,
    riskLevel,
    criticalDataClasses,
    recommendation,
  };
}

module.exports = { checkPassword, checkEmail, getBreachReport };

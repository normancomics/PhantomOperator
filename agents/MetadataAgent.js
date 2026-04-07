/**
 * MetadataAgent.js
 *
 * HTTP and HTML metadata privacy auditor.
 *
 * Fetches a target URL and analyses all metadata that could inadvertently
 * reveal the identity of the author, the technology stack, the server
 * environment, or the physical location of infrastructure:
 *
 *   - HTTP response headers (Server, X-Powered-By, X-Generator, Via, …)
 *   - HTML <meta> tags (author, generator, description, keywords, geo.*)
 *   - Open Graph / Twitter Card tags
 *   - Inline HTML comments (often contain version strings, file paths, CMS names)
 *   - External resource origins (CDN / third-party script domains)
 *
 * Each finding is classified with a riskLevel:
 *   critical — directly leaks identity / credentials
 *   high     — leaks precise server software/version or author PII
 *   medium   — leaks technology stack or approximate location
 *   low      — informational / minor fingerprint
 *
 * Uses only axios + cheerio (already installed).  No extra dependencies.
 */

'use strict';

const axios   = require('axios');
const cheerio = require('cheerio');

const USER_AGENT = 'SovereignAgent-MetaAudit/1.0 (https://github.com/normancomics/sovereignagent)';
const REQUEST_TIMEOUT_MS = 15000;

// ── SSRF guard ────────────────────────────────────────────────────────────────
// Block requests to private/loopback/link-local addresses and special hostnames
// that would otherwise allow server-side request forgery.

const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|::1|fc|fd)/i;
const PRIVATE_HOST_RE = /^(localhost|.*\.local|.*\.internal|metadata\.google\.internal)$/i;

/**
 * Throw if the URL targets a private, loopback, or otherwise disallowed host.
 * This is a best-effort static guard — runtime DNS rebinding is not prevented
 * here but should be addressed at the network layer for production deployments.
 * @param {string} rawUrl
 */
function assertSafeUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { throw new Error('Invalid URL'); }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS URLs are permitted');
  }

  const host = parsed.hostname;
  if (PRIVATE_HOST_RE.test(host) || PRIVATE_IP_RE.test(host)) {
    throw new Error('Requests to private or internal network addresses are not permitted');
  }
}

// ── Risk classification rules ─────────────────────────────────────────────────

// HTTP headers and the risk each leaks
const HEADER_RISK = {
  // High: software + version
  'server':          { level: 'high',   label: 'Web server fingerprint' },
  'x-powered-by':    { level: 'high',   label: 'Server-side tech stack' },
  'x-generator':     { level: 'high',   label: 'CMS/generator fingerprint' },
  'x-aspnet-version':{ level: 'high',   label: 'ASP.NET version' },
  'x-aspnetmvc-version':{ level:'high', label: 'ASP.NET MVC version' },
  'x-drupal-cache':  { level: 'medium', label: 'Drupal CMS detected' },
  'x-wp-total':      { level: 'medium', label: 'WordPress detected' },
  // Medium: routing / infra
  'via':             { level: 'medium', label: 'Proxy / CDN chain' },
  'x-varnish':       { level: 'medium', label: 'Varnish cache detected' },
  'x-cache':         { level: 'low',    label: 'Cache status disclosed' },
  'x-request-id':    { level: 'low',    label: 'Internal request ID leaked' },
  'x-amz-request-id':{ level: 'medium', label: 'AWS infrastructure detected' },
  'x-amzn-requestid':{ level: 'medium', label: 'AWS ALB/API GW detected' },
  'x-azure-ref':     { level: 'medium', label: 'Azure infrastructure detected' },
  // Missing security headers are their own risk category — handled separately
};

// Meta tag names/properties that carry identity or geo risk
const META_RISK = {
  'author':           { level: 'high',     label: 'Author name in metadata' },
  'creator':          { level: 'high',     label: 'Creator name in metadata' },
  'owner':            { level: 'high',     label: 'Owner name in metadata' },
  'geo.position':     { level: 'medium',   label: 'GPS coordinates in metadata' },
  'geo.placename':    { level: 'medium',   label: 'Geographic location in metadata' },
  'geo.region':       { level: 'low',      label: 'Region code in metadata' },
  'generator':        { level: 'medium',   label: 'CMS/generator disclosed in <meta>' },
  'copyright':        { level: 'low',      label: 'Copyright attribution in metadata' },
  'reply-to':         { level: 'critical', label: 'Email address in reply-to meta tag' },
  'email':            { level: 'critical', label: 'Email address in metadata' },
};

// Security headers that SHOULD be present; absence is flagged
const EXPECTED_SECURITY_HEADERS = [
  'x-content-type-options',
  'x-frame-options',
  'content-security-policy',
  'referrer-policy',
  'permissions-policy',
  'strict-transport-security',
];

const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;

// ── MetadataAgent ─────────────────────────────────────────────────────────────

class MetadataAgent {
  /**
   * Fetch a URL and return a full privacy/metadata audit report.
   *
   * @param {string} targetUrl - absolute HTTP/HTTPS URL to audit
   * @returns {Promise<MetadataAuditReport>}
   */
  static async audit(targetUrl) {
    // SSRF guard — must run before any network call
    assertSafeUrl(targetUrl);

    const { responseHeaders, body, finalUrl, statusCode } =
      await MetadataAgent._fetch(targetUrl);

    const headerFindings  = MetadataAgent._analyseHeaders(responseHeaders);
    const $ = cheerio.load(body);
    const metaFindings    = MetadataAgent._analyseMeta($);
    const commentFindings = MetadataAgent._analyseComments($, body);
    const resourceFindings = MetadataAgent._analyseExternalResources($, finalUrl);

    const allFindings = [
      ...headerFindings,
      ...metaFindings,
      ...commentFindings,
      ...resourceFindings,
    ];

    const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of allFindings) riskCounts[f.riskLevel] = (riskCounts[f.riskLevel] || 0) + 1;

    const overallRisk =
      riskCounts.critical > 0 ? 'critical' :
      riskCounts.high     > 0 ? 'high'     :
      riskCounts.medium   > 0 ? 'medium'   :
      riskCounts.low      > 0 ? 'low'      : 'none';

    return {
      url:          finalUrl,
      statusCode,
      overallRisk,
      findingCounts: riskCounts,
      findings:     allFindings,
      recommendation: MetadataAgent._buildRecommendation(allFindings, overallRisk),
      timestamp:    new Date().toISOString(),
    };
  }

  // ── Private: HTTP fetch ─────────────────────────────────────────────────────

  static async _fetch(url) {
    const resp = await axios.get(url, {
      headers:          { 'User-Agent': USER_AGENT },
      timeout:          REQUEST_TIMEOUT_MS,
      maxRedirects:     5,
      validateStatus:   () => true, // capture any status code
      responseType:     'text',
      maxContentLength: 2 * 1024 * 1024, // 2 MB cap
    });

    return {
      responseHeaders: resp.headers,
      body:            resp.data || '',
      finalUrl:        resp.request.res.responseUrl || url,
      statusCode:      resp.status,
    };
  }

  // ── Private: Header analysis ────────────────────────────────────────────────

  static _analyseHeaders(headers) {
    const findings = [];

    // Flag known leaky headers
    for (const [name, meta] of Object.entries(HEADER_RISK)) {
      const value = headers[name];
      if (value) {
        findings.push({
          category:  'http-header',
          riskLevel:  meta.level,
          label:      meta.label,
          field:      name,
          value:      String(value),
        });
      }
    }

    // Flag missing security headers
    for (const name of EXPECTED_SECURITY_HEADERS) {
      if (!headers[name]) {
        findings.push({
          category:  'missing-security-header',
          riskLevel:  'medium',
          label:      `Missing security header: ${name}`,
          field:      name,
          value:      null,
        });
      }
    }

    return findings;
  }

  // ── Private: <meta> tag analysis ───────────────────────────────────────────

  static _analyseMeta($) {
    const findings = [];

    $('meta').each((_, el) => {
      const name     = ($(el).attr('name')     || '').toLowerCase();
      const property = ($(el).attr('property') || '').toLowerCase();
      const content  = $(el).attr('content')   || '';

      const key = name || property;
      if (!key || !content) return;

      const risk = META_RISK[key];
      if (risk) {
        findings.push({
          category:  'meta-tag',
          riskLevel:  risk.level,
          label:      risk.label,
          field:      key,
          value:      content,
        });
        return;
      }

      // Catch any meta tag whose value contains an email address
      if (EMAIL_RE.test(content)) {
        findings.push({
          category:  'meta-tag',
          riskLevel:  'critical',
          label:      'Email address embedded in <meta> tag',
          field:      key,
          value:      content,
        });
      }
    });

    return findings;
  }

  // ── Private: HTML comment analysis ─────────────────────────────────────────

  static _analyseComments($, rawHtml) {
    const findings = [];
    const commentRe = /<!--([\s\S]*?)-->/g;
    let match;

    while ((match = commentRe.exec(rawHtml)) !== null) {
      const text = match[1].trim();
      if (!text || text.length < 5) continue;

      // Email in comment
      if (EMAIL_RE.test(text)) {
        findings.push({
          category:  'html-comment',
          riskLevel:  'critical',
          label:      'Email address in HTML comment',
          field:      'comment',
          value:      text.slice(0, 300),
        });
        continue;
      }

      // Version string / path / CMS fingerprint in comment
      const hasVersion = /v\d+\.\d+|\bversion\b|\brelease\b/i.test(text);
      const hasPath    = /\/[a-z0-9_\-]+\/[a-z0-9_\-]+\.[a-z]{2,4}/i.test(text);
      if (hasVersion || hasPath) {
        findings.push({
          category:  'html-comment',
          riskLevel:  'medium',
          label:      'Version string or internal path in HTML comment',
          field:      'comment',
          value:      text.slice(0, 300),
        });
      }
    }

    return findings;
  }

  // ── Private: external resource origin analysis ──────────────────────────────

  static _analyseExternalResources($, pageUrl) {
    const findings = [];
    let pageOrigin = '';
    try { pageOrigin = new URL(pageUrl).origin; } catch { /* ignore */ }

    const attrs = [
      { selector: 'script[src]',     attr: 'src' },
      { selector: 'link[href]',      attr: 'href' },
      { selector: 'img[src]',        attr: 'src' },
      { selector: 'iframe[src]',     attr: 'src' },
    ];

    const thirdPartyOrigins = new Set();

    for (const { selector, attr } of attrs) {
      $(selector).each((_, el) => {
        const raw = $(el).attr(attr) || '';
        try {
          const abs = new URL(raw, pageUrl);
          if ((abs.protocol === 'http:' || abs.protocol === 'https:') &&
              abs.origin !== pageOrigin) {
            thirdPartyOrigins.add(abs.origin);
          }
        } catch { /* relative or invalid URL */ }
      });
    }

    if (thirdPartyOrigins.size > 0) {
      findings.push({
        category:  'third-party-resources',
        riskLevel:  'low',
        label:      `${thirdPartyOrigins.size} third-party resource origin(s) detected (privacy / tracking risk)`,
        field:      'external-origins',
        value:      [...thirdPartyOrigins].join(', '),
      });
    }

    return findings;
  }

  // ── Private: recommendation ─────────────────────────────────────────────────

  static _buildRecommendation(findings, overallRisk) {
    if (overallRisk === 'none') {
      return 'No metadata privacy issues detected. Continue auditing periodically.';
    }

    const parts = [];
    const hasEmail = findings.some(f => f.riskLevel === 'critical');
    const missingHeaders = findings.filter(f => f.category === 'missing-security-header');
    const leakyHeaders   = findings.filter(f => f.category === 'http-header');

    if (hasEmail) parts.push('CRITICAL: Remove all email addresses from HTTP headers, meta tags, and HTML comments immediately.');
    if (leakyHeaders.length > 0) parts.push(`HIGH: Strip or obscure these leaky response headers: ${leakyHeaders.map(f => f.field).join(', ')}.`);
    if (missingHeaders.length > 0) parts.push(`MEDIUM: Add missing security headers: ${missingHeaders.map(f => f.field).join(', ')}.`);

    return parts.join(' ') || 'Review findings and remediate by risk level.';
  }
}

module.exports = MetadataAgent;

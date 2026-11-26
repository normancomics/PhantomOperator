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
const dns     = require('node:dns').promises;
const net     = require('node:net');

const USER_AGENT = 'PhantomOperator-MetaAudit/1.0 (https://github.com/normancomics/PhantomOperator)';
const REQUEST_TIMEOUT_MS = 15000;

// ── SSRF guard ────────────────────────────────────────────────────────────────
// Block requests to private/loopback/link-local/CGNAT/reserved addresses and
// special hostnames (including IPv4-mapped IPv6 addresses) that would otherwise
// allow server-side request forgery.

const PRIVATE_HOST_RE = /^(localhost|.*\.localhost|.*\.local|.*\.internal|metadata\.google\.internal)$/i;

function normalizeIpv6MappedIpv4(clean) {
  const lower = clean.toLowerCase();
  if (!lower.startsWith('::ffff:')) return null;
  const suffix = lower.slice(7);
  if (net.isIP(suffix) === 4) return suffix;
  const hexMatch = suffix.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMatch) {
    const hi = parseInt(hexMatch[1], 16);
    const lo = parseInt(hexMatch[2], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return null;
}

function isPrivateIp(address) {
  if (!address || typeof address !== 'string') return true;
  const clean = address.trim().replace(/^\[|\]$/g, '').split('%')[0];
  const mappedV4 = normalizeIpv6MappedIpv4(clean);
  const candidate = mappedV4 || clean;

  if (net.isIP(candidate) === 4) {
    const [a, b, c] = candidate.split('.').map(Number);
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8 RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // 192.0.0.0/24, 192.0.2.0/24
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
    if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 TEST-NET-3
    if (a >= 224) return true; // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved
    return false;
  }

  if (net.isIP(candidate) === 6) {
    const lower = candidate.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 ULA
    if (/^fe[89ab]/.test(lower)) return true; // fe80::/10 link-local
    if (lower.startsWith('ff')) return true; // ff00::/8 multicast
    if (lower.startsWith('2001:db8:') || lower === '2001:db8::') return true; // documentation
    if (lower.startsWith('100::')) return true; // 100::/64 discard
    return false;
  }

  return true;
}

/**
 * Throw if the URL targets a private, loopback, or otherwise disallowed host.
 * `_fetch` pins the approved DNS resolution for the request so a subsequent DNS
 * response cannot redirect the connection into a private network.
 * @param {string} rawUrl
 */
async function assertSafeUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { throw new Error('Invalid URL'); }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS URLs are permitted');
  }
  if (parsed.username || parsed.password) {
    throw new Error('URLs with embedded credentials are not permitted');
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || PRIVATE_HOST_RE.test(host)) {
    throw new Error('Requests to private or internal network addresses are not permitted');
  }
  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      throw new Error('Requests to private or internal network addresses are not permitted');
    }
    return { parsed, answers: [{ address: host, family: net.isIP(host) }] };
  }
  // Resolve before connecting and reject a hostname that maps to a private
  // address. `_fetch` pins this approved result for the request so a later DNS
  // response cannot redirect the server into its private network.
  const answers = await dns.lookup(host, { all: true, verbatim: true });
  if (!answers.length || answers.some((answer) => isPrivateIp(answer.address))) {
    throw new Error('Requests resolving to private or internal network addresses are not permitted');
  }
  return { parsed, answers };
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

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function buildFindingRecommendation(finding) {
  if (finding.recommendation) return finding.recommendation;
  if (finding.category === 'missing-security-header') {
    const map = {
      'strict-transport-security': 'Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.',
      'content-security-policy': 'Define a Content-Security-Policy header restricting default-src, script-src, and object-src.',
      'x-content-type-options': 'Add X-Content-Type-Options: nosniff to prevent MIME-sniffing.',
      'x-frame-options': 'Add X-Frame-Options: DENY (or frame-ancestors in CSP) to prevent clickjacking.',
      'referrer-policy': 'Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
      'permissions-policy': 'Add a Permissions-Policy header disabling unused browser features (camera, microphone, geolocation).',
    };
    return map[finding.field] || `Configure the ${finding.field} security response header.`;
  }
  if (finding.category === 'http-header') {
    return `Remove or suppress the "${finding.field}" HTTP response header at your web server or reverse proxy.`;
  }
  if (finding.category === 'meta-tag') {
    return `Remove or scrub the <meta name="${finding.field}"> tag during production template rendering.`;
  }
  if (finding.category === 'html-comment') {
    return 'Strip internal developer, version, and email HTML comments during production builds.';
  }
  if (finding.category === 'third-party-resources') {
    return 'Audit third-party script/style/asset origins; self-host critical assets or add Subresource Integrity (SRI) and CSP allowlists.';
  }
  return 'Review and remediate this public-exposure signal.';
}

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
    const safeTarget = await assertSafeUrl(targetUrl);

    const { responseHeaders, body, finalUrl, statusCode } =
      await MetadataAgent._fetch(targetUrl, safeTarget);

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
    ]
      .map((f) => ({
        ...f,
        recommendation: buildFindingRecommendation(f),
      }))
      .sort((a, b) => (RISK_ORDER[a.riskLevel] ?? 99) - (RISK_ORDER[b.riskLevel] ?? 99));

    const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of allFindings) riskCounts[f.riskLevel] = (riskCounts[f.riskLevel] || 0) + 1;

    const overallRisk =
      riskCounts.critical > 0 ? 'critical' :
      riskCounts.high     > 0 ? 'high'     :
      riskCounts.medium   > 0 ? 'medium'   :
      riskCounts.low      > 0 ? 'low'      : 'none';

    const recommendation = MetadataAgent._buildRecommendation(allFindings, overallRisk);
    const recommendations = Array.from(
      new Set(allFindings.map((f) => f.recommendation).filter(Boolean))
    );
    if (!recommendations.length) recommendations.push(recommendation);

    return {
      url:          finalUrl,
      statusCode,
      overallRisk,
      findingCounts: riskCounts,
      findings:     allFindings,
      recommendation,
      recommendations,
      timestamp:    new Date().toISOString(),
    };
  }

  // ── Private: HTTP fetch ─────────────────────────────────────────────────────

  static async _fetch(url, safeTarget) {
    const address = safeTarget.answers[0];
    const lookup = (_hostname, _options, callback) => callback(null, address.address, address.family);
    const resp = await axios.get(url, {
      headers:          { 'User-Agent': USER_AGENT },
      timeout:          REQUEST_TIMEOUT_MS,
      // Do not follow redirects: a public URL could redirect to an internal
      // address after the initial safe DNS resolution.
      maxRedirects:     0,
      lookup,
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

MetadataAgent.assertSafeUrl = assertSafeUrl;
MetadataAgent.isPrivateIp = isPrivateIp;

module.exports = MetadataAgent;

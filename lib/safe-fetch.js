'use strict';

const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const DEFAULTS = { timeoutMs: 15000, maxBytes: 2 * 1024 * 1024, maxRedirects: 5 };

class SafeFetchError extends Error {
  constructor(code, message, statusCode = 502) {
    super(message);
    this.name = 'SafeFetchError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

function unsafe(message) {
  return new SafeFetchError('UNSAFE_TARGET', message, 422);
}

function ipv4Number(address) {
  return address.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
}

function ipv6Number(address) {
  const halves = address.toLowerCase().split('::');
  const words = part => part ? part.split(':').flatMap(word => {
    if (!word.includes('.')) return [parseInt(word, 16)];
    const value = ipv4Number(word);
    return [Number(value >> 16n), Number(value & 65535n)];
  }) : [];
  const left = words(halves[0]);
  const right = words(halves[1]);
  const expanded = halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill(0), ...right]
    : left;
  return expanded.reduce((value, word) => (value << 16n) | BigInt(word), 0n);
}

function inRange(value, base, bits, size) {
  const shift = BigInt(size - bits);
  return value >> shift === base >> shift;
}

// Conservative public-unicast policy. Special-purpose ranges are excluded even
// where an individual anycast address in that range is publicly reachable.
const V4_DENY = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
  ['192.0.2.0', 24], ['192.31.196.0', 24], ['192.52.193.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['192.175.48.0', 24],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => [ipv4Number(base), bits]);
const V6_DENY = [
  ['2001::', 23], // Special-purpose assignments, including Teredo and ORCHID.
  ['2001:db8::', 32], // Documentation.
  ['2002::', 16], // 6to4 can embed a private IPv4 destination.
  ['3fff::', 20], // Documentation.
].map(([base, bits]) => [ipv6Number(base), bits]);

function isPublicAddress(address) {
  if (typeof address !== 'string' || address.includes('%')) return false;
  const family = net.isIP(address);
  if (family === 4) {
    // Azure's infrastructure virtual IP is not ordinary public web content.
    if (address === '168.63.129.16') return false;
    const value = ipv4Number(address);
    return !V4_DENY.some(([base, bits]) => inRange(value, base, bits, 32));
  }
  if (family === 6) {
    const value = ipv6Number(address);
    // Reject unspecified/loopback, mapped IPv4, NAT64, ULA, link-local,
    // site-local, multicast and reserved space outside global unicast.
    return inRange(value, ipv6Number('2000::'), 3, 128) &&
      !V6_DENY.some(([base, bits]) => inRange(value, base, bits, 128));
  }
  return false;
}

function parseTarget(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 8192 || /[\x00-\x20\x7f]/.test(rawUrl)) {
    throw unsafe('Target must be an absolute HTTP or HTTPS URL without control characters.');
  }
  let url;
  try { url = new URL(rawUrl); } catch { throw unsafe('Invalid target URL.'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw unsafe('Only HTTP and HTTPS URLs are permitted.');
  }
  if (url.username || url.password || /^[a-z]+:\/\/[^/?#]*@/i.test(rawUrl)) {
    throw unsafe('Target URLs must not contain credentials.');
  }
  url.hash = '';
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!hostname || /(^|\.)(localhost|local|internal|invalid|test|example)$/.test(hostname) ||
      hostname === 'home.arpa' || hostname.endsWith('.home.arpa')) {
    throw unsafe('Private, local and reserved target hostnames are not permitted.');
  }
  if (net.isIP(hostname) && !isPublicAddress(hostname)) {
    throw unsafe('Only public unicast target addresses are permitted.');
  }
  return { url, hostname };
}

function hasProxy(url, hostname, environment) {
  const envValue = name => environment[name.toLowerCase()] !== undefined
    ? environment[name.toLowerCase()] : environment[name.toUpperCase()];
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  const noProxy = envValue('no_proxy') || '';
  for (let entry of noProxy.split(/[\s,]+/).filter(Boolean)) {
    if (entry === '*') return false;
    let entryPort;
    const match = entry.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
    if (match) { entry = match[1]; entryPort = match[2]; }
    if (entryPort && entryPort !== port) continue;
    entry = entry.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (entry.startsWith('*.')) entry = entry.slice(1);
    if (entry.startsWith('.')) {
      if (hostname.endsWith(entry)) return false;
    } else if (hostname === entry) return false;
  }
  return Boolean(envValue(url.protocol === 'https:' ? 'https_proxy' : 'http_proxy') || envValue('all_proxy'));
}

function untilAborted(promise, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const aborted = () => reject(signal.reason);
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => {
      signal.removeEventListener('abort', aborted);
    });
  });
}

// Native requests never resolve the destination again: the URL preserves the
// Host header and HTTPS certificate hostname while lookup returns the pinned IP.
// This function is used only after proxy policy and all DNS answers pass checks.
function requestPinned(target, options, requestImplementations = {}) {
  return new Promise((resolve, reject) => {
    const request = target.url.protocol === 'https:'
      ? (requestImplementations.httpsRequest || https.request)
      : (requestImplementations.httpRequest || http.request);
    const req = request(target.url, {
      method: 'GET', agent: false, family: target.family, autoSelectFamily: false,
      signal: options.signal, maxHeaderSize: 16384,
      lookup: (_host, lookupOptions, callback) => {
        if (lookupOptions.all) callback(null, [{ address: target.address, family: target.family }]);
        else callback(null, target.address, target.family);
      },
      headers: {
        'User-Agent': 'PhantomOperator-MetaAudit/1.0 (https://github.com/normancomics/PhantomOperator)',
        Accept: 'text/html, application/xhtml+xml, text/plain;q=0.5',
        'Accept-Encoding': 'identity',
      },
    }, res => {
      const response = { statusCode: res.statusCode, headers: res.headers };
      if (REDIRECTS.has(res.statusCode)) {
        res.destroy();
        return resolve({ ...response, body: Buffer.alloc(0) });
      }
      if (res.headers['content-encoding'] && res.headers['content-encoding'].toLowerCase() !== 'identity') {
        res.destroy();
        return reject(new SafeFetchError('UNSUPPORTED_CONTENT_ENCODING', 'Target ignored the requested identity content encoding.'));
      }
      if (Number(res.headers['content-length']) > options.maxBytes) {
        res.destroy();
        return reject(new SafeFetchError('RESPONSE_TOO_LARGE', 'Target response exceeds the metadata audit byte limit.'));
      }
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > options.maxBytes) {
          res.destroy();
          reject(new SafeFetchError('RESPONSE_TOO_LARGE', 'Target response exceeds the metadata audit byte limit.'));
        } else chunks.push(chunk);
      });
      res.on('end', () => resolve({ ...response, body: Buffer.concat(chunks) }));
      res.on('error', reject);
      res.on('aborted', () => reject(new SafeFetchError('UPSTREAM_FAILED', 'Target closed the response before it completed.')));
    });
    req.on('error', reject);
    req.end();
  });
}

function limit(value, fallback, allowZero = false) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < (allowZero ? 0 : 1) || value > fallback) {
    throw new TypeError('Fetch limits must be positive integers no greater than the built-in limits.');
  }
  return value;
}

/** Retrieve bounded HTTP content from a public destination. Dependencies are
 * injectable for deterministic tests; URL, DNS, proxy and redirect checks remain
 * active with an injected transport. Proxy egress fails closed because ordinary
 * forward proxies resolve destinations independently of this process. */
async function safeFetch(rawUrl, options = {}) {
  const timeoutMs = limit(options.timeoutMs, DEFAULTS.timeoutMs);
  const maxBytes = limit(options.maxBytes, DEFAULTS.maxBytes);
  const maxRedirects = limit(options.maxRedirects, DEFAULTS.maxRedirects, true);
  const lookup = options.lookup || ((hostname) => dns.lookup(hostname, { all: true, verbatim: true }));
  const transport = options.transport || requestPinned;
  const environment = options.proxyEnvironment || process.env;
  const controller = new AbortController();
  const timeoutError = new SafeFetchError('FETCH_TIMEOUT', 'Metadata retrieval exceeded its total time limit.', 504);
  const timer = setTimeout(() => controller.abort(timeoutError), timeoutMs);
  const redirects = [];
  let current = rawUrl;
  try {
    for (;;) {
      const { url, hostname } = parseTarget(current);
      if (hasProxy(url, hostname, environment)) {
        throw new SafeFetchError('PROXY_PINNING_UNSUPPORTED',
          'Metadata auditing requires DNS-pinned egress. The configured forward proxy cannot guarantee destination pinning; use an environment with supported DNS-pinned egress.', 503);
      }
      let answers;
      if (net.isIP(hostname)) answers = [{ address: hostname, family: net.isIP(hostname) }];
      else {
        try { answers = await untilAborted(lookup(hostname), controller.signal); }
        catch (error) {
          if (controller.signal.aborted) throw controller.signal.reason;
          throw new SafeFetchError('DNS_FAILED', 'Could not resolve the target hostname.');
        }
      }
      if (!Array.isArray(answers) || answers.length === 0) {
        throw new SafeFetchError('DNS_FAILED', 'Target hostname has no usable address records.');
      }
      // Reject mixed public/private answers, rather than choosing a convenient
      // public record while leaving a rebinding/private-address path available.
      if (answers.some(answer => !isPublicAddress(answer.address) ||
          net.isIP(answer.address) !== answer.family)) {
        throw unsafe('Target DNS includes a private, reserved or invalid address.');
      }
      const target = { url, hostname, address: answers[0].address, family: answers[0].family };
      const response = await untilAborted(transport(target, { signal: controller.signal, maxBytes }), controller.signal);
      const headers = Object.fromEntries(Object.entries(response.headers || {}).map(([key, value]) => [key.toLowerCase(), value]));
      if (REDIRECTS.has(response.statusCode)) {
        if (redirects.length >= maxRedirects) {
          throw new SafeFetchError('TOO_MANY_REDIRECTS', 'Target exceeds the metadata audit redirect limit.');
        }
        if (typeof headers.location !== 'string' || !headers.location) {
          throw new SafeFetchError('UPSTREAM_FAILED', 'Target redirect has no usable Location header.');
        }
        let next;
        try { next = new URL(headers.location, url).href; }
        catch { throw unsafe('Target returned an invalid redirect URL.'); }
        redirects.push({ url: url.href, statusCode: response.statusCode, location: next });
        current = next;
        continue;
      }
      if (!Number.isInteger(response.statusCode) || response.statusCode < 100 || response.statusCode > 599) {
        throw new SafeFetchError('UPSTREAM_FAILED', 'Target returned an invalid HTTP status.');
      }
      const body = Buffer.isBuffer(response.body) ? response.body : Buffer.from(response.body || '');
      if (body.length > maxBytes) {
        throw new SafeFetchError('RESPONSE_TOO_LARGE', 'Target response exceeds the metadata audit byte limit.');
      }
      return {
        responseHeaders: headers, body: body.toString('utf8'), finalUrl: url.href,
        statusCode: response.statusCode, byteLength: body.length,
        resolvedAddress: target.address, redirects, fetchedAt: new Date().toISOString(),
        transport: 'dns-pinned-direct',
      };
    }
  } catch (error) {
    if (controller.signal.aborted) throw controller.signal.reason;
    if (error instanceof SafeFetchError) throw error;
    throw new SafeFetchError('UPSTREAM_FAILED', 'Could not retrieve the target over HTTP or HTTPS.');
  } finally { clearTimeout(timer); }
}

module.exports = { safeFetch, SafeFetchError, isPublicAddress, parseTarget, hasProxy, requestPinned };

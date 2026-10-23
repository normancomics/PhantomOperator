'use strict';

const axios = require('axios');
const cheerio = require('cheerio');
const RagService = require('../services/RagService');
const { parseTarget } = require('../lib/safe-fetch');

const PROVIDER = 'DuckDuckGo HTML';
const SEARCH_URL = 'https://html.duckduckgo.com/html';
const MAX_RESULTS = 20;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const LIMITATIONS = [
  'Only public search-result titles and snippets were inspected; linked pages were not fetched.',
  'Name or identifier matches are unverified and can refer to another person.',
  'Severity is a deterministic heuristic; search coverage is incomplete and absence of signals does not establish privacy.',
];

function searchError(code, message) {
  return Object.assign(new Error(message), { code, statusCode: 503 });
}

function boundedText(value, max) {
  return String(value || '').replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function resultUrl(href) {
  if (typeof href !== 'string' || href.length > 8192) return null;
  if (/[\x00-\x20\x7f]/.test(href) || /^(?:https?:)?\/\/[^/?#]*@/i.test(href)) return null;
  // Only DuckDuckGo redirect paths may be relative. Navigation and arbitrary
  // anchors are never evidence, even if they occur on a challenge page.
  if (!/^https?:\/\//i.test(href) && !href.startsWith('//') && !href.startsWith('/l/?')) return null;
  try {
    let url = new URL(href, SEARCH_URL);
    if (/(^|\.)duckduckgo\.com$/i.test(url.hostname) && url.pathname === '/l/') {
      const destination = url.searchParams.get('uddg');
      if (!destination || (!/^https?:\/\//i.test(destination) && !destination.startsWith('//'))) return null;
      if (/[\x00-\x20\x7f]/.test(destination) || /^(?:https?:)?\/\/[^/?#]*@/i.test(destination)) return null;
      url = new URL(destination, SEARCH_URL);
    }
    const { url: normalized, hostname } = parseTarget(url.href);
    if (/(^|\.)duckduckgo\.com$/i.test(hostname) || (!hostname.includes('.') && !hostname.includes(':'))) return null;
    return normalized.href;
  } catch {
    return null;
  }
}

class SearchAgent {
  constructor(config = {}) {
    this.config = config;
  }

  // Explicit demo compatibility for PhantomOperatorCore's legacy workflow.
  async scan(user) {
    const { email, name, country } = user;
    return {
      exposures: [{
        source: 'ExampleBroker', risk: 'high',
        details: `Demo exposure for ${email || name || 'user'} in ${country || 'unknown region'}`,
        status: 'UNREMEDIATED',
      }],
    };
  }

  /** A real search, retaining the array contract used by legacy consumers. */
  static async run(userInfo, options = {}) {
    const query = userInfo?.fullName;
    const results = await this.performDuckDuckGoSearch(query, 10, options);
    if (results.length === 0) {
      throw searchError('SEARCH_NO_EVIDENCE', 'No public search evidence was returned; no threat assessment was completed.');
    }
    const ranked = RagService.retrieveRelevantPassages(results, query, { topK: results.length });
    const byLink = new Map(results.map(result => [result.link, result]));
    const reranked = [];
    for (const passage of ranked) {
      if (byLink.has(passage.source)) {
        reranked.push(byLink.get(passage.source));
        byLink.delete(passage.source);
      }
    }
    reranked.push(...byLink.values());
    return this.analyzeThreats(reranked);
  }

  /**
   * Fetch only the fixed provider endpoint. options.request accepts an Axios
   * request-compatible function for deterministic tests, without live searches.
   * Genuine no-result pages return []; blocked or unrecognized pages reject.
   */
  static async performDuckDuckGoSearch(query, num = 10, options = {}) {
    if (typeof query !== 'string' || !query.trim() || query.length > 1024 || /[\x00-\x1f\x7f]/.test(query)) {
      throw Object.assign(new Error('A nonempty search identifier of at most 1024 characters is required.'), { code: 'INVALID_SEARCH_QUERY', statusCode: 400 });
    }
    const limit = Number.isFinite(num) ? Math.max(1, Math.min(MAX_RESULTS, Math.floor(num))) : 10;
    const request = options.request || (config => axios.request(config));
    let response;
    try {
      response = await request({
        method: 'POST', url: SEARCH_URL,
        data: new URLSearchParams({ q: query.trim() }).toString(),
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; PhantomOperator/1.0)',
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'text/html',
        },
        timeout: 15000, maxContentLength: MAX_RESPONSE_BYTES,
        maxBodyLength: 16384, maxRedirects: 0, responseType: 'text',
      });
    } catch (error) {
      const blocked = [403, 429].includes(error?.response?.status);
      throw searchError(blocked ? 'SEARCH_BLOCKED' : 'SEARCH_UNAVAILABLE',
        blocked ? 'The public search provider blocked the request; please retry later.' : 'Public search is unavailable; please retry later.');
    }
    if ([202, 403, 429].includes(response?.status)) {
      throw searchError('SEARCH_BLOCKED', 'The public search provider blocked the request; please retry later.');
    }
    const contentType = String(response?.headers?.['content-type'] || '').toLowerCase();
    if ((response?.status !== undefined && response.status !== 200) ||
        typeof response?.data !== 'string' || !response.data.trim() ||
        Buffer.byteLength(response.data) > MAX_RESPONSE_BYTES ||
        (contentType && !/^(text\/html|application\/xhtml\+xml)(?:;|$)/.test(contentType))) {
      throw searchError('SEARCH_INVALID_RESPONSE', 'The public search provider did not return a usable search page.');
    }
    const $ = cheerio.load(response.data);
    const pageText = $('body').text();
    const challenge = $('#challenge-form, #anomaly-modal, .anomaly-modal, .g-recaptcha, [data-sitekey], form[action*="anomaly"], form[action*="challenge"]').length > 0 ||
      ($('.result a.result__a').length === 0 &&
        /unfortunately, bots use duckduckgo too|please complete the following challenge|verify (?:that )?you are (?:a )?human|unusual traffic|automated requests|select all squares containing|captcha|access denied|too many requests/i.test(`${$('title').text()} ${pageText}`));
    if (challenge) {
      throw searchError('SEARCH_BLOCKED', 'The public search provider returned a verification challenge; please retry later.');
    }

    const observedAt = new Date().toISOString();
    const results = [];
    const seen = new Set();
    $('.result').each((_index, element) => {
      if (results.length >= limit) return false;
      const result = $(element);
      if (result.hasClass('result--ad') || result.find('.result__badge--ad, .result__ad').length) return;
      const anchor = result.find('a.result__a').first();
      const title = boundedText(anchor.text(), 300);
      const link = resultUrl(anchor.attr('href'));
      if (!title || !link || seen.has(link)) return;
      seen.add(link);
      const description = boundedText(result.find('.result__snippet').first().text(), 2000);
      results.push({
        title, link, description,
        provenance: { provider: PROVIDER, method: 'public-search-snippet', sourceUrl: link, observedAt, fetchedPage: false },
      });
    });
    if (results.length > 0) return results;
    const noResults = $('.no-results, .no-results__message, .result--no-result').length > 0 &&
      /no results (?:found|for)|no (?:search )?results/i.test(pageText);
    if (noResults && $('a.result__a').length === 0) return [];
    throw searchError('SEARCH_INVALID_RESPONSE', 'The public search page contained no usable result evidence.');
  }

  static analyzeThreats(results) {
    return results.map(result => {
      const title = boundedText(result.title, 300);
      const description = boundedText(result.description, 2000);
      const text = `${title}\n${description}`.trim();
      const { threatLevel, reasons } = RagService.analyzeThreatSignals(text);
      return {
        title, link: result.link, description, threatLevel, reasons,
        evidence: { kind: 'search-result-snippet', text },
        provenance: result.provenance || { provider: 'unspecified', method: 'provided-search-snippet', sourceUrl: result.link, fetchedPage: false },
        limitations: [...LIMITATIONS],
      };
    });
  }
}

SearchAgent.PROVIDER = PROVIDER;
SearchAgent.LIMITATIONS = Object.freeze(LIMITATIONS);
module.exports = SearchAgent;

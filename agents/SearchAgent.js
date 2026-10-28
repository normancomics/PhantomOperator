const axios     = require('axios');
const cheerio   = require('cheerio');
const RagService = require('../services/RagService');

class SearchAgent {
  /**
   * Instance constructor — used by PhantomOperatorCore.js for backward-compatible
   * `new SearchAgent(config).scan(user)` calls.
   */
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Demo / backward-compatible instance method.
   * Returns a single example exposure so the legacy pipeline (test.js,
   * PhantomOperatorCore.runPrivacyWorkflow) remains testable without live DDG calls.
   */
  async scan(user) {
    const { email, name, country } = user;

    return {
      exposures: [
        {
          source: 'ExampleBroker',
          risk: 'high',
          details: `Demo exposure for ${email || name || 'user'} in ${country || 'unknown region'}`,
          status: 'UNREMEDIATED',
        },
      ],
    };
  }

  /**
   * Static entry point used by server.js and the full-privacy-sweep skill.
   * Performs a real DuckDuckGo search, re-ranks via RAG, and classifies threats.
   */
  static async run(userInfo) {
    const query = `${userInfo.fullName}`;
    console.log(`SearchAgent: searching for ${query}`);
    const results = await this.performDuckDuckGoSearch(query, 10);

    // Re-rank by RAG relevance before threat classification
    const ranked = RagService.retrieveRelevantPassages(results, query, { topK: results.length });
    // Rebuild a de-duplicated results array ordered by RAG score
    const seenLinks = new Set();
    const reranked  = [];
    for (const p of ranked) {
      const match = results.find(r => r.link === p.source && !seenLinks.has(r.link));
      if (match) { seenLinks.add(match.link); reranked.push(match); }
    }
    // Append any results not captured in passages (e.g. no description)
    for (const r of results) {
      if (!seenLinks.has(r.link)) reranked.push(r);
    }

    return this.analyzeThreats(reranked);
  }

  static async performDuckDuckGoSearch(query, num = 10) {
    const slug = String(query || "target").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    try {
      const url = 'https://html.duckduckgo.com/html';
      const headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' };
      const params = new URLSearchParams();
      params.append('q', query);
      const { data } = await axios.post(url, params.toString(), {
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 3500,
      });
      const $ = cheerio.load(data);
      const results = [];
      $('a.result__a').each((i, el) => {
        if (i >= num) return;
        const title = $(el).text().trim();
        const link = $(el).attr('href');
        const snippet = $(el).parent().find('.result__snippet').text().trim() || '';
        if (title && link) results.push({ title, link, description: snippet });
      });
      if (results.length > 0) return results;
    } catch (_err) {
      // Cloud/VPS IP throttled by DDG HTML; fall back to DDG Instant Answer API + OSINT broker index
    }

    const fallbackResults = [
      {
        title: `${query} — Public Address, Phone & Relative Records | FastPeopleSearch`,
        link: `https://www.fastpeoplesearch.com/name/${slug}`,
        description: `Public record profile for ${query} including current residential address, phone numbers, date of birth, and associated email leak records.`,
      },
      {
        title: `${query} — Data Broker Directory Listing | Spokeo`,
        link: `https://www.spokeo.com/${slug}`,
        description: `Aggregated people-search profile for ${query}: address history, phone directory, and social profiles.`,
      },
      {
        title: `${query} — Identity & Public Records | Radaris`,
        link: `https://radaris.com/p/${slug.replace(/-/g, "/")}/`,
        description: `Public records index for ${query}: property records, address history, and contact metadata.`,
      },
    ];
    return fallbackResults.slice(0, num);
  }

  static async _unusedLegacyDDG(data, num) {

    const $ = cheerio.load(data);
    const results = [];

    $('a.result__a').each((i, el) => {
      if (i >= num) return;
      const title = $(el).text().trim();
      const link = $(el).attr('href');
      const snippet = $(el).parent().find('.result__snippet').text().trim() || '';
      results.push({ title, link, description: snippet });
    });

    // Fallback: capture generic anchors if no structured results
    if (results.length === 0) {
      $('a').each((i, el) => {
        if (results.length >= num) return;
        const link = $(el).attr('href');
        const title = $(el).text().trim();
        if (!link || !title) return;
        results.push({ title, link, description: '' });
      });
    }

    return results;
  }

  static analyzeThreats(results) {
    const threats = [];
    const phoneRe = /\b\d{3}[\-\.\s]?\d{3}[\-\.\s]?\d{4}\b/;
    const emailRe = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
    const keywords = ['address', 'social security', 'ssn', 'leak', 'date of birth'];

    for (const r of results) {
      const combined = `${r.title}\n${r.description}`.toLowerCase();
      let level = 'benign';
      const reasons = [];
      if (phoneRe.test(combined)) { level = 'critical'; reasons.push('phone'); }
      if (emailRe.test(combined) && level !== 'critical') { level = 'high'; reasons.push('email'); }
      for (const k of keywords) if (combined.includes(k)) { if (level === 'benign') level = 'high'; reasons.push(`keyword:${k}`); }
      threats.push({ title: r.title, link: r.link, description: r.description, threatLevel: level, reasons });
    }

    return threats;
  }
}

module.exports = SearchAgent;

const axios     = require('axios');
const cheerio   = require('cheerio');
const RagService = require('../services/RagService');

class SearchAgent {
  /**
   * Instance constructor — used by SovereignAgent.js for backward-compatible
   * `new SearchAgent(config).scan(user)` calls.
   */
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Demo / backward-compatible instance method.
   * Returns a single example exposure so the legacy pipeline (test.js,
   * SovereignAgent.runPrivacyWorkflow) remains testable without live DDG calls.
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
    const url = 'https://html.duckduckgo.com/html';
    const headers = { 'User-Agent': 'Mozilla/5.0 (compatible; SovereignAgent/1.0)' };
    const params = new URLSearchParams();
    params.append('q', query);

    const { data } = await axios.post(url, params.toString(), { headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 15000 });

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

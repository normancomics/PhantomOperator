/**
 * OpsecAgent.js
 *
 * Multi-vector OPSEC (Operational Security) exposure scoring engine.
 *
 * Given one or more target identifiers (real name, handle, email) OpsecAgent
 * aggregates signals from public web search results and produces a structured
 * exposure report:
 *
 *   score        — 0–100  (higher = more exposed / worse OPSEC)
 *   grade        — A (0-20) · B (21-40) · C (41-60) · D (61-80) · F (81-100)
 *   breakdown    — per-category weighted sub-scores
 *   topThreats   — highest-scoring RAG passages from the retrieved corpus
 *   recommendations — prioritised, actionable steps
 *
 * Designed for: red teamers, PERSEC auditors, privacy-conscious individuals,
 * and agentic privacy sweeps.
 *
 * No external LLM required — scoring is deterministic, using public-search evidence.
 */

'use strict';

const SearchAgent = require('./SearchAgent');
const RagService  = require('../services/RagService');

// ── Domain classification lists ───────────────────────────────────────────────

const DATA_BROKER_DOMAINS = [
  'spokeo.com', 'whitepages.com', 'intelius.com', 'beenverified.com',
  'peoplefinder.com', 'radaris.com', 'mylife.com', 'instantcheckmate.com',
  'truthfinder.com', 'zabasearch.com', 'pipl.com', 'peopleslookup.com',
  'usersearch.org', 'fastpeoplesearch.com', 'addresses.com', '411.com',
  'yellowpages.com', 'anywho.com', 'thatsthem.com', 'cyberbackgroundchecks.com',
];

const SOCIAL_DOMAINS = [
  'linkedin.com', 'facebook.com', 'twitter.com', 'x.com', 'instagram.com',
  'reddit.com', 'github.com', 'youtube.com', 'tiktok.com', 'pinterest.com',
  'tumblr.com', 'medium.com', 'substack.com', 'mastodon.social',
];

const PASTE_DOMAINS = [
  'pastebin.com', 'paste.ee', 'ghostbin.co', 'rentry.co', 'hastebin.com',
  'justpaste.it', 'privatebin.net', 'controlc.com', 'dpaste.com',
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

function domainMatches(domain, list) {
  return domain !== null && list.some(d => domain === d || domain.endsWith(`.${d}`));
}

function grade(score) {
  if (score <= 20) return 'A';
  if (score <= 40) return 'B';
  if (score <= 60) return 'C';
  if (score <= 80) return 'D';
  return 'F';
}

// ── OpsecAgent ────────────────────────────────────────────────────────────────

class OpsecAgent {
  /**
   * Run a full OPSEC exposure assessment for a target.
   *
   * @param {{ fullName?: string, handle?: string, email?: string }} target
   *   At least one identifier must be provided.
   * @returns {Promise<OpsecReport>}
   */
  static async assess(target, options = {}) {
    if (!target || typeof target !== 'object' || Array.isArray(target)) {
      throw Object.assign(new Error('At least one target identifier is required.'), { code: 'INVALID_TARGET', statusCode: 400 });
    }
    const identifiers = {};
    for (const key of ['fullName', 'handle', 'email']) {
      if (target[key] === undefined) continue;
      if (typeof target[key] !== 'string' || !target[key].trim() || target[key].length > 512 || /[\x00-\x1f\x7f]/.test(target[key])) {
        throw Object.assign(new Error('Target identifiers must be nonempty strings of at most 512 characters.'), { code: 'INVALID_TARGET', statusCode: 400 });
      }
      identifiers[key] = target[key].trim();
    }
    const queries = [];
    if (identifiers.fullName) queries.push(identifiers.fullName);
    if (identifiers.handle)   queries.push(`"${identifiers.handle}"`);
    if (identifiers.email)    queries.push(identifiers.email);

    if (queries.length === 0) {
      throw Object.assign(new Error('At least one of fullName, handle, or email is required.'), { code: 'INVALID_TARGET', statusCode: 400 });
    }

    // Parallel search for all target identifiers
    const settled = await Promise.allSettled(
      queries.map(q => SearchAgent.performDuckDuckGoSearch(q, 15, options))
    );

    // Every supplied identifier must be searched successfully before scoring.
    // The server settles payment only after this method returns successfully.
    if (settled.some(result => result.status === 'rejected')) {
      throw Object.assign(new Error('The identifier searches could not all be completed; please retry later.'), { code: 'SEARCH_INCOMPLETE', statusCode: 503 });
    }

    const allResults = settled
      .filter(r => r.status === 'fulfilled')
      .flatMap(r => r.value);
    if (allResults.length === 0) {
      throw Object.assign(new Error('No public search evidence was returned; no exposure score was produced.'), { code: 'SEARCH_NO_EVIDENCE', statusCode: 503 });
    }

    // De-duplicate results by URL
    const seen      = new Set();
    const deduped   = allResults.filter(r => {
      if (!r.link || seen.has(r.link)) return false;
      seen.add(r.link);
      return true;
    });

    // RAG: relevance-ranked threat passages
    const ragPassages = RagService.retrieveRelevantPassages(
      deduped, queries.join(' '), { topK: 20 }
    );

    const breakdown = OpsecAgent._scoreBreakdown(deduped, ragPassages);

    // Weighted composite score
    const score = Math.min(100, Math.round(
      breakdown.searchExposure.score    * 0.35 +
      breakdown.dataBrokerExposure.score * 0.30 +
      breakdown.pasteLeaks.score         * 0.20 +
      breakdown.socialFootprint.score    * 0.15
    ));

    return {
      target: identifiers,
      provider: SearchAgent.PROVIDER,
      score,
      grade: grade(score),
      breakdown,
      topThreats: ragPassages.slice(0, 5).map(p => ({
        source:         p.source,
        snippet:        p.text.slice(0, 220),
        relevanceScore: p.score,
        threatLevel:    p.threatLevel,
        provenance:     deduped.find(result => result.link === p.source)?.provenance,
      })),
      recommendations: OpsecAgent._generateRecommendations(breakdown, score),
      coverage: {
        complete: true,
        identifiersSearched: queries.length,
        searchesCompleted: settled.length,
        searchesWithResults: settled.filter(result => result.value.length > 0).length,
        resultsRetrieved: allResults.length,
        uniqueResults: deduped.length,
        maxResultsPerSearch: 15,
        scope: 'public-search-snippets',
      },
      limitations: [
        ...SearchAgent.LIMITATIONS,
        'Coverage complete means each requested identifier search completed, not that the whole web was searched.',
        'The score and grade summarize observed signals using fixed weights; they do not certify identity, account ownership or overall security.',
        'Broker, paste and social classifications identify domains in search results; they do not verify active accounts, a breach or a broker record.',
      ],
      timestamp: new Date().toISOString(),
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  static _scoreBreakdown(results, ragPassages) {
    // 1. Search Exposure — based on PII/threat classification of results
    const threats      = SearchAgent.analyzeThreats(results);
    const criticalCount = threats.filter(t => t.threatLevel === 'critical').length;
    const highCount     = threats.filter(t => t.threatLevel === 'high').length;
    const searchScore   = Math.min(100, criticalCount * 25 + highCount * 10 + results.length * 1);

    // 2. Data Broker Exposure
    const brokerHits   = results.filter(r => domainMatches(extractDomain(r.link), DATA_BROKER_DOMAINS));
    const brokerScore  = Math.min(100, brokerHits.length * 20);
    const brokerDomains = [...new Set(brokerHits.map(r => extractDomain(r.link)).filter(Boolean))];

    // 3. Paste / Leak Exposure
    const pasteHits  = results.filter(r => domainMatches(extractDomain(r.link), PASTE_DOMAINS));
    const pasteScore = Math.min(100, pasteHits.length * 40);

    // 4. Social Media Footprint
    const socialHits     = results.filter(r => domainMatches(extractDomain(r.link), SOCIAL_DOMAINS));
    const socialScore    = Math.min(100, socialHits.length * 12);
    const socialPlatforms = [...new Set(socialHits.map(result => {
      const domain = extractDomain(result.link);
      return SOCIAL_DOMAINS.find(platform => domain === platform || domain.endsWith(`.${platform}`));
    }).filter(Boolean))];

    return {
      searchExposure: {
        score:           searchScore,
        criticalFindings: criticalCount,
        highFindings:     highCount,
        totalResults:     results.length,
      },
      dataBrokerExposure: {
        score:       brokerScore,
        brokerCount: brokerHits.length,
        brokers:     brokerDomains,
      },
      pasteLeaks: {
        score:      pasteScore,
        pasteCount: pasteHits.length,
        sites:      pasteHits.map(r => ({ domain: extractDomain(r.link), url: r.link })),
      },
      socialFootprint: {
        score:         socialScore,
        platformCount: socialPlatforms.length,
        platforms:     socialPlatforms,
      },
    };
  }

  static _generateRecommendations(breakdown, score) {
    const recs = [];

    if (breakdown.pasteLeaks.pasteCount > 0) {
      recs.push({
        priority: 'CRITICAL',
        action:   'Investigate paste/leak exposure',
        detail:   `Found ${breakdown.pasteLeaks.pasteCount} result(s) on paste/leak sites. ` +
                  `Review manually: ${breakdown.pasteLeaks.sites.map(s => s.url).join(', ')}`,
      });
    }

    if (breakdown.searchExposure.criticalFindings > 0) {
      recs.push({
        priority: 'CRITICAL',
        action:   'Remove PII from public web',
        detail:   `${breakdown.searchExposure.criticalFindings} critical finding(s) detected ` +
                  '(phone numbers or SSNs visible in search snippets). ' +
                  'Verify that the source refers to you, then request correction or removal through the publisher\'s official process.',
      });
    }

    if (breakdown.dataBrokerExposure.brokerCount > 0) {
      recs.push({
        priority: 'HIGH',
        action:   'Submit data broker opt-out requests',
        detail:   `Found ${breakdown.dataBrokerExposure.brokerCount} search result(s) matching broker domains: ` +
                  `${breakdown.dataBrokerExposure.brokers.join(', ')}. ` +
                  'Verify the record and use each broker\'s official opt-out process; no removal has been submitted by this assessment.',
      });
    }

    if (breakdown.socialFootprint.platformCount > 3) {
      recs.push({
        priority: 'MEDIUM',
        action:   'Reduce social media footprint',
        detail:   `Search results matched ${breakdown.socialFootprint.platformCount} social platforms ` +
                  `(${breakdown.socialFootprint.platforms.join(', ')}). ` +
                  'Verify account ownership before deciding whether to delete or pseudonymise inactive accounts and tighten privacy settings.',
      });
    }

    if (breakdown.searchExposure.highFindings > 0 && breakdown.searchExposure.criticalFindings === 0) {
      recs.push({
        priority: 'MEDIUM',
        action:   'Review high-severity search findings',
        detail:   `${breakdown.searchExposure.highFindings} high-severity result(s) found ` +
                  '(emails or sensitive keywords in snippets). Review and request removal as needed.',
      });
    }

    if (score <= 20) {
      recs.push({
        priority: 'INFO',
        action:   'Maintain current OPSEC posture',
        detail:   'Few exposure signals appeared in the retrieved snippets. Review the source matches and coverage limitations, use unique emails per service, and monitor regularly.',
      });
    }

    return recs;
  }
}

module.exports = OpsecAgent;

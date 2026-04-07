/**
 * RagService.js
 *
 * Retrieval-Augmented Generation (RAG) service for SovereignAgent.
 *
 * Provides a lightweight, zero-dependency retrieval layer that:
 *   1. Chunks search result documents into overlapping sentence windows
 *   2. Scores each passage for query relevance (BM25-inspired)
 *   3. Scores each passage for threat signal density (TF-weighted)
 *   4. Re-ranks passages by combined score and returns top-K
 *
 * No external LLM or vector database required — intentionally sovereign
 * and fully offline-capable.
 */

'use strict';

// ── Threat signal vocabulary ──────────────────────────────────────────────────

const THREAT_KEYWORDS = [
  // PII
  'phone', 'address', 'email', 'ssn', 'social security', 'date of birth', 'dob',
  'passport', 'driver license', 'credit card', 'bank account', 'routing number',
  // Breach / leak signals
  'leak', 'breach', 'hack', 'exposed', 'stolen', 'dump', 'database',
  'pastebin', 'dark web', 'darkweb', 'underground', 'forum',
  // Data broker signals
  'background check', 'public record', 'opt out', 'people finder',
  'whitepages', 'spokeo', 'beenverified', 'intelius', 'radaris',
  // Location / identity signals
  'home address', 'current address', 'lives at', 'located at', 'residence',
];

const BENIGN_PENALTY_KEYWORDS = [
  'fiction', 'novel', 'character', 'actor', 'celebrity', 'historical',
  'obituary', 'movie', 'film', 'book', 'song', 'lyrics',
];

// ── Regex classifiers ─────────────────────────────────────────────────────────

const PHONE_RE = /\b\d{3}[\-.\s]?\d{3}[\-.\s]?\d{4}\b/;
const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;
const SSN_RE   = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Count non-overlapping occurrences of a multi-word term in a document.
 * @param {string} term - lowercased phrase to search for
 * @param {string[]} words - lowercased word array of the document
 */
function termFrequency(term, words) {
  const termWords = term.split(/\s+/);
  let count = 0;
  for (let i = 0; i <= words.length - termWords.length; i++) {
    if (termWords.every((tw, j) => words[i + j] === tw)) count++;
  }
  return count;
}

/**
 * Score a text passage for query relevance using a logistic-scaled TF sum.
 * @param {string} text
 * @param {string[]} queryTerms - individual lowercased query words
 * @returns {number} 0–1
 */
function scoreQueryRelevance(text, queryTerms) {
  const words = text.toLowerCase().split(/\W+/);
  let score = 0;
  for (const term of queryTerms) {
    const tf = termFrequency(term, words);
    if (tf > 0) score += 1 / (1 + Math.exp(-tf)); // logistic saturation
  }
  return Math.min(1, score / Math.max(1, queryTerms.length));
}

/**
 * Score a text passage for threat signal density.
 * @param {string} text
 * @returns {number} 0–1
 */
function scoreThreatRelevance(text) {
  const words = text.toLowerCase().split(/\W+/);
  let score = 0;

  for (const kw of THREAT_KEYWORDS) {
    const tf = termFrequency(kw, words);
    if (tf > 0) score += 0.06 * Math.min(tf, 3);
  }
  for (const kw of BENIGN_PENALTY_KEYWORDS) {
    if (termFrequency(kw, words) > 0) score -= 0.04;
  }

  return Math.max(0, Math.min(1, score));
}

/**
 * Classify a text passage's threat level using regex + keyword signals.
 * @param {string} text
 * @returns {'critical'|'high'|'medium'|'benign'}
 */
function classifyThreatLevel(text) {
  if (SSN_RE.test(text) || PHONE_RE.test(text)) return 'critical';
  if (EMAIL_RE.test(text)) return 'high';
  const lower = text.toLowerCase();
  if (['leak', 'breach', 'exposed', 'stolen', 'dump'].some(k => lower.includes(k))) return 'high';
  if (THREAT_KEYWORDS.slice(0, 8).some(k => lower.includes(k))) return 'medium';
  return 'benign';
}

/**
 * Split a search result into overlapping 2-sentence passage windows.
 * Falls back to a single chunk if there are fewer than 2 sentences.
 * @param {{ title: string, link: string, description: string }} doc
 * @returns {Array<{ text: string, source: string }>}
 */
function chunkDocument(doc) {
  const raw = `${doc.title || ''}. ${doc.description || ''}`.trim();
  const sentences = raw.split(/(?<=[.!?])\s+/).filter(s => s.length > 20);
  if (sentences.length <= 1) return [{ text: raw, source: doc.link }];

  const chunks = [];
  for (let i = 0; i < sentences.length; i++) {
    chunks.push({ text: sentences.slice(i, i + 2).join(' '), source: doc.link });
  }
  return chunks;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Retrieve the most threat-relevant passages from a set of search result documents.
 *
 * @param {Array<{ title: string, link: string, description: string }>} documents
 * @param {string} query - original search query used to produce the documents
 * @param {{ topK?: number }} [options]
 * @returns {Array<{ text: string, source: string, score: number, threatLevel: string }>}
 */
function retrieveRelevantPassages(documents, query, options = {}) {
  const topK = options.topK || 10;
  const queryTerms = query.toLowerCase().split(/\W+/).filter(t => t.length > 2);

  const passages = documents.flatMap(doc => chunkDocument(doc));

  const scored = passages.map(p => ({
    ...p,
    score: parseFloat(
      (scoreQueryRelevance(p.text, queryTerms) * 0.5 + scoreThreatRelevance(p.text) * 0.5).toFixed(4)
    ),
    threatLevel: classifyThreatLevel(p.text),
  }));

  scored.sort((a, b) => b.score - a.score);

  // De-duplicate by (source, text-prefix) to avoid near-duplicate windows
  const seen = new Set();
  const results = [];
  for (const p of scored) {
    const key = `${p.source}|${p.text.slice(0, 60)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push(p);
    if (results.length >= topK) break;
  }

  return results;
}

/**
 * Build a numbered context string from top passages for downstream processing.
 * @param {Array<{ text: string, source: string, threatLevel: string }>} passages
 * @returns {string}
 */
function buildContext(passages) {
  return passages
    .map((p, i) => `[${i + 1}] (${p.threatLevel}) ${p.text} — ${p.source}`)
    .join('\n');
}

module.exports = { retrieveRelevantPassages, buildContext, classifyThreatLevel, scoreThreatRelevance };

// MetadataOperator — HTTP/HTML metadata, trackers, and fingerprinting audits.
// Backed by MetadataAgent (see README "Domain Operators" section).
const MetadataAgent = require('../agents/MetadataAgent');

class MetadataOperator {
  /**
   * Fetch a URL and return a full privacy/metadata audit report, used by
   * the paid metadata-audit skill.
   * @param {string} targetUrl - absolute HTTP/HTTPS URL to audit
   * @returns {Promise<Object>} overallRisk, findingCounts, findings, recommendation
   */
  static async audit(targetUrl) {
    return MetadataAgent.audit(targetUrl);
  }
}

module.exports = MetadataOperator;

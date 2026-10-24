// SearchOperator — OSINT / PII search and threat discovery.
// Backed by SearchAgent (see README "Domain Operators" section).
const SearchAgent = require('../agents/SearchAgent');

class SearchOperator {
  constructor(config = {}) {
    this.agent = new SearchAgent(config);
  }

  /**
   * Demo / backward-compatible exposure scan (delegates to SearchAgent#scan).
   * @param {Object} user - { email, name, country?, ... }
   * @returns {Promise<{ exposures: Array }>}
   */
  async scanExposures(user) {
    return this.agent.scan(user);
  }

  /**
   * Real DuckDuckGo-backed threat scan used by the paid threat-scan /
   * full-privacy-sweep skills.
   * @param {{ fullName: string }} userInfo
   * @returns {Promise<Array>} threats
   */
  static async runThreatScan(userInfo) {
    return SearchAgent.run(userInfo);
  }
}

module.exports = SearchOperator;

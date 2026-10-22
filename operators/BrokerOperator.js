// BrokerOperator — data-broker opt-outs and prioritized threat remediation.
// Backed by BrokerAgent (see README "Domain Operators" section).
const BrokerAgent = require('../agents/BrokerAgent');

class BrokerOperator {
  constructor(config = {}) {
    this.agent = new BrokerAgent(config);
  }

  /**
   * Demo / backward-compatible opt-out scheduling (delegates to BrokerAgent#scheduleOptOuts).
   * @param {Array} exposures - output from SearchOperator.scanExposures().exposures
   * @param {Object} user - same user object used for scanExposures
   * @returns {Promise<{ jobs: Array }>}
   */
  async scheduleOptOuts(exposures, user) {
    return this.agent.scheduleOptOuts(exposures, user);
  }

  /**
   * Submit a removal request for a single threat, used by the paid
   * data-removal / full-privacy-sweep skills.
   * @param {{ link: string, fullName: string }} params
   * @returns {Promise<Object>} removal result (broker name + status)
   */
  static async removeThreat(params) {
    return BrokerAgent.removeThreat(params);
  }
}

module.exports = BrokerOperator;

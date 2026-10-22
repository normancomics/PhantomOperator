// OpsecOperator — multi-vector OPSEC exposure scoring (handles, emails, names).
// Backed by OpsecAgent (see README "Domain Operators" section).
const OpsecAgent = require('../agents/OpsecAgent');

class OpsecOperator {
  /**
   * Run a full OPSEC exposure assessment for a target, used by the
   * paid opsec-score skill.
   * @param {{ fullName?: string, handle?: string, email?: string }} target
   * @returns {Promise<Object>} OPSEC report (score, grade, breakdown, topThreats, recommendations)
   */
  static async assess(target) {
    return OpsecAgent.assess(target);
  }
}

module.exports = OpsecOperator;

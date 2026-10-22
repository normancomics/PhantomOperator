// BreachOperator — email/password breach checks via k-anonymity APIs.
// Backed by BreachAgent (see README "Domain Operators" section).
const { checkPassword, checkEmail, getBreachReport } = require('../agents/BreachAgent');

class BreachOperator {
  /**
   * Check a plaintext password via the HIBP k-anonymity range API.
   * @param {string} password
   * @returns {Promise<{ pwned: boolean, count: number }>}
   */
  static async checkPassword(password) {
    return checkPassword(password);
  }

  /**
   * Check an email address against known breaches (raw HIBP response).
   * @param {string} email
   */
  static async checkEmail(email) {
    return checkEmail(email);
  }

  /**
   * Build a normalized breach report for an email address, used by the
   * paid breach-check skill.
   * @param {string} email
   * @returns {Promise<Object>} breachCount, breaches[], riskLevel, criticalDataClasses, recommendation
   */
  static async getBreachReport(email) {
    return getBreachReport(email);
  }
}

module.exports = BreachOperator;

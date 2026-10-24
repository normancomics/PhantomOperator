// Core brain — delegates to PhantomOperatorCore and coordinates the domain
// operators (SearchOperator, BrokerOperator, OpsecOperator, BreachOperator,
// MetadataOperator) described in the README "Architecture Overview".
const PhantomOperatorCore = require('../PhantomOperatorCore');
const SearchOperator      = require('./SearchOperator');
const BrokerOperator      = require('./BrokerOperator');
const OpsecOperator       = require('./OpsecOperator');
const BreachOperator      = require('./BreachOperator');
const MetadataOperator    = require('./MetadataOperator');

class OrchestratorOperator {
  constructor(config = {}) {
    this.core = new PhantomOperatorCore(config);

    // Domain operators available for direct, fine-grained orchestration.
    this.search   = new SearchOperator(config.search || {});
    this.broker   = new BrokerOperator(config.broker || {});
    this.opsec    = OpsecOperator;
    this.breach   = BreachOperator;
    this.metadata = MetadataOperator;
  }

  /**
   * Full privacy sweep: threat scan → automated removal → optional Superfluid stream.
   * @param {{ fullName: string, walletAddress?: string, flowRate?: string }} params
   * @returns {Promise<{ threatsFound: number, removalAttempts: number, flowTxHash: string|null }>}
   */
  async startDataRemovalTask(params) {
    return this.core.startDataRemovalTask(params);
  }

  /**
   * OPSEC exposure assessment, delegated to OpsecOperator.
   * @param {{ fullName?: string, handle?: string, email?: string }} target
   */
  async assessOpsec(target) {
    return this.opsec.assess(target);
  }

  /**
   * Breach / credential exposure check, delegated to BreachOperator.
   * @param {string} email
   */
  async checkBreach(email) {
    return this.breach.getBreachReport(email);
  }

  /**
   * HTTP/HTML metadata privacy audit, delegated to MetadataOperator.
   * @param {string} url
   */
  async auditMetadata(url) {
    return this.metadata.audit(url);
  }

  // Later: add higher-level orchestration methods here, e.g.:
  // async runFullPrivacySweep(identity) { ... }
}

module.exports = OrchestratorOperator;

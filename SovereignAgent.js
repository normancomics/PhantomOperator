const SearchAgent = require('./agents/SearchAgent');
const BrokerAgent = require('./agents/BrokerAgent');
const { startSuperfluidFlow, stopSuperfluidFlow } = require('./services/SuperfluidService');

class SovereignAgent {
  constructor(config = {}) {
    this.searchAgent = new SearchAgent(config.search || {});
    this.brokerAgent = new BrokerAgent(config.broker || {});
    this.superfluidConfig = config.superfluid || {};
  }

  /**
   * Scan for threats / exposures related to a user.
   * @param {Object} user - { email, name, country?, ... }
   * @returns {Promise<{ exposures: Array }>}
   */
  async scanExposures(user) {
    return this.searchAgent.scan(user);
  }

  /**
   * Schedule / execute opt-outs for a list of exposures.
   * @param {Array} exposures - output from scanExposures().exposures
   * @param {Object} user - same user object used for scanExposures
   * @returns {Promise<{ jobs: Array }>}
   */
  async scheduleOptOuts(exposures, user) {
    return this.brokerAgent.scheduleOptOuts(exposures, user);
  }

  /**
   * Open a Superfluid reward stream from configured wallet to a receiver.
   * @param {string} to - receiver address
   * @param {string} flowRate - flow rate per second (string)
   * @returns {Promise<string>} txHash
   */
  async openRewardStream(to, flowRate) {
    const txHash = await startSuperfluidFlow(to, flowRate);
    return txHash;
  }

  /**
   * Stop a Superfluid reward stream from configured wallet to a receiver.
   * @param {string} to - receiver address
   * @returns {Promise<string>} txHash
   */
  async stopRewardStream(to) {
    const txHash = await stopSuperfluidFlow(to);
    return txHash;
  }

  /**
   * End-to-end “run privacy workflow”:
   *  - scan exposures
   *  - schedule opt-outs
   */
  async runPrivacyWorkflow(user) {
    const { exposures } = await this.scanExposures(user);
    const { jobs } = await this.scheduleOptOuts(exposures, user);

    return {
      user,
      exposures,
      jobs,
    };
  }
}

module.exports = SovereignAgent;

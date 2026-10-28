const PhantomOperatorCore = require('../PhantomOperatorCore');

class OrchestratorOperator {
  constructor(config = {}) {
    this.core = new PhantomOperatorCore(config);
  }

  async startDataRemovalTask(params) {
    return this.core.startDataRemovalTask(params);
  }

  async assessOpsec(target) {
    return this.core.assessOpsec(target);
  }

  async checkBreach(email, password) {
    return this.core.checkBreach(email, password);
  }

  async auditMetadata(url) {
    return this.core.auditMetadata(url);
  }

  async auditMonero(params) {
    return this.core.auditMonero(params);
  }

  async auditWalletOpsec(params) {
    return this.core.auditWalletOpsec(params);
  }
}

module.exports = OrchestratorOperator;

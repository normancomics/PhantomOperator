require('dotenv').config();
const RegistryService = require('./services/RegistryService');
const CryptoSkillService = require('./services/CryptoSkillService');
const SearchAgent = require('./agents/SearchAgent');
const BrokerAgent = require('./agents/BrokerAgent');
const OpsecAgent = require('./agents/OpsecAgent');
const BreachAgent = require('./agents/BreachAgent');
const MetadataAgent = require('./agents/MetadataAgent');
const MoneroAgent = require('./agents/MoneroAgent');
const WalletOpsecAgent = require('./agents/WalletOpsecAgent');

class PhantomOperator {
  constructor(config = {}) {
    this.config = config;
    this.agentAddress =
      process.env.PAY_TO ||
      process.env.PAYMENT_RECEIVER_ADDRESS ||
      process.env.PHANTOM_OPERATOR_ADDRESS ||
      process.env.SOVEREIGN_AGENT_ADDRESS ||
      '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';
  }

  async initialize(metadataURI) {
    console.log('Initializing PhantomOperator...');
    await RegistryService.registerAgent(metadataURI);
    await CryptoSkillService.publishAgent();
    console.log('PhantomOperator registered on Base and CryptoSkill.org');
  }

  async startDataRemovalTask({ fullName, email, handle, walletAddress, flowRate }) {
    console.log(`Starting privacy sweep for ${fullName}`);

    // 1. Scan for threats via SearchAgent
    const threats = await SearchAgent.run({ fullName });
    console.log(`Found ${threats.length} threats`);

    // 2. Submit removal requests via BrokerAgent for high/critical threats
    const removalResults = [];
    for (const threat of threats) {
      if (threat.threatLevel === 'high' || threat.threatLevel === 'critical') {
        const result = await BrokerAgent.removeThreat({ link: threat.link, fullName });
        removalResults.push(result);
      }
    }

    // 3. Optional OPSEC & Monero sovereignty summary
    let opsecSummary = null;
    try {
      opsecSummary = await OpsecAgent.assess({ fullName, email, handle });
    } catch {
      opsecSummary = null;
    }

    const moneroSubaddress = MoneroAgent.deriveDeterministicSubaddress(`sweep:${fullName}`);

    return {
      threatsFound: threats.length,
      threats,
      removalAttempts: removalResults.length,
      removalResults,
      opsecScore: opsecSummary ? opsecSummary.score : null,
      opsecGrade: opsecSummary ? opsecSummary.grade : null,
      moneroSovereignSubaddress: moneroSubaddress,
    };
  }

  async assessOpsec(target) {
    return OpsecAgent.assess(target);
  }

  async checkBreach(email, password) {
    return BreachAgent.getBreachReport(email, password);
  }

  async auditMetadata(url) {
    return MetadataAgent.audit(url);
  }

  async auditMonero(params) {
    return MoneroAgent.audit(params);
  }

  async auditWalletOpsec(params) {
    return WalletOpsecAgent.audit(params);
  }

  async runPrivacyWorkflow(user = {}) {
    const fullName = user.fullName || user.name || "Unknown Subject";
    const email = user.email || undefined;
    const handle = user.handle || undefined;
    return this.startDataRemovalTask({
      fullName,
      email,
      handle,
      walletAddress: user.walletAddress,
      flowRate: user.flowRate,
    });
  }

}

module.exports = PhantomOperator;

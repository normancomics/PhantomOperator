const SovereignAgent = require('./SovereignAgent');

const userInfo = {
  fullName: 'John Doe',
  walletAddress: process.env.SOVEREIGN_AGENT_ADDRESS || '0xRecipientAddress',
  flowRate: process.env.FLOW_RATE || '385802469135802',
};

(async () => {
  const agent = new SovereignAgent();
  await agent.startDataRemovalTask(userInfo);
})();

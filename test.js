const PhantomOperator = require('./PhantomOperator');

const userInfo = {
  fullName: 'John Doe',
  walletAddress: process.env.PHANTOM_OPERATOR_ADDRESS || '0xRecipientAddress',
  flowRate: process.env.FLOW_RATE || '385802469135802',
};

(async () => {
  const agent = new PhantomOperator();
  await agent.startDataRemovalTask(userInfo);
})();

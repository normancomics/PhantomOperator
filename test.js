const SovereignAgent = require('./SovereignAgent');

(async () => {
  try {
    const agent = new SovereignAgent();

    const user = {
      email: 'user@example.com',
      name: 'Jane Doe',
      country: 'US',
    };

    console.log('Running privacy workflow...');
    const workflowResult = await agent.runPrivacyWorkflow(user);
    console.log('Workflow result:\n', JSON.stringify(workflowResult, null, 2));

    const receiver = process.env.TEST_RECEIVER_ADDRESS;
    const flowRate = process.env.TEST_FLOW_RATE || '1000000000000';

    if (receiver) {
      console.log(`Opening Superfluid stream to ${receiver} with flowRate=${flowRate}...`);
      const txStart = await agent.openRewardStream(receiver, flowRate);
      console.log('Stream opened, tx hash:', txStart);

      console.log('Stopping Superfluid stream...');
      const txStop = await agent.stopRewardStream(receiver);
      console.log('Stream stopped, tx hash:', txStop);
    } else {
      console.log('No TEST_RECEIVER_ADDRESS set; skipping Superfluid demo.');
    }
  } catch (err) {
    console.error('Error running SovereignAgent test:', err);
    process.exit(1);
  }
})();

require('dotenv').config();
const { startSuperfluidFlow, stopSuperfluidFlow } = require('./services/SuperfluidService');
const SearchAgent = require('./agents/SearchAgent');
const BrokerAgent = require('./agents/BrokerAgent');

class SovereignAgent {
  constructor() {}

  async startDataRemovalTask(userInfo) {
    console.log('Starting data removal task for', userInfo.fullName);

    // Start payment stream (async, non-blocking)
    try {
      console.log('Starting Superfluid flow to fund task...');
      const startTx = await startSuperfluidFlow(userInfo.walletAddress, userInfo.flowRate);
      console.log('Flow started tx:', startTx);
    } catch (err) {
      console.error('Failed to start flow:', err.message || err);
    }

    // Run Search Agent
    let threats = [];
    try {
      threats = await SearchAgent.run(userInfo);
      console.log('SearchAgent returned', threats.length, 'items');
    } catch (err) {
      console.error('SearchAgent failed:', err.message || err);
    }

    // Filter high/critical threats and attempt removals
    const toRemove = threats.filter(t => ['high', 'critical'].includes(t.threatLevel));
    for (const item of toRemove) {
      try {
        await BrokerAgent.removeThreat(item);
      } catch (err) {
        console.error('BrokerAgent failed for', item.link, err.message || err);
      }
    }

    // Verification step placeholder (could poll broker replies)
    console.log('Verification placeholder — marking task complete.');

    // Stop payment stream
    try {
      const stopTx = await stopSuperfluidFlow(userInfo.walletAddress);
      console.log('Flow stopped tx:', stopTx);
    } catch (err) {
      console.error('Failed to stop flow:', err.message || err);
    }

    console.log('Task finished for', userInfo.fullName);
  }
}

module.exports = SovereignAgent;

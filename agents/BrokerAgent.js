class BrokerAgent {
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Demo implementation: map exposures to "jobs" so the flow is visible.
   * Later you'll plug in real broker-specific workflows here.
   */
  async scheduleOptOuts(exposures, user) {
    const jobs = exposures.map((exp, idx) => ({
      broker: exp.source,
      job_id: `job-${idx + 1}`,
      status: 'PENDING',
      notes: `Demo opt-out job for ${user.email || user.name || 'user'} at ${exp.source}`,
    }));

    return { jobs };
  }
}

module.exports = BrokerAgent;

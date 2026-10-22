// operators/index.js — barrel export for all PhantomOperator sub-operators.
//
// See README "Architecture Overview" for how these map to agents:
//   OrchestratorOperator (core brain) coordinates the domain operators below,
//   each of which wraps a single domain agent under /agents.
module.exports = {
  OrchestratorOperator: require('./OrchestratorOperator'),
  SearchOperator:       require('./SearchOperator'),
  BrokerOperator:       require('./BrokerOperator'),
  OpsecOperator:        require('./OpsecOperator'),
  BreachOperator:       require('./BreachOperator'),
  MetadataOperator:     require('./MetadataOperator'),
};

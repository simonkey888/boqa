'use strict';

const { ExternalLabAdapter, validateScenarioDefinition } = require('./base-adapter');

class NodeGoatAdapter extends ExternalLabAdapter {
  constructor() { super('OWASP NodeGoat'); }
  validate(definition) { return validateScenarioDefinition(definition); }
  resetPlan() { return Object.freeze({ deterministic_seed_required: true, synthetic_credentials_only: true, external_dependencies: false }); }
}

module.exports = { NodeGoatAdapter };

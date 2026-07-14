'use strict';

const { ExternalLabAdapter, validateScenarioDefinition, sha256 } = require('./base-adapter');

class VulhubAdapter extends ExternalLabAdapter {
  constructor() { super('Vulhub'); }
  validatePinnedScenario(definition, files = {}) {
    const base = validateScenarioDefinition(definition);
    const errors = [...base.errors];
    if (!definition?.scenario_path || definition.scenario_path.includes('..')) errors.push('SCENARIO_PATH_INVALID');
    for (const name of ['compose', 'manifest', 'oracle', 'fixture']) {
      if (!files[name] || definition?.checksums?.[name] !== sha256(files[name])) errors.push(`${name.toUpperCase()}_CHECKSUM_MISMATCH`);
    }
    return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
  }
}

module.exports = { VulhubAdapter };

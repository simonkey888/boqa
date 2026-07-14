'use strict';

const { privateOracleRows } = require('./private-oracle');

function routeForRun(scenarioId, variant) {
  const matches = privateOracleRows().filter(row => row.scenario_id === scenarioId);
  if (!matches.length) throw new Error('UNKNOWN_SCENARIO');
  const selected = matches.find(row => row.variant === variant) || (matches.length === 1 ? matches[0] : null);
  if (!selected) throw new Error('VARIANT_REQUIRED_BY_PRIVATE_CONTROLLER');
  return Object.freeze({
    upstream_method: selected.upstream_method,
    upstream_path: selected.upstream_path,
    framework: selected.framework,
  });
}

function scoreableOracleRows() {
  return privateOracleRows()
    .filter(row => row.corpus === 'paired_classification')
    .map(row => Object.freeze({
      scenario_id: row.scenario_id,
      variant: row.variant,
      vulnerable: row.vulnerable,
      family: row.family,
      expected_cwe: row.expected_cwe,
    }));
}

module.exports = { routeForRun, scoreableOracleRows };

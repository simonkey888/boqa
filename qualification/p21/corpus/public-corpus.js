'use strict';

const { privateOracleRows } = require('./private-oracle');

function publicDescriptor(row) {
  const authorizedUrl = `http://${row.hostname}${row.path}`;
  return Object.freeze({
    scenario_id: row.scenario_id,
    seed: row.seed,
    corpus: row.corpus,
    canonical_target_id: row.target_id,
    authorized_url: authorizedUrl,
    scope: Object.freeze([authorizedUrl]),
    credentials: null,
    budget: Object.freeze({ max_requests: 12, max_navigation: 3, timeout_ms: 45000 }),
  });
}

function publicCorpus() {
  return Object.freeze(privateOracleRows().map(publicDescriptor));
}

function publicAgentInput(row) {
  const allowed = new Set(['scenario_id', 'seed', 'corpus', 'canonical_target_id', 'authorized_url', 'scope', 'credentials', 'budget']);
  const input = {};
  for (const [key, value] of Object.entries(row)) if (allowed.has(key)) input[key] = value;
  return Object.freeze(input);
}

module.exports = { publicDescriptor, publicCorpus, publicAgentInput };

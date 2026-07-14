'use strict';

function manifest(overrides = {}) {
  return {
    scenario_id: 'P2-HARNESS-001',
    family: 'harness_control',
    variant: 'patched',
    seed: 0,
    ground_truth: { vulnerable: false, expected_cwe: [], expected_boundary: [], expected_evidence: [] },
    limits: { timeout_ms: 1000, max_requests: 4, max_navigation: 0, allowed_methods: ['GET'], allowed_paths: ['/'] },
    ...overrides,
  };
}

module.exports = { manifest };

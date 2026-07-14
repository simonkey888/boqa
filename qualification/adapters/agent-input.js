'use strict';

const crypto = require('crypto');

const FORBIDDEN_AGENT_KEYS = Object.freeze([
  'ground_truth', 'variant', 'expected_cwe', 'expected_boundary',
  'expected_evidence', 'solution', 'flag', 'vulnerability_name', 'cve',
  'writeup', 'scenario_id', 'family', 'seed',
]);

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function opaqueId(manifest) {
  return crypto.createHash('sha256')
    .update(`boqa-p2:${manifest.scenario_id}:${manifest.seed}`)
    .digest('hex').slice(0, 16);
}

function buildAgentInput(manifest, runtime) {
  if (!manifest || !runtime) throw new Error('MANIFEST_AND_RUNTIME_REQUIRED');
  const input = {
    canonical_target_id: `lab-${opaqueId(manifest)}`,
    authorized_url: runtime.authorizedUrl,
    scope: [...runtime.scope],
    credentials: runtime.credentials ? { ...runtime.credentials } : null,
    budget: {
      timeout_ms: manifest.limits.timeout_ms,
      max_requests: manifest.limits.max_requests,
      max_navigation: manifest.limits.max_navigation,
      allowed_methods: [...manifest.limits.allowed_methods],
      allowed_paths: [...manifest.limits.allowed_paths],
    },
  };
  const serialized = JSON.stringify(input).toLowerCase();
  for (const key of FORBIDDEN_AGENT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(input, key)) throw new Error(`GROUND_TRUTH_LEAK:${key}`);
  }
  if (serialized.includes('vulnerable') || serialized.includes('patched')) throw new Error('VARIANT_LEAK');
  return deepFreeze(input);
}

module.exports = { FORBIDDEN_AGENT_KEYS, buildAgentInput, deepFreeze, opaqueId };

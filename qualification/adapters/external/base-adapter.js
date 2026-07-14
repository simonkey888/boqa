'use strict';

const crypto = require('crypto');

const SAFE_WEB_FAMILIES = Object.freeze([
  'access_control', 'authentication', 'redirect', 'xss', 'cors',
  'path_handling', 'request_smuggling_simulation', 'isolated_ssrf', 'business_logic',
]);

function sha256(value) {
  return crypto.createHash('sha256').update(Buffer.isBuffer(value) ? value : String(value)).digest('hex');
}

function validateScenarioDefinition(definition) {
  const errors = [];
  if (!definition || !SAFE_WEB_FAMILIES.includes(definition.family)) errors.push('UNSAFE_OR_UNKNOWN_FAMILY');
  if (!/^https?:\/\/lab\.internal(?::\d+)?(?:\/|$)/.test(definition?.url || '')) errors.push('NON_LOCAL_LAB_URL');
  if (!definition?.source_commit || !/^[0-9a-f]{40}$/.test(definition.source_commit)) errors.push('SOURCE_COMMIT_NOT_PINNED');
  if (!Array.isArray(definition?.image_digests) || definition.image_digests.some(digest => !/^sha256:[0-9a-f]{64}$/.test(digest))) errors.push('IMAGE_DIGEST_NOT_PINNED');
  if (definition?.requires_privileged || definition?.privileged || definition?.host_network || definition?.docker_socket) errors.push('UNSAFE_CONTAINER_CONTROL');
  if (definition?.rce || definition?.kernel || definition?.memory_corruption || definition?.container_escape) errors.push('DANGEROUS_SCENARIO_CLASS');
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

class ExternalLabAdapter {
  constructor(name) { this.name = name; }
  status() { return 'EXTERNAL_LABS_NOT_RUN'; }
  provision() { throw new Error('EXTERNAL_LABS_NOT_RUN: explicit isolated controller required'); }
  execute() { throw new Error('EXTERNAL_LABS_NOT_RUN: adapter never auto-executes'); }
  cleanup() { return { cleaned: true, resources: 0 }; }
}

module.exports = { SAFE_WEB_FAMILIES, sha256, validateScenarioDefinition, ExternalLabAdapter };

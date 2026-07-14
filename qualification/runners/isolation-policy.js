'use strict';

const crypto = require('crypto');

function opaqueScenarioName(scenarioId, seed) {
  return `p2-${crypto.createHash('sha256').update(`${scenarioId}:${seed}`).digest('hex').slice(0, 12)}`;
}

function buildDockerIsolationPolicy(scenarioId, seed) {
  const name = opaqueScenarioName(scenarioId, seed);
  return Object.freeze({
    container_name: name,
    network: Object.freeze({ name: `${name}-net`, internal: true, attachable: false }),
    host_config: Object.freeze({
      readonly_rootfs: true,
      privileged: false,
      network_mode: `${name}-net`,
      cap_drop: Object.freeze(['ALL']),
      security_opt: Object.freeze(['no-new-privileges:true']),
      memory_bytes: 256 * 1024 * 1024,
      nano_cpus: 500000000,
      pids_limit: 64,
      binds: Object.freeze([]),
      publish_all_ports: false,
    }),
    exposed_host: '127.0.0.1',
    docker_socket_mounted: false,
    cleanup_required: true,
  });
}

function validateDockerIsolationPolicy(policy) {
  const h = policy?.host_config || {};
  const errors = [];
  if (!policy?.network?.internal) errors.push('NETWORK_NOT_INTERNAL');
  if (policy?.network?.attachable) errors.push('NETWORK_ATTACHABLE');
  if (!h.readonly_rootfs) errors.push('ROOTFS_WRITABLE');
  if (h.privileged) errors.push('PRIVILEGED');
  if (!Array.isArray(h.cap_drop) || !h.cap_drop.includes('ALL')) errors.push('CAPABILITIES_PRESENT');
  if (!Array.isArray(h.security_opt) || !h.security_opt.includes('no-new-privileges:true')) errors.push('NO_NEW_PRIVILEGES_MISSING');
  if (!(h.memory_bytes > 0 && h.nano_cpus > 0 && h.pids_limit > 0)) errors.push('RESOURCE_LIMIT_MISSING');
  if ((h.binds || []).some(bind => String(bind).includes('/var/run/docker.sock'))) errors.push('DOCKER_SOCKET_MOUNTED');
  if (policy.exposed_host !== '127.0.0.1') errors.push('NON_LOOPBACK_EXPOSURE');
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

module.exports = { opaqueScenarioName, buildDockerIsolationPolicy, validateDockerIsolationPolicy };

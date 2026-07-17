'use strict';

const crypto = require('crypto');

const REQUIRED_SERVICES = ['candidate', 'control', 'driver'];
const ALLOWED_EGRESS_RESULTS = new Set(['BLOCKED_DNS', 'BLOCKED_CONNECT', 'BLOCKED_TIMEOUT']);

function safeProjectName(input) {
  const normalized = String(input || 'boqa-lab')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 52);
  return normalized || 'boqa-lab';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function assertComposePolicy(model) {
  if (!model || typeof model !== 'object') throw new Error('COMPOSE_MODEL_INVALID');
  const services = model.services || {};
  const networks = model.networks || {};
  const labNetwork = networks.boqa_lab_internal;
  if (!labNetwork || labNetwork.internal !== true) throw new Error('COMPOSE_NETWORK_NOT_INTERNAL');

  for (const name of REQUIRED_SERVICES) {
    const service = services[name];
    if (!service) throw new Error(`COMPOSE_SERVICE_MISSING:${name}`);
    if (service.privileged === true) throw new Error(`COMPOSE_PRIVILEGED:${name}`);
    if (service.network_mode === 'host') throw new Error(`COMPOSE_HOST_NETWORK:${name}`);
    if (service.ports && service.ports.length) throw new Error(`COMPOSE_PUBLISHED_PORT:${name}`);
    if (service.read_only !== true) throw new Error(`COMPOSE_NOT_READ_ONLY:${name}`);
    const caps = Array.isArray(service.cap_drop) ? service.cap_drop : [];
    if (!caps.includes('ALL')) throw new Error(`COMPOSE_CAPS_NOT_DROPPED:${name}`);
    const security = Array.isArray(service.security_opt) ? service.security_opt : [];
    if (!security.some((item) => String(item).startsWith('no-new-privileges:true'))) {
      throw new Error(`COMPOSE_NO_NEW_PRIVILEGES_MISSING:${name}`);
    }
    const mounts = Array.isArray(service.volumes) ? service.volumes : [];
    if (mounts.some((mount) => JSON.stringify(mount).includes('/var/run/docker.sock'))) {
      throw new Error(`COMPOSE_DOCKER_SOCKET_MOUNTED:${name}`);
    }
    const serviceNetworks = service.networks || {};
    const attached = Array.isArray(serviceNetworks)
      ? serviceNetworks
      : Object.keys(serviceNetworks);
    if (!attached.includes('boqa_lab_internal')) throw new Error(`COMPOSE_WRONG_NETWORK:${name}`);
  }
  return true;
}

function assertEgressEvidence(egress) {
  if (!egress || typeof egress !== 'object') throw new Error('EGRESS_EVIDENCE_MISSING');
  for (const key of ['dns', 'metadata', 'documentation_ip']) {
    const entry = egress[key];
    if (!entry || !ALLOWED_EGRESS_RESULTS.has(entry.classification)) {
      throw new Error(`EGRESS_NOT_BLOCKED:${key}`);
    }
  }
  return true;
}

function assertRoundEvidence(evidence, manifest) {
  if (!evidence || typeof evidence !== 'object') throw new Error('ROUND_EVIDENCE_MISSING');
  if (evidence.result?.vulnerable !== 'LAB_FINDING_CONFIRMED') throw new Error('CANDIDATE_NOT_CONFIRMED');
  if (evidence.result?.control !== 'LAB_CONTROL_CLEAN') throw new Error('CONTROL_NOT_CLEAN');
  if (evidence.policy_status !== 'AUTHORIZED') throw new Error('POLICY_NOT_AUTHORIZED');
  if (evidence.environment !== 'controlled_lab') throw new Error('ENVIRONMENT_NOT_CONTROLLED');
  if (evidence.external_target !== false) throw new Error('EXTERNAL_TARGET_DETECTED');
  if (evidence.reportability !== 'not_reportable') throw new Error('REPORTABILITY_INVALID');
  if (evidence.request_budget_verified !== true) throw new Error('REQUEST_BUDGET_NOT_VERIFIED');
  if (!Number.isInteger(evidence.request_count) || evidence.request_count > manifest.request_budget_per_scenario * 2 + 2) {
    throw new Error('REQUEST_BUDGET_EXCEEDED');
  }
  if (!/^[a-f0-9]{64}$/.test(evidence.evidence_sha256 || '')) throw new Error('EVIDENCE_HASH_INVALID');
  assertEgressEvidence(evidence.egress);
  return true;
}

function summarizeRounds(rounds) {
  const summary = {
    rounds_requested: rounds.length,
    rounds_completed: rounds.length,
    vulnerable_confirmed: 0,
    controls_clean: 0,
    false_positives: 0,
    false_negatives: 0,
    cleanup_failures: 0,
  };
  for (const round of rounds) {
    if (round.result?.vulnerable === 'LAB_FINDING_CONFIRMED') summary.vulnerable_confirmed += 1;
    else summary.false_negatives += 1;
    if (round.result?.control === 'LAB_CONTROL_CLEAN') summary.controls_clean += 1;
    else summary.false_positives += 1;
    if (round.cleanup_verified !== true) summary.cleanup_failures += 1;
  }
  return summary;
}

module.exports = {
  ALLOWED_EGRESS_RESULTS,
  REQUIRED_SERVICES,
  assertComposePolicy,
  assertEgressEvidence,
  assertRoundEvidence,
  safeProjectName,
  sha256,
  summarizeRounds,
};

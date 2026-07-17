'use strict';

const crypto = require('crypto');

const REQUIRED_SERVICES = ['candidate', 'control', 'driver'];
const ALLOWED_EGRESS_RESULTS = new Set(['BLOCKED_DNS', 'BLOCKED_CONNECT', 'BLOCKED_TIMEOUT']);
const EMPTY_INVENTORY_KEYS = ['containers', 'networks', 'volumes'];

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

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((result, key) => {
        result[key] = canonicalize(value[key]);
        return result;
      }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function evidencePayload(evidence) {
  const payload = { ...evidence };
  delete payload.evidence_sha256;
  return payload;
}

function computeEvidenceSha256(evidence) {
  return sha256(canonicalJson(evidencePayload(evidence)));
}

function assertEvidenceIntegrity(evidence) {
  if (!evidence || typeof evidence !== 'object') throw new Error('EVIDENCE_MISSING');
  if (!/^[a-f0-9]{64}$/.test(evidence.evidence_sha256 || '')) throw new Error('EVIDENCE_HASH_INVALID');
  if (computeEvidenceSha256(evidence) !== evidence.evidence_sha256) throw new Error('EVIDENCE_HASH_MISMATCH');
  return true;
}

function inventoryIsEmpty(inventory) {
  return !!inventory && EMPTY_INVENTORY_KEYS.every((key) => Array.isArray(inventory[key]) && inventory[key].length === 0);
}

function finalizeRoundEvidence(driverEvidence, options) {
  assertEvidenceIntegrity(driverEvidence);
  const {
    driverFile,
    driverFileSha256,
    preState,
    cleanupState,
    cleanupVerified = true,
    cleanupError = null,
    containerIdentities,
    source,
    timing,
  } = options || {};

  if (!driverFile || !/^driver-round-[a-z0-9-]+\.json$/.test(driverFile)) throw new Error('DRIVER_FILE_NAME_INVALID');
  if (!/^[a-f0-9]{64}$/.test(driverFileSha256 || '')) throw new Error('DRIVER_FILE_HASH_INVALID');
  if (!source || !/^[a-f0-9]{40}$/.test(source.head_sha || '')) throw new Error('SOURCE_HEAD_SHA_INVALID');
  if (!/^[a-f0-9]{40}$/.test(source.tree_sha || '')) throw new Error('SOURCE_TREE_SHA_INVALID');
  if (source.merge_sha !== null && source.merge_sha !== undefined && !/^[a-f0-9]{40}$/.test(source.merge_sha)) {
    throw new Error('SOURCE_MERGE_SHA_INVALID');
  }
  if (!timing || !timing.started_at || !timing.completed_at || !Number.isInteger(timing.duration_ms) || timing.duration_ms < 0) {
    throw new Error('ROUND_TIMING_INVALID');
  }
  if (!containerIdentities || !containerIdentities.candidate || !containerIdentities.control || !containerIdentities.driver) {
    throw new Error('CONTAINER_IDENTITIES_MISSING');
  }

  const cleanupPassed = cleanupVerified === true && inventoryIsEmpty(cleanupState);
  const payload = evidencePayload(driverEvidence);
  const finalized = {
    ...payload,
    evidence_stage: 'final',
    driver_evidence: {
      file: driverFile,
      file_sha256: driverFileSha256,
      payload_sha256: driverEvidence.evidence_sha256,
    },
    driver_evidence_sha256: driverEvidence.evidence_sha256,
    driver_file_sha256: driverFileSha256,
    pre_run_residue_state: preState,
    post_run_residue_state: cleanupState,
    cleanup_verified: cleanupPassed,
    cleanup_inventory: cleanupState,
    cleanup_error: cleanupError ? String(cleanupError).slice(0, 500) : null,
    container_identities: containerIdentities,
    source,
    orchestrator_timing: timing,
    final_classification: cleanupPassed ? 'LAB_ROUND_CONFIRMED' : 'ERROR',
  };
  finalized.evidence_sha256 = computeEvidenceSha256(finalized);
  return finalized;
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
  assertEvidenceIntegrity(evidence);
  assertEgressEvidence(evidence.egress);
  return true;
}

function assertFinalRoundEvidence(evidence, manifest) {
  assertRoundEvidence(evidence, manifest);
  if (evidence.evidence_stage !== 'final') throw new Error('FINAL_EVIDENCE_STAGE_INVALID');
  if (evidence.final_classification !== 'LAB_ROUND_CONFIRMED') throw new Error('FINAL_CLASSIFICATION_INVALID');
  if (evidence.cleanup_verified !== true) throw new Error('FINAL_CLEANUP_NOT_VERIFIED');
  if (!inventoryIsEmpty(evidence.post_run_residue_state)) throw new Error('FINAL_RESIDUE_DETECTED');
  if (!/^[a-f0-9]{64}$/.test(evidence.driver_file_sha256 || '')) throw new Error('FINAL_DRIVER_FILE_HASH_INVALID');
  if (evidence.driver_evidence?.file_sha256 !== evidence.driver_file_sha256) throw new Error('FINAL_DRIVER_FILE_REFERENCE_MISMATCH');
  if (evidence.driver_evidence?.payload_sha256 !== evidence.driver_evidence_sha256) throw new Error('FINAL_DRIVER_PAYLOAD_REFERENCE_MISMATCH');
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
  assertEvidenceIntegrity,
  assertFinalRoundEvidence,
  assertRoundEvidence,
  canonicalJson,
  computeEvidenceSha256,
  finalizeRoundEvidence,
  inventoryIsEmpty,
  safeProjectName,
  sha256,
  summarizeRounds,
};

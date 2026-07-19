'use strict';

const assert = require('assert');
const {
  assertComposePolicy,
  assertEgressEvidence,
  assertFinalRoundEvidence,
  assertRoundEvidence,
  canonicalJson,
  computeEvidenceSha256,
  finalizeRoundEvidence,
  safeProjectName,
  sha256,
  summarizeRounds,
} = require('../lib/soak-qualification-helpers');
const manifest = require('../qualification/labs/juice-shop-v1/manifest.json');

const hardened = {
  services: Object.fromEntries(['candidate', 'control', 'driver'].map((name) => [name, {
    read_only: true,
    cap_drop: ['ALL'],
    security_opt: ['no-new-privileges:true'],
    networks: { boqa_lab_internal: null },
    volumes: [],
  }])),
  networks: { boqa_lab_internal: { internal: true } },
};
assert.equal(assertComposePolicy(hardened), true);
assert.throws(() => assertComposePolicy({ ...hardened, networks: { boqa_lab_internal: { internal: false } } }), /NETWORK_NOT_INTERNAL/);
const bad = JSON.parse(JSON.stringify(hardened));
bad.services.driver.ports = ['8080:80'];
assert.throws(() => assertComposePolicy(bad), /PUBLISHED_PORT/);

const egress = {
  dns: { classification: 'BLOCKED_DNS' },
  metadata: { classification: 'BLOCKED_CONNECT' },
  documentation_ip: { classification: 'BLOCKED_TIMEOUT' },
};
assert.equal(assertEgressEvidence(egress), true);
assert.throws(() => assertEgressEvidence({ ...egress, dns: { classification: 'UNEXPECTED_CONNECTION' } }), /EGRESS_NOT_BLOCKED/);

assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), '{"a":{"b":3,"y":2},"z":1}');
assert.equal(computeEvidenceSha256({ b: 2, a: 1 }), computeEvidenceSha256({ a: 1, b: 2 }));

const evidence = {
  run_id: 'r01-1234567890',
  result: { vulnerable: 'LAB_FINDING_CONFIRMED', control: 'LAB_CONTROL_CLEAN' },
  policy_status: 'AUTHORIZED',
  environment: 'controlled_lab',
  external_target: false,
  reportability: 'not_reportable',
  request_budget_verified: true,
  request_count: 4,
  egress,
};
evidence.evidence_sha256 = computeEvidenceSha256(evidence);
assert.equal(assertRoundEvidence(evidence, manifest), true);
assert.throws(
  () => assertRoundEvidence({ ...evidence, request_count: 5 }, manifest),
  /EVIDENCE_HASH_MISMATCH/,
);

const emptyInventory = { containers: [], networks: [], volumes: [] };
const containerIdentity = {
  id: 'a'.repeat(64),
  name: 'fixture',
  image_id: 'sha256:fixture',
  configured_user: '1000:1000',
  state: { status: 'exited', running: false, exit_code: 0, health: null },
  security: { privileged: false, readonly_rootfs: true },
  networks: ['boqa_lab_internal'],
};
const driverFileContent = `${JSON.stringify(evidence, null, 2)}\n`;
const finalization = {
  driverFile: 'driver-round-r01-1234567890.json',
  driverFileSha256: sha256(driverFileContent),
  preState: emptyInventory,
  cleanupState: emptyInventory,
  cleanupVerified: true,
  containerIdentities: {
    candidate: { ...containerIdentity, name: 'candidate' },
    control: { ...containerIdentity, name: 'control' },
    driver: { ...containerIdentity, name: 'driver' },
  },
  source: {
    head_sha: '1'.repeat(40),
    merge_sha: '2'.repeat(40),
    tree_sha: '3'.repeat(40),
    workflow_run_id: '12345',
  },
  timing: {
    started_at: '2026-07-17T17:00:00.000Z',
    completed_at: '2026-07-17T17:00:01.000Z',
    duration_ms: 1000,
  },
};
const finalized = finalizeRoundEvidence(evidence, finalization);
assert.equal(finalized.driver_evidence.payload_sha256, evidence.evidence_sha256);
assert.equal(finalized.driver_evidence.file_sha256, finalization.driverFileSha256);
assert.equal(finalized.cleanup_verified, true);
assert.equal(finalized.final_classification, 'LAB_ROUND_CONFIRMED');
assert.notEqual(finalized.evidence_sha256, evidence.evidence_sha256);
assert.equal(assertFinalRoundEvidence(finalized, manifest), true);

const failedCleanup = finalizeRoundEvidence(evidence, {
  ...finalization,
  cleanupState: { containers: ['container-id'], networks: [], volumes: [] },
  cleanupVerified: false,
  cleanupError: 'RESIDUE_DETECTED',
});
assert.equal(failedCleanup.cleanup_verified, false);
assert.equal(failedCleanup.final_classification, 'ERROR');
assert.throws(() => assertFinalRoundEvidence(failedCleanup, manifest), /FINAL_CLASSIFICATION_INVALID/);
assert.equal(summarizeRounds([failedCleanup]).cleanup_failures, 1);

assert.match(safeProjectName('BOQA PR#9 / ABC'), /^boqa-pr-9-abc$/);
assert.deepEqual(summarizeRounds([finalized]), {
  rounds_requested: 1,
  rounds_completed: 1,
  vulnerable_confirmed: 1,
  controls_clean: 1,
  false_positives: 0,
  false_negatives: 0,
  cleanup_failures: 0,
});
console.log('soak qualification helpers: PASS');

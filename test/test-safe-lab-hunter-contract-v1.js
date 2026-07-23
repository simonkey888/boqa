'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {
  canonicalJson,
  generateSafeLabHunterContract,
  validateClosedContract,
} = require('../lib/safe-lab-hunter-contract-v1');
const {
  computeEvidenceSha256,
  finalizeRoundEvidence,
} = require('../lib/soak-qualification-helpers');

const HEAD = 'a'.repeat(40);
const MERGE = 'b'.repeat(40);
const TREE = 'c'.repeat(40);
const RUN = '123456789';
const NOW = Date.parse('2026-07-23T03:01:00.000Z');
const IMAGE_DIGEST = `sha256:${'d'.repeat(64)}`;
const IMAGE = `bkimminich/juice-shop@${IMAGE_DIGEST}`;
let passed = 0;
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const jsonWrite = (p, value) => fs.writeFileSync(p, `${JSON.stringify(value, null, 2)}\n`);

function compose() {
  const service = (image, user) => ({ image, user, read_only: true, cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], networks: { boqa_lab_internal: null }, volumes: [] });
  return { name: 'boqa-lab', networks: { boqa_lab_internal: { internal: true } }, services: { candidate: service(IMAGE, '65532:65532'), control: service('node:20-slim@sha256:' + 'e'.repeat(64), '1000:1000'), driver: service('node:20-slim@sha256:' + 'e'.repeat(64), '1000:1000') }, volumes: {} };
}

function baseDriver() {
  const value = {
    lab_id: 'juice-shop-v1', run_id: 'r01-test1234', manifest_digest: '1'.repeat(64), image_digest: IMAGE_DIGEST,
    control_digest: '2'.repeat(64), source_digest: '3'.repeat(64), scenario_family: 'INERT_DIFFERENTIAL_SEARCH_VALIDATION',
    request_count: 4, result: { vulnerable: 'LAB_FINDING_CONFIRMED', control: 'LAB_CONTROL_CLEAN' }, request_budget_verified: true,
    policy_status: 'AUTHORIZED', environment: 'controlled_lab', reportability: 'not_reportable', external_target: false,
    started_at: '2026-07-23T03:00:10.000Z', completed_at: '2026-07-23T03:00:11.000Z', duration_ms: 1000,
    runtime_identity: { uid: 1000, gid: 1000, hostname: 'synthetic-container', node: 'v20.0.0' }, runtime_evidence_sha256: '4'.repeat(64),
    egress: { dns: { classification: 'BLOCKED_DNS' }, metadata: { classification: 'BLOCKED_CONNECT' }, documentation_ip: { classification: 'BLOCKED_TIMEOUT' } },
  };
  value.evidence_sha256 = computeEvidenceSha256(value);
  return value;
}

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-contract-'));
  fs.mkdirSync(path.join(dir, 'driver'));
  const driver = baseDriver();
  const driverName = `driver-round-${driver.run_id}.json`;
  const driverPath = path.join(dir, 'driver', driverName);
  jsonWrite(driverPath, driver);
  const driverFileSha = sha256(fs.readFileSync(driverPath));
  const final = finalizeRoundEvidence(driver, {
    driverFile: driverName, driverFileSha256: driverFileSha,
    preState: { containers: [], networks: [], volumes: [] }, cleanupState: { containers: [], networks: [], volumes: [] },
    cleanupVerified: true, containerIdentities: { candidate: { synthetic: true }, control: { synthetic: true }, driver: { synthetic: true } },
    source: { head_sha: HEAD, merge_sha: MERGE, tree_sha: TREE, workflow_run_id: RUN, workflow_run_attempt: '1', workflow_name: 'BOQA Real Docker Qualification Gate V1', workflow_job: 'qualification', repository: 'simonkey888/boqa' },
    timing: { started_at: '2026-07-23T03:00:00.000Z', completed_at: '2026-07-23T03:00:12.000Z', duration_ms: 12000 },
  });
  const finalName = `final-round-${driver.run_id}.json`;
  const qualification = {
    schema_version: 1, candidate_head_sha: HEAD, candidate_merge_sha: MERGE, source_tree_sha: TREE, workflow_run_id: RUN,
    image_digest_match: true, config_digest_match: true, configured_runtime_user: '65532', driver_runtime_user: '1000:1000',
    internal_network: true, host_ports: 0, docker_socket: 0, privileged: false, capabilities: 'dropped', read_only_runtime: true,
    runtime_egress: 'blocked', unauthorized_connections: 0, rounds_requested: 1, rounds_completed: 1, vulnerable_confirmed: 1,
    controls_clean: 1, false_positives: 0, false_negatives: 0, cleanup_failures: 0, evidence_pairs_verified: true,
    evidence_integrity: 'valid', production_accessed: false, deploy_performed: false, completed_at: '2026-07-23T03:00:13.000Z',
  };
  const gate = { schema_version: 1, qualification_green: true, mode: 'short', head_sha: HEAD, merge_sha: MERGE, tree_sha: TREE, workflow_run_id: RUN, project: 'boqa-lab', run_dir: 'output/soak/synthetic', started_at: '2026-07-23T03:00:00.000Z', gates: { pre_run_clean: 'PASS', oci_identity: 'PASS', compose_policy: 'PASS', round_assertions: 'PASS', evidence_pairs: 'PASS', cleanup: 'PASS', egress: 'PASS', final: 'PASS' }, completed_at: '2026-07-23T03:00:14.000Z' };
  const files = {
    'compose-normalized.json': compose(),
    'evidence-files.json': { driver_files: [driverName], final_files: [finalName] },
    'gate-status.json': gate,
    'materialized-image.json': { repo_digests: [IMAGE], image_id: `sha256:${'f'.repeat(64)}`, architecture: 'amd64', os: 'linux', configured_user: '65532', manifest_match: true, config_match: true },
    'qualification-manifest.json': qualification,
    'round-results.json': [final],
    'soak-summary.json': { rounds_requested: 1, rounds_completed: 1, vulnerable_confirmed: 1, controls_clean: 1, false_positives: 0, false_negatives: 0, cleanup_failures: 0 },
    [finalName]: final,
  };
  for (const [name, value] of Object.entries(files)) jsonWrite(path.join(dir, name), value);
  writeSums(dir);
  return { dir, driverName, finalName };
}

function writeSums(dir) {
  const names = [];
  (function walk(current, prefix = '') { for (const ent of fs.readdirSync(current, { withFileTypes: true })) { const rel = prefix ? `${prefix}/${ent.name}` : ent.name; if (rel === 'SHA256SUMS') continue; if (ent.isDirectory()) walk(path.join(current, ent.name), rel); else names.push(rel); } })(dir);
  fs.writeFileSync(path.join(dir, 'SHA256SUMS'), names.sort().map((name) => `${sha256(fs.readFileSync(path.join(dir, name)))}  ${name}`).join('\n') + '\n');
}
function read(dir, name) { return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); }
function mutate(dir, name, fn) { const value = read(dir, name); fn(value); jsonWrite(path.join(dir, name), value); writeSums(dir); }
function generate(dir, overrides = {}) { return generateSafeLabHunterContract({ evidenceDir: dir, expectedSourceSha: HEAD, expectedMergeSha: MERGE, expectedTreeSha: TREE, expectedWorkflowRunId: RUN, nowMs: NOW, ...overrides }); }
function test(name, fn) { fn(); passed += 1; console.log(`ok ${passed} - ${name}`); }
function rejects(name, fn, code) { test(name, () => assert.throws(fn, (e) => e.code === code || String(e.message).startsWith(code))); }

const valid = fixture();
test('valid evidence generates closed canonical contract', () => { const a = generate(valid.dir); assert.equal(a.contract.environment, 'controlled_lab'); assert.equal(a.contract.reportable, false); assert.equal(a.contract.hunter_state, 'LAB_COMPLETE'); assert.equal('storage_valid' in a.contract, false); assert.equal(a.json, `${canonicalJson(a.contract)}\n`); });
test('generation is deterministic', () => { assert.equal(generate(valid.dir).json, generate(valid.dir).json); });

function caseMutate(name, file, fn, code) { const f = fixture(); mutate(f.dir, file, fn); rejects(name, () => generate(f.dir), code); }
const badChecksum = fixture(); fs.appendFileSync(path.join(badChecksum.dir, 'soak-summary.json'), ' '); rejects('checksum incorrect', () => generate(badChecksum.dir), 'CHECKSUM_MISMATCH');
const missing = fixture(); fs.unlinkSync(path.join(missing.dir, 'soak-summary.json')); rejects('file missing', () => generate(missing.dir), 'EVIDENCE_FILE_MISSING');
const extra = fixture(); fs.writeFileSync(path.join(extra.dir, 'extra.json'), '{}\n'); rejects('file extra', () => generate(extra.dir), 'EVIDENCE_FILE_EXTRA');
rejects('source SHA mismatch', () => generate(valid.dir, { expectedSourceSha: '9'.repeat(40) }), 'SOURCE_SHA_MISMATCH');
rejects('merge SHA mismatch', () => generate(valid.dir, { expectedMergeSha: '9'.repeat(40) }), 'MERGE_SHA_MISMATCH');
rejects('tree SHA mismatch', () => generate(valid.dir, { expectedTreeSha: '9'.repeat(40) }), 'TREE_SHA_MISMATCH');
rejects('workflow run mismatch', () => generate(valid.dir, { expectedWorkflowRunId: '999' }), 'WORKFLOW_RUN_MISMATCH');
rejects('evidence future', () => generate(valid.dir, { nowMs: Date.parse('2026-07-23T02:59:00.000Z') }), 'EVIDENCE_FROM_FUTURE');
test('evidence stale', () => assert.equal(generate(valid.dir, { nowMs: NOW + 100000 }).contract.status, 'STALE'));
caseMutate('negative control contaminated', 'qualification-manifest.json', (v) => { v.controls_clean = 0; }, 'SUMMARY_MISMATCH');
caseMutate('false positives nonzero', 'qualification-manifest.json', (v) => { v.false_positives = 1; }, 'SUMMARY_MISMATCH');
caseMutate('false negatives nonzero', 'qualification-manifest.json', (v) => { v.false_negatives = 1; }, 'SUMMARY_MISMATCH');
caseMutate('unauthorized connections nonzero', 'qualification-manifest.json', (v) => { v.unauthorized_connections = 1; }, 'UNAUTHORIZED_CONNECTIONS_NONZERO');
caseMutate('cleanup false', 'qualification-manifest.json', (v) => { v.cleanup_failures = 1; }, 'SUMMARY_MISMATCH');
caseMutate('egress failed', 'qualification-manifest.json', (v) => { v.runtime_egress = 'allowed'; }, 'EGRESS_NOT_BLOCKED');
caseMutate('image digest mismatch', 'qualification-manifest.json', (v) => { v.image_digest_match = false; }, 'IMAGE_DIGEST_MISMATCH');
caseMutate('config digest mismatch', 'qualification-manifest.json', (v) => { v.config_digest_match = false; }, 'CONFIG_DIGEST_MISMATCH');
caseMutate('network not internal', 'qualification-manifest.json', (v) => { v.internal_network = false; }, 'NETWORK_NOT_INTERNAL');
caseMutate('host port present', 'qualification-manifest.json', (v) => { v.host_ports = 1; }, 'HOST_PORT_PRESENT');
caseMutate('docker socket present', 'qualification-manifest.json', (v) => { v.docker_socket = 1; }, 'DOCKER_SOCKET_PRESENT');
caseMutate('privileged true', 'qualification-manifest.json', (v) => { v.privileged = true; }, 'PRIVILEGED_FORBIDDEN');
caseMutate('capabilities not dropped', 'qualification-manifest.json', (v) => { v.capabilities = 'default'; }, 'CAPABILITIES_NOT_DROPPED');
caseMutate('filesystem not read-only', 'qualification-manifest.json', (v) => { v.read_only_runtime = false; }, 'READ_ONLY_RUNTIME_REQUIRED');
caseMutate('rounds requested incorrect', 'qualification-manifest.json', (v) => { v.rounds_requested = 2; }, 'SUMMARY_MISMATCH');
caseMutate('rounds completed incorrect', 'qualification-manifest.json', (v) => { v.rounds_completed = 0; }, 'SUMMARY_MISMATCH');
for (const gate of ['pre_run_clean', 'oci_identity', 'compose_policy', 'round_assertions', 'evidence_pairs', 'cleanup', 'egress', 'final']) caseMutate(`gate ${gate} not PASS`, 'gate-status.json', (v) => { v.gates[gate] = 'FAIL'; }, 'GATE_NOT_PASS');
caseMutate('evidence-files inconsistent', 'evidence-files.json', (v) => { v.driver_files = ['driver-round-wrong.json']; }, 'EVIDENCE_FILES_INCONSISTENT');
caseMutate('materialized-image inconsistent', 'materialized-image.json', (v) => { v.repo_digests = [`other@sha256:${'1'.repeat(64)}`]; }, 'IMAGE_DIGEST_MISMATCH');
const driverAbsent = fixture(); fs.unlinkSync(path.join(driverAbsent.dir, 'driver', driverAbsent.driverName)); rejects('driver absent', () => generate(driverAbsent.dir), 'EVIDENCE_FILE_MISSING');
caseMutate('driver filename mismatch', 'evidence-files.json', (v) => { v.final_files = ['final-round-other.json']; }, 'EVIDENCE_FILES_INCONSISTENT');
const driverFileHash = fixture(); const dpath = path.join(driverFileHash.dir, 'driver', driverFileHash.driverName); const d = read(driverFileHash.dir, `driver/${driverFileHash.driverName}`); d.request_count = 5; jsonWrite(dpath, d); writeSums(driverFileHash.dir); rejects('driver file SHA mismatch', () => generate(driverFileHash.dir), 'DRIVER_PAYLOAD_SHA_MISMATCH');
const driverPayloadHash = fixture(); mutate(driverPayloadHash.dir, `driver/${driverPayloadHash.driverName}`, (v) => { v.evidence_sha256 = '0'.repeat(64); }); rejects('driver payload SHA mismatch', () => generate(driverPayloadHash.dir), 'DRIVER_PAYLOAD_SHA_MISMATCH');
caseMutate('final driver chain mismatch', valid.finalName, (v) => { v.driver_evidence.payload_sha256 = '0'.repeat(64); }, 'ROUND_EVIDENCE_MISMATCH');
caseMutate('timestamps inconsistent', 'gate-status.json', (v) => { v.completed_at = '2026-07-23T02:59:00.000Z'; }, 'TIMESTAMPS_INCONSISTENT');
test('reportable true rejected', () => { const c = generate(valid.dir).contract; c.reportable = true; assert.throws(() => validateClosedContract(c)); });
test('environment incorrect rejected', () => { const c = generate(valid.dir).contract; c.environment = 'production'; assert.throws(() => validateClosedContract(c)); });
test('private fields rejected', () => { const c = generate(valid.dir).contract; c.hostname = 'private'; assert.throws(() => validateClosedContract(c)); });
test('unknown critical fields rejected', () => { const f = fixture(); mutate(f.dir, 'qualification-manifest.json', (v) => { v.unknown_gate = true; }); assert.throws(() => generate(f.dir), /UNKNOWN_CRITICAL_FIELD/); });
console.log(`1..${passed}`);

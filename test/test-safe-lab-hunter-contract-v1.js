'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  EXISTING_DASHBOARD_FRESH_MS,
  canonicalJson,
  generateSafeLabHunterContract,
} = require('../lib/safe-lab-hunter-contract-v1');

const SOURCE_SHA = 'a'.repeat(40);
const BASE_NOW = Date.parse('2026-07-23T03:00:00.000Z');
let passed = 0;

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeJson(root, relative, value) {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function baseEvidence() {
  const gateStarted = '2026-07-23T02:59:50.000Z';
  const started = '2026-07-23T02:59:51.000Z';
  const finished = '2026-07-23T02:59:52.000Z';
  const qualificationCompleted = '2026-07-23T02:59:53.000Z';
  const gateCompleted = '2026-07-23T02:59:54.000Z';
  const round = {
    lab_id: 'juice-shop-v1',
    run_id: 'r01-controlled',
    manifest_digest: 'b'.repeat(64),
    image_digest: `sha256:${'c'.repeat(64)}`,
    control_digest: 'd'.repeat(64),
    source_digest: 'e'.repeat(64),
    scenario_family: 'INERT_DIFFERENTIAL_SEARCH_VALIDATION',
    request_count: 4,
    result: { vulnerable: 'LAB_FINDING_CONFIRMED', control: 'LAB_CONTROL_CLEAN' },
    request_budget_verified: true,
    policy_status: 'AUTHORIZED',
    environment: 'controlled_lab',
    reportability: 'not_reportable',
    external_target: false,
    started_at: started,
    completed_at: finished,
    duration_ms: 1000,
    runtime_identity: { uid: 1000, gid: 1000, hostname: 'private-container-host', node: 'v20.20.2' },
    runtime_evidence_sha256: 'f'.repeat(64),
    egress: {
      dns: { classification: 'BLOCKED_DNS', code: 'EAI_AGAIN' },
      metadata: { classification: 'BLOCKED_CONNECT', code: 'ENETUNREACH' },
      documentation_ip: { classification: 'BLOCKED_CONNECT', code: 'ENETUNREACH' },
    },
    evidence_stage: 'final',
    driver_evidence: { file: 'driver-round-r01-controlled.json', file_sha256: '1'.repeat(64), payload_sha256: '2'.repeat(64) },
    driver_evidence_sha256: '2'.repeat(64),
    driver_file_sha256: '1'.repeat(64),
    pre_run_residue_state: { containers: [], networks: [], volumes: [] },
    post_run_residue_state: { containers: [], networks: [], volumes: [] },
    cleanup_verified: true,
    cleanup_inventory: { containers: [], networks: [], volumes: [] },
    cleanup_error: null,
    container_identities: {
      candidate: { id: 'private-container-id', name: 'private-container-name' },
      control: { id: 'private-control-id', name: 'private-control-name' },
      driver: { id: 'private-driver-id', name: 'private-driver-name' },
    },
    source: {
      head_sha: SOURCE_SHA,
      merge_sha: '3'.repeat(40),
      tree_sha: '4'.repeat(40),
      workflow_run_id: '123456',
      workflow_run_attempt: '1',
      workflow_name: 'BOQA Real Docker Qualification Gate V1',
      workflow_job: 'qualification',
      repository: 'simonkey888/boqa',
    },
    orchestrator_timing: { started_at: gateStarted, completed_at: qualificationCompleted, duration_ms: 3000 },
    final_classification: 'LAB_ROUND_CONFIRMED',
    evidence_sha256: '5'.repeat(64),
  };
  return {
    qualification: {
      schema_version: 1,
      candidate_head_sha: SOURCE_SHA,
      candidate_merge_sha: '3'.repeat(40),
      source_tree_sha: '4'.repeat(40),
      workflow_run_id: '123456',
      image_digest_match: true,
      config_digest_match: true,
      configured_runtime_user: '65532',
      driver_runtime_user: '1000:1000',
      internal_network: true,
      host_ports: 0,
      docker_socket: 0,
      privileged: false,
      capabilities: 'dropped',
      read_only_runtime: true,
      runtime_egress: 'blocked',
      unauthorized_connections: 0,
      rounds_requested: 1,
      rounds_completed: 1,
      vulnerable_confirmed: 1,
      controls_clean: 1,
      false_positives: 0,
      false_negatives: 0,
      cleanup_failures: 0,
      evidence_pairs_verified: true,
      evidence_integrity: 'valid',
      production_accessed: false,
      deploy_performed: false,
      completed_at: qualificationCompleted,
    },
    summary: {
      rounds_requested: 1,
      rounds_completed: 1,
      vulnerable_confirmed: 1,
      controls_clean: 1,
      false_positives: 0,
      false_negatives: 0,
      cleanup_failures: 0,
    },
    gateStatus: {
      schema_version: 1,
      qualification_green: true,
      mode: 'short',
      head_sha: SOURCE_SHA,
      merge_sha: '3'.repeat(40),
      tree_sha: '4'.repeat(40),
      workflow_run_id: '123456',
      project: 'boqa-lab-redacted',
      run_dir: 'output/soak/redacted',
      started_at: gateStarted,
      gates: { pre_run_clean: 'PASS', compose_policy: 'PASS', round_assertions: 'PASS', evidence_pairs: 'PASS', cleanup: 'PASS', egress: 'PASS', final: 'PASS' },
      completed_at: gateCompleted,
    },
    round,
  };
}

function materialize(mutator = null) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-safe-lab-contract-'));
  const state = baseEvidence();
  if (mutator) mutator(state);
  writeJson(root, 'compose-normalized.json', { services: { candidate: {}, control: {}, driver: {} }, networks: { internal: true } });
  writeJson(root, 'evidence-files.json', { driver_files: ['driver-round-r01-controlled.json'], final_files: ['final-round-r01-controlled.json'] });
  writeJson(root, 'gate-status.json', state.gateStatus);
  writeJson(root, 'materialized-image.json', { manifest_match: true, config_match: true, configured_user: '65532' });
  writeJson(root, 'qualification-manifest.json', state.qualification);
  writeJson(root, 'round-results.json', [state.round]);
  writeJson(root, 'soak-summary.json', state.summary);
  writeJson(root, 'final-round-r01-controlled.json', state.round);
  writeJson(root, 'driver/driver-round-r01-controlled.json', { result: state.round.result, environment: state.round.environment, reportability: state.round.reportability });
  refreshChecksums(root);
  return { root, state };
}

function refreshChecksums(root) {
  const files = [];
  function walk(dir, prefix = '') {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (relative === 'SHA256SUMS') continue;
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(absolute, relative);
      else files.push(relative);
    }
  }
  walk(root);
  const lines = files.sort().map((relative) => `${sha256(fs.readFileSync(path.join(root, relative)))}  ${relative}`);
  fs.writeFileSync(path.join(root, 'SHA256SUMS'), `${lines.join('\n')}\n`);
}

function regenerateFiles(fixture) {
  writeJson(fixture.root, 'qualification-manifest.json', fixture.state.qualification);
  writeJson(fixture.root, 'soak-summary.json', fixture.state.summary);
  writeJson(fixture.root, 'gate-status.json', fixture.state.gateStatus);
  writeJson(fixture.root, 'round-results.json', [fixture.state.round]);
  writeJson(fixture.root, 'final-round-r01-controlled.json', fixture.state.round);
  writeJson(fixture.root, 'driver/driver-round-r01-controlled.json', { result: fixture.state.round.result, environment: fixture.state.round.environment, reportability: fixture.state.round.reportability });
  refreshChecksums(fixture.root);
}

function generate(fixture, options = {}) {
  return generateSafeLabHunterContract({
    evidenceDir: fixture.root,
    expectedSourceSha: options.sourceSha || SOURCE_SHA,
    nowMs: options.nowMs ?? BASE_NOW,
  });
}

function expectCode(code, fn) {
  assert.throws(fn, (error) => error && error.code === code, `expected ${code}`);
}

function test(name, fn) {
  fn();
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
}

test('valid evidence produces closed FRESH one-shot contract', () => {
  const fixture = materialize();
  const generated = generate(fixture);
  assert.equal(generated.contract.status, 'FRESH');
  assert.equal(generated.contract.environment, 'controlled_lab');
  assert.equal(generated.contract.reportable, false);
  assert.equal(generated.contract.hunter_state, 'LAB_COMPLETE');
  assert.ok(!generated.json.includes('ACTIVE'));
  assert.match(generated.checksum, /^sha256:[a-f0-9]{64}$/);
});

test('incorrect checksum is rejected', () => {
  const fixture = materialize();
  fs.appendFileSync(path.join(fixture.root, 'soak-summary.json'), ' ');
  expectCode('CHECKSUM_MISMATCH', () => generate(fixture));
});

test('missing file is rejected', () => {
  const fixture = materialize();
  fs.rmSync(path.join(fixture.root, 'materialized-image.json'));
  expectCode('EVIDENCE_FILE_MISSING', () => generate(fixture));
});

test('extra file is rejected', () => {
  const fixture = materialize();
  fs.writeFileSync(path.join(fixture.root, 'unexpected.txt'), 'unexpected');
  expectCode('EVIDENCE_FILE_EXTRA', () => generate(fixture));
});

test('source SHA mismatch is rejected', () => {
  const fixture = materialize();
  expectCode('SOURCE_SHA_MISMATCH', () => generate(fixture, { sourceSha: 'b'.repeat(40) }));
});

test('future evidence is rejected', () => {
  const fixture = materialize();
  expectCode('EVIDENCE_FROM_FUTURE', () => generate(fixture, { nowMs: Date.parse('2026-07-23T02:59:53.500Z') }));
});

test('stale evidence is labelled STALE using centralized injected clock', () => {
  const fixture = materialize();
  const nowMs = Date.parse(fixture.state.gateStatus.completed_at) + EXISTING_DASHBOARD_FRESH_MS + 1;
  assert.equal(generate(fixture, { nowMs }).contract.status, 'STALE');
});

test('contaminated negative control is rejected', () => {
  const fixture = materialize((state) => { state.round.result.control = 'INDETERMINATE'; });
  expectCode('NEGATIVE_CONTROL_CONTAMINATED', () => generate(fixture));
});

test('false positives greater than zero are rejected', () => {
  const fixture = materialize((state) => { state.qualification.false_positives = 1; state.summary.false_positives = 1; });
  expectCode('FALSE_POSITIVES_NONZERO', () => generate(fixture));
});

test('false negatives greater than zero are rejected', () => {
  const fixture = materialize((state) => { state.qualification.false_negatives = 1; state.summary.false_negatives = 1; });
  expectCode('FALSE_NEGATIVES_NONZERO', () => generate(fixture));
});

test('unauthorized connections greater than zero are rejected', () => {
  const fixture = materialize((state) => { state.qualification.unauthorized_connections = 1; });
  expectCode('UNAUTHORIZED_CONNECTIONS_NONZERO', () => generate(fixture));
});

test('cleanup false is rejected', () => {
  const fixture = materialize((state) => { state.round.cleanup_verified = false; });
  expectCode('CLEANUP_NOT_VERIFIED', () => generate(fixture));
});

test('egress failure is rejected', () => {
  const fixture = materialize((state) => { state.round.egress.dns.classification = 'ALLOWED'; });
  expectCode('EGRESS_NOT_BLOCKED', () => generate(fixture));
});

test('reportable evidence is rejected', () => {
  const fixture = materialize((state) => { state.round.reportability = 'reportable'; });
  expectCode('REPORTABLE_EVIDENCE_FORBIDDEN', () => generate(fixture));
});

test('incorrect environment is rejected', () => {
  const fixture = materialize((state) => { state.round.environment = 'production'; });
  expectCode('ENVIRONMENT_INVALID', () => generate(fixture));
});

test('inconsistent timestamps are rejected', () => {
  const fixture = materialize((state) => { state.round.started_at = '2026-07-23T02:59:55.000Z'; });
  expectCode('TIMESTAMPS_INCONSISTENT', () => generate(fixture));
});

test('generation is deterministic for identical evidence and clock', () => {
  const fixture = materialize();
  const first = generate(fixture);
  const second = generate(fixture);
  assert.equal(first.json, second.json);
  assert.equal(first.checksum, second.checksum);
  assert.equal(canonicalJson(first.contract), canonicalJson(second.contract));
});

test('private raw fields never enter the public contract', () => {
  const fixture = materialize();
  const json = generate(fixture).json;
  for (const forbidden of ['private-container-host', 'private-container-id', 'private-control-id', 'private-driver-id', 'container_identities', 'runtime_identity']) {
    assert.ok(!json.includes(forbidden), forbidden);
  }
});

test('unknown critical qualification field is rejected', () => {
  const fixture = materialize();
  fixture.state.qualification.target_url = 'https://forbidden.invalid';
  regenerateFiles(fixture);
  expectCode('UNKNOWN_CRITICAL_FIELD', () => generate(fixture));
});

assert.equal(passed, 19);
console.log(`1..${passed}`);

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCHEMA = require('../schemas/safe-lab-hunter-contract-v1.schema.json');

const CONTRACT_SCHEMA_VERSION = 1;
const POLICY_ID = 'safe-lab-readonly-v1';
const EXISTING_DASHBOARD_FRESH_MS = 90_000;
const DEFAULT_UNAVAILABLE_MS = 24 * 60 * 60 * 1000;
const ALLOWED_EGRESS_RESULTS = new Set(['BLOCKED_DNS', 'BLOCKED_CONNECT', 'BLOCKED_TIMEOUT']);
const EXPECTED_STATIC_FILES = new Set([
  'compose-normalized.json',
  'evidence-files.json',
  'gate-status.json',
  'materialized-image.json',
  'qualification-manifest.json',
  'round-results.json',
  'soak-summary.json',
]);
const QUALIFICATION_KEYS = new Set([
  'schema_version', 'candidate_head_sha', 'candidate_merge_sha', 'source_tree_sha', 'workflow_run_id',
  'image_digest_match', 'config_digest_match', 'configured_runtime_user', 'driver_runtime_user',
  'internal_network', 'host_ports', 'docker_socket', 'privileged', 'capabilities', 'read_only_runtime',
  'runtime_egress', 'unauthorized_connections', 'rounds_requested', 'rounds_completed',
  'vulnerable_confirmed', 'controls_clean', 'false_positives', 'false_negatives', 'cleanup_failures',
  'evidence_pairs_verified', 'evidence_integrity', 'production_accessed', 'deploy_performed', 'completed_at',
]);
const SUMMARY_KEYS = new Set([
  'rounds_requested', 'rounds_completed', 'vulnerable_confirmed', 'controls_clean',
  'false_positives', 'false_negatives', 'cleanup_failures',
]);
const GATE_STATUS_KEYS = new Set([
  'schema_version', 'qualification_green', 'mode', 'head_sha', 'merge_sha', 'tree_sha',
  'workflow_run_id', 'project', 'run_dir', 'started_at', 'gates', 'completed_at',
]);
const PROHIBITED_PUBLIC_KEY_PATTERN = /(hostname|container|ocid|ip_address|private_path|secret|cookie|authorization|payload|user_data)/i;
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const CHECKSUM_PATTERN = /^([a-f0-9]{64})  ([A-Za-z0-9._/-]+)$/;

function fail(code, detail) {
  const error = new Error(detail ? `${code}:${detail}` : code);
  error.code = code;
  throw error;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonicalize(value[key]);
      return result;
    }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    fail('INVALID_JSON', path.basename(filePath));
  }
}

function assertExactKeys(value, allowed, context) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('INVALID_SCHEMA', context);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail('UNKNOWN_CRITICAL_FIELD', `${context}.${key}`);
  }
}

function listFiles(root) {
  const files = [];
  function walk(dir, prefix = '') {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) fail('EVIDENCE_SYMLINK_FORBIDDEN', relative);
      if (entry.isDirectory()) walk(absolute, relative);
      else if (entry.isFile()) files.push(relative);
      else fail('EVIDENCE_FILE_TYPE_FORBIDDEN', relative);
    }
  }
  walk(root);
  return files.sort();
}

function parseChecksums(evidenceDir) {
  const checksumPath = path.join(evidenceDir, 'SHA256SUMS');
  if (!fs.existsSync(checksumPath)) fail('CHECKSUM_FILE_MISSING');
  const raw = fs.readFileSync(checksumPath, 'utf8');
  const entries = new Map();
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const match = CHECKSUM_PATTERN.exec(line);
    if (!match) fail('CHECKSUM_FORMAT_INVALID');
    const [, digest, relative] = match;
    if (relative.includes('..') || path.isAbsolute(relative)) fail('CHECKSUM_PATH_INVALID', relative);
    if (entries.has(relative)) fail('CHECKSUM_DUPLICATE_PATH', relative);
    entries.set(relative, digest);
  }
  return { entries, raw };
}

function verifyEvidenceFiles(evidenceDir) {
  const { entries } = parseChecksums(evidenceDir);
  const actual = listFiles(evidenceDir).filter((file) => file !== 'SHA256SUMS');
  const expected = [...entries.keys()].sort();
  const missing = expected.filter((file) => !actual.includes(file));
  const extra = actual.filter((file) => !entries.has(file));
  if (missing.length) fail('EVIDENCE_FILE_MISSING', missing[0]);
  if (extra.length) fail('EVIDENCE_FILE_EXTRA', extra[0]);
  if (actual.length !== 9) fail('EVIDENCE_FILE_COUNT_INVALID', String(actual.length));

  const dynamicFinal = actual.filter((file) => /^final-round-[A-Za-z0-9_-]+\.json$/.test(file));
  const dynamicDriver = actual.filter((file) => /^driver\/driver-round-[A-Za-z0-9_-]+\.json$/.test(file));
  if (dynamicFinal.length !== 1 || dynamicDriver.length !== 1) fail('EVIDENCE_PAIR_COUNT_INVALID');
  for (const file of EXPECTED_STATIC_FILES) if (!entries.has(file)) fail('EVIDENCE_FILE_MISSING', file);

  for (const [relative, expectedDigest] of entries) {
    const absolute = path.join(evidenceDir, relative);
    const actualDigest = sha256(fs.readFileSync(absolute));
    if (actualDigest !== expectedDigest) fail('CHECKSUM_MISMATCH', relative);
  }

  const normalizedLines = [...entries.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([relative, digest]) => `${digest}  ${relative}`)
    .join('\n') + '\n';
  return {
    files: actual,
    finalFile: dynamicFinal[0],
    driverFile: dynamicDriver[0],
    evidenceChecksum: `sha256:${sha256(normalizedLines)}`,
  };
}

function parseIso(value, context) {
  if (typeof value !== 'string') fail('TIMESTAMP_INVALID', context);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail('TIMESTAMP_INVALID', context);
  return parsed;
}

function classifyFreshness(completedMs, nowMs, options = {}) {
  const freshMs = Number.isFinite(options.freshMs) ? options.freshMs : EXISTING_DASHBOARD_FRESH_MS;
  const unavailableMs = Number.isFinite(options.unavailableMs) ? options.unavailableMs : DEFAULT_UNAVAILABLE_MS;
  if (!Number.isFinite(nowMs)) fail('CLOCK_INVALID');
  if (completedMs > nowMs) fail('EVIDENCE_FROM_FUTURE');
  const ageMs = nowMs - completedMs;
  if (ageMs <= freshMs) return 'FRESH';
  if (ageMs <= unavailableMs) return 'STALE';
  return 'UNAVAILABLE';
}

function assertQualification(qualification, summary, gateStatus, rounds, finalRound, expectedSourceSha, nowMs) {
  assertExactKeys(qualification, QUALIFICATION_KEYS, 'qualification_manifest');
  assertExactKeys(summary, SUMMARY_KEYS, 'soak_summary');
  assertExactKeys(gateStatus, GATE_STATUS_KEYS, 'gate_status');
  if (!SHA_PATTERN.test(expectedSourceSha || '')) fail('SOURCE_SHA_INVALID');
  if (qualification.schema_version !== 1 || gateStatus.schema_version !== 1) fail('QUALIFICATION_SCHEMA_INVALID');
  if (qualification.candidate_head_sha !== expectedSourceSha || gateStatus.head_sha !== expectedSourceSha) fail('SOURCE_SHA_MISMATCH');
  if (!Array.isArray(rounds) || rounds.length !== 1) fail('ROUND_COUNT_INVALID');
  const round = rounds[0];
  if (!round || round.source?.head_sha !== expectedSourceSha || finalRound.source?.head_sha !== expectedSourceSha) fail('SOURCE_SHA_MISMATCH');
  if (canonicalJson(round) !== canonicalJson(finalRound)) fail('ROUND_EVIDENCE_MISMATCH');

  const startedMs = parseIso(round.started_at, 'round.started_at');
  const finishedMs = parseIso(round.completed_at, 'round.completed_at');
  const qualificationCompletedMs = parseIso(qualification.completed_at, 'qualification.completed_at');
  const gateStartedMs = parseIso(gateStatus.started_at, 'gate_status.started_at');
  const gateCompletedMs = parseIso(gateStatus.completed_at, 'gate_status.completed_at');
  if (!(gateStartedMs <= startedMs && startedMs <= finishedMs && finishedMs <= qualificationCompletedMs && qualificationCompletedMs <= gateCompletedMs)) {
    fail('TIMESTAMPS_INCONSISTENT');
  }
  if (gateCompletedMs > nowMs) fail('EVIDENCE_FROM_FUTURE');

  if (qualification.qualification_green === false || gateStatus.qualification_green !== true) fail('QUALIFICATION_NOT_GREEN');
  if (qualification.vulnerable_confirmed !== 1 || summary.vulnerable_confirmed !== 1 || round.result?.vulnerable !== 'LAB_FINDING_CONFIRMED') fail('CANDIDATE_NOT_CONFIRMED');
  if (qualification.controls_clean !== 1 || summary.controls_clean !== 1 || round.result?.control !== 'LAB_CONTROL_CLEAN') fail('NEGATIVE_CONTROL_CONTAMINATED');
  if (qualification.false_positives !== 0 || summary.false_positives !== 0) fail('FALSE_POSITIVES_NONZERO');
  if (qualification.false_negatives !== 0 || summary.false_negatives !== 0) fail('FALSE_NEGATIVES_NONZERO');
  if (qualification.unauthorized_connections !== 0) fail('UNAUTHORIZED_CONNECTIONS_NONZERO');
  if (qualification.cleanup_failures !== 0 || summary.cleanup_failures !== 0 || round.cleanup_verified !== true) fail('CLEANUP_NOT_VERIFIED');
  if (qualification.runtime_egress !== 'blocked') fail('EGRESS_NOT_BLOCKED');
  if (!round.egress || Object.values(round.egress).some((entry) => !ALLOWED_EGRESS_RESULTS.has(entry?.classification))) fail('EGRESS_NOT_BLOCKED');
  if (round.environment !== 'controlled_lab') fail('ENVIRONMENT_INVALID');
  if (round.reportability !== 'not_reportable' || round.external_target !== false) fail('REPORTABLE_EVIDENCE_FORBIDDEN');
  if (round.policy_status !== 'AUTHORIZED') fail('POLICY_NOT_AUTHORIZED');
  if (round.request_budget_verified !== true) fail('REQUEST_BUDGET_NOT_VERIFIED');
  if (round.final_classification !== 'LAB_ROUND_CONFIRMED') fail('ROUND_CLASSIFICATION_INVALID');
  if (qualification.evidence_integrity !== 'valid' || qualification.evidence_pairs_verified !== true) fail('EVIDENCE_INTEGRITY_INVALID');
  if (qualification.production_accessed !== false || qualification.deploy_performed !== false) fail('PRODUCTION_MUTATION_DETECTED');

  return { round, startedMs, finishedMs, gateCompletedMs };
}

function validateClosedContract(contract) {
  const required = SCHEMA.required;
  const keys = Object.keys(contract).sort();
  const expectedKeys = Object.keys(SCHEMA.properties).sort();
  if (canonicalJson(keys) !== canonicalJson(expectedKeys)) fail('CONTRACT_FIELDS_INVALID');
  for (const key of required) if (!(key in contract)) fail('CONTRACT_FIELD_MISSING', key);
  for (const [key, rule] of Object.entries(SCHEMA.properties)) {
    const value = contract[key];
    if ('const' in rule && value !== rule.const) fail('CONTRACT_FIELD_INVALID', key);
    if (rule.enum && !rule.enum.includes(value)) fail('CONTRACT_FIELD_INVALID', key);
    if (rule.type === 'string' && typeof value !== 'string') fail('CONTRACT_FIELD_INVALID', key);
    if (rule.pattern && !new RegExp(rule.pattern).test(value)) fail('CONTRACT_FIELD_INVALID', key);
    if (rule.format === 'date-time') parseIso(value, `contract.${key}`);
  }
  const serialized = canonicalJson(contract);
  if (/\bACTIVE\b/.test(serialized)) fail('ACTIVE_FORBIDDEN_FOR_ONE_SHOT');
  for (const key of Object.keys(contract)) if (PROHIBITED_PUBLIC_KEY_PATTERN.test(key)) fail('PRIVATE_FIELD_FORBIDDEN', key);
  return true;
}

function generateSafeLabHunterContract(options = {}) {
  const evidenceDir = path.resolve(options.evidenceDir || '');
  const expectedSourceSha = String(options.expectedSourceSha || '').trim();
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  if (!fs.existsSync(evidenceDir) || !fs.statSync(evidenceDir).isDirectory()) fail('EVIDENCE_DIR_INVALID');

  const verified = verifyEvidenceFiles(evidenceDir);
  const qualification = readJson(path.join(evidenceDir, 'qualification-manifest.json'));
  const summary = readJson(path.join(evidenceDir, 'soak-summary.json'));
  const gateStatus = readJson(path.join(evidenceDir, 'gate-status.json'));
  const rounds = readJson(path.join(evidenceDir, 'round-results.json'));
  const finalRound = readJson(path.join(evidenceDir, verified.finalFile));
  const asserted = assertQualification(qualification, summary, gateStatus, rounds, finalRound, expectedSourceSha, nowMs);
  const status = classifyFreshness(asserted.gateCompletedMs, nowMs, options.freshness);
  const freshMs = Number.isFinite(options.freshness?.freshMs) ? options.freshness.freshMs : EXISTING_DASHBOARD_FRESH_MS;

  const contract = {
    schema_version: CONTRACT_SCHEMA_VERSION,
    environment: 'controlled_lab',
    status,
    hunter_state: 'LAB_COMPLETE',
    reportable: false,
    authorized_scope: 'synthetic_fixture',
    target_kind: 'owasp_juice_shop_pinned',
    policy_id: POLICY_ID,
    source_sha: expectedSourceSha,
    run_id: `sha256:${sha256(String(asserted.round.run_id)).slice(0, 16)}`,
    cycle_started_at: new Date(asserted.startedMs).toISOString(),
    cycle_finished_at: new Date(asserted.finishedMs).toISOString(),
    observed_at: new Date(asserted.gateCompletedMs).toISOString(),
    fresh_until: new Date(asserted.gateCompletedMs + freshMs).toISOString(),
    finding_count: 1,
    control_finding_count: 0,
    false_positive_count: 0,
    false_negative_count: 0,
    unauthorized_connection_count: 0,
    cleanup_verified: true,
    egress_blocked: true,
    storage_valid: true,
    request_budget_verified: true,
    evidence_checksum: verified.evidenceChecksum,
    message: 'Validación completada en laboratorio controlado',
  };
  validateClosedContract(contract);
  const json = `${canonicalJson(contract)}\n`;
  return {
    contract,
    json,
    checksum: `sha256:${sha256(json)}`,
    checksumLine(fileName = 'hunter-status-public.json') {
      return `${sha256(json)}  ${fileName}\n`;
    },
  };
}

module.exports = {
  CONTRACT_SCHEMA_VERSION,
  POLICY_ID,
  EXISTING_DASHBOARD_FRESH_MS,
  DEFAULT_UNAVAILABLE_MS,
  canonicalJson,
  classifyFreshness,
  validateClosedContract,
  verifyEvidenceFiles,
  generateSafeLabHunterContract,
};

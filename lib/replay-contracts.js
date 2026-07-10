/**
 * BOQA P5 Contract Schema Freeze — Replay API Response Contract Definitions
 *
 * This file defines the exact response schemas for all P5 replay API endpoints.
 * These contracts are frozen and must not change without version increment.
 *
 * Version: 1.0.0
 * Frozen at: Phase 5 Finalization
 */

const CONTRACT_VERSION = '1.0.0';

// ═══════════════════════════════════════════════════════════════════════
//  Manifest Contract (replay_manifest_v1)
// ═══════════════════════════════════════════════════════════════════════

const MANIFEST_SCHEMA = {
  schema_name: 'replay_manifest_v1',
  required_fields: [
    'schema_name', 'replay_id', 'boqa_version', 'node_version',
    'playwright_version', 'chromium_version', 'os_version',
    'timestamp_utc', 'target_domain', 'scenario_name', 'scenario_tags',
    'config', 'environment', 'fingerprint', 'session_timestamps',
    'storage_meta', 'network_summary', 'state_hash', 'artifact_index',
    'artifact_hash', 'events_count', 'redaction_summary',
  ],
  optional_fields: ['internal_state', 'signature'],
  field_types: {
    schema_name: 'string',
    replay_id: 'string',              // Format: RPL-{uuid-prefix-12}
    boqa_version: 'string',
    node_version: 'string',
    playwright_version: 'string',
    chromium_version: 'string',
    os_version: 'string',
    timestamp_utc: 'string',          // ISO 8601
    target_domain: 'string|null',
    scenario_name: 'string',
    scenario_tags: 'string[]',
    config: 'object',
    environment: 'object',
    fingerprint: 'object',
    session_timestamps: 'object',
    storage_meta: 'object',
    network_summary: 'object',
    internal_state: 'object|null',
    state_hash: 'string|null',        // SHA-256 hex
    artifact_index: 'object',
    artifact_hash: 'string',          // SHA-256 hex
    events_count: 'number',
    signature: 'string|null',
    redaction_summary: 'object',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Recording Contract (UniversalSessionRecorder.export())
// ═══════════════════════════════════════════════════════════════════════

const RECORDING_SCHEMA = {
  required_fields: [
    'recorder_id', 'manifest_id', 'context_hash',
    'started_at', 'ended_at', 'duration_ms',
    'total_events', 'step_boundaries', 'stats', 'events',
  ],
  field_types: {
    recorder_id: 'string',            // Format: REC-{uuid-prefix-8}
    manifest_id: 'string|null',
    context_hash: 'string',           // SHA-256 hex
    started_at: 'number',
    ended_at: 'number',
    duration_ms: 'number',
    total_events: 'number',
    step_boundaries: 'array',
    stats: 'object',
    events: 'array',
  },
  event_schema: {
    required_fields: ['seq', 'ts', 'type', 'source', 'step', 'recorder_id'],
    field_types: {
      seq: 'number',
      ts: 'number',
      type: 'string',
      url: 'string|null',
      method: 'string|null',
      status: 'number|null',
      headers: 'object|null',
      payload: 'object|null',
      source: 'string',
      meta: 'object',
      step: 'number',
      recorder_id: 'string',
    },
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Recording Start Response Contract
// ═══════════════════════════════════════════════════════════════════════

const RECORDING_START_SCHEMA = {
  required_fields: ['recorder_id', 'manifest_id', 'started_at'],
  field_types: {
    recorder_id: 'string',
    manifest_id: 'string|null',
    started_at: 'number',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Recording Stop Response Contract
// ═══════════════════════════════════════════════════════════════════════

const RECORDING_STOP_SCHEMA = {
  required_fields: [
    'recorder_id', 'manifest_id', 'started_at', 'ended_at',
    'duration_ms', 'events_count', 'step_boundaries', 'context_hash', 'stats',
  ],
  field_types: {
    recorder_id: 'string',
    manifest_id: 'string|null',
    started_at: 'number',
    ended_at: 'number',
    duration_ms: 'number',
    events_count: 'number',
    step_boundaries: 'number',
    context_hash: 'string',
    stats: 'object',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Replay Report Contract (DeterministicReplayEngine.replay())
// ═══════════════════════════════════════════════════════════════════════

const REPLAY_REPORT_SCHEMA = {
  required_fields: [
    'type', 'recorder_id', 'manifest_id', 'replayed_at',
    'total_events', 'network_total', 'passed', 'failed', 'skipped',
    'pass_rate', 'steps_processed', 'clock_advances', 'rng_seed', 'verdict',
  ],
  optional_fields: ['context_hash_match', 'results'],
  field_types: {
    type: 'string',                   // 'deterministic_replay_report'
    recorder_id: 'string|null',
    manifest_id: 'string|null',
    replayed_at: 'number',
    total_events: 'number',
    network_total: 'number',
    passed: 'number',
    failed: 'number',
    skipped: 'number',
    pass_rate: 'number',              // 0.0–1.0
    context_hash_match: 'boolean|null',
    steps_processed: 'number',
    clock_advances: 'number',
    rng_seed: 'string',
    verdict: 'string',                // deterministic_clean|deterministic_warning|deterministic_critical
    results: 'array',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Verification Result Contract
// ═══════════════════════════════════════════════════════════════════════

const VERIFICATION_SCHEMA = {
  required_fields: [
    'verification_id', 'original_recorder_id', 'replay_recorder_id',
    'verified_at', 'axes', 'composite_score', 'verdict', 'thresholds',
  ],
  field_types: {
    verification_id: 'string',        // Format: VER-{uuid-prefix-8}
    original_recorder_id: 'string',
    replay_recorder_id: 'string',
    verified_at: 'number',
    axes: 'object',
    composite_score: 'number',        // 0.0–1.0
    verdict: 'string',                // exact_match|acceptable_match|partial_match|mismatch
    thresholds: 'object',
  },
  axis_fields: ['dom', 'visual', 'network', 'cookies', 'storage', 'console', 'websocket', 'internal_state'],
  axis_result_types: {
    score: 'number',
    verdict: 'string',               // pass|fail|no_data|skipped
    within_threshold: 'boolean',
    threshold: 'number',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Security Operation Contracts
// ═══════════════════════════════════════════════════════════════════════

const REDACTION_SCHEMA = {
  required_fields: ['redacted', 'redaction_summary'],
  field_types: {
    redacted: 'object',
    redaction_summary: 'object',
  },
};

const SIGNING_SCHEMA = {
  required_fields: ['signature', 'algorithm', 'signed_at'],
  field_types: {
    signature: 'string',             // HMAC-SHA256 hex
    algorithm: 'string',             // 'hmac-sha256'
    signed_at: 'number',
  },
};

const SIGNATURE_VERIFY_SCHEMA = {
  required_fields: ['valid', 'algorithm'],
  field_types: {
    valid: 'boolean',
    algorithm: 'string',
  },
};

const ENCRYPTION_SCHEMA = {
  required_fields: ['encrypted', 'iv', 'algorithm', 'encrypted_at'],
  field_types: {
    encrypted: 'string',             // AES-256-CBC hex
    iv: 'string',                    // 16-byte hex
    algorithm: 'string',             // 'aes-256-cbc'
    encrypted_at: 'number',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Farm Job Contract
// ═══════════════════════════════════════════════════════════════════════

const FARM_JOB_SCHEMA = {
  required_fields: [
    'id', 'recording', 'manifest', 'scenarioName', 'priority',
    'replayOptions', 'state', 'submittedAt',
  ],
  optional_fields: ['startedAt', 'completedAt', 'result', 'error', 'retries', 'workerId'],
  field_types: {
    id: 'string',                     // Format: JOB-{uuid-prefix-8}
    recording: 'object',
    manifest: 'object|null',
    scenarioName: 'string',
    priority: 'number',
    replayOptions: 'object',
    state: 'string',                  // queued|running|completed|failed|retrying|cancelled|timed_out
    submittedAt: 'number',
    startedAt: 'number|null',
    completedAt: 'number|null',
    result: 'object|null',
    error: 'string|null',
    retries: 'number',
    workerId: 'string|null',
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  API Response Envelope Contract
// ═══════════════════════════════════════════════════════════════════════

const API_ENVELOPE = {
  success: {
    ok: true,
    // + endpoint-specific data
  },
  error: {
    ok: false,
    error: 'string',                  // Machine-readable error code
  },
};

// ═══════════════════════════════════════════════════════════════════════
//  Schema Validation Utility
// ═══════════════════════════════════════════════════════════════════════

function validateContract(data, schema) {
  const missing = schema.required_fields.filter(f => !(f in data));
  const violations = [];

  for (const [field, expectedType] of Object.entries(schema.field_types || {})) {
    if (field in data) {
      const actual = data[field];
      const nullable = expectedType.endsWith('|null');
      const baseType = nullable ? expectedType.replace('|null', '') : expectedType;

      if (nullable && (actual === null || actual === undefined)) continue;

      if (baseType === 'string' && typeof actual !== 'string') {
        violations.push(`${field}: expected string, got ${typeof actual}`);
      } else if (baseType === 'number' && typeof actual !== 'number') {
        violations.push(`${field}: expected number, got ${typeof actual}`);
      } else if (baseType === 'boolean' && typeof actual !== 'boolean') {
        violations.push(`${field}: expected boolean, got ${typeof actual}`);
      } else if (baseType === 'object' && (typeof actual !== 'object' || actual === null)) {
        violations.push(`${field}: expected object, got ${typeof actual}`);
      } else if (baseType === 'array' && !Array.isArray(actual)) {
        violations.push(`${field}: expected array, got ${typeof actual}`);
      }
    }
  }

  return {
    valid: missing.length === 0 && violations.length === 0,
    missing_fields: missing,
    type_violations: violations,
    contract_version: CONTRACT_VERSION,
  };
}

module.exports = {
  CONTRACT_VERSION,
  MANIFEST_SCHEMA,
  RECORDING_SCHEMA,
  RECORDING_START_SCHEMA,
  RECORDING_STOP_SCHEMA,
  REPLAY_REPORT_SCHEMA,
  VERIFICATION_SCHEMA,
  REDACTION_SCHEMA,
  SIGNING_SCHEMA,
  SIGNATURE_VERIFY_SCHEMA,
  ENCRYPTION_SCHEMA,
  FARM_JOB_SCHEMA,
  API_ENVELOPE,
  validateContract,
};


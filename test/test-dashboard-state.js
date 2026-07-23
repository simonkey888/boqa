'use strict';

const assert = require('assert');
const State = require('../dashboard/dashboard-state');

const now = Date.parse('2026-07-17T18:40:00.000Z');
const hunterPayload = {
  state: 'ACTIVE',
  freshness: { heartbeat_fresh: true, cycle_fresh: true, invariants_fresh: true },
  heartbeat_at: '2026-07-17T18:39:50.000Z',
  last_started_at: '2026-07-17T18:39:40.000Z',
  last_completed_at: '2026-07-17T18:39:45.000Z',
  next_scheduled_at: '2026-07-17T18:44:45.000Z',
  timestamp: '2026-07-17T18:39:50.000Z',
};
const healthPayload = {
  status: 'ok',
  version: '1.4.0',
  release_sha: 'release-a',
  process_uptime_ms: 10_000,
  timestamp: '2026-07-17T18:39:50.000Z',
};

let model = State.createInitialModel();
assert.equal(model.overall.view_state, 'LOADING');

model = State.buildModel({
  previous: model,
  nowMs: now,
  hunter: { ok: true, status: 200, payload: hunterPayload },
  health: { ok: true, status: 200, payload: healthPayload },
});
assert.equal(model.overall.view_state, 'FRESH');
assert.equal(model.sources.hunter.payload.state, 'ACTIVE');
assert.equal(model.sources.health.payload.release_sha, 'release-a');

const partial = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  hunter: { ok: true, status: 200, payload: { state: 'ACTIVE', timestamp: hunterPayload.timestamp } },
  health: { ok: true, status: 200, payload: healthPayload },
});
assert.equal(partial.overall.view_state, 'FRESH');
assert.equal(partial.sources.hunter.payload.last_completed_at, undefined);

const invalid = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  hunter: { ok: true, status: 200, payload: { timestamp: hunterPayload.timestamp } },
  health: { ok: true, status: 200, payload: healthPayload },
});
assert.equal(invalid.sources.hunter.view_state, 'N/D');
assert.equal(invalid.overall.view_state, 'N/D');

const stale = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  maxAgeMs: 30_000,
  hunter: { ok: true, status: 200, payload: { ...hunterPayload, timestamp: '2026-07-17T18:38:00.000Z' } },
  health: { ok: true, status: 200, payload: healthPayload },
});
assert.equal(stale.sources.hunter.view_state, 'STALE');
assert.equal(stale.overall.view_state, 'STALE');

const explicitDegraded = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  hunter: { ok: true, status: 200, payload: { ...hunterPayload, state: 'DEGRADED' } },
  health: { ok: true, status: 200, payload: healthPayload },
});
assert.equal(explicitDegraded.sources.hunter.view_state, 'DEGRADED');
assert.equal(explicitDegraded.overall.view_state, 'DEGRADED');

const unavailable = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  hunter: { ok: false, status: 504, error: { code: 'network_error' } },
  health: { ok: false, status: 503 },
});
assert.equal(unavailable.overall.view_state, 'UNAVAILABLE');

const changed = State.buildModel({
  previous: model,
  nowMs: now + 1_000,
  hunter: { ok: true, status: 200, payload: { ...hunterPayload, timestamp: '2026-07-17T18:40:00.000Z' } },
  health: { ok: true, status: 200, payload: { ...healthPayload, release_sha: 'release-b', timestamp: '2026-07-17T18:40:00.000Z' } },
});
assert.equal(changed.release_changed, true);
assert.equal(changed.release_sha, 'release-b');
assert.equal(changed.sources.hunter.payload.state, 'ACTIVE');

const recovered = State.buildModel({
  previous: unavailable,
  nowMs: now + 2_000,
  hunter: { ok: true, status: 200, payload: { ...hunterPayload, timestamp: '2026-07-17T18:40:01.000Z' } },
  health: { ok: true, status: 200, payload: { ...healthPayload, timestamp: '2026-07-17T18:40:01.000Z' } },
});
assert.equal(recovered.overall.view_state, 'FRESH');


const labPayload = {
  schema_version: 1,
  environment: 'controlled_lab',
  status: 'FRESH',
  hunter_state: 'LAB_COMPLETE',
  reportable: false,
  authorized_scope: 'synthetic_fixture',
  target_kind: 'owasp_juice_shop_pinned',
  policy_id: 'safe-lab-readonly-v1',
  source_sha: 'a'.repeat(40),
  run_id: 'sha256:0123456789abcdef',
  cycle_started_at: '2026-07-17T18:39:40.000Z',
  cycle_finished_at: '2026-07-17T18:39:45.000Z',
  observed_at: '2026-07-17T18:39:46.000Z',
  fresh_until: '2026-07-17T18:40:30.000Z',
  unavailable_after: '2026-07-18T18:39:46.000Z',
  finding_count: 1,
  control_finding_count: 0,
  false_positive_count: 0,
  false_negative_count: 0,
  unauthorized_connection_count: 0,
  cleanup_verified: true,
  egress_blocked: true,
  storage_valid: true,
  request_budget_verified: true,
  evidence_checksum: `sha256:${'b'.repeat(64)}`,
  message: 'Validación completada en laboratorio controlado',
};
const labHealth = {
  status: 'ok',
  environment: 'controlled_lab',
  timestamp: '2026-07-17T18:39:59.000Z',
};

const labFresh = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  hunter: { ok: true, status: 200, payload: labPayload },
  health: { ok: true, status: 200, payload: labHealth },
});
assert.equal(labFresh.environment, 'controlled_lab');
assert.equal(labFresh.sources.hunter.view_state, 'FRESH');
assert.equal(labFresh.overall.view_state, 'FRESH');
assert.equal(labFresh.sources.hunter.payload.hunter_state, 'LAB_COMPLETE');

const labStale = State.buildModel({
  previous: labFresh,
  nowMs: Date.parse('2026-07-17T18:41:00.000Z'),
  hunter: { ok: true, status: 200, payload: labPayload },
  health: { ok: true, status: 200, payload: { ...labHealth, timestamp: '2026-07-17T18:40:59.000Z' } },
});
assert.equal(labStale.sources.hunter.view_state, 'STALE');
assert.equal(labStale.sources.hunter.reason, 'lab_evidence_stale');
assert.equal(labStale.overall.view_state, 'STALE');

const labExpired = State.buildModel({
  previous: labStale,
  nowMs: Date.parse('2026-07-18T18:40:00.000Z'),
  hunter: { ok: true, status: 200, payload: labPayload },
  health: { ok: true, status: 200, payload: { ...labHealth, timestamp: '2026-07-18T18:39:59.000Z' } },
});
assert.equal(labExpired.sources.hunter.view_state, 'UNAVAILABLE');
assert.equal(labExpired.sources.hunter.reason, 'lab_evidence_expired');
assert.equal(labExpired.overall.view_state, 'DEGRADED');

const labFuture = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: Date.parse('2026-07-17T18:39:30.000Z'),
  hunter: { ok: true, status: 200, payload: labPayload },
  health: { ok: true, status: 200, payload: { ...labHealth, timestamp: '2026-07-17T18:39:29.000Z' } },
});
assert.equal(labFuture.sources.hunter.view_state, 'N/D');
assert.equal(labFuture.sources.hunter.reason, 'lab_contract_timestamp_future');

const labUnknownField = State.buildModel({
  previous: State.createInitialModel(),
  nowMs: now,
  hunter: { ok: true, status: 200, payload: { ...labPayload, private_path: '/internal/evidence' } },
  health: { ok: true, status: 200, payload: labHealth },
});
assert.equal(labUnknownField.sources.hunter.view_state, 'N/D');
assert.equal(labUnknownField.sources.hunter.reason, 'lab_contract_fields_invalid');



async function runNetworkContracts() {
  const ok = await State.fetchJsonContract(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ status: 'ok' }),
  }), '/api/health');
  assert.equal(ok.ok, true);

  const non2xx = await State.fetchJsonContract(async () => ({
    ok: false,
    status: 503,
    json: async () => ({ error: 'backend_unavailable' }),
  }), '/api/health');
  assert.equal(non2xx.ok, false);
  assert.equal(non2xx.status, 503);

  const invalidJson = await State.fetchJsonContract(async () => ({
    ok: true,
    status: 200,
    json: async () => { throw new Error('bad json'); },
  }), '/api/health');
  assert.equal(invalidJson.error.code, 'invalid_json');

  class FakeAbortController {
    constructor() { this.signal = {}; }
    abort() {}
  }
  const timeout = await State.fetchJsonContract(() => new Promise((_, reject) => {
    setTimeout(() => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      reject(error);
    }, 5);
  }), '/api/health', { timeoutMs: 1, AbortControllerImpl: FakeAbortController });
  assert.equal(timeout.error.code, 'timeout');

  const network = await State.fetchJsonContract(async () => { throw new Error('offline'); }, '/api/health');
  assert.equal(network.error.code, 'network_error');
  console.log('dashboard state and network contracts: PASS');
}

runNetworkContracts().catch((error) => {
  console.error(error);
  process.exit(1);
});

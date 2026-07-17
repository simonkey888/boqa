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

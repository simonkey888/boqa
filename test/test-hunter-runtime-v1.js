'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { HunterRuntime } = require('../lib/hunter-runtime');
const { createManualCycleController } = require('../routes/hunter-v1');
const { createHealthHandler } = require('../lib/health');

function fixturePolicy() {
  return {
    status: 'READY',
    authorized_assets: [{
      id: 'fixture',
      type: 'fixture_local',
      environment_type: 'owned_or_lab',
      checks: ['availability', 'schema'],
    }],
  };
}

function completedCycle() {
  return {
    scheduler_status: 'ACTIVE',
    engine_status: 'ACTIVE',
    controls_completed: 2,
    validated_findings: 0,
    reportable_findings: 0,
    evidence_integrity_status: 'VALID',
  };
}

function response() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    set(name, value) { this.headers[name] = value; return this; },
    setHeader(name, value) { this.headers[name] = value; return this; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

async function run() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-hunter-runtime-'));
  let now = Date.now();
  const runtime = new HunterRuntime({
    cycleRunner: async () => completedCycle(),
    policyProvider: fixturePolicy,
    statePath: path.join(root, 'state.json'),
    lockPath: path.join(root, 'runtime.lock'),
    intervalMs: 10_000,
    heartbeatIntervalMs: 1_000,
    heartbeatFreshnessMs: 3_000,
    cycleFreshnessMs: 30_000,
    now: () => now,
  });

  const started = await runtime.start();
  assert.equal(started.state, 'ACTIVE');
  assert.equal(started.lock_status, 'ACQUIRED');
  assert.equal(started.policy_status, 'READY');
  assert.equal(started.storage_status, 'READY');
  assert.equal(started.last_result.status, 'COMPLETED');

  const publicKeys = Object.keys(runtime.publicStatus()).sort();
  assert.deepEqual(publicKeys, [
    'freshness',
    'heartbeat_at',
    'last_completed_at',
    'last_started_at',
    'next_scheduled_at',
    'state',
    'timestamp',
  ]);

  now += 4_000;
  assert.equal(runtime.publicStatus().state, 'DEGRADED');
  runtime._heartbeat();
  assert.equal(runtime.publicStatus().state, 'ACTIVE');

  let releaseCycle;
  runtime.cycleRunner = () => new Promise((resolve) => { releaseCycle = resolve; });
  const first = runtime.runCycle('manual');
  await new Promise((resolve) => setImmediate(resolve));
  const overlap = await runtime.runCycle('manual');
  assert.equal(overlap.accepted, false);
  assert.equal(overlap.reason, 'CYCLE_ALREADY_RUNNING');
  releaseCycle(completedCycle());
  assert.equal((await first).accepted, true);

  const second = new HunterRuntime({
    cycleRunner: async () => completedCycle(),
    policyProvider: fixturePolicy,
    statePath: path.join(root, 'second-state.json'),
    lockPath: path.join(root, 'runtime.lock'),
    intervalMs: 10_000,
  });
  const locked = await second.start();
  assert.equal(locked.state, 'BLOCKED');
  assert.equal(locked.reason, 'HUNTER_LOCK_HELD');

  const blockedPolicy = new HunterRuntime({
    cycleRunner: async () => completedCycle(),
    policyProvider: () => ({ status: 'BLOCKED', reason: 'AUTHORIZATION_EXPIRED', authorized_assets: [] }),
    statePath: path.join(root, 'blocked-state.json'),
    lockPath: path.join(root, 'blocked.lock'),
  });
  const blocked = await blockedPolicy.start();
  assert.equal(blocked.state, 'BLOCKED');
  assert.equal(blocked.policy_status, 'BLOCKED');

  const storageBlocker = path.join(root, 'not-a-directory');
  fs.writeFileSync(storageBlocker, 'block');
  const recovering = new HunterRuntime({
    cycleRunner: async () => completedCycle(),
    policyProvider: fixturePolicy,
    statePath: path.join(storageBlocker, 'state.json'),
    lockPath: path.join(root, 'recover.lock'),
  });
  const failedStorage = await recovering.start();
  assert.equal(failedStorage.state, 'ERROR');
  assert.equal(failedStorage.storage_status, 'ERROR');
  fs.unlinkSync(storageBlocker);
  fs.mkdirSync(storageBlocker);
  const recovered = await recovering.start();
  assert.equal(recovered.state, 'ACTIVE');
  assert.equal(recovered.storage_status, 'READY');

  const previousKey = process.env.BOQA_API_KEY;
  const previousSecret = process.env.BOQA_HMAC_SECRET;
  process.env.BOQA_API_KEY = 'test-api-key';
  process.env.BOQA_HMAC_SECRET = 'test-hmac-secret';

  let manualCalls = 0;
  const routeRuntime = {
    preflightManual: () => ({ allowed: true, reason: 'AUTHORIZED' }),
    runCycle: async () => {
      manualCalls += 1;
      return { accepted: true, result: { status: 'COMPLETED' }, hunter: { state: 'ACTIVE' } };
    },
  };
  const controller = createManualCycleController({ now: () => now, rateLimit: 3 });
  const baseReq = {
    ip: '127.0.0.1',
    headers: { 'x-api-key': 'test-api-key' },
    boqaAuth: { apiKey: true, hmac: true },
    get(name) { return this.headers[String(name).toLowerCase()] || null; },
  };

  const unauth = response();
  await controller.handle({ ...baseReq, boqaAuth: { apiKey: false, hmac: false } }, unauth, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  assert.equal(unauth.statusCode, 401);

  const missingKey = response();
  await controller.handle(baseReq, missingKey, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  assert.equal(missingKey.statusCode, 400);

  const req1 = { ...baseReq, headers: { ...baseReq.headers, 'idempotency-key': 'manual-cycle-0001' } };
  const accepted = response();
  await controller.handle(req1, accepted, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  assert.equal(accepted.statusCode, 202);
  assert.equal(manualCalls, 1);

  const replay = response();
  await controller.handle(req1, replay, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  assert.equal(replay.statusCode, 200);
  assert.equal(replay.body.idempotent_replay, true);
  assert.equal(manualCalls, 1);

  routeRuntime.preflightManual = () => ({ allowed: false, reason: 'CYCLE_ALREADY_RUNNING' });
  const overlapRoute = response();
  const overlapReq = { ...baseReq, headers: { ...baseReq.headers, 'idempotency-key': 'manual-cycle-0002' } };
  await controller.handle(overlapReq, overlapRoute, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  assert.equal(overlapRoute.statusCode, 409);

  routeRuntime.preflightManual = () => ({ allowed: true, reason: 'AUTHORIZED' });
  for (const key of ['manual-cycle-0003', 'manual-cycle-0004']) {
    const res = response();
    await controller.handle({ ...baseReq, headers: { ...baseReq.headers, 'idempotency-key': key } }, res, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  }
  const limited = response();
  await controller.handle({ ...baseReq, headers: { ...baseReq.headers, 'idempotency-key': 'manual-cycle-0005' } }, limited, (error) => { throw error; }, { hunterRuntime: routeRuntime });
  assert.equal(limited.statusCode, 429);

  const healthCtx = {
    hunterRuntime: { internalStatus: () => started },
    serverStartTime: Date.now() - 1_000,
    agent: null,
    defensiveValidation: {},
    bus: { eventIndex: 0, clients: new Set() },
  };
  const healthOk = response();
  createHealthHandler(healthCtx)({}, healthOk);
  assert.equal(healthOk.statusCode, 200);
  assert.equal(healthOk.body.hunter.state, 'ACTIVE');

  healthCtx.hunterRuntime.internalStatus = () => ({ ...started, state: 'DEGRADED', reason: 'heartbeat_stale' });
  const healthDegraded = response();
  createHealthHandler(healthCtx)({}, healthDegraded);
  assert.equal(healthDegraded.statusCode, 503);

  await runtime.stop('test_complete');
  await recovering.stop('test_complete');
  assert.equal(fs.existsSync(path.join(root, 'runtime.lock')), false);

  if (previousKey === undefined) delete process.env.BOQA_API_KEY;
  else process.env.BOQA_API_KEY = previousKey;
  if (previousSecret === undefined) delete process.env.BOQA_HMAC_SECRET;
  else process.env.BOQA_HMAC_SECRET = previousSecret;

  fs.rmSync(root, { recursive: true, force: true });
  console.log('hunter runtime gate: PASS');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

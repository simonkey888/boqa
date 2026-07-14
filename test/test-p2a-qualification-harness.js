'use strict';

const { buildAgentInput, FORBIDDEN_AGENT_KEYS, opaqueId } = require('../qualification/adapters/agent-input');
const { buildDockerIsolationPolicy, validateDockerIsolationPolicy, opaqueScenarioName } = require('../qualification/runners/isolation-policy');
const { createIsolatedRuntime } = require('../qualification/runners/isolated-runtime');
const { runQualification } = require('../qualification/runners/harness');
const { calculateMetrics } = require('../qualification/reports/metrics');
const { manifest: makeManifest } = require('../qualification/fixtures/noop-scenario');

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`PASS ${name}`); }
  catch (error) { failed++; console.error(`FAIL ${name}: ${error.stack || error.message}`); }
}
function assert(value, message) { if (!value) throw new Error(message); }

(async () => {
  await test('agent input excludes every private oracle field', () => {
    const m = makeManifest({ variant: 'vulnerable', ground_truth: { vulnerable: true, expected_cwe: ['CWE-X'], expected_boundary: ['x'], expected_evidence: ['y'] } });
    const runtime = createIsolatedRuntime({ allowedPaths: ['/'] });
    const input = buildAgentInput(m, runtime);
    for (const key of FORBIDDEN_AGENT_KEYS) assert(!Object.prototype.hasOwnProperty.call(input, key), `${key} leaked`);
    assert(!JSON.stringify(input).match(/vulnerable|patched|CWE-X/), 'private value leaked');
    runtime.cleanup();
  });

  await test('vulnerable and patched variants have equivalent opaque public identity', () => {
    const a = makeManifest({ scenario_id: 'P2-PAIR-001', variant: 'vulnerable' });
    const b = makeManifest({ scenario_id: 'P2-PAIR-001', variant: 'patched' });
    assert(opaqueId(a) === opaqueId(b), 'variant changed target ID');
    assert(opaqueScenarioName(a.scenario_id, a.seed) === opaqueScenarioName(b.scenario_id, b.seed), 'variant changed container name');
  });

  await test('Docker policy is internal, bounded, unprivileged and socket-free', () => {
    const policy = buildDockerIsolationPolicy('P2-HARNESS-001', 0);
    const result = validateDockerIsolationPolicy(policy);
    assert(result.valid, result.errors.join(','));
    assert(policy.docker_socket_mounted === false && policy.host_config.binds.length === 0, 'host mount present');
  });

  await test('runtime blocks DNS, Internet, metadata, host and peer scenarios', async () => {
    const runtime = createIsolatedRuntime({ allowedPaths: ['/'] });
    for (const method of ['resolve', 'connect', 'metadata', 'host', 'peerScenario']) {
      let blocked = false;
      try { await runtime[method]('outside.invalid'); } catch (_) { blocked = true; }
      assert(blocked, `${method} was not blocked`);
    }
    assert(runtime.stats().externalNetworkAttempts === 5, 'attempt count mismatch');
    runtime.cleanup();
  });

  await test('cleanup removes all state and prevents persistence', () => {
    const runtime = createIsolatedRuntime({ allowedPaths: ['/'] });
    runtime.persist('synthetic', 'value');
    runtime.cleanup();
    assert(runtime.stats().persistedKeys === 0 && runtime.stats().cleaned, 'state survived cleanup');
    let rejected = false;
    try { runtime.persist('after', 'cleanup'); } catch (_) { rejected = true; }
    assert(rejected, 'post-cleanup persistence allowed');
  });

  await test('oracle scoring occurs only after agent completion', async () => {
    const order = [];
    const runtime = createIsolatedRuntime({ allowedPaths: ['/'] });
    const record = await runQualification({
      manifest: makeManifest(), runtime,
      clock: (() => { let now = 0; return () => (now += 10); })(),
      agent: { async evaluate() { order.push('agent'); return { reports: [] }; } },
    });
    order.push(record.oracle_result.outcome);
    assert(order.join(',') === 'agent,TN', `order=${order}`);
  });

  await test('editing an agent report cannot mutate ground truth', async () => {
    const m = makeManifest({ variant: 'vulnerable', ground_truth: { vulnerable: true, expected_cwe: ['CWE-X'], expected_boundary: [], expected_evidence: [] } });
    const original = JSON.stringify(m.ground_truth);
    const runtime = createIsolatedRuntime({ allowedPaths: ['/'] });
    const report = { qualifies: true, ground_truth: { vulnerable: false } };
    const record = await runQualification({ manifest: m, runtime, agent: { async evaluate() { return { reports: [report] }; } } });
    report.qualifies = false;
    assert(JSON.stringify(m.ground_truth) === original, 'ground truth changed');
    assert(record.oracle_result.outcome === 'TP', 'post-run report edit changed score');
  });

  await test('missing report on vulnerable scenario is FN', async () => {
    const m = makeManifest({ variant: 'vulnerable', ground_truth: { vulnerable: true, expected_cwe: [], expected_boundary: [], expected_evidence: [] } });
    const record = await runQualification({ manifest: m, runtime: createIsolatedRuntime({ allowedPaths: ['/'] }), agent: { async evaluate() { return { reports: [] }; } } });
    assert(record.oracle_result.outcome === 'FN', record.oracle_result.outcome);
  });

  await test('report on patched scenario is FP', async () => {
    const record = await runQualification({ manifest: makeManifest(), runtime: createIsolatedRuntime({ allowedPaths: ['/'] }), agent: { async evaluate() { return { reports: [{ qualifies: true }] }; } } });
    assert(record.oracle_result.outcome === 'FP', record.oracle_result.outcome);
  });

  await test('oracle computes central confusion metrics', () => {
    const records = ['TP', 'FP', 'TN', 'FN'].map(outcome => ({ oracle_result: { outcome }, requests: 1, scope_violations: 0, agent_result: { report_reproducible: true } }));
    const metrics = calculateMetrics(records);
    assert(metrics.precision === 0.5 && metrics.recall === 0.5 && metrics.F1 === 0.5, JSON.stringify(metrics));
    assert(metrics.false_positive_rate === 0.5 && metrics.false_negative_rate === 0.5, 'error rates wrong');
  });

  console.log(`\n${passed}/${passed + failed} tests passed`);
  process.exit(failed ? 1 : 0);
})();

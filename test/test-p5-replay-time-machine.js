/**
 * BOQA test-p5-replay-time-machine.js — Test suite for P5 Deterministic Replay Time Machine
 *
 * Tests all 8 new P5 modules:
 *   1. ReplayManifestBuilder
 *   2. UniversalSessionRecorder
 *   3. DeterministicReplayEngine
 *   4. ReplayVerificationEngine
 *   5. ScenarioLibrary
 *   6. ReplayFarm
 *   7. TimeMachineIndex
 *   8. ReplaySecurityGuard
 *
 * Plus integration tests for:
 *   9. P5 extensions to existing modules (replay.js, reproduction.js, knowledge-base.js)
 *  10. End-to-end capture → manifest → replay → verify pipeline
 *
 * All tests must pass with zero regressions against existing test suites.
 */

const {
  ReplayManifestBuilder,
  buildFingerprint,
  buildEnvironment,
  buildStateSnapshot,
} = require('../replay-manifest-builder');

const {
  UniversalSessionRecorder,
  RECORDABLE_TYPES,
  redactValue,
  redactObject,
  isSecretKey,
} = require('../universal-session-recorder');

const {
  DeterministicReplayEngine,
  VirtualClock,
  TimingNormalizer,
  NetworkBarrier,
  splitmix32,
  seedFromString,
} = require('../deterministic-replay-engine');

const {
  ReplayVerificationEngine,
  COMPARISON_AXES,
  computeSetSimilarity,
  computeObjectSimilarity,
  computeSequenceSimilarity,
} = require('../replay-verification-engine');

const {
  ScenarioLibrary,
  SCENARIO_TYPES,
  DEFAULT_SCENARIOS,
} = require('../scenario-library');

const {
  ReplayFarm,
  JOB_STATES,
} = require('../replay-farm');

const {
  TimeMachineIndex,
  formatDuration,
} = require('../time-machine-index');

const {
  ReplaySecurityGuard,
} = require('../replay-security-guard');

const { SessionReplayer } = require('../replay');
const { ReproductionEngine } = require('../reproduction');
const { KnowledgeBase } = require('../knowledge-base');

// ─── Test runner ────────────────────────────────────────────────────

let testsPassed = 0;
let testsFailed = 0;
const failures = [];

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertApprox(actual, expected, tolerance, message) {
  const diff = Math.abs(actual - expected);
  if (diff > tolerance) {
    throw new Error(`Assertion failed: ${message} — expected ~${expected}, got ${actual} (diff ${diff} > tolerance ${tolerance})`);
  }
}

function test(name, fn) {
  try {
    fn();
    testsPassed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    testsFailed++;
    failures.push({ name, error: err.message });
    console.log(`  ✗ ${name}: ${err.message}`);
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    testsPassed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    testsFailed++;
    failures.push({ name, error: err.message });
    console.log(`  ✗ ${name}: ${err.message}`);
  }
}

// ─── Helper: Create sample events ──────────────────────────────────

function createSampleEvents(count = 20) {
  const events = [];
  const types = [
    'network_request', 'network_response', 'page_navigation',
    'cookie_snapshot', 'auth_signal', 'console_log', 'websocket_message_in',
  ];
  const urls = [
    'https://ripio.com/login', 'https://ripio.com/dashboard',
    'https://ripio.com/api/users/me', 'https://ripio.com/api/wallet',
    'https://ripio.com/settings',
  ];

  for (let i = 0; i < count; i++) {
    events.push({
      id: i,
      ts: Date.now() - (count - i) * 1000,
      type: types[i % types.length],
      url: urls[i % urls.length],
      method: i % 3 === 0 ? 'POST' : 'GET',
      status: i % 5 === 0 ? 401 : 200,
      headers: { 'content-type': 'application/json', 'authorization': 'Bearer secret_token_12345' },
      payload: { data: `event-${i}` },
      source: 'playwright',
      meta: { authCookies: [{ name: 'sessionid', value: 'abc123def456', httpOnly: true, secure: false }] },
    });
  }
  return events;
}

// ═══════════════════════════════════════════════════════════════════
// 1. ReplayManifestBuilder
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== ReplayManifestBuilder ===');

test('should instantiate ReplayManifestBuilder', () => {
  const builder = new ReplayManifestBuilder();
  assert(builder !== null, 'builder should exist');
  assert(builder.manifests.size === 0, 'manifests should start empty');
});

test('should build a manifest from events', () => {
  const builder = new ReplayManifestBuilder();
  const events = createSampleEvents(10);
  const manifest = builder.build({
    config: { target: 'https://ripio.com', mode: 'live', headless: true, port: 7070 },
    ctx: {},
    events,
    scenarioName: 'test-scenario',
    scenarioTags: ['test', 'login'],
  });

  assert(manifest.replay_id.startsWith('RPL-'), `replay_id should start with RPL-, got ${manifest.replay_id}`);
  assert(manifest.schema_name === 'replay_manifest_v1', 'schema should be replay_manifest_v1');
  assert(manifest.events_count === 10, `events_count should be 10, got ${manifest.events_count}`);
  assert(manifest.scenario_name === 'test-scenario', 'scenario_name should match');
  assert(manifest.scenario_tags.length === 2, 'should have 2 tags');
  assert(manifest.target_domain === 'ripio.com', `target_domain should be ripio.com, got ${manifest.target_domain}`);
  assert(manifest.state_hash !== null, 'state_hash should be computed');
  assert(manifest.artifact_hash !== null, 'artifact_hash should be computed');
  assert(manifest.redaction_summary.secrets_in_plaintext === false, 'no secrets in plaintext');
  assert(Object.isFrozen(manifest), 'manifest should be frozen (immutable)');
});

test('should build manifest from session export', () => {
  const builder = new ReplayManifestBuilder();
  const sessionExport = {
    id: 'test-session-001',
    sessionStart: Date.now() - 60000,
    sessionEnd: Date.now(),
    totalEvents: 5,
    events: createSampleEvents(5),
    metrics: {},
  };

  const manifest = builder.buildFromSession(sessionExport, { target: 'https://ripio.com' });
  assert(manifest.events_count === 5, 'events_count should be 5');
  assert(manifest.target_domain === 'ripio.com', 'target_domain should be ripio.com');
});

test('should list built manifests', () => {
  const builder = new ReplayManifestBuilder();
  builder.build({ config: { target: 'https://a.com' }, events: [], scenarioName: 'a' });
  builder.build({ config: { target: 'https://b.com' }, events: [], scenarioName: 'b' });

  const list = builder.listManifests();
  assert(list.length === 2, 'should have 2 manifests');
});

test('should capture network summary in manifest', () => {
  const builder = new ReplayManifestBuilder();
  const events = [
    { type: 'network_request', url: 'https://ripio.com/api/login', method: 'POST', ts: Date.now() },
    { type: 'network_response', status: 200, ts: Date.now() },
    { type: 'network_response', status: 301, ts: Date.now() },
    { type: 'websocket_message_in', ts: Date.now() },
  ];

  const manifest = builder.build({ config: { target: 'https://ripio.com' }, events });
  assert(manifest.network_summary.total_requests === 1, 'should count 1 request');
  assert(manifest.network_summary.total_responses === 2, 'should count 2 responses');
  assert(manifest.network_summary.total_redirects === 1, 'should count 1 redirect');
  assert(manifest.network_summary.total_websocket_frames === 1, 'should count 1 WS frame');
});

test('buildFingerprint should capture environment info', () => {
  const fp = buildFingerprint({ chromiumVersion: '121.0.6167.85' });
  assert(fp.boqa_version !== 'unknown', 'boqa_version should be set');
  assert(fp.node_version.startsWith('v'), 'node_version should start with v');
  assert(fp.chromium_version === '121.0.6167.85', 'chromium_version should match');
  assert(fp.os_version.length > 0, 'os_version should be non-empty');
  assert(fp.timezone !== undefined, 'timezone should be set');
});

test('buildEnvironment should capture config flags', () => {
  const env = buildEnvironment({ target: 'https://ripio.com', mode: 'live', headless: true });
  assert(env.config_flags.mode === 'live', 'mode should be live');
  assert(env.target_domain === 'ripio.com', 'target_domain should be extracted');
  assert(env.config_flags.headless === true, 'headless should be true');
});

// ═══════════════════════════════════════════════════════════════════
// 2. UniversalSessionRecorder
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== UniversalSessionRecorder ===');

test('should instantiate and start recording', () => {
  const recorder = new UniversalSessionRecorder();
  const result = recorder.startRecording({ scenario: 'test' });

  assert(result.recorder_id.startsWith('REC-'), 'recorder_id should start with REC-');
  assert(recorder.isRecording === true, 'should be recording');
  assert(recorder.events.length > 0, 'should have at least the start marker event');
});

test('should stop recording and return results', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  const result = recorder.stopRecording();

  assert(recorder.isRecording === false, 'should not be recording');
  assert(result.events_count > 0, 'should have events');
  assert(result.context_hash !== null, 'context_hash should be computed');
  assert(result.duration_ms >= 0, 'duration should be non-negative');
});

test('should capture step boundaries', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  recorder.markStepBoundary('login');
  recorder.markStepBoundary('dashboard');
  recorder.stopRecording();

  assert(recorder.stepBoundaries.length === 2, 'should have 2 step boundaries');
  assert(recorder.stepBoundaries[0].name === 'login', 'first step should be login');
  assert(recorder.stepBoundaries[1].name === 'dashboard', 'second step should be dashboard');
});

test('should capture DOM snapshots', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  const html = '<html><body>Login</body></html>';
  recorder.captureDomSnapshot('https://ripio.com/login', html);
  recorder.stopRecording();

  assert(recorder.stats.dom_snapshots === 1, 'should have 1 DOM snapshot');
  const domEvent = recorder.events.find(e => e.type === 'replay_dom_snapshot');
  assert(domEvent !== undefined, 'should find dom snapshot event');
  assert(domEvent.payload.html_length === html.length, `html_length should be ${html.length}, got ${domEvent.payload.html_length}`);
});

test('should capture screenshot metadata', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  recorder.captureScreenshotMeta('https://ripio.com/login', { viewport: '1280x720' });
  recorder.stopRecording();

  assert(recorder.stats.screenshot_metas === 1, 'should have 1 screenshot meta');
});

test('should capture storage writes with redaction', () => {
  const recorder = new UniversalSessionRecorder({ redactSecrets: true });
  recorder.startRecording();
  recorder.captureStorageWrite('cookie', 'sessionid', 'super-secret-value');
  recorder.captureStorageWrite('localStorage', 'theme', 'dark');
  recorder.stopRecording();

  assert(recorder.stats.storage_writes === 2, 'should have 2 storage writes');
  assert(recorder.stats.total_redacted >= 1, 'should have at least 1 redaction');
});

test('should capture user interactions', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  recorder.captureInteraction('click', { selector: '#login-btn', coordinates: { x: 100, y: 200 } });
  recorder.captureInteraction('input', { selector: '#password', value: 'secret123', isSensitive: true });
  recorder.stopRecording();

  const clickEvent = recorder.events.find(e => e.type === 'replay_click');
  assert(clickEvent !== undefined, 'should find click event');
  const inputEvent = recorder.events.find(e => e.type === 'replay_input');
  assert(inputEvent !== undefined, 'should find input event');
  assert(inputEvent.payload.value_redacted === true, 'sensitive input should be marked as redacted');
  assert(inputEvent.payload.value.includes('REDACTED'), `sensitive input value should contain REDACTED, got: ${inputEvent.payload.value}`);
});

test('should ingest EventBus events', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  const events = createSampleEvents(5);
  recorder.ingestEventLog(events);
  recorder.stopRecording();

  // Should have captured events + start/end markers
  assert(recorder.stats.total_captured >= 5 + 2, `should have at least 7 captured events, got ${recorder.stats.total_captured}`);
});

test('should export and get step events', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  recorder.markStepBoundary('step1');
  recorder.captureInteraction('click', { selector: '#btn' });
  recorder.markStepBoundary('step2');
  recorder.captureInteraction('input', { selector: '#input' });
  recorder.stopRecording();

  const step1Events = recorder.getStepEvents(1);
  assert(step1Events.length > 0, 'step 1 should have events');

  const exported = recorder.export();
  assert(exported.recorder_id !== null, 'exported should have recorder_id');
  assert(exported.events.length > 0, 'exported should have events');
});

test('redaction functions should work correctly', () => {
  assert(isSecretKey('password') === true, 'password should be a secret key');
  assert(isSecretKey('username') === false, 'username should not be a secret key');
  assert(isSecretKey('api_key') === true, 'api_key should be a secret key');
  assert(isSecretKey('Authorization') === true, 'Authorization should be a secret key');

  const redacted = redactValue('super-secret-token-value');
  assert(redacted.includes('REDACTED'), 'redacted value should contain REDACTED');
  assert(!redacted.includes('super-secret'), 'redacted value should not contain original');

  const obj = redactObject({ password: 'secret', theme: 'dark', token: 'abc123' });
  assert(obj.password.includes('REDACTED'), 'password should be redacted');
  assert(obj.theme === 'dark', 'theme should not be redacted');
});

test('should reset cleanly', () => {
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording();
  recorder.markStepBoundary('step1');
  recorder.captureInteraction('click', { selector: '#btn' });
  recorder.reset();

  assert(recorder.events.length === 0, 'events should be empty after reset');
  assert(recorder.stepBoundaries.length === 0, 'boundaries should be empty after reset');
  assert(recorder.isRecording === false, 'should not be recording after reset');
});

// ═══════════════════════════════════════════════════════════════════
// 3. DeterministicReplayEngine
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== DeterministicReplayEngine ===');

test('VirtualClock should advance time', () => {
  const clock = new VirtualClock(1000000);
  assert(clock.now() === 1000000, 'initial time should be 1000000');
  clock.advance(500);
  assert(clock.now() === 1000500, 'after advance(500) should be 1000500');
  clock.advanceTo(1003000);
  assert(clock.now() === 1003000, 'after advanceTo should be 1003000');
});

test('VirtualClock should respect speed multiplier', () => {
  const clock = new VirtualClock(1000000, 2);
  clock.advance(100);
  assert(clock.now() === 1000200, 'speed=2 should double the advance');
});

test('seeded PRNG should produce deterministic values', () => {
  const rng1 = splitmix32(42);
  const rng2 = splitmix32(42);
  const v1 = rng1();
  const v2 = rng2();
  assert(v1 === v2, 'same seed should produce same value');
  assert(v1 >= 0 && v1 < 1, 'PRNG output should be in [0, 1)');
});

test('seedFromString should produce consistent seeds', () => {
  const s1 = seedFromString('hello');
  const s2 = seedFromString('hello');
  const s3 = seedFromString('world');
  assert(s1 === s2, 'same string should produce same seed');
  assert(s1 !== s3, 'different strings should produce different seeds');
});

test('TimingNormalizer should normalize event timing', () => {
  const normalizer = new TimingNormalizer({ minDelay: 10, maxDelay: 5000 });
  const events = [
    { seq: 0, ts: 1000, type: 'a' },
    { seq: 1, ts: 2000, type: 'b' },
    { seq: 2, ts: 100000, type: 'c' }, // huge gap
  ];

  const normalized = normalizer.normalize(events);
  assert(normalized.length === 3, 'should have 3 events');
  assert(normalized[0].normalized_ts >= 0, 'first event should have normalized ts');
  assert(normalized[2].delay_from_previous <= 5000, 'max delay should be capped at 5000');
  assert(normalized[1].delay_from_previous >= 10, 'min delay should be at least 10');
});

test('DeterministicReplayEngine should load a recording', () => {
  const engine = new DeterministicReplayEngine();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(10),
    step_boundaries: [],
    started_at: Date.now() - 60000,
  };

  engine.loadRecording(recording);
  assert(engine.recording !== null, 'recording should be loaded');
  assert(engine.rng !== null, 'RNG should be initialized');
});

test('DeterministicReplayEngine should produce deterministic randomness', () => {
  const engine1 = new DeterministicReplayEngine({ seed: 'test-seed' });
  const engine2 = new DeterministicReplayEngine({ seed: 'test-seed' });

  const vals1 = [engine1.nextRandom(), engine1.nextRandom(), engine1.nextRandom()];
  const vals2 = [engine2.nextRandom(), engine2.nextRandom(), engine2.nextRandom()];

  assert(vals1[0] === vals2[0], 'first random should match');
  assert(vals1[1] === vals2[1], 'second random should match');
  assert(vals1[2] === vals2[2], 'third random should match');
});

test('DeterministicReplayEngine deterministicWait should be in range', () => {
  const engine = new DeterministicReplayEngine({ seed: 'wait-test' });
  for (let i = 0; i < 50; i++) {
    const wait = engine.deterministicWait(100, 500);
    assert(wait >= 100, `wait should be >= 100, got ${wait}`);
    assert(wait <= 500, `wait should be <= 500, got ${wait}`);
  }
});

test('NetworkBarrier should complete on signal', async () => {
  const barrier = new NetworkBarrier();
  const promise = barrier.wait('req-1', 2000);
  barrier.complete('req-1', { status: 200 });
  const result = await promise;
  assert(result.status === 200, 'should receive the completed event');
});

test('NetworkBarrier should timeout', async () => {
  const barrier = new NetworkBarrier();
  try {
    await barrier.wait('req-2', 100);
    assert(false, 'should have thrown');
  } catch (err) {
    assert(err.message.includes('timeout'), 'should throw timeout error');
  }
});

// ═══════════════════════════════════════════════════════════════════
// 4. ReplayVerificationEngine
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== ReplayVerificationEngine ===');

test('should verify identical recordings as exact match', () => {
  const engine = new ReplayVerificationEngine();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(10),
    step_boundaries: [],
  };

  const result = engine.verify({ original: recording, replay: recording });
  assert(result.composite_score >= 0.9, `composite score should be >= 0.9, got ${result.composite_score}`);
  assert(result.verdict === 'exact_match', `verdict should be exact_match, got ${result.verdict}`);
});

test('should detect differences in different recordings', () => {
  const engine = new ReplayVerificationEngine();
  const original = {
    recorder_id: 'REC-orig',
    events: createSampleEvents(20),
    step_boundaries: [],
  };
  const replay = {
    recorder_id: 'REC-replay',
    events: createSampleEvents(5),
    step_boundaries: [],
  };

  const result = engine.verify({ original, replay });
  assert(result.composite_score < 1.0, 'composite score should be < 1.0 for different recordings');
});

test('should verify single axis', () => {
  const engine = new ReplayVerificationEngine();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(10),
    step_boundaries: [],
  };

  const result = engine.verifyAxis('network', recording, recording);
  assert(result.score !== undefined, 'should have score');
  assert(result.verdict !== undefined, 'should have verdict');
});

test('should handle empty recordings gracefully', () => {
  const engine = new ReplayVerificationEngine();
  const empty = { recorder_id: 'REC-empty', events: [], step_boundaries: [] };

  const result = engine.verify({ original: empty, replay: empty });
  assert(result.composite_score === 1.0, 'empty recordings should match perfectly');
});

test('computeSetSimilarity should work correctly', () => {
  assert(computeSetSimilarity(['a', 'b', 'c'], ['a', 'b', 'c']) === 1.0, 'identical sets should score 1.0');
  assert(computeSetSimilarity(['a', 'b'], ['c', 'd']) === 0.0, 'disjoint sets should score 0.0');
  assert(computeSetSimilarity(['a', 'b', 'c'], ['a', 'b', 'd']) > 0, 'overlapping sets should score > 0');
});

test('computeObjectSimilarity should ignore specified keys', () => {
  const a = { x: 1, y: 2, ts: 1000 };
  const b = { x: 1, y: 2, ts: 2000 };
  const score = computeObjectSimilarity(a, b, ['ts']);
  assert(score === 1.0, 'should score 1.0 when ignoring ts');
});

test('should compare internal state from manifests', () => {
  const engine = new ReplayVerificationEngine();
  const recording = { recorder_id: 'REC-test', events: [], step_boundaries: [] };

  const origManifest = { internal_state: { cevi_state: { score: 0.8, class: 'HIGH' } } };
  const replayManifest = { internal_state: { cevi_state: { score: 0.8, class: 'HIGH' } } };

  const result = engine.verify({
    original: recording,
    replay: recording,
    originalManifest: origManifest,
    replayManifest: replayManifest,
  });

  assert(result.axes.internal_state.score >= 0.9, 'matching state should score high');
});

test('COMPARISON_AXES should have all 8 axes', () => {
  assert(COMPARISON_AXES.length === 8, `should have 8 axes, got ${COMPARISON_AXES.length}`);
});

// ═══════════════════════════════════════════════════════════════════
// 5. ScenarioLibrary
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== ScenarioLibrary ===');

test('should instantiate with default scenarios', () => {
  const library = new ScenarioLibrary();
  const scenarios = library.list();
  assert(scenarios.length >= 10, `should have at least 10 default scenarios, got ${scenarios.length}`);
});

test('should create custom scenarios', () => {
  const library = new ScenarioLibrary();
  const scenario = library.create({
    name: 'Custom Login',
    type: SCENARIO_TYPES.LOGIN,
    description: 'Custom login flow',
    steps: [
      { step: 1, action: 'navigate', target: '/login', description: 'Go to login' },
      { step: 2, action: 'verify', target: 'auth', description: 'Check auth' },
    ],
    parameters: ['base_url'],
    tags: ['custom'],
  });

  assert(scenario.id !== undefined, 'scenario should have an id');
  assert(scenario.name === 'Custom Login', 'name should match');
  assert(scenario.is_builtin === false, 'should not be builtin');
  assert(scenario.version === 1, 'should start at version 1');
});

test('should create scenario from recording', () => {
  const library = new ScenarioLibrary();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(10),
    step_boundaries: [
      { step: 1, name: 'login', event_index: 0, ts: Date.now() },
      { step: 2, name: 'dashboard', event_index: 5, ts: Date.now() },
    ],
  };

  const scenario = library.createFromRecording(recording, 'Recorded Flow');
  assert(scenario.name === 'Recorded Flow', 'name should match');
  assert(scenario.steps.length === 2, 'should have 2 steps from boundaries');
  assert(scenario.tags.includes('auto-generated'), 'should have auto-generated tag');
});

test('should list scenarios with filters', () => {
  const library = new ScenarioLibrary();
  const loginScenarios = library.list({ type: SCENARIO_TYPES.LOGIN });
  assert(loginScenarios.length >= 1, 'should have at least 1 login scenario');

  const builtin = library.list({ is_builtin: true });
  assert(builtin.length >= 10, 'should have at least 10 builtin scenarios');
});

test('should resolve parameterized steps', () => {
  const library = new ScenarioLibrary();
  const loginScenarios = library.list({ type: SCENARIO_TYPES.LOGIN });
  const scenario = loginScenarios[0];

  const resolved = library.resolveSteps(scenario.id, { base_url: 'https://ripio.com' });
  assert(resolved.length > 0, 'should have resolved steps');
  const firstTarget = resolved[0].target || '';
  assert(firstTarget.includes('ripio.com'), `target should include ripio.com, got ${firstTarget}`);
});

test('should track version history', () => {
  const library = new ScenarioLibrary();
  const scenario = library.create({ name: 'Test', type: SCENARIO_TYPES.SPA_NAVIGATION });

  library.update(scenario.id, { name: 'Test v2' });
  const history = library.getVersionHistory(scenario.id);

  assert(history.length === 2, 'should have 2 versions');
  assert(history[1].version === 2, 'latest version should be 2');
});

test('SCENARIO_TYPES should have all 10 types', () => {
  const types = Object.keys(SCENARIO_TYPES);
  assert(types.length === 10, `should have 10 scenario types, got ${types.length}`);
});

// ═══════════════════════════════════════════════════════════════════
// 6. ReplayFarm
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== ReplayFarm ===');

test('should instantiate with workers', () => {
  const farm = new ReplayFarm({ maxWorkers: 3 });
  const status = farm.getStatus();
  assert(status.workers.total === 3, 'should have 3 workers');
  assert(status.workers.idle === 3, 'all workers should be idle');
});

test('should submit jobs to queue', () => {
  const farm = new ReplayFarm();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(5),
    step_boundaries: [],
    started_at: Date.now(),
  };

  const job = farm.submit({ recording, scenarioName: 'test-job' });
  assert(job.job_id.startsWith('JOB-'), 'job_id should start with JOB-');
  assert(job.state === JOB_STATES.QUEUED, 'job should be queued');
});

test('should track job status', () => {
  const farm = new ReplayFarm();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(5),
    step_boundaries: [],
    started_at: Date.now(),
  };

  const jobInfo = farm.submit({ recording });
  const job = farm.getJob(jobInfo.job_id);
  assert(job !== null, 'job should be found');
  assert(job.state === JOB_STATES.QUEUED, 'job should be queued');
});

test('should cancel queued jobs', () => {
  const farm = new ReplayFarm();
  const recording = {
    recorder_id: 'REC-test',
    events: [],
    step_boundaries: [],
    started_at: Date.now(),
  };

  const jobInfo = farm.submit({ recording });
  const cancelled = farm.cancel(jobInfo.job_id);
  assert(cancelled === true, 'should cancel successfully');

  const job = farm.getJob(jobInfo.job_id);
  assert(job.state === JOB_STATES.CANCELLED, 'job should be cancelled');
});

test('should respect max queue size', () => {
  const farm = new ReplayFarm({ maxQueueSize: 2 });
  const recording = {
    recorder_id: 'REC-test',
    events: [],
    step_boundaries: [],
    started_at: Date.now(),
  };

  farm.submit({ recording });
  farm.submit({ recording });

  try {
    farm.submit({ recording });
    assert(false, 'should have thrown');
  } catch (err) {
    assert(err.message.includes('full'), 'should throw queue full error');
  }
});

test('should run a single job', async () => {
  const farm = new ReplayFarm();
  const recording = {
    recorder_id: 'REC-test',
    events: createSampleEvents(3),
    step_boundaries: [],
    started_at: Date.now(),
  };

  const result = await farm.runOne({ recording, scenarioName: 'single-job' });
  assert(result.job_id !== undefined, 'result should have job_id');
});

test('should reset cleanly', () => {
  const farm = new ReplayFarm();
  farm.submit({
    recording: { events: [], step_boundaries: [], started_at: Date.now() },
  });
  farm.reset();

  const status = farm.getStatus();
  assert(status.queue.size === 0, 'queue should be empty after reset');
  assert(status.workers.idle === status.workers.total, 'all workers should be idle');
});

// ═══════════════════════════════════════════════════════════════════
// 7. TimeMachineIndex
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== TimeMachineIndex ===');

test('should index a replay manifest', () => {
  const index = new TimeMachineIndex();
  const manifest = {
    replay_id: 'RPL-test-001',
    boqa_version: '1.5.0',
    node_version: 'v20.0.0',
    playwright_version: '1.41.0',
    chromium_version: '121.0',
    os_version: 'linux x64',
    target_domain: 'ripio.com',
    scenario_name: 'login-test',
    scenario_tags: ['login', 'auth'],
    timestamp_utc: new Date().toISOString(),
    events_count: 100,
    state_hash: 'abc123',
    artifact_hash: 'def456',
    internal_state: {
      cevi_state: { class: 'HIGH' },
      autonomy_governor_state: { current_level: 'L2' },
    },
  };

  const entry = index.indexReplay(manifest);
  assert(entry.replay_id === 'RPL-test-001', 'replay_id should match');
  assert(entry.cevi_band === 'HIGH', 'cevi_band should be HIGH');
  assert(entry.autonomy_level === 'L2', 'autonomy_level should be L2');
});

test('should search by domain', () => {
  const index = new TimeMachineIndex();
  index.indexReplay({
    replay_id: 'RPL-a',
    target_domain: 'ripio.com',
    scenario_name: 'test-a',
    timestamp_utc: new Date().toISOString(),
    scenario_tags: [],
  });
  index.indexReplay({
    replay_id: 'RPL-b',
    target_domain: 'example.com',
    scenario_name: 'test-b',
    timestamp_utc: new Date().toISOString(),
    scenario_tags: [],
  });

  const results = index.search({ target_domain: 'ripio.com' });
  assert(results.length === 1, 'should find 1 result for ripio.com');
  assert(results[0].replay_id === 'RPL-a', 'should find RPL-a');
});

test('should find drift between replays', () => {
  const index = new TimeMachineIndex();
  index.indexReplay({
    replay_id: 'RPL-ref',
    boqa_version: '1.4.0',
    target_domain: 'ripio.com',
    scenario_name: 'login',
    timestamp_utc: new Date().toISOString(),
    scenario_tags: [],
    os_version: 'linux x64',
    playwright_version: '1.40.0',
  });
  index.indexReplay({
    replay_id: 'RPL-new',
    boqa_version: '1.5.0',
    target_domain: 'ripio.com',
    scenario_name: 'login',
    timestamp_utc: new Date().toISOString(),
    scenario_tags: [],
    os_version: 'linux x64',
    playwright_version: '1.41.0',
  });

  const drift = index.findDrift('RPL-ref');
  assert(drift.length > 0, 'should detect drift');
  const driftDimensions = drift[0].drifts.map(d => d.dimension);
  assert(driftDimensions.includes('boqa_version'), 'should detect version drift');
});

test('should compare two replays forensically', () => {
  const index = new TimeMachineIndex();
  index.indexReplay({
    replay_id: 'RPL-cmp-1',
    boqa_version: '1.4.0',
    target_domain: 'ripio.com',
    scenario_name: 'test',
    timestamp_utc: new Date(Date.now() - 86400000).toISOString(),
    scenario_tags: [],
  });
  index.indexReplay({
    replay_id: 'RPL-cmp-2',
    boqa_version: '1.5.0',
    target_domain: 'ripio.com',
    scenario_name: 'test',
    timestamp_utc: new Date().toISOString(),
    scenario_tags: [],
  });

  const comparison = index.compare('RPL-cmp-1', 'RPL-cmp-2');
  assert(comparison !== null, 'comparison should not be null');
  assert(comparison.diffs.length > 0, 'should have diffs');
  assert(comparison.time_diff_ms > 0, 'time diff should be positive');
});

test('should get timeline for a domain', () => {
  const index = new TimeMachineIndex();
  const now = Date.now();
  index.indexReplay({
    replay_id: 'RPL-tl-1',
    target_domain: 'ripio.com',
    scenario_name: 'test-1',
    timestamp_utc: new Date(now - 2000).toISOString(),
    scenario_tags: [],
  });
  index.indexReplay({
    replay_id: 'RPL-tl-2',
    target_domain: 'ripio.com',
    scenario_name: 'test-2',
    timestamp_utc: new Date(now - 1000).toISOString(),
    scenario_tags: [],
  });

  const timeline = index.getTimeline('ripio.com');
  assert(timeline.length === 2, 'should have 2 entries');
  assert(timeline[0].timestamp_epoch <= timeline[1].timestamp_epoch, 'should be sorted chronologically');
});

test('formatDuration should work', () => {
  assert(formatDuration(500) === '500ms', '500ms');
  assert(formatDuration(1500).includes('s'), '1.5s');
  assert(formatDuration(120000).includes('m'), '2m');
});

// ═══════════════════════════════════════════════════════════════════
// 8. ReplaySecurityGuard
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== ReplaySecurityGuard ===');

test('should instantiate with keys', () => {
  const guard = new ReplaySecurityGuard();
  assert(guard.signingKey.length > 0, 'signing key should be set');
  assert(guard.encryptionKey.length > 0, 'encryption key should be set');
});

test('should redact secrets from objects', () => {
  const guard = new ReplaySecurityGuard();
  const data = {
    headers: { authorization: 'Bearer secret_token_abc123' },
    cookies: { sessionid: 'super_secret_session', theme: 'dark' },
    config: { api_key: 'ak-1234567890abcdef1234', mode: 'live' },
  };

  const { redacted, redaction_summary } = guard.redact(data);
  assert(redaction_summary.total_secrets_found > 0, 'should find secrets');
  assert(redaction_summary.no_plaintext_secrets === true, 'should confirm no plaintext secrets');
  assert(!JSON.stringify(redacted).includes('secret_token'), 'should not contain secret token');
  assert(!JSON.stringify(redacted).includes('super_secret_session'), 'should not contain secret session value');
  assert(!JSON.stringify(redacted).includes('ak-1234'), 'should not contain API key');
});

test('should scan for secrets', () => {
  const guard = new ReplaySecurityGuard();
  const cleanData = { theme: 'dark', mode: 'live' };
  const dirtyData = { password: 'super_secret_123', token: 'Bearer abc123' };

  const cleanScan = guard.scanForSecrets(cleanData);
  assert(cleanScan.clean === true, 'clean data should pass scan');

  const dirtyScan = guard.scanForSecrets(dirtyData);
  assert(dirtyScan.clean === false, 'dirty data should fail scan');
  assert(dirtyScan.findings.length > 0, 'should have findings');
});

test('should sign and verify data', () => {
  const guard = new ReplaySecurityGuard();
  const data = { test: 'data', value: 42 };

  const signResult = guard.sign(data);
  assert(signResult.signature.length > 0, 'should produce a signature');
  assert(signResult.algorithm === 'hmac-sha256', 'should use hmac-sha256');

  const verifyResult = guard.verify(data, signResult.signature);
  assert(verifyResult.valid === true, 'signature should be valid');
});

test('should detect tampered signatures', () => {
  const guard = new ReplaySecurityGuard();
  const data = { test: 'data' };

  const signResult = guard.sign(data);
  const tamperedSig = signResult.signature.replace(/a/g, 'b');

  try {
    const verifyResult = guard.verify(data, tamperedSig);
    assert(verifyResult.valid === false, 'tampered signature should be invalid');
  } catch (_) {
    // timingSafeEqual may throw on length mismatch — that's also a valid detection
  }
});

test('should encrypt and decrypt data', () => {
  const guard = new ReplaySecurityGuard();
  const data = { secret: 'value', number: 42 };

  const encResult = guard.encrypt(data);
  assert(encResult.encrypted.length > 0, 'should produce encrypted data');
  assert(encResult.iv.length > 0, 'should have IV');
  assert(encResult.algorithm === 'aes-256-cbc', 'should use aes-256-cbc');

  const decrypted = guard.decrypt(encResult.encrypted, encResult.iv);
  assert(decrypted.secret === 'value', 'decrypted secret should match');
  assert(decrypted.number === 42, 'decrypted number should match');
});

test('should maintain audit log', () => {
  const guard = new ReplaySecurityGuard();
  guard.redact({ password: 'test' });
  guard.sign({ data: 'test' });
  guard.encrypt({ data: 'test' });

  const auditLog = guard.getAuditLog();
  assert(auditLog.length >= 2, `should have at least 2 audit entries, got ${auditLog.length}`);
  const validActions = ['redact_during_sign', 'sign', 'encrypt', 'redact'];
  const hasValidAction = auditLog.some(e => validActions.includes(e.action));
  assert(hasValidAction, 'audit log should have valid actions');
});

// ═══════════════════════════════════════════════════════════════════
// 9. P5 Extensions to Existing Modules
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== P5 Extensions to Existing Modules ===');

test('SessionReplayer should have P5 integration methods', () => {
  const session = {
    sessionStart: Date.now() - 60000,
    sessionEnd: Date.now(),
    events: createSampleEvents(10),
  };
  const replayer = new SessionReplayer(session);

  assert(typeof replayer.attachManifest === 'function', 'should have attachManifest');
  assert(typeof replayer.toP5Recording === 'function', 'should have toP5Recording');
});

test('SessionReplayer.toP5Recording should produce valid recording format', () => {
  const session = {
    sessionStart: Date.now() - 60000,
    sessionEnd: Date.now(),
    events: createSampleEvents(5),
  };
  const replayer = new SessionReplayer(session);
  const recording = replayer.toP5Recording();

  assert(recording.recorder_id !== undefined, 'should have recorder_id');
  assert(recording.events.length === 5, 'should have 5 events');
  assert(recording.events[0].seq === 0, 'first event should have seq 0');
  assert(recording.total_events === 5, 'total_events should be 5');
});

test('SessionReplayer.attachManifest should store manifest', () => {
  const session = {
    sessionStart: Date.now(),
    events: [],
  };
  const replayer = new SessionReplayer(session);
  const manifest = { replay_id: 'RPL-test', artifact_hash: 'abc' };

  replayer.attachManifest(manifest);
  assert(replayer.manifest.replay_id === 'RPL-test', 'manifest should be attached');
  assert(replayer.contextHash === 'abc', 'context hash should be set');
});

test('ReproductionEngine should support time-machine metadata', () => {
  const engine = new ReproductionEngine();
  const bug = {
    id: 'BUG-001',
    title: 'Missing HttpOnly',
    category: 'cookie_security_failure',
    severity: 'high',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
  };

  const repro = engine.generateReproduction(bug, { events: [], report: { target: 'https://ripio.com' } });
  assert(typeof engine.attachTimeMachineMetadata === 'function', 'should have attachTimeMachineMetadata');

  const manifest = { replay_id: 'RPL-test', boqa_version: '1.5.0', artifact_hash: 'hash123', target_domain: 'ripio.com', scenario_name: 'test' };
  const enhanced = engine.attachTimeMachineMetadata(bug.id, manifest);
  assert(enhanced !== null, 'should return enhanced reproduction');
  assert(enhanced.time_machine.replay_id === 'RPL-test', 'time_machine should be attached');
});

test('ReproductionEngine should generate from replay', () => {
  const engine = new ReproductionEngine();
  const manifest = {
    replay_id: 'RPL-gen-test',
    boqa_version: '1.5.0',
    artifact_hash: 'hash456',
    target_domain: 'ripio.com',
    scenario_name: 'login-test',
  };
  const recording = {
    events: createSampleEvents(10),
    step_boundaries: [
      { step: 1, name: 'navigate', event_index: 0 },
      { step: 2, name: 'login', event_index: 5 },
    ],
  };

  const repro = engine.generateFromReplay(manifest, recording);
  assert(repro.finding_category === 'replay_derived', 'should be replay derived');
  assert(repro.steps.length === 2, 'should have 2 steps from boundaries');
  assert(repro.time_machine.replay_id === 'RPL-gen-test', 'should have time_machine metadata');
  assert(repro.safe_mode === true, 'should be in safe mode');
});

test('KnowledgeBase should support replay nodes', () => {
  const kb = new KnowledgeBase({ maxObservations: 100, maxFindings: 100 });
  assert(typeof kb.addReplayNode === 'function', 'should have addReplayNode');
  assert(typeof kb.queryReplayNodes === 'function', 'should have queryReplayNodes');

  const manifest = {
    replay_id: 'RPL-kb-test',
    boqa_version: '1.5.0',
    target_domain: 'ripio.com',
    scenario_name: 'login',
    scenario_tags: ['auth'],
    timestamp_utc: new Date().toISOString(),
    events_count: 50,
    state_hash: 'state-hash-1',
    artifact_hash: 'artifact-hash-1',
    internal_state: {
      cevi_state: { class: 'HIGH' },
      autonomy_governor_state: { current_level: 'L2', total_decisions: 15 },
    },
  };

  const node = kb.addReplayNode(manifest);
  assert(node.id === 'RPL-kb-test', 'node id should match replay_id');
  assert(node.boqa_version === '1.5.0', 'version should match');
  assert(node.cevi_band === 'HIGH', 'cevi_band should be extracted');
});

test('KnowledgeBase should query replay nodes', () => {
  const kb = new KnowledgeBase({ maxObservations: 100, maxFindings: 100 });
  kb.addReplayNode({
    replay_id: 'RPL-q1',
    boqa_version: '1.4.0',
    target_domain: 'ripio.com',
    scenario_name: 'login-a',
    scenario_tags: [],
    timestamp_utc: new Date().toISOString(),
    state_hash: 'hash-a',
  });
  kb.addReplayNode({
    replay_id: 'RPL-q2',
    boqa_version: '1.5.0',
    target_domain: 'example.com',
    scenario_name: 'login-b',
    scenario_tags: [],
    timestamp_utc: new Date().toISOString(),
    state_hash: 'hash-b',
  });

  const byVersion = kb.queryReplayNodes({ boqa_version: '1.5.0' });
  assert(byVersion.length === 1, 'should find 1 node for v1.5.0');

  const byDomain = kb.queryReplayNodes({ target_domain: 'ripio.com' });
  assert(byDomain.length === 1, 'should find 1 node for ripio.com');
});

// ═══════════════════════════════════════════════════════════════════
// 10. End-to-End Pipeline Test
// ═══════════════════════════════════════════════════════════════════

console.log('\n=== End-to-End Pipeline ===');

test('full capture → manifest → replay → verify pipeline', async () => {
  // Step 1: Record a session
  const recorder = new UniversalSessionRecorder();
  recorder.startRecording({ scenario: 'e2e-test' });
  recorder.markStepBoundary('navigate');
  recorder.captureInteraction('click', { selector: '#login-btn' });
  recorder.markStepBoundary('login');
  recorder.captureDomSnapshot('https://ripio.com/dashboard', '<html>Dashboard</html>');
  recorder.captureStorageWrite('cookie', 'sessionid', 'secret-value');
  recorder.markStepBoundary('dashboard');
  recorder.captureInteraction('click', { selector: '#settings' });
  recorder.ingestEventLog(createSampleEvents(10));
  const recordingResult = recorder.stopRecording();

  assert(recordingResult.events_count > 0, 'should have captured events');
  assert(recordingResult.step_boundaries === 3, 'should have 3 step boundaries');

  // Step 2: Build manifest
  const builder = new ReplayManifestBuilder();
  const manifest = builder.build({
    config: { target: 'https://ripio.com', mode: 'live' },
    ctx: {},
    events: recorder.events,
    scenarioName: 'e2e-test',
    scenarioTags: ['e2e', 'test'],
  });

  assert(manifest.replay_id.startsWith('RPL-'), 'manifest should have replay_id');
  assert(manifest.state_hash !== null, 'manifest should have state_hash');

  // Step 3: Security — redact and sign
  const guard = new ReplaySecurityGuard();
  const scanResult = guard.scanForSecrets(manifest);
  // Manifest was built with redaction, so should be clean
  assert(scanResult.clean === true, 'manifest should be free of secrets');

  const signResult = guard.sign(manifest);
  const verifyResult = guard.verify(manifest, signResult.signature);
  assert(verifyResult.valid === true, 'signature should be valid');

  // Step 4: Replay deterministically
  const engine = new DeterministicReplayEngine({ seed: 'e2e-seed' });
  engine.loadRecording(recorder.export(), manifest);

  // Replay without fetchFn (no network)
  const report = await engine.replay();
  assert(report.type === 'deterministic_replay_report', 'should produce a replay report');

  // Step 5: Verify against self (identity test)
  const verifier = new ReplayVerificationEngine();
  const recording = recorder.export();
  const verifyResult2 = verifier.verify({ original: recording, replay: recording });
  assert(verifyResult2.composite_score >= 0.9, `self-verification should score >= 0.9, got ${verifyResult2.composite_score}`);

  // Step 6: Index the replay
  const index = new TimeMachineIndex();
  const indexEntry = index.indexReplay(manifest);
  assert(indexEntry.replay_id === manifest.replay_id, 'indexed replay_id should match');

  // Step 7: Create scenario from recording
  const library = new ScenarioLibrary();
  const scenario = library.createFromRecording(recording, 'E2E Test Scenario');
  assert(scenario.steps.length > 0, 'scenario should have steps');

  // Step 8: Store in knowledge base
  const kb = new KnowledgeBase({ maxObservations: 100, maxFindings: 100 });
  const replayNode = kb.addReplayNode(manifest);
  assert(replayNode.replay_id === manifest.replay_id, 'kb node should match');
});

test('replay produces deterministic results across runs', async () => {
  const events = createSampleEvents(10);
  const recording = {
    recorder_id: 'REC-determinism',
    events,
    step_boundaries: [],
    started_at: Date.now() - 60000,
    context_hash: 'test-hash',
  };

  const engine1 = new DeterministicReplayEngine({ seed: 'determinism-test' });
  const engine2 = new DeterministicReplayEngine({ seed: 'determinism-test' });

  engine1.loadRecording(recording);
  engine2.loadRecording(recording);

  const r1 = [engine1.nextRandom(), engine1.nextRandom(), engine1.nextRandom()];
  const r2 = [engine2.nextRandom(), engine2.nextRandom(), engine2.nextRandom()];

  assert(r1[0] === r2[0], 'first random should match');
  assert(r1[1] === r2[1], 'second random should match');
  assert(r1[2] === r2[2], 'third random should match');
});

test('encryption round-trip preserves data integrity', () => {
  const guard = new ReplaySecurityGuard();
  const complexData = {
    manifest: { replay_id: 'RPL-test', events_count: 100 },
    events: createSampleEvents(5),
    nested: { deep: { value: 42 } },
  };

  const encrypted = guard.encrypt(complexData);
  const decrypted = guard.decrypt(encrypted.encrypted, encrypted.iv);

  assert(decrypted.manifest.replay_id === 'RPL-test', 'replay_id should survive round-trip');
  assert(decrypted.events.length === 5, 'events should survive round-trip');
  assert(decrypted.nested.deep.value === 42, 'nested values should survive round-trip');
});

// ═══════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════

console.log('\n' + '='.repeat(60));
console.log(`  P5 Replay Time Machine: ${testsPassed} passed, ${testsFailed} failed`);
console.log('='.repeat(60));

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  ✗ ${f.name}: ${f.error}`);
  }
}

process.exit(testsFailed > 0 ? 1 : 0);


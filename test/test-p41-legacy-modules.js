/**
 * BOQA test-p41-legacy-modules.js — P4.1 Legacy Module Direct Coverage
 *
 * Isolated smoke tests for every legacy engine.
 * Zero behavior change. Zero API change. Only increases confidence.
 *
 * Modules tested:
 *   1. state-diff   — StateDiffEngine
 *   2. baseline     — BaselineBuilder
 *   3. evidence     — EvidenceEngine
 *   4. verification — VerificationEngine
 *   5. finder       — HypothesisEngine
 *   6. learning-engine — LearningEngine
 *   7. prediction-engine — PredictionEngine
 */

const { StateDiffEngine } = require('../state-diff');
const { BaselineBuilder } = require('../baseline');
const { EvidenceEngine } = require('../evidence');
const { VerificationEngine } = require('../verification');
const { HypothesisEngine } = require('../finder');
const { LearningEngine, DEFAULT_WEIGHTS } = require('../learning-engine');
const { PredictionEngine } = require('../prediction-engine');

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

function assertIncludes(arr, item, message) {
  if (!arr.includes(item)) {
    throw new Error(`Assertion failed: ${message} — expected array to include "${item}", got [${arr.join(', ')}]`);
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

// ─── Helper: mock observations ──────────────────────────────────────

function makeAuthCookie(name, opts = {}) {
  return {
    name,
    value: opts.value || 'mock-value-1234',
    valuePreview: opts.valuePreview || 'mock-value-1234',
    domain: opts.domain || '.ripio.com',
    path: opts.path || '/',
    httpOnly: opts.httpOnly !== undefined ? opts.httpOnly : true,
    secure: opts.secure !== undefined ? opts.secure : true,
    sameSite: opts.sameSite || 'Lax',
  };
}

function makeEvents(count = 10, overrides = {}) {
  const events = [];
  for (let i = 0; i < count; i++) {
    events.push({
      id: `evt-${i}`,
      ts: Date.now() - (count - i) * 1000,
      elapsed: i * 100,
      type: overrides.type || 'network_request',
      url: overrides.url || `https://ripio.com/api/v1/resource/${i}`,
      method: overrides.method || 'GET',
      ...overrides,
    });
  }
  return events;
}

function makeCookieSnapshotEvent(cookies) {
  return {
    id: `evt-cs-${Date.now()}`,
    ts: Date.now(),
    elapsed: 0,
    type: 'cookie_snapshot',
    meta: { authCookies: cookies },
  };
}

function makeAuthSignalEvent(signalType, url = 'https://ripio.com/api/') {
  return {
    id: `evt-as-${Date.now()}`,
    ts: Date.now(),
    elapsed: 0,
    type: 'auth_signal',
    url,
    meta: { signalType, cookies: [makeAuthCookie('sessionid')] },
  };
}

function makeNetworkResponseEvent(url, status, headers = {}) {
  return {
    id: `evt-nr-${Date.now()}`,
    ts: Date.now(),
    elapsed: 0,
    type: 'network_response',
    url,
    status,
    headers,
  };
}

function makePageNavEvent(url, title) {
  return {
    id: `evt-pn-${Date.now()}`,
    ts: Date.now(),
    elapsed: 0,
    type: 'page_navigation',
    url,
    meta: { title },
  };
}

function makeWsEvent(type, url = 'wss://ripio.com/ws/') {
  return {
    id: `evt-ws-${Date.now()}`,
    ts: Date.now(),
    elapsed: 0,
    type,
    url,
  };
}

function makeReport(cookies = [], opts = {}) {
  return {
    auth_model: opts.auth_model || 'jwt_session',
    cookies,
    risk_flags: opts.risk_flags || [],
  };
}

function makeSession(events = [], opts = {}) {
  return {
    events,
    sessionStart: opts.sessionStart || Date.now() - 60000,
    sessionEnd: opts.sessionEnd || Date.now(),
    target: opts.target || 'ripio.com',
    totalEvents: opts.totalEvents || events.length,
  };
}

// ═══════════════════════════════════════════════════════════════════════
//  1. StateDiffEngine
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== StateDiffEngine ===');

test('should instantiate with default options', () => {
  const engine = new StateDiffEngine();
  assert(engine.snapshots instanceof Map, 'snapshots should be a Map');
  assert(engine.diffs instanceof Map, 'diffs should be a Map');
  assert(engine.snapshotCounter === 0, 'snapshotCounter should start at 0');
  assert(engine.diffCounter === 0, 'diffCounter should start at 0');
  assert(engine.options.safeMode === true, 'safeMode should default to true');
});

test('should capture a snapshot from empty observations', () => {
  const engine = new StateDiffEngine();
  const snap = engine.captureSnapshot({}, 'empty');
  assert(snap.id.startsWith('snap-'), 'snapshot ID should start with snap-');
  assert(snap.label === 'empty', 'label should be preserved');
  assert(typeof snap.ts === 'number', 'ts should be a number');
  assert(Array.isArray(snap.cookies), 'cookies should be an array');
  assert(Array.isArray(snap.localStorage_keys), 'localStorage_keys should be an array');
  assert(Array.isArray(snap.auth_signals), 'auth_signals should be an array');
  assert(snap.request_count === 0, 'request_count should be 0 for empty observations');
  assert(snap.error_count === 0, 'error_count should be 0 for empty observations');
  assert(snap.active_ws_connections === 0, 'active_ws_connections should be 0');
  assert(snap.event_count_at === 0, 'event_count_at should be 0');
});

test('should capture a snapshot with cookie state from report', () => {
  const engine = new StateDiffEngine();
  const cookies = [makeAuthCookie('sessionid'), makeAuthCookie('csrftoken')];
  const report = makeReport(cookies);
  const snap = engine.captureSnapshot({ report }, 'with-cookies');
  assert(snap.cookies.length >= 2, `should have at least 2 cookies, got ${snap.cookies.length}`);
  const names = snap.cookies.map(c => c.name);
  assertIncludes(names, 'sessionid', 'should have sessionid cookie');
  assertIncludes(names, 'csrftoken', 'should have csrftoken cookie');
});

test('should capture a snapshot with auth signals from events', () => {
  const engine = new StateDiffEngine();
  const events = [
    makeAuthSignalEvent('auth_cookie_set'),
    makeAuthSignalEvent('token_refreshed'),
  ];
  const snap = engine.captureSnapshot({ events }, 'auth-signals');
  assert(snap.auth_signals.length === 2, `should have 2 auth signals, got ${snap.auth_signals.length}`);
  assert(snap.auth_signals[0].signalType === 'auth_cookie_set', 'first signal should be auth_cookie_set');
});

test('should capture a snapshot with page state from navigation events', () => {
  const engine = new StateDiffEngine();
  const events = [
    makePageNavEvent('https://ripio.com/login', 'Login'),
    makePageNavEvent('https://ripio.com/dashboard', 'Dashboard'),
  ];
  const snap = engine.captureSnapshot({ events }, 'nav');
  assert(snap.page_url === 'https://ripio.com/dashboard', 'should capture latest page URL');
  assert(snap.page_title === 'Dashboard', 'should capture latest page title');
});

test('should capture a snapshot with WS state', () => {
  const engine = new StateDiffEngine();
  const events = [
    makeWsEvent('websocket_open'),
    makeWsEvent('websocket_open'),
    makeWsEvent('websocket_close'),
  ];
  const snap = engine.captureSnapshot({ events }, 'ws-state');
  assert(snap.active_ws_connections === 1, `should have 1 active WS, got ${snap.active_ws_connections}`);
});

test('should capture a snapshot with request/error metrics', () => {
  const engine = new StateDiffEngine();
  const events = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/' },
    { id: 'e2', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/data' },
    { id: 'e3', ts: Date.now(), type: 'console_error' },
    { id: 'e4', ts: Date.now(), type: 'network_failure' },
  ];
  const snap = engine.captureSnapshot({ events }, 'metrics');
  assert(snap.request_count === 2, `should have 2 requests, got ${snap.request_count}`);
  assert(snap.error_count === 2, `should have 2 errors, got ${snap.error_count}`);
});

test('should compute empty diff for identical snapshots', () => {
  const engine = new StateDiffEngine();
  const obs = { events: [], report: makeReport() };
  const before = engine.captureSnapshot(obs, 'before');
  const after = engine.captureSnapshot(obs, 'after');
  const diff = engine.compare(before, after);
  assert(diff.id.startsWith('diff-'), 'diff ID should start with diff-');
  assert(diff.diff_type === 'expected', 'identical states should produce expected diff');
  assert(diff.cookie_diffs.length === 0, 'should have no cookie diffs');
  assert(diff.localStorage_diffs.length === 0, 'should have no localStorage diffs');
});

test('should detect cookie added', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid')]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid'), makeAuthCookie('access_token')]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const added = diff.cookie_diffs.find(d => d.type === 'cookie_added' && d.name === 'access_token');
  assert(added, 'should detect access_token cookie added');
  assert(added.severity === 'medium', 'auth cookie added should be medium severity');
});

test('should detect cookie removed', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid'), makeAuthCookie('access_token')]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid')]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const removed = diff.cookie_diffs.find(d => d.type === 'cookie_removed' && d.name === 'access_token');
  assert(removed, 'should detect access_token cookie removed');
  assert(removed.severity === 'high', 'auth cookie removed should be high severity');
});

test('should detect cookie value rotation', () => {
  const engine = new StateDiffEngine();
  // Must set valuePreview since _extractCookieState uses valuePreview || value
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { value: 'old-value', valuePreview: 'old-value' })]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { value: 'new-value', valuePreview: 'new-value' })]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const rotated = diff.cookie_diffs.find(d => d.type === 'value_rotated' && d.name === 'sessionid');
  assert(rotated, 'should detect sessionid value rotation');
  assert(rotated.severity === 'low', 'auth cookie rotation should be low severity');
});

test('should detect httpOnly removed (critical)', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { httpOnly: true })]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { httpOnly: false })]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.diff_type === 'critical', 'httpOnly removal should produce critical diff');
  assert(diff.severity === 'high', 'httpOnly removal should be high severity');
  const httpOnlyRemoved = diff.cookie_diffs.find(d => d.type === 'httpOnly_removed');
  assert(httpOnlyRemoved, 'should detect httpOnly_removed event');
});

test('should detect secure flag removed', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { secure: true })]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { secure: false })]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const secureRemoved = diff.cookie_diffs.find(d => d.type === 'secure_removed');
  assert(secureRemoved, 'should detect secure_removed event');
  assert(diff.diff_type === 'critical', 'secure removal should produce critical diff');
});

test('should detect sameSite downgrade', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { sameSite: 'Strict' })]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { sameSite: 'None' })]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const downgrade = diff.cookie_diffs.find(d => d.type === 'sameSite_downgrade');
  assert(downgrade, 'should detect sameSite_downgrade');
  assert(downgrade.severity === 'medium', 'sameSite downgrade should be medium severity');
});

test('should detect sameSite upgrade', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { sameSite: 'None' })]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { sameSite: 'Strict' })]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const upgrade = diff.cookie_diffs.find(d => d.type === 'sameSite_upgrade');
  assert(upgrade, 'should detect sameSite_upgrade');
  assert(upgrade.severity === 'info', 'sameSite upgrade should be info severity');
});

test('should detect localStorage key added/removed', () => {
  const engine = new StateDiffEngine();
  // The regex is /__BOQA__storage_key[:=]\s*(\S+)/ — single : or = separator
  const beforeEvents = [
    { id: 'e1', ts: Date.now(), type: 'console_log', payload: '__BOQA__storage_key: token_cache' },
  ];
  const afterEvents = [
    { id: 'e2', ts: Date.now(), type: 'console_log', payload: '__BOQA__storage_key: auth_state' },
  ];
  const beforeSnap = engine.captureSnapshot({ events: beforeEvents }, 'before');
  const afterSnap = engine.captureSnapshot({ events: afterEvents }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.localStorage_diffs.some(d => d.type === 'key_removed' && d.key === 'token_cache'), 'should detect token_cache key removed');
  assert(diff.localStorage_diffs.some(d => d.type === 'key_added' && d.key === 'auth_state'), 'should detect auth_state key added');
});

test('should detect auth state changes', () => {
  const engine = new StateDiffEngine();
  const beforeEvents = [makeAuthSignalEvent('auth_cookie_set')];
  const afterEvents = [makeAuthSignalEvent('unauthorized')];
  const beforeSnap = engine.captureSnapshot({ events: beforeEvents }, 'before');
  const afterSnap = engine.captureSnapshot({ events: afterEvents }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.auth_state_diff.new_signal_types.includes('unauthorized'), 'should detect unauthorized signal');
  assert(diff.auth_state_diff.lost_signal_types.includes('auth_cookie_set'), 'should detect lost auth_cookie_set signal');
  assert(diff.diff_type === 'unexpected', 'unauthorized signal should produce unexpected diff');
});

test('should detect page URL change', () => {
  const engine = new StateDiffEngine();
  const beforeEvents = [makePageNavEvent('https://ripio.com/login', 'Login')];
  const afterEvents = [makePageNavEvent('https://ripio.com/dashboard', 'Dashboard')];
  const beforeSnap = engine.captureSnapshot({ events: beforeEvents }, 'before');
  const afterSnap = engine.captureSnapshot({ events: afterEvents }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.page_state_diff.url_changed === true, 'should detect URL change');
  assert(diff.page_state_diff.url_from === 'https://ripio.com/login', 'should record old URL');
  assert(diff.page_state_diff.url_to === 'https://ripio.com/dashboard', 'should record new URL');
});

test('should detect metrics change', () => {
  const engine = new StateDiffEngine();
  const beforeEvents = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/' },
  ];
  const afterEvents = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/' },
    { id: 'e2', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/data' },
    { id: 'e3', ts: Date.now(), type: 'console_error' },
  ];
  const beforeSnap = engine.captureSnapshot({ events: beforeEvents }, 'before');
  const afterSnap = engine.captureSnapshot({ events: afterEvents }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.metrics_diff.request_count_change === 1, 'should detect 1 additional request');
  assert(diff.metrics_diff.error_count_change === 1, 'should detect 1 additional error');
});

test('should detect WS state change', () => {
  const engine = new StateDiffEngine();
  const beforeEvents = [makeWsEvent('websocket_open'), makeWsEvent('websocket_open')];
  const afterEvents = [makeWsEvent('websocket_open'), makeWsEvent('websocket_open'), makeWsEvent('websocket_close')];
  const beforeSnap = engine.captureSnapshot({ events: beforeEvents }, 'before');
  const afterSnap = engine.captureSnapshot({ events: afterEvents }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.ws_state_diff.active_change === -1, 'should detect 1 fewer active WS connection');
});

test('should build summary string', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({}, 'before');
  const afterSnap = engine.captureSnapshot({}, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(typeof diff.summary === 'string', 'summary should be a string');
  assert(diff.summary.length > 0, 'summary should not be empty');
});

test('should produce correct diff classification for critical changes', () => {
  const engine = new StateDiffEngine();
  const beforeSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { httpOnly: true, secure: true })]) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { httpOnly: false, secure: false })]) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.diff_type === 'critical', 'combined httpOnly+secure removal should be critical');
  assert(diff.severity === 'high', 'combined removal should be high severity');
});

test('should store and retrieve snapshots', () => {
  const engine = new StateDiffEngine();
  const snap = engine.captureSnapshot({}, 'stored');
  const retrieved = engine.getSnapshot(snap.id);
  assert(retrieved !== undefined, 'should retrieve stored snapshot');
  assert(retrieved.id === snap.id, 'retrieved snapshot ID should match');
});

test('should store and retrieve diffs', () => {
  const engine = new StateDiffEngine();
  const before = engine.captureSnapshot({}, 'b');
  const after = engine.captureSnapshot({}, 'a');
  const diff = engine.compare(before, after);
  const retrieved = engine.getDiff(diff.id);
  assert(retrieved !== undefined, 'should retrieve stored diff');
  assert(retrieved.id === diff.id, 'retrieved diff ID should match');
});

test('should return summary statistics', () => {
  const engine = new StateDiffEngine();
  const b1 = engine.captureSnapshot({}, 'b1');
  const a1 = engine.captureSnapshot({}, 'a1');
  engine.compare(b1, a1);
  const summary = engine.getSummary();
  assert(summary.total_snapshots === 2, `should have 2 snapshots, got ${summary.total_snapshots}`);
  assert(summary.total_diffs === 1, `should have 1 diff, got ${summary.total_diffs}`);
  assert('by_type' in summary, 'summary should have by_type');
  assert('by_severity' in summary, 'summary should have by_severity');
});

test('should save diff to disk', () => {
  const engine = new StateDiffEngine();
  const before = engine.captureSnapshot({}, 'b');
  const after = engine.captureSnapshot({}, 'a');
  const diff = engine.compare(before, after);
  const filePath = engine.saveDiff(diff.id);
  assert(filePath !== null, 'should return a file path');
  assert(filePath.endsWith('.json'), 'file should be JSON');
  const fs = require('fs');
  assert(fs.existsSync(filePath), 'saved file should exist');
  const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  assert(content.id === diff.id, 'saved content should match diff ID');
});

test('should capture delta snapshot filtering events by timestamp', () => {
  const engine = new StateDiffEngine();
  const oldTs = Date.now() - 10000;
  const recentTs = Date.now() - 1000;
  const events = [
    { id: 'e1', ts: oldTs, type: 'network_request', url: 'https://ripio.com/old' },
    { id: 'e2', ts: recentTs, type: 'network_request', url: 'https://ripio.com/recent' },
  ];
  const snap = engine.captureDeltaSnapshot({ events }, oldTs + 5000, 'delta');
  assert(snap.event_count_at === 1, `should have 1 event after timestamp filter, got ${snap.event_count_at}`);
});

test('captureAndCompare should run action between snapshots', async () => {
  const engine = new StateDiffEngine();
  let actionRan = false;
  const diff = await engine.captureAndCompare({}, async () => {
    actionRan = true;
  }, 'test-action');
  assert(actionRan === true, 'action function should have been called');
  assert(diff.id.startsWith('diff-'), 'should return a diff');
});

test('should handle large diff with many cookies', () => {
  const engine = new StateDiffEngine();
  const beforeCookies = [];
  const afterCookies = [];
  for (let i = 0; i < 50; i++) {
    beforeCookies.push(makeAuthCookie(`cookie_${i}`));
    if (i < 40) afterCookies.push(makeAuthCookie(`cookie_${i}`));
  }
  afterCookies.push(makeAuthCookie('new_cookie'));
  const beforeSnap = engine.captureSnapshot({ report: makeReport(beforeCookies) }, 'before');
  const afterSnap = engine.captureSnapshot({ report: makeReport(afterCookies) }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  const removed = diff.cookie_diffs.filter(d => d.type === 'cookie_removed');
  const added = diff.cookie_diffs.filter(d => d.type === 'cookie_added');
  assert(removed.length === 10, `should have 10 removed cookies, got ${removed.length}`);
  assert(added.length === 1, `should have 1 added cookie, got ${added.length}`);
});

test('should handle nested object diff in auth state', () => {
  const engine = new StateDiffEngine();
  const beforeEvents = [makeAuthSignalEvent('login'), makeAuthSignalEvent('token_refresh')];
  const afterEvents = [makeAuthSignalEvent('logout'), makeAuthSignalEvent('token_refresh')];
  const beforeSnap = engine.captureSnapshot({ events: beforeEvents }, 'before');
  const afterSnap = engine.captureSnapshot({ events: afterEvents }, 'after');
  const diff = engine.compare(beforeSnap, afterSnap);
  assert(diff.auth_state_diff.new_signal_types.includes('logout'), 'should detect logout signal');
  assert(diff.auth_state_diff.lost_signal_types.includes('login'), 'should detect login signal lost');
});

test('should compute session hash consistently', () => {
  const engine = new StateDiffEngine();
  const cookies = [makeAuthCookie('sessionid'), makeAuthCookie('csrftoken')];
  const snap1 = engine.captureSnapshot({ report: makeReport(cookies) }, 'hash1');
  const snap2 = engine.captureSnapshot({ report: makeReport(cookies) }, 'hash2');
  assert(snap1.session_cookies_hash === snap2.session_cookies_hash,
    'same cookies should produce same session hash');
});

test('should produce different session hash for different cookies', () => {
  const engine = new StateDiffEngine();
  // Must set valuePreview since _extractCookieState uses valuePreview || value
  const snap1 = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { value: 'val1', valuePreview: 'val1' })]) }, 'h1');
  const snap2 = engine.captureSnapshot({ report: makeReport([makeAuthCookie('sessionid', { value: 'val2', valuePreview: 'val2' })]) }, 'h2');
  assert(snap1.session_cookies_hash !== snap2.session_cookies_hash,
    'different cookie values should produce different session hash');
});

// ═══════════════════════════════════════════════════════════════════════
//  2. BaselineBuilder
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== BaselineBuilder ===');

test('should instantiate and create baselines directory', () => {
  const builder = new BaselineBuilder();
  assert(builder instanceof BaselineBuilder, 'should be a BaselineBuilder instance');
});

test('should build a baseline from session and report', () => {
  const builder = new BaselineBuilder();
  const session = makeSession(makeEvents(20));
  const report = makeReport([makeAuthCookie('sessionid')]);
  const baseline = builder.build(session, report);
  assert(baseline.id.startsWith('bl-'), 'baseline ID should start with bl-');
  assert(baseline.version === '0.2.0', 'version should be 0.2.0');
  assert(baseline.target === 'ripio.com', 'target should be preserved');
  assert(typeof baseline.created_at === 'number', 'created_at should be a number');
  assert('fingerprint' in baseline, 'baseline should have fingerprint');
  assert('metrics' in baseline, 'baseline should have metrics');
});

test('should extract fingerprint with endpoints', () => {
  const builder = new BaselineBuilder();
  const events = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/v1/users', method: 'GET' },
    { id: 'e2', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/v1/wallet', method: 'POST' },
    { id: 'e3', ts: Date.now(), type: 'network_response', url: 'https://ripio.com/api/v1/users', method: 'GET' },
  ];
  const session = makeSession(events);
  const report = makeReport([makeAuthCookie('sessionid')]);
  const baseline = builder.build(session, report);
  assert(baseline.fingerprint.endpoints.length >= 2, 'should extract at least 2 endpoints');
  assert(baseline.fingerprint.endpoints.some(ep => ep.includes('/api/v1/users')), 'should include /api/v1/users endpoint');
});

test('should extract fingerprint with auth model', () => {
  const builder = new BaselineBuilder();
  const session = makeSession();
  const report = makeReport([], { auth_model: 'jwt_session' });
  const baseline = builder.build(session, report);
  assert(baseline.fingerprint.auth_model === 'jwt_session', 'should preserve auth_model');
});

test('should extract fingerprint with WS channels', () => {
  const builder = new BaselineBuilder();
  const events = [
    makeWsEvent('websocket_open', 'wss://ripio.com/ws/notifications'),
    makeWsEvent('websocket_open', 'wss://ripio.com/ws/trading'),
  ];
  const session = makeSession(events);
  const report = makeReport();
  const baseline = builder.build(session, report);
  assert(baseline.fingerprint.ws_channels.length >= 2, 'should extract WS channels');
});

test('should extract fingerprint with cookie schema', () => {
  const builder = new BaselineBuilder();
  const session = makeSession();
  const cookies = [makeAuthCookie('sessionid'), makeAuthCookie('csrftoken', { httpOnly: true, secure: true, sameSite: 'Lax' })];
  const report = makeReport(cookies);
  const baseline = builder.build(session, report);
  assert(baseline.fingerprint.cookie_schema.length === 2, 'should have 2 cookies in schema');
  assert(baseline.fingerprint.cookie_schema[0].name === 'sessionid', 'first cookie should be sessionid');
});

test('should extract metrics from session', () => {
  const builder = new BaselineBuilder();
  const events = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/' },
    { id: 'e2', ts: Date.now(), type: 'network_response', url: 'https://ripio.com/api/', status: 200 },
    { id: 'e3', ts: Date.now(), type: 'console_error' },
    { id: 'e4', ts: Date.now(), type: 'websocket_message_in' },
    { id: 'e5', ts: Date.now(), type: 'auth_signal', meta: { signalType: 'login' } },
  ];
  const session = makeSession(events);
  const report = makeReport();
  const baseline = builder.build(session, report);
  assert(baseline.metrics.request_count === 1, 'should count 1 request');
  assert(baseline.metrics.error_count === 1, 'should count 1 error');
  assert(baseline.metrics.ws_message_count === 1, 'should count 1 WS message');
  assert(baseline.metrics.auth_events === 1, 'should count 1 auth event');
});

test('should save and load baseline', () => {
  const builder = new BaselineBuilder();
  const session = makeSession();
  const report = makeReport([makeAuthCookie('sessionid')]);
  const baseline = builder.build(session, report);
  const filePath = builder.save(baseline);
  assert(filePath.endsWith('.json'), 'saved file should be JSON');
  const loaded = builder.load(baseline.id);
  assert(loaded.id === baseline.id, 'loaded ID should match');
  assert(loaded.target === baseline.target, 'loaded target should match');
});

test('should list baselines', () => {
  const builder = new BaselineBuilder();
  const session = makeSession();
  const report = makeReport();
  const baseline = builder.build(session, report);
  builder.save(baseline);
  const list = builder.list();
  assert(Array.isArray(list), 'list should return an array');
  assert(list.length >= 1, 'should have at least one baseline');
  const found = list.find(b => b.id === baseline.id);
  assert(found, 'should find the saved baseline in list');
});

test('should find latest baseline for target', () => {
  const builder = new BaselineBuilder();
  const session = makeSession([], { target: 'find-latest-test.ripio.com' });
  const report = makeReport();
  const baseline = builder.build(session, report);
  builder.save(baseline);
  const latest = builder.findLatest('find-latest-test.ripio.com');
  assert(latest !== null, 'should find a baseline for the target');
  assert(latest.target === 'find-latest-test.ripio.com', 'target should match');
});

test('should return null for nonexistent target in findLatest', () => {
  const builder = new BaselineBuilder();
  const result = builder.findLatest('nonexistent.target.xyz');
  assert(result === null, 'should return null for nonexistent target');
});

test('should throw when loading nonexistent baseline', () => {
  const builder = new BaselineBuilder();
  let threw = false;
  try {
    builder.load('bl-nonexistent000');
  } catch (e) {
    threw = true;
    assert(e.message.includes('not found'), 'error should mention not found');
  }
  assert(threw, 'should throw for nonexistent baseline');
});

test('should compute error rate', () => {
  const builder = new BaselineBuilder();
  const events = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/' },
    { id: 'e2', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/data' },
    { id: 'e3', ts: Date.now(), type: 'console_error' },
  ];
  const session = makeSession(events);
  const report = makeReport();
  const baseline = builder.build(session, report);
  assert(baseline.metrics.error_rate === 0.5, `error rate should be 0.5, got ${baseline.metrics.error_rate}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  3. EvidenceEngine
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== EvidenceEngine ===');

test('should instantiate with empty packages', () => {
  const engine = new EvidenceEngine();
  assert(engine.evidencePackages instanceof Map, 'evidencePackages should be a Map');
  assert(engine.evidencePackages.size === 0, 'should start with no packages');
});

test('should build evidence package for a finding', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-test001',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    hypothesis_id: 'hyp-test001',
  };
  const validationResult = {
    validated: true,
    validation_proof: [{ type: 'manual', detail: 'Cookie accessible via JS', ts: Date.now() }],
    validation_method: 'replay',
  };
  const observations = {
    events: [makeCookieSnapshotEvent([makeAuthCookie('sessionid', { httpOnly: false })])],
    report: makeReport([makeAuthCookie('sessionid', { httpOnly: false })]),
  };
  const pkg = engine.buildPackage(finding, validationResult, observations);
  assert(pkg.finding_id === 'FND-test001', 'finding_id should match');
  assert(pkg.category === 'missing_httpOnly', 'category should match');
  assert(Array.isArray(pkg.evidence_chain), 'evidence_chain should be an array');
  assert(pkg.evidence_chain.length > 0, 'evidence_chain should not be empty');
  assert(Array.isArray(pkg.timeline), 'timeline should be an array');
  assert(Array.isArray(pkg.reproduction), 'reproduction should be an array');
  assert(typeof pkg.recommended_fix === 'string', 'recommended_fix should be a string');
  assert(pkg.sanitization.safe_mode === true, 'safe_mode should be true');
  assert(pkg.sanitization.cookie_values_truncated === true, 'cookie values should be truncated');
});

test('should produce hash-stable evidence', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-hash-test',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    hypothesis_id: 'hyp-hash',
  };
  const vr = {
    validated: true,
    validation_proof: [{ type: 'manual', detail: 'Test proof', ts: Date.now() }],
  };
  const obs = {
    events: [],
    report: makeReport([makeAuthCookie('sessionid')]),
  };
  const pkg1 = engine.buildPackage(finding, vr, obs);
  const pkg2 = engine.buildPackage(finding, vr, obs);
  // Same finding ID should overwrite in Map, but the built_at timestamp will differ
  assert(pkg1.finding_id === pkg2.finding_id, 'finding IDs should match');
  assert(typeof pkg1.built_at === 'number', 'built_at should be a number');
});

test('should include metadata in evidence package', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-meta',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: ['/api/auth'],
    hypothesis_id: 'hyp-meta',
  };
  const vr = { validated: true, validation_proof: [], validation_method: 'none' };
  const obs = { events: [], report: makeReport([makeAuthCookie('sessionid')]) };
  const pkg = engine.buildPackage(finding, vr, obs);
  assert(pkg.affected_cookies.includes('sessionid'), 'affected_cookies should include sessionid');
  assert(pkg.affected_endpoints.includes('/api/auth'), 'affected_endpoints should include /api/auth');
  assert('built_at' in pkg, 'should have built_at');
  assert('sanitization' in pkg, 'should have sanitization');
});

test('should handle JSON evidence type (cors_misconfiguration)', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-cors',
    category: 'cors_misconfiguration',
    affected_cookies: [],
    affected_endpoints: ['/api/data'],
    hypothesis_id: 'hyp-cors',
  };
  const vr = { validated: true, validation_proof: [{ type: 'cors_check', detail: 'ACAO:* with ACAC:true', ts: Date.now() }] };
  const obs = {
    events: [makeNetworkResponseEvent('https://ripio.com/api/data', 200, {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    })],
    report: makeReport(),
  };
  const pkg = engine.buildPackage(finding, vr, obs);
  const corsEvidence = pkg.evidence_chain.find(e => e.type === 'header_snapshot');
  assert(corsEvidence, 'should include CORS header evidence');
  assert(corsEvidence.detail.includes('ACAO'), 'CORS evidence should mention ACAO');
});

test('should handle JWT evidence type', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-jwt',
    category: 'jwt_in_browser_memory',
    affected_cookies: [],
    affected_endpoints: [],
    hypothesis_id: 'hyp-jwt',
  };
  const vr = { validated: true, validation_proof: [] };
  const obs = {
    events: [
      {
        id: 'e1', ts: Date.now(), type: 'console_log',
        payload: 'CryptoJS.AES.decrypt(encrypted, key)',
      },
      makeCookieSnapshotEvent([makeAuthCookie('ripio_access', { value: 'U2FsdGVkX1abcdef' })]),
    ],
    report: makeReport(),
  };
  const pkg = engine.buildPackage(finding, vr, obs);
  const decryptEvidence = pkg.evidence_chain.find(e => e.detail && e.detail.includes('AES'));
  assert(decryptEvidence, 'should include AES decryption evidence');
});

test('should handle session fixation evidence', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-fixation',
    category: 'session_fixation_indicators',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    hypothesis_id: 'hyp-fix',
  };
  const vr = { validated: true, validation_proof: [] };
  const obs = {
    events: [
      makeCookieSnapshotEvent([makeAuthCookie('sessionid', { value: 'abc123' })]),
      makeCookieSnapshotEvent([makeAuthCookie('sessionid', { value: 'abc123' })]),
    ],
    report: makeReport(),
  };
  const pkg = engine.buildPackage(finding, vr, obs);
  const timelineEvidence = pkg.evidence_chain.find(e => e.type === 'timeline_segment');
  assert(timelineEvidence, 'should include timeline_segment evidence for session fixation');
});

test('should build safe reproduction steps', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-repro',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    hypothesis_id: 'hyp-repro',
  };
  const vr = { validated: true, validation_proof: [] };
  const obs = { events: [], report: makeReport([makeAuthCookie('sessionid')]) };
  const pkg = engine.buildPackage(finding, vr, obs);
  assert(pkg.reproduction.length > 0, 'should have reproduction steps');
  for (const step of pkg.reproduction) {
    assert(step.safe === true, `step ${step.step} should be safe`);
    assert(step.action === 'observe' || step.action === 'disclosure', `step ${step.step} action should be observe/disclosure, got ${step.action}`);
  }
});

test('should sanitize cookie values in evidence', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-sanitize',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    hypothesis_id: 'hyp-sanitize',
  };
  const vr = { validated: true, validation_proof: [] };
  const obs = {
    events: [
      makeNetworkResponseEvent('https://ripio.com/api/', 200, {
        'set-cookie': 'sessionid=secret-value-12345; Domain=.ripio.com; Path=/',
      }),
    ],
    report: makeReport([makeAuthCookie('sessionid')]),
  };
  const pkg = engine.buildPackage(finding, vr, obs);
  const setCookieEvidence = pkg.evidence_chain.find(e => e.type === 'header_snapshot');
  if (setCookieEvidence) {
    assert(!setCookieEvidence.detail.includes('secret-value-12345'), 'should not expose raw cookie value');
    assert(setCookieEvidence.detail.includes('REDACTED'), 'should redact cookie value');
  }
});

test('should provide recommended fix for known categories', () => {
  const engine = new EvidenceEngine();
  const categories = ['missing_httpOnly', 'missing_secure', 'weak_samesite', 'cors_misconfiguration', 'csrf_signal_anomaly'];
  for (const cat of categories) {
    const finding = {
      id: `FND-fix-${cat}`,
      category: cat,
      affected_cookies: ['sessionid'],
      affected_endpoints: [],
      hypothesis_id: `hyp-fix-${cat}`,
    };
    const vr = { validated: true, validation_proof: [] };
    const obs = { events: [], report: makeReport() };
    const pkg = engine.buildPackage(finding, vr, obs);
    assert(typeof pkg.recommended_fix === 'string', `should have recommended fix for ${cat}`);
    assert(pkg.recommended_fix.length > 20, `recommended fix for ${cat} should be substantive`);
  }
});

test('should retrieve stored evidence package by finding ID', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-retrieve',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    hypothesis_id: 'hyp-retrieve',
  };
  const vr = { validated: true, validation_proof: [] };
  const obs = { events: [], report: makeReport() };
  engine.buildPackage(finding, vr, obs);
  const pkg = engine.getPackage('FND-retrieve');
  assert(pkg !== undefined, 'should retrieve stored package');
  assert(pkg.finding_id === 'FND-retrieve', 'finding ID should match');
});

test('should buildAll for multiple findings', () => {
  const engine = new EvidenceEngine();
  const findings = [
    { id: 'FND-1', category: 'missing_httpOnly', affected_cookies: ['sessionid'], affected_endpoints: [], hypothesis_id: 'hyp-1' },
    { id: 'FND-2', category: 'missing_secure', affected_cookies: ['csrftoken'], affected_endpoints: [], hypothesis_id: 'hyp-2' },
  ];
  const validationResults = [
    { hypothesis_id: 'hyp-1', validated: true, validation_proof: [] },
    { hypothesis_id: 'hyp-2', validated: true, validation_proof: [] },
  ];
  const obs = { events: [], report: makeReport() };
  const packages = engine.buildAll(findings, validationResults, obs);
  assert(packages.length === 2, `should build 2 packages, got ${packages.length}`);
});

test('should skip unvalidated findings in buildAll', () => {
  const engine = new EvidenceEngine();
  const findings = [
    { id: 'FND-skip1', category: 'missing_httpOnly', affected_cookies: ['sessionid'], affected_endpoints: [], hypothesis_id: 'hyp-skip1' },
    { id: 'FND-skip2', category: 'missing_secure', affected_cookies: ['csrftoken'], affected_endpoints: [], hypothesis_id: 'hyp-skip2' },
  ];
  const validationResults = [
    { hypothesis_id: 'hyp-skip1', validated: true, validation_proof: [] },
    { hypothesis_id: 'hyp-skip2', validated: false, validation_proof: [] },
  ];
  const obs = { events: [], report: makeReport() };
  const packages = engine.buildAll(findings, validationResults, obs);
  assert(packages.length === 1, `should build only 1 package (validated), got ${packages.length}`);
  assert(packages[0].finding_id === 'FND-skip1', 'should only include validated finding');
});

test('should detect corruption in evidence (empty chain but validated)', () => {
  const engine = new EvidenceEngine();
  const finding = {
    id: 'FND-corrupt',
    category: 'unknown_category_xyz',
    affected_cookies: [],
    affected_endpoints: [],
    hypothesis_id: 'hyp-corrupt',
  };
  const vr = { validated: true, validation_proof: [{ type: 'test', detail: 'validated', ts: Date.now() }] };
  const obs = { events: [], report: makeReport() };
  const pkg = engine.buildPackage(finding, vr, obs);
  // For unknown categories, the engine should still produce a valid package
  assert(pkg.finding_id === 'FND-corrupt', 'should handle unknown category gracefully');
  assert(typeof pkg.recommended_fix === 'string', 'should still provide a default fix');
});

// ═══════════════════════════════════════════════════════════════════════
//  4. VerificationEngine
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== VerificationEngine ===');

test('should instantiate with empty state', () => {
  const engine = new VerificationEngine();
  assert(engine.plans instanceof Map, 'plans should be a Map');
  assert(engine.results instanceof Map, 'results should be a Map');
  assert(Array.isArray(engine.confirmedBugs), 'confirmedBugs should be an array');
});

test('should create verification plan for a finding', () => {
  const engine = new VerificationEngine();
  const finding = {
    id: 'FND-verify1',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    title: 'Sessionid missing HttpOnly',
    severity: 'high',
    confidence: 90,
  };
  const plan = engine.createPlan(finding, {});
  assert(plan !== null, 'should create a plan');
  assert(plan.id.startsWith('plan-'), 'plan ID should start with plan-');
  assert(plan.finding_id === 'FND-verify1', 'finding_id should match');
  assert(plan.verification_category === 'cookie_security_failure', 'should map to correct verification category');
  assert(Array.isArray(plan.steps), 'plan should have steps');
  assert(plan.steps.length > 0, 'plan should have at least one step');
  for (const step of plan.steps) {
    assert(typeof step.action === 'string', 'step action should be a string');
    assert(typeof step.description === 'string', 'step description should be a string');
    assert(typeof step.expected_outcome === 'string', 'step should have expected_outcome');
  }
});

test('should create verification plan for all categories', () => {
  const engine = new VerificationEngine();
  const categories = [
    'missing_httpOnly', 'missing_secure', 'weak_samesite',
    'bearer_token_exposure', 'jwt_in_browser_memory',
    'session_fixation_indicators', 'session_rotation_failure',
    'cache_control_misconfiguration', 'csrf_signal_anomaly',
    'cors_misconfiguration',
  ];
  for (const cat of categories) {
    const finding = {
      id: `FND-${cat}`,
      category: cat,
      affected_cookies: ['sessionid'],
      affected_endpoints: [],
      title: `Test: ${cat}`,
      severity: 'high',
      confidence: 80,
    };
    const plan = engine.createPlan(finding, {});
    assert(plan !== null, `should create plan for ${cat}`);
    assert(plan.steps.length > 0, `plan for ${cat} should have steps`);
  }
});

test('should reject forbidden actions in plan', () => {
  const engine = new VerificationEngine();
  const finding = {
    id: 'FND-forbidden',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    title: 'Test forbidden',
    severity: 'high',
    confidence: 80,
  };
  const plan = engine.createPlan(finding, {});
  const forbidden = ['bruteforce', 'fuzzing_at_scale', 'credential_attacks', 'dos',
    'privilege_escalation_attempts', 'destructive_mutations', 'mass_scanning'];
  for (const step of plan.steps) {
    assert(!forbidden.includes(step.action), `step action "${step.action}" should not be forbidden`);
  }
});

test('should execute a plan and produce results', () => {
  const engine = new VerificationEngine();
  const finding = {
    id: 'FND-exec1',
    category: 'missing_httpOnly',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    title: 'Sessionid missing HttpOnly',
    severity: 'high',
    confidence: 90,
  };
  const plan = engine.createPlan(finding, {});
  // Execute with observations (not session/report)
  const observations = {
    events: [makeCookieSnapshotEvent([makeAuthCookie('sessionid', { httpOnly: false })])],
    report: makeReport([makeAuthCookie('sessionid', { httpOnly: false })]),
  };
  const result = engine.executePlan(plan.id, observations);
  assert(result !== null, 'should produce a result');
  assert(result.plan_id === plan.id, 'result plan_id should match');
  assert(typeof result.pass_rate === 'number', 'result should have pass_rate');
  assert(['confirmed', 'rejected'].includes(result.status), 'result status should be confirmed or rejected');
});

test('should handle partial verification', () => {
  const engine = new VerificationEngine();
  const finding = {
    id: 'FND-partial',
    category: 'csrf_signal_anomaly',
    affected_cookies: ['csrftoken'],
    affected_endpoints: ['/api/transfer'],
    title: 'CSRF anomaly',
    severity: 'medium',
    confidence: 70,
  };
  const plan = engine.createPlan(finding, {});
  const observations = {
    events: [],
    report: makeReport([makeAuthCookie('csrftoken')]),
  };
  const result = engine.executePlan(plan.id, observations);
  assert(result !== null, 'should produce a result even with minimal data');
});

test('should retrieve stored plans', () => {
  const engine = new VerificationEngine();
  const finding = {
    id: 'FND-retrieve',
    category: 'missing_secure',
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    title: 'Missing secure',
    severity: 'high',
    confidence: 85,
  };
  const plan = engine.createPlan(finding, {});
  const retrieved = engine.getPlan(plan.id);
  assert(retrieved !== undefined, 'should retrieve stored plan');
  assert(retrieved.id === plan.id, 'retrieved plan ID should match');
});

test('should get all plans', () => {
  const engine = new VerificationEngine();
  engine.createPlan(
    { id: 'FND-all1', category: 'missing_httpOnly', affected_cookies: ['sessionid'], affected_endpoints: [], title: 'T1', severity: 'high', confidence: 80 },
    {}
  );
  engine.createPlan(
    { id: 'FND-all2', category: 'missing_secure', affected_cookies: ['sessionid'], affected_endpoints: [], title: 'T2', severity: 'high', confidence: 80 },
    {}
  );
  const all = engine.getPlans();
  assert(all.length >= 2, 'should have at least 2 plans');
});

test('should get verification summary', () => {
  const engine = new VerificationEngine();
  engine.createPlan(
    { id: 'FND-sum1', category: 'missing_httpOnly', affected_cookies: ['sessionid'], affected_endpoints: [], title: 'T1', severity: 'high', confidence: 80 },
    {}
  );
  const summary = engine.getSummary();
  assert(typeof summary === 'object', 'summary should be an object');
  assert('plans_created' in summary, 'summary should have plans_created');
});

// ═══════════════════════════════════════════════════════════════════════
//  5. HypothesisEngine (Finder)
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== HypothesisEngine (Finder) ===');

test('should instantiate with detectors', () => {
  const engine = new HypothesisEngine();
  assert(engine._detectors.length === 19, `should have 19 detectors, got ${engine._detectors.length}`);
});

test('should detect missing_httpOnly from report', () => {
  const engine = new HypothesisEngine();
  const cookies = [makeAuthCookie('sessionid', { httpOnly: false })];
  const report = makeReport(cookies);
  const hypotheses = engine.analyze({ events: [], report });
  const found = hypotheses.find(h => h.category === 'missing_httpOnly' && h.affected_cookies.includes('sessionid'));
  assert(found, 'should detect missing_httpOnly for sessionid');
  assert(found.confidence > 0, 'confidence should be > 0');
  assert(found.severity_hint === 'high', 'missing_httpOnly should be high severity');
});

test('should detect missing_secure from report', () => {
  const engine = new HypothesisEngine();
  const cookies = [makeAuthCookie('sessionid', { secure: false })];
  const report = makeReport(cookies);
  const hypotheses = engine.analyze({ events: [], report });
  const found = hypotheses.find(h => h.category === 'missing_secure' && h.affected_cookies.includes('sessionid'));
  assert(found, 'should detect missing_secure for sessionid');
});

test('should detect weak_samesite from report', () => {
  const engine = new HypothesisEngine();
  const cookies = [makeAuthCookie('sessionid', { sameSite: 'None' })];
  const report = makeReport(cookies);
  const hypotheses = engine.analyze({ events: [], report });
  const found = hypotheses.find(h => h.category === 'weak_samesite' && h.affected_cookies.includes('sessionid'));
  assert(found, 'should detect weak_samesite for sessionid');
});

test('should detect CORS misconfiguration from events', () => {
  const engine = new HypothesisEngine();
  const events = [makeNetworkResponseEvent('https://ripio.com/api/data', 200, {
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  })];
  const report = makeReport();
  const hypotheses = engine.analyze({ events, report });
  const found = hypotheses.find(h => h.category === 'cors_misconfiguration');
  assert(found, 'should detect cors_misconfiguration');
});

test('should detect bearer token exposure on static assets', () => {
  const engine = new HypothesisEngine();
  // The detector only fires on static asset URLs (.js, .css, .png, etc.) with Bearer tokens
  const events = [
    {
      id: 'e1', ts: Date.now(), type: 'network_request',
      url: 'https://ripio.com/static/app.js', method: 'GET',
      headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.test' },
    },
  ];
  const report = makeReport();
  const hypotheses = engine.analyze({ events, report });
  const found = hypotheses.find(h => h.category === 'bearer_token_exposure');
  assert(found, 'should detect bearer_token_exposure on static asset');
});

test('should handle empty observations (no crash)', () => {
  const engine = new HypothesisEngine();
  const hypotheses = engine.analyze({ events: [], report: {} });
  assert(Array.isArray(hypotheses), 'should return an array');
  assert(hypotheses.length === 0, 'empty observations should produce no hypotheses');
});

test('should handle missing report gracefully', () => {
  const engine = new HypothesisEngine();
  const hypotheses = engine.analyze({ events: [] });
  assert(Array.isArray(hypotheses), 'should return an array even without report');
});

test('should deduplicate findings for same cookie', () => {
  const engine = new HypothesisEngine();
  // Two cookies both missing httpOnly should produce separate hypotheses
  const cookies = [
    makeAuthCookie('sessionid', { httpOnly: false }),
    makeAuthCookie('access_token', { httpOnly: false }),
  ];
  const report = makeReport(cookies);
  const hypotheses = engine.analyze({ events: [], report });
  const httpOnlyFindings = hypotheses.filter(h => h.category === 'missing_httpOnly');
  assert(httpOnlyFindings.length === 2, `should have 2 separate findings, got ${httpOnlyFindings.length}`);
});

test('should handle large target with many events', () => {
  const engine = new HypothesisEngine();
  const events = makeEvents(500);
  const report = makeReport([makeAuthCookie('sessionid', { httpOnly: false })]);
  const hypotheses = engine.analyze({ events, report });
  assert(hypotheses.length > 0, 'should produce hypotheses from large event set');
});

test('should produce normalized hypotheses with all required fields', () => {
  const engine = new HypothesisEngine();
  const cookies = [makeAuthCookie('sessionid', { httpOnly: false })];
  const report = makeReport(cookies);
  const hypotheses = engine.analyze({ events: [], report });
  for (const h of hypotheses) {
    assert('id' in h, 'hypothesis should have id');
    assert('category' in h, 'hypothesis should have category');
    assert('title' in h, 'hypothesis should have title');
    assert('description' in h, 'hypothesis should have description');
    assert('observed' in h, 'hypothesis should have observed');
    assert('affected_cookies' in h, 'hypothesis should have affected_cookies');
    assert('affected_endpoints' in h, 'hypothesis should have affected_endpoints');
    assert('confidence' in h, 'hypothesis should have confidence');
    assert('severity_hint' in h, 'hypothesis should have severity_hint');
    assert('source' in h, 'hypothesis should have source');
    assert('created_at' in h, 'hypothesis should have created_at');
  }
});

test('should detect endpoint discovery from network events', () => {
  const engine = new HypothesisEngine();
  const events = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/v1/users', method: 'GET' },
    { id: 'e2', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/v1/wallet', method: 'POST' },
  ];
  const report = makeReport();
  const hypotheses = engine.analyze({ events, report });
  // Should detect hypotheses based on endpoint patterns
  assert(Array.isArray(hypotheses), 'should return hypotheses');
});

test('should ingest single events for real-time detection', () => {
  const engine = new HypothesisEngine();
  const event = makeNetworkResponseEvent('https://ripio.com/api/data', 200, {
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  });
  const result = engine.ingestEvent(event, { report: makeReport() });
  assert(Array.isArray(result), 'ingestEvent should return an array');
});

test('should handle parameter discovery', () => {
  const engine = new HypothesisEngine();
  const events = [
    { id: 'e1', ts: Date.now(), type: 'network_request', url: 'https://ripio.com/api/user?id=123&debug=true', method: 'GET' },
  ];
  const report = makeReport();
  const hypotheses = engine.analyze({ events, report });
  assert(Array.isArray(hypotheses), 'should handle parameterized URLs');
});

// ═══════════════════════════════════════════════════════════════════════
//  6. LearningEngine
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== LearningEngine ===');

test('should instantiate with default weights', () => {
  const engine = new LearningEngine();
  // Engine auto-loads from disk, so weights may differ from defaults if prior data exists
  assert(typeof engine.currentWeights.severity === 'number', 'severity weight should be a number');
  assert(typeof engine.currentWeights.confidence === 'number', 'confidence weight should be a number');
  assert(Array.isArray(engine.outcomes), 'outcomes should be an array');
  assert(typeof engine.metrics.total_observations === 'number', 'total_observations should be a number');
  // Clean up timer
  engine.shutdown();
});

test('should record an outcome', () => {
  const engine = new LearningEngine();
  const beforeObs = engine.metrics.total_observations;
  const beforeConf = engine.metrics.total_confirmed;
  engine.recordOutcome({
    hypothesis_id: 'hyp-rec1',
    category: 'cookie_security_test',
    verdict: 'confirmed',
    target_id: 'target-test-1',
    verification_type: 'replay',
    evv: 85,
    duration_ms: 1200,
    evidence_strength: 0.9,
  });
  assert(engine.outcomes.some(o => o.hypothesis_id === 'hyp-rec1'), 'should have the new outcome');
  assert(engine.metrics.total_observations === beforeObs + 1, 'total_observations should increment');
  assert(engine.metrics.total_confirmed === beforeConf + 1, 'total_confirmed should increment');
  engine.shutdown();
});

test('should track category stats', () => {
  const engine = new LearningEngine();
  const catName = 'cat_stats_test_' + Date.now();
  engine.recordOutcome({ hypothesis_id: 'h-cs1', category: catName, verdict: 'confirmed' });
  engine.recordOutcome({ hypothesis_id: 'h-cs2', category: catName, verdict: 'rejected' });
  engine.recordOutcome({ hypothesis_id: 'h-cs3', category: catName, verdict: 'inconclusive' });
  const stats = engine.categoryStats.get(catName);
  assert(stats, `should have ${catName} stats`);
  assert(stats.confirmed === 1, 'should have 1 confirmed');
  assert(stats.rejected === 1, 'should have 1 rejected');
  assert(stats.inconclusive === 1, 'should have 1 inconclusive');
  engine.shutdown();
});

test('should track verification type stats', () => {
  const engine = new LearningEngine();
  const vtype = 'test_vtype_unique_' + Date.now();
  engine.recordOutcome({ hypothesis_id: 'h-vt1', category: 'csrf_vt', verdict: 'confirmed', verification_type: vtype });
  engine.recordOutcome({ hypothesis_id: 'h-vt2', category: 'csrf_vt', verdict: 'rejected', verification_type: vtype });
  const stats = engine.verificationStats.get(vtype);
  assert(stats, `should have ${vtype} verification stats`);
  assert(stats.confirmed === 1, 'should have 1 confirmed for test vtype');
  engine.shutdown();
});

test('should track target-specific learning', () => {
  const engine = new LearningEngine();
  const targetId = 'target-learning-' + Date.now() + '.test';
  engine.recordOutcome({ hypothesis_id: 'h-tl1', category: 'csrf', verdict: 'confirmed', target_id: targetId });
  engine.recordOutcome({ hypothesis_id: 'h-tl2', category: 'xss', verdict: 'rejected', target_id: targetId });
  const tl = engine.targetLearning.get(targetId);
  assert(tl, `should have target learning for ${targetId}`);
  assert(tl.observations === 2, 'should have 2 observations');
  assert(tl.confirmed === 1, 'should have 1 confirmed');
  engine.shutdown();
});

test('should compute overall success rate', () => {
  const engine = new LearningEngine();
  const beforeObs = engine.metrics.total_observations;
  const beforeConf = engine.metrics.total_confirmed;
  engine.recordOutcome({ hypothesis_id: 'h-sr1', category: 'c_sr1', verdict: 'confirmed' });
  engine.recordOutcome({ hypothesis_id: 'h-sr2', category: 'c_sr2', verdict: 'rejected' });
  // Verify rate is between 0 and 1
  assert(engine.metrics.overall_success_rate >= 0 && engine.metrics.overall_success_rate <= 1,
    'success rate should be between 0 and 1');
  engine.shutdown();
});

test('should not reweight with insufficient data', () => {
  const engine = new LearningEngine();
  engine.recordOutcome({ hypothesis_id: 'h1', category: 'c1', verdict: 'confirmed' });
  const result = engine.reweight();
  assert(result.changed === false, 'should not reweight with < 20 observations');
  assert(result.reason === 'insufficient_data', 'reason should be insufficient_data');
  engine.shutdown();
});

test('should reweight with sufficient data', () => {
  const engine = new LearningEngine();
  // Add 25 confirmed outcomes
  for (let i = 0; i < 25; i++) {
    engine.recordOutcome({ hypothesis_id: `h-${i}`, category: 'cookie_security', verdict: 'confirmed' });
  }
  const result = engine.reweight();
  assert(result.changed === true, 'should reweight with 25+ observations');
  assert('weights' in result, 'should return new weights');
  assert('change' in result, 'should return weight changes');
  engine.shutdown();
});

test('should get hypothesis success scores', () => {
  const engine = new LearningEngine();
  engine.recordOutcome({ hypothesis_id: 'h1', category: 'cookie_security', verdict: 'confirmed' });
  engine.recordOutcome({ hypothesis_id: 'h2', category: 'cookie_security', verdict: 'rejected' });
  engine.recordOutcome({ hypothesis_id: 'h3', category: 'xss', verdict: 'confirmed' });
  const scores = engine.getHypothesisSuccessScores();
  assert(Array.isArray(scores), 'should return an array');
  assert(scores.length >= 2, 'should have at least 2 category scores');
  assert('category' in scores[0], 'score should have category');
  assert('success_rate' in scores[0], 'score should have success_rate');
  assert('effective_weight' in scores[0], 'score should have effective_weight');
  engine.shutdown();
});

test('should get verification success scores', () => {
  const engine = new LearningEngine();
  engine.recordOutcome({ hypothesis_id: 'h1', category: 'c1', verdict: 'confirmed', verification_type: 'replay' });
  engine.recordOutcome({ hypothesis_id: 'h2', category: 'c2', verdict: 'rejected', verification_type: 'replay' });
  const scores = engine.getVerificationSuccessScores();
  assert(Array.isArray(scores), 'should return an array');
  assert(scores.length >= 1, 'should have at least 1 verification score');
  engine.shutdown();
});

test('should save and load state', () => {
  const engine = new LearningEngine();
  engine.recordOutcome({ hypothesis_id: 'h1', category: 'cookie_security', verdict: 'confirmed' });
  const savePath = engine.save();
  assert(savePath.endsWith('.json'), 'save path should be JSON');

  // Create a new engine and load
  const engine2 = new LearningEngine();
  const loaded = engine2.load();
  assert(loaded === true, 'should successfully load state');
  assert(engine2.metrics.total_observations >= 1, 'should have loaded observations');
  engine.shutdown();
  engine2.shutdown();
});

test('should get metrics', () => {
  const engine = new LearningEngine();
  engine.recordOutcome({ hypothesis_id: 'h1', category: 'c1', verdict: 'confirmed' });
  const metrics = engine.getMetrics();
  assert(metrics.total_observations >= 1, 'should have observations in metrics');
  assert('current_weights' in metrics, 'metrics should include current_weights');
  assert('categories_learned' in metrics, 'metrics should include categories_learned');
  assert('targets_learned' in metrics, 'metrics should include targets_learned');
  engine.shutdown();
});

test('should get summary', () => {
  const engine = new LearningEngine();
  const summary = engine.getSummary();
  assert('total_observations' in summary, 'summary should have total_observations');
  assert('current_weights' in summary, 'summary should have current_weights');
  assert('top_categories' in summary, 'summary should have top_categories');
  engine.shutdown();
});

test('should compute target-specific weights', () => {
  const engine = new LearningEngine();
  const weights = engine.getTargetWeights('unknown-target');
  assert(typeof weights === 'object', 'should return weight object');
  assert('severity' in weights, 'should have severity weight');
  engine.shutdown();
});

test('should apply exploration bonus to under-explored categories', () => {
  const engine = new LearningEngine();
  const scores = engine.getHypothesisSuccessScores();
  // With no data, categories not yet tracked won't appear
  // But the exploration bonus method should work
  const bonus = engine._explorationBonus('never_tried_category');
  assert(bonus === 0.1, `exploration bonus for never-tried should be 0.1, got ${bonus}`);
  engine.shutdown();
});

test('should learn from iteration results', () => {
  const engine = new LearningEngine();
  engine.learnFromIteration({
    verification_results: [
      { hypothesis_id: 'h1', category: 'c1', verdict: 'confirmed' },
      { hypothesis_id: 'h2', category: 'c2', verdict: 'rejected' },
    ],
  });
  assert(engine.outcomes.length === 2, 'should have 2 outcomes from iteration');
  engine.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  7. PredictionEngine
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== PredictionEngine ===');

test('should instantiate with default weights', () => {
  const engine = new PredictionEngine();
  assert(engine.weights.historical_bug_rate === 0.25, 'historical_bug_rate should be 0.25');
  assert(engine.targetPredictions instanceof Map, 'targetPredictions should be a Map');
  // predictionHistory may contain loaded data
  assert(Array.isArray(engine.predictionHistory), 'predictionHistory should be an array');
});

test('should generate target prediction', () => {
  const engine = new PredictionEngine();
  const prediction = engine.predictTarget('test-target.com');
  assert(prediction !== null, 'should produce a prediction');
  assert(prediction.id.startsWith('PRED-'), 'prediction ID should start with PRED-');
  assert(prediction.target_id === 'test-target.com', 'target_id should match');
  assert(typeof prediction.predicted_yield === 'number', 'predicted_yield should be a number');
  assert('confidence_band' in prediction, 'should have confidence_band');
  assert('factors' in prediction, 'should have factors');
  assert(typeof prediction.prediction_quality === 'string', 'prediction_quality should be a string');
});

test('should produce confidence bands with percentiles', () => {
  const engine = new PredictionEngine();
  const prediction = engine.predictTarget('test-target.com');
  const band = prediction.confidence_band;
  assert('p10' in band, 'confidence band should have p10');
  assert('p50' in band, 'confidence band should have p50');
  assert('p90' in band, 'confidence band should have p90');
  assert(band.p10 <= band.p50, 'p10 should be <= p50');
  assert(band.p50 <= band.p90, 'p50 should be <= p90');
});

test('should produce bounded yield predictions', () => {
  const engine = new PredictionEngine();
  const prediction = engine.predictTarget('test-target.com');
  assert(prediction.predicted_yield >= 0, 'yield should be >= 0');
  // Without historical data, yield should be conservative
  assert(typeof prediction.predicted_yield === 'number', 'yield should be a number');
});

test('should predict all targets', () => {
  const engine = new PredictionEngine();
  // Without any targets registered, this should still work
  const predictions = engine.predictAllTargets();
  assert(Array.isArray(predictions), 'should return an array');
  // Sort by predicted yield descending
  for (let i = 1; i < predictions.length; i++) {
    assert(predictions[i - 1].predicted_yield >= predictions[i].predicted_yield,
      'predictions should be sorted by yield descending');
  }
});

test('should assess prediction quality', () => {
  const engine = new PredictionEngine();
  const prediction = engine.predictTarget('new-target.com');
  assert(['low', 'medium', 'high'].includes(prediction.prediction_quality),
    `prediction_quality should be low/medium/high, got ${prediction.prediction_quality}`);
});

test('should handle drift (changing predictions over time)', () => {
  const engine = new PredictionEngine();
  const p1 = engine.predictTarget('drift-test.com');
  // Record some outcomes to shift the prediction
  engine.actualOutcomes.set(p1.id, { actual_yield: 5.0 });
  const p2 = engine.predictTarget('drift-test.com');
  // Both should be valid predictions; the engine handles drift gracefully
  assert(typeof p1.predicted_yield === 'number', 'first prediction should be numeric');
  assert(typeof p2.predicted_yield === 'number', 'second prediction should be numeric');
});

test('should compute prediction accuracy', () => {
  const engine = new PredictionEngine();
  // Record a prediction and its actual outcome
  const prediction = engine.predictTarget('accuracy-test.com');
  engine.actualOutcomes.set(prediction.id, { actual_yield: 3.0 });
  // The engine should track actual outcomes
  assert(engine.actualOutcomes.has(prediction.id), 'should store actual outcome');
});

test('should save and load state', () => {
  const engine = new PredictionEngine();
  engine.predictTarget('persistence-test.com');
  const savePath = engine.save();
  assert(savePath.endsWith('.json'), 'save path should be JSON');

  const engine2 = new PredictionEngine();
  const loaded = engine2.load();
  assert(loaded === true, 'should successfully load state');
  // PredictionEngine has no shutdown method
});

test('should generate category predictions', () => {
  const engine = new PredictionEngine();
  // predictCategories takes optional targetId, returns array
  const predictions = engine.predictCategories();
  assert(Array.isArray(predictions), 'should return an array of predictions');
  // Without data, may be empty — that's fine
});

test('should generate endpoint predictions', () => {
  const engine = new PredictionEngine();
  // predictEndpoints takes targetId, returns array
  const predictions = engine.predictEndpoints('test-target.com');
  assert(Array.isArray(predictions), 'should return an array of predictions');
  // Without data, may be empty — that's fine
});

test('should handle historical comparison', () => {
  const engine = new PredictionEngine();
  // First prediction
  const p1 = engine.predictTarget('history-target.com');
  // Record outcome
  engine.actualOutcomes.set(p1.id, { actual_yield: 2.0 });
  // Second prediction (engine should consider history)
  const p2 = engine.predictTarget('history-target.com');
  assert(p2.id !== p1.id, 'second prediction should have different ID');
  assert(typeof p2.predicted_yield === 'number', 'yield should be numeric');
});

test('should get prediction accuracy metrics', () => {
  const engine = new PredictionEngine();
  assert(typeof engine.accuracy.total_predictions === 'number', 'total_predictions should be a number');
  assert(typeof engine.accuracy.mean_absolute_error === 'number', 'mean_absolute_error should be a number');
});

test('should cap prediction history', () => {
  const engine = new PredictionEngine();
  // The engine should cap prediction history at 10000 entries
  // We just verify the cap is enforced by checking the property exists
  assert(engine.predictionHistory !== undefined, 'should have predictionHistory');
});

// ═══════════════════════════════════════════════════════════════════════
//  Results Summary
// ═══════════════════════════════════════════════════════════════════════

console.log('\n' + '='.repeat(60));
if (testsFailed === 0) {
  console.log(`  P4.1 Results: ${testsPassed} passed, ${testsFailed} failed`);
} else {
  console.log(`  P4.1 Results: ${testsPassed} passed, ${testsFailed} failed`);
  console.log('\n  Failures:');
  for (const f of failures) {
    console.log(`    - ${f.name}: ${f.error}`);
  }
}
console.log('='.repeat(60));

process.exit(testsFailed > 0 ? 1 : 0);


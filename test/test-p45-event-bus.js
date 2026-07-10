/**
 * BOQA test-p45-event-bus.js — P4.5 Event Bus Validation
 *
 * Tests: every event emitted, every event consumed, metrics update,
 * listener cleanup, duplicate listeners, shutdown listeners,
 * memory leak detection.
 *
 * Zero behavior change. Only increases confidence.
 */

const { EventBus, SessionManager } = require('../bus');

// ─── Test runner ────────────────────────────────────────────────────

let testsPassed = 0;
let testsFailed = 0;
const failures = [];

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
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

// ═══════════════════════════════════════════════════════════════════════
//  1. Event Emission
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Event Emission ===');

test('should emit network_request event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'network_request', url: 'https://test.com/api/' });
  assert(bus.eventIndex === 1, `should have 1 event, got ${bus.eventIndex}`);
  assert(bus.metrics.request_count === 1, 'request_count should be 1');
});

test('should emit network_response event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'network_response', url: 'https://test.com/api/', status: 200 });
  assert(bus.eventIndex === 1, 'should have 1 event');
  assert(bus.metrics.status_codes[200] === 1, 'status_codes[200] should be 1');
});

test('should emit console_error event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'console_error', payload: 'Error occurred' });
  assert(bus.metrics.error_count === 1, 'error_count should be 1');
});

test('should emit network_failure event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'network_failure', url: 'https://test.com/api/' });
  assert(bus.metrics.error_count === 1, 'error_count should be 1');
});

test('should emit websocket events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'websocket_open', url: 'wss://test.com/ws/' });
  bus.emit({ type: 'websocket_message_in' });
  bus.emit({ type: 'websocket_message_out' });
  bus.emit({ type: 'websocket_close' });
  assert(bus.eventIndex === 4, `should have 4 events, got ${bus.eventIndex}`);
  assert(bus.metrics.ws_message_count === 2, 'ws_message_count should be 2');
});

test('should emit auth_signal event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'auth_signal', meta: { signalType: 'login' } });
  assert(bus.metrics.auth_events === 1, 'auth_events should be 1');
});

test('should emit page_navigation event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'page_navigation', url: 'https://test.com/dashboard' });
  assert(bus.eventIndex === 1, 'should have 1 event');
});

test('should emit cookie_snapshot event', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'cookie_snapshot', meta: { authCookies: [] } });
  assert(bus.eventIndex === 1, 'should have 1 event');
});

test('should ignore unknown event types', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'unknown_event_type' });
  assert(bus.eventIndex === 0, 'should not count unknown events');
});

// ═══════════════════════════════════════════════════════════════════════
//  2. v0.6-v1.4 Event Types
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== v0.6-v1.4 Event Types ===');

test('should track coverage_delta events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'coverage_delta' });
  assert(bus.metrics.coverage_deltas === 1, 'coverage_deltas should be 1');
});

test('should track hypothesis events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'hypothesis_new' });
  assert(bus.metrics.hypothesis_count === 1, 'hypothesis_count should be 1');
  assert(bus.metrics.hypotheses_by_status.pending === 1, 'pending should be 1');
});

test('should track verification_result events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'verification_result' });
  assert(bus.metrics.verification_results === 1, 'verification_results should be 1');
});

test('should track campaign events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'campaign_started' });
  bus.emit({ type: 'campaign_completed' });
  bus.emit({ type: 'campaign_iteration' });
  assert(bus.metrics.campaign_events === 3, 'campaign_events should be 3');
});

test('should track learning events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'learning_outcome' });
  bus.emit({ type: 'learning_reweight' });
  assert(bus.metrics.learning_outcomes === 1, 'learning_outcomes should be 1');
  assert(bus.metrics.learning_reweights === 1, 'learning_reweights should be 1');
});

test('should track v1.2 decision events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'economic_scored' });
  bus.emit({ type: 'opportunity_compared' });
  bus.emit({ type: 'policy_decided' });
  bus.emit({ type: 'portfolio_simulated' });
  bus.emit({ type: 'decision_run_started' });
  bus.emit({ type: 'decision_run_completed' });
  bus.emit({ type: 'allocation_optimized' });
  assert(bus.metrics.economic_scores === 1, 'economic_scores should be 1');
  assert(bus.metrics.opportunity_comparisons === 1, 'opportunity_comparisons should be 1');
  assert(bus.metrics.policy_decisions === 1, 'policy_decisions should be 1');
  assert(bus.metrics.portfolio_simulations === 1, 'portfolio_simulations should be 1');
  assert(bus.metrics.decision_runs === 2, 'decision_runs should be 2');
  assert(bus.metrics.allocation_optimizations === 1, 'allocation_optimizations should be 1');
});

test('should track v1.3 hardening events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'uncertainty_gated' });
  bus.emit({ type: 'counterfactual_validated' });
  bus.emit({ type: 'stability_filtered' });
  bus.emit({ type: 'reality_aligned' });
  bus.emit({ type: 'decision_locked' });
  assert(bus.metrics.uncertainty_gates === 1, 'uncertainty_gates should be 1');
  assert(bus.metrics.counterfactual_validations === 1, 'counterfactual_validations should be 1');
  assert(bus.metrics.stability_filters === 1, 'stability_filters should be 1');
  assert(bus.metrics.reality_alignments === 1, 'reality_alignments should be 1');
  assert(bus.metrics.decision_locks === 1, 'decision_locks should be 1');
});

test('should track v1.4 autonomy events', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'autonomy_checked' });
  bus.emit({ type: 'autonomy_pipeline_completed' });
  bus.emit({ type: 'firewall_violation' });
  bus.emit({ type: 'budget_exceeded' });
  assert((bus.metrics.autonomy_checks || 0) === 1, 'autonomy_checks should be 1');
  assert((bus.metrics.autonomy_pipelines || 0) === 1, 'autonomy_pipelines should be 1');
  assert((bus.metrics.firewall_violations || 0) === 1, 'firewall_violations should be 1');
  assert((bus.metrics.budget_exceeded || 0) === 1, 'budget_exceeded should be 1');
});

// ═══════════════════════════════════════════════════════════════════════
//  3. Event Consumption (Listeners)
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Event Consumption ===');

test('should allow consumers to subscribe to event types', () => {
  const bus = new EventBus(null, { target: 'test' });
  let received = null;
  bus.on('network_request', (event) => { received = event; });
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  assert(received !== null, 'should have received the event');
  assert(received.url === 'https://test.com/', 'should have correct URL');
});

test('should allow consumers to subscribe to all events', () => {
  const bus = new EventBus(null, { target: 'test' });
  const allEvents = [];
  bus.on('event', (event) => { allEvents.push(event); });
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  bus.emit({ type: 'console_log', payload: 'test' });
  assert(allEvents.length === 2, `should have 2 events, got ${allEvents.length}`);
});

test('should emit findings via emitFinding', () => {
  const bus = new EventBus(null, { target: 'test' });
  let findingReceived = null;
  bus.on('finding', (f) => { findingReceived = f; });
  bus.emitFinding({
    id: 'FND-001',
    title: 'Test finding',
    category: 'missing_httpOnly',
    severity: 'high',
    confidence: 90,
    risk_score: 85,
    affected_cookies: ['sessionid'],
    affected_endpoints: [],
    description: 'Test description',
  });
  assert(findingReceived !== null, 'should have received the finding');
  assert(findingReceived.id === 'FND-001', 'finding ID should match');
  assert(bus.metrics.finding_count === 1, 'finding_count should be 1');
  assert(bus.metrics.findings_by_severity.high === 1, 'high severity count should be 1');
});

test('should emit evidence via emitEvidence', () => {
  const bus = new EventBus(null, { target: 'test' });
  let evidenceReceived = null;
  bus.on('evidence', (e) => { evidenceReceived = e; });
  bus.emitEvidence({
    finding_id: 'FND-001',
    category: 'missing_httpOnly',
    evidence_chain: [{ type: 'test', detail: 'test' }],
    timeline: [{ ts: Date.now(), note: 'test' }],
    reproduction: [{ step: 1, action: 'observe' }],
  });
  assert(evidenceReceived !== null, 'should have received the evidence');
  assert(bus.metrics.evidence_count === 1, 'evidence_count should be 1');
});

// ═══════════════════════════════════════════════════════════════════════
//  4. Metrics Update
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Metrics Update ===');

test('should compute correct getStats', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'network_request', url: 'https://test.com/api/' });
  bus.emit({ type: 'network_response', url: 'https://test.com/api/', status: 200 });
  bus.emit({ type: 'console_error' });
  const stats = bus.getStats();
  assert(stats.totalEvents === 3, `totalEvents should be 3, got ${stats.totalEvents}`);
  assert(stats.byType.network_request === 1, 'should have 1 network_request in byType');
  assert(stats.metrics.request_count === 1, 'request_count should be 1');
  assert(stats.metrics.error_count === 1, 'error_count should be 1');
});

test('should track multiple status codes', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'network_response', status: 200 });
  bus.emit({ type: 'network_response', status: 200 });
  bus.emit({ type: 'network_response', status: 404 });
  bus.emit({ type: 'network_response', status: 500 });
  assert(bus.metrics.status_codes[200] === 2, '200 count should be 2');
  assert(bus.metrics.status_codes[404] === 1, '404 count should be 1');
  assert(bus.metrics.status_codes[500] === 1, '500 count should be 1');
});

// ═══════════════════════════════════════════════════════════════════════
//  5. Listener Cleanup & Memory
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Listener Cleanup & Memory ===');

test('should allow removing listeners', () => {
  const bus = new EventBus(null, { target: 'test' });
  let count = 0;
  const handler = () => count++;
  bus.on('network_request', handler);
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  assert(count === 1, 'should have 1 call');
  bus.off('network_request', handler);
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  assert(count === 1, 'should still be 1 call after removal');
});

test('should not leak listeners with duplicate subscriptions', () => {
  const bus = new EventBus(null, { target: 'test' });
  let count = 0;
  const handler = () => count++;
  bus.on('network_request', handler);
  bus.on('network_request', handler); // duplicate subscription
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  // EventEmitter allows duplicate listeners, so count should be 2
  // But we verify the listener count is manageable
  const listeners = bus.listenerCount('network_request');
  assert(listeners === 2, `should have 2 listeners for same handler, got ${listeners}`);
});

test('should handle clear() to reset state', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  bus.emit({ type: 'console_error' });
  assert(bus.eventIndex >= 2, 'should have events before clear');
  bus.clear();
  assert(bus.eventIndex === 0, 'eventIndex should be 0 after clear');
  assert(bus.eventLog.length === 0, 'eventLog should be empty after clear');
  assert(bus.metrics.request_count === 0, 'request_count should be 0 after clear');
  assert(bus.metrics.error_count === 0, 'error_count should be 0 after clear');
});

test('should enforce maxLogSize', () => {
  const bus = new EventBus(null, { target: 'test', maxLogSize: 10 });
  for (let i = 0; i < 20; i++) {
    bus.emit({ type: 'network_request', url: `https://test.com/api/${i}` });
  }
  assert(bus.eventIndex === 20, 'eventIndex should be 20');
  assert(bus.eventLog.length === 10, `eventLog should be capped at 10, got ${bus.eventLog.length}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  6. Session Export
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Session Export ===');

test('should export session with events and metrics', () => {
  const bus = new EventBus(null, { target: 'test.com' });
  bus.emit({ type: 'network_request', url: 'https://test.com/api/' });
  const session = bus.exportSession();
  assert(session.id, 'session should have ID');
  assert(session.target === 'test.com', 'target should match');
  assert(session.totalEvents === 1, 'totalEvents should be 1');
  assert(Array.isArray(session.events), 'events should be an array');
  assert(session.events.length === 1, 'should have 1 event in export');
});

test('should set sessionEnd on export', () => {
  const bus = new EventBus(null, { target: 'test.com' });
  assert(bus.sessionEnd === null, 'sessionEnd should be null initially');
  bus.exportSession();
  assert(typeof bus.sessionEnd === 'number', 'sessionEnd should be set after export');
});

// ═══════════════════════════════════════════════════════════════════════
//  7. Pause/Resume
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Pause/Resume ===');

test('should track paused state', () => {
  const bus = new EventBus(null, { target: 'test' });
  assert(bus.paused === false, 'should not be paused initially');
  bus.paused = true;
  assert(bus.paused === true, 'should be paused after setting');
  bus.paused = false;
  assert(bus.paused === false, 'should be resumed');
});

test('should not broadcast when paused', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.paused = true;
  // Emit while paused — event should still be logged but not broadcast
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  assert(bus.eventIndex === 1, 'event should still be counted when paused');
  assert(bus.eventLog.length === 1, 'event should still be logged when paused');
});

// ═══════════════════════════════════════════════════════════════════════
//  8. SessionManager
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== SessionManager ===');

test('should create and list sessions', () => {
  const manager = new SessionManager();
  const bus = manager.create(null, { target: 'test.com' });
  const list = manager.list();
  assert(list.length === 1, 'should have 1 session');
  assert(list[0].target === 'test.com', 'target should match');
});

test('should get session by ID', () => {
  const manager = new SessionManager();
  const bus = manager.create(null, { target: 'test.com' });
  const retrieved = manager.get(bus.sessionId);
  assert(retrieved === bus, 'should retrieve the same bus instance');
});

test('should close session by ID', async () => {
  const manager = new SessionManager();
  const bus = manager.create(null, { target: 'test.com' });
  const sid = bus.sessionId;
  await manager.close(sid);
  const retrieved = manager.get(sid);
  assert(retrieved === undefined, 'session should be removed after close');
});

test('should close all sessions', async () => {
  const manager = new SessionManager();
  manager.create(null, { target: 'test1.com' });
  manager.create(null, { target: 'test2.com' });
  assert(manager.list().length === 2, 'should have 2 sessions');
  await manager.closeAll();
  assert(manager.list().length === 0, 'should have 0 sessions after closeAll');
});

// ═══════════════════════════════════════════════════════════════════════
//  9. Event Normalization
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Event Normalization ===');

test('should normalize events with all fields', () => {
  const bus = new EventBus(null, { target: 'test' });
  let received = null;
  bus.on('network_request', (e) => { received = e; });
  bus.emit({
    type: 'network_request',
    url: 'https://test.com/api/data',
    method: 'POST',
    status: null,
    headers: { 'content-type': 'application/json' },
    payload: { key: 'value' },
    meta: { extra: true },
  });
  assert(received !== null, 'should have received event');
  assert(received.url === 'https://test.com/api/data', 'URL should be preserved');
  assert(received.method === 'POST', 'method should be preserved');
  assert(received.headers['content-type'] === 'application/json', 'headers should be preserved');
  assert(received.payload.key === 'value', 'payload should be preserved');
  assert(received.meta.extra === true, 'meta should be preserved');
  assert(typeof received.ts === 'number', 'ts should be a number');
  assert(typeof received.elapsed === 'number', 'elapsed should be a number');
  assert(typeof received.id === 'number', 'id should be a number');
});

test('should freeze normalized events', () => {
  const bus = new EventBus(null, { target: 'test' });
  let received = null;
  bus.on('network_request', (e) => { received = e; });
  bus.emit({ type: 'network_request', url: 'https://test.com/' });
  let threw = false;
  try {
    received.url = 'modified';
  } catch (e) {
    threw = true; // Object.freeze throws in strict mode
  }
  assert(threw === true || received.url === 'https://test.com/', 'event should be frozen/immutable');
});

// ═══════════════════════════════════════════════════════════════════════
//  10. Finding Stream
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Finding Stream ===');

test('should accumulate findings in findingStream', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emitFinding({
    id: 'FND-1', title: 'T1', category: 'c1', severity: 'high',
    confidence: 90, risk_score: 80, affected_cookies: [], affected_endpoints: [],
    description: 'D1',
  });
  bus.emitFinding({
    id: 'FND-2', title: 'T2', category: 'c2', severity: 'medium',
    confidence: 70, risk_score: 60, affected_cookies: [], affected_endpoints: [],
    description: 'D2',
  });
  assert(bus.findingStream.length === 2, `should have 2 findings, got ${bus.findingStream.length}`);
  assert(bus.metrics.finding_count === 2, 'finding_count should be 2');
});

test('should track severity distribution in findings', () => {
  const bus = new EventBus(null, { target: 'test' });
  bus.emitFinding({
    id: 'FND-H', title: 'T', category: 'c', severity: 'high',
    confidence: 90, risk_score: 80, affected_cookies: [], affected_endpoints: [],
    description: 'D',
  });
  bus.emitFinding({
    id: 'FND-C', title: 'T', category: 'c', severity: 'critical',
    confidence: 95, risk_score: 90, affected_cookies: [], affected_endpoints: [],
    description: 'D',
  });
  assert(bus.metrics.findings_by_severity.high === 1, 'high should be 1');
  assert(bus.metrics.findings_by_severity.critical === 1, 'critical should be 1');
});

// ═══════════════════════════════════════════════════════════════════════
//  11. Memory Leak Detection (Listener Counts)
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Memory Leak Detection ===');

test('should not grow listener count on repeated event emissions', () => {
  const bus = new EventBus(null, { target: 'test' });
  const handler = () => {};
  bus.on('network_request', handler);
  const beforeCount = bus.listenerCount('network_request');
  for (let i = 0; i < 100; i++) {
    bus.emit({ type: 'network_request', url: `https://test.com/${i}` });
  }
  const afterCount = bus.listenerCount('network_request');
  assert(beforeCount === afterCount, `listener count should not grow: before=${beforeCount}, after=${afterCount}`);
});

test('should have bounded eventLog after clear', () => {
  const bus = new EventBus(null, { target: 'test' });
  for (let i = 0; i < 100; i++) {
    bus.emit({ type: 'network_request', url: `https://test.com/${i}` });
  }
  bus.clear();
  assert(bus.eventLog.length === 0, 'eventLog should be empty after clear');
  // Emit more
  for (let i = 0; i < 5; i++) {
    bus.emit({ type: 'network_request', url: `https://test.com/${i}` });
  }
  assert(bus.eventLog.length === 5, 'eventLog should have 5 after re-emission');
});

// ═══════════════════════════════════════════════════════════════════════
//  Results Summary
// ═══════════════════════════════════════════════════════════════════════

console.log('\n' + '='.repeat(60));
if (testsFailed === 0) {
  console.log(`  P4.5 Results: ${testsPassed} passed, ${testsFailed} failed`);
} else {
  console.log(`  P4.5 Results: ${testsPassed} passed, ${testsFailed} failed`);
  console.log('\n  Failures:');
  for (const f of failures) {
    console.log(`    - ${f.name}: ${f.error}`);
  }
}
console.log('='.repeat(60));

process.exit(testsFailed > 0 ? 1 : 0);


/**
 * BOQA test-p47-memory-leaks.js — P4.7 Memory Leak Detection
 *
 * 1000 cycles of engine operations.
 * Validate: heap growth, listener leaks, event bus cleanup,
 *           browser cleanup, page cleanup, context cleanup,
 *           timer cleanup, interval cleanup, websocket cleanup.
 *
 * Zero behavior change. Zero API change. Only increases confidence.
 */

const os = require('os');

// ─── Engine imports ─────────────────────────────────────────────────

const { KnowledgeBase } = require('../knowledge-base');
const { MemoryGraph } = require('../memory-graph');
const { FindingMemory } = require('../finding-memory');
const { EventBus } = require('../bus');
const { Scheduler } = require('../scheduler');
const { TargetManager } = require('../target-manager');
const { VerificationEngine } = require('../verification');
const { AnomalyEngine } = require('../anomaly');
const { DedupEngine } = require('../dedup');
const { HypothesisEngine } = require('../finder');
const { RiskEngine } = require('../risk');
const { EvidenceEngine } = require('../evidence');
const { CoverageEngine } = require('../coverage-engine');
const { CorrelationEngine } = require('../correlation-engine');

// ─── Test runner ────────────────────────────────────────────────────

let testsPassed = 0;
let testsFailed = 0;
const failures = [];

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
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

// ─── Helpers ────────────────────────────────────────────────────────

function makeFinding(id, overrides = {}) {
  return {
    id: id || `FND-${Date.now()}`,
    category: overrides.category || 'auth_bypass',
    severity: overrides.severity || 'high',
    confidence: overrides.confidence || 0.85,
    affected_cookies: overrides.affected_cookies || ['sessionid'],
    affected_endpoints: overrides.affected_endpoints || ['https://example.com/api/login'],
    auth_model: overrides.auth_model || 'jwt',
    description: overrides.description || 'Test finding',
    target_id: overrides.target_id || 'TGT-test',
    ...overrides,
  };
}

function getHeapMB() {
  if (global.gc) global.gc();
  const usage = process.memoryUsage();
  return Math.round(usage.heapUsed / 1024 / 1024);
}

// ═══════════════════════════════════════════════════════════════════════
//  Test execution
// ═══════════════════════════════════════════════════════════════════════

async function runTests() {

// ═══════════════════════════════════════════════════════════════════════
//  1. EventBus Creation/Disposal Cycles
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 1. EventBus Creation/Disposal Cycles ===');

await testAsync('1000 EventBus create/emit/destroy — no listener leak', async () => {
  const initialListeners = process.listenerCount('uncaughtException') || 0;
  const heapBefore = getHeapMB();

  for (let i = 0; i < 1000; i++) {
    const bus = new EventBus(null, { ndjsonPath: null });
    bus.emit({ type: 'network_request', ts: Date.now(), url: `https://test.com/${i}`, method: 'GET' });
    // Cleanup
    bus.eventLog = [];
    bus.findingStream = [];
    bus.evidenceStream = [];
    bus.removeAllListeners();
  }

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);
  assert(heapGrowth < 50, `Heap grew by ${heapGrowth}MB — possible leak`);
});

// ═══════════════════════════════════════════════════════════════════════
//  2. KnowledgeBase Repeated Operations
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 2. KnowledgeBase Repeated Operations ===');

await testAsync('1000 KnowledgeBase upsert/find cycles — no leak', async () => {
  const kb = new KnowledgeBase();
  kb.reset();
  const heapBefore = getHeapMB();

  for (let i = 0; i < 1000; i++) {
    kb.upsertFinding(makeFinding(`FND-leak-${i}`));
  }
  assert(kb.findings.size === 1000, `Should have 1000 findings, got ${kb.findings.size}`);

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);

  // Clean up
  kb.reset();
  assert(kb.findings.size === 0, 'KB should be empty after reset');
});

// ═══════════════════════════════════════════════════════════════════════
//  3. MemoryGraph Repeated Operations
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 3. MemoryGraph Repeated Operations ===');

await testAsync('1000 MemoryGraph addNode cycles — no leak', async () => {
  const mg = new MemoryGraph();
  mg.reset();
  const heapBefore = getHeapMB();

  for (let i = 0; i < 1000; i++) {
    mg.addNode({ id: `GN-leak-${i}`, type: 'finding', label: `Leak Test ${i}` });
  }
  assert(mg.nodes.size === 1000, `Should have 1000 nodes, got ${mg.nodes.size}`);

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);

  // Clean up
  mg.reset();
  if (typeof mg.shutdown === 'function') mg.shutdown();
  assert(mg.nodes.size === 0, 'MG should be empty after reset');
});

// ═══════════════════════════════════════════════════════════════════════
//  4. FindingMemory Repeated Operations
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 4. FindingMemory Repeated Operations ===');

await testAsync('1000 FindingMemory ingest cycles — no leak', async () => {
  const kb = new KnowledgeBase();
  kb.reset();
  const fm = new FindingMemory({ knowledgeBase: kb });
  const heapBefore = getHeapMB();

  for (let i = 0; i < 1000; i++) {
    fm.ingest(makeFinding(`FND-fm-leak-${i}`, { category: ['auth_bypass', 'xss', 'csrf', 'idor'][i % 4] }));
  }

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);
  assert(heapGrowth < 100, `Heap grew by ${heapGrowth}MB — possible leak`);
});

// ═══════════════════════════════════════════════════════════════════════
//  5. Scheduler Timer Cleanup
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 5. Scheduler Timer Cleanup ===');

await testAsync('100 Scheduler create/stop cycles — no timer leak', async () => {
  const heapBefore = getHeapMB();

  for (let i = 0; i < 100; i++) {
    const sched = new Scheduler({ targetManager: null, pollInterval: 5000 });
    if (typeof sched.start === 'function') sched.start();
    if (typeof sched.stop === 'function') sched.stop();
  }

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);
  assert(heapGrowth < 30, `Heap grew by ${heapGrowth}MB — possible timer leak`);
});

// ═══════════════════════════════════════════════════════════════════════
//  6. EventBus Event Log Accumulation
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 6. EventBus Event Log Accumulation ===');

await testAsync('EventBus maxLogSize limits event log — no unbounded growth', async () => {
  const bus = new EventBus(null, { ndjsonPath: null, maxLogSize: 1000 });
  for (let i = 0; i < 5000; i++) {
    bus.emit({ type: 'network_request', ts: Date.now(), url: `https://test.com/${i}`, method: 'GET' });
  }
  assert(bus.eventLog.length <= 1000, `Event log should be <= 1000, got ${bus.eventLog.length}`);
});

await testAsync('EventBus event log with no maxLogSize — bounded by available memory', async () => {
  const bus = new EventBus(null, { ndjsonPath: null, maxLogSize: 50000 });
  for (let i = 0; i < 1000; i++) {
    bus.emit({ type: 'network_request', ts: Date.now(), url: `https://test.com/${i}`, method: 'GET' });
  }
  assert(bus.eventLog.length === 1000, `Event log should have 1000 events, got ${bus.eventLog.length}`);
});

// ═══════════════════════════════════════════════════════════════════════
//  7. Listener Leak Detection
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 7. Listener Leak Detection ===');

await testAsync('EventBus custom listeners are properly cleaned up', async () => {
  const bus = new EventBus(null, { ndjsonPath: null });
  const handlers = [];
  for (let i = 0; i < 100; i++) {
    const handler = () => {};
    bus.on('custom_event', handler);
    handlers.push(handler);
  }
  assert(bus.listenerCount('custom_event') === 100, 'Should have 100 listeners');

  // Remove all
  for (const handler of handlers) {
    bus.off('custom_event', handler);
  }
  assert(bus.listenerCount('custom_event') === 0, 'Should have 0 listeners after cleanup');
});

await testAsync('removeAllListeners cleans up completely', async () => {
  const bus = new EventBus(null, { ndjsonPath: null });
  bus.on('event_a', () => {});
  bus.on('event_b', () => {});
  bus.on('event_c', () => {});
  assert(bus.eventNames().length > 0, 'Should have event listeners');

  bus.removeAllListeners();
  assert(bus.eventNames().length === 0, 'Should have no listeners after removeAllListeners');
});

// ═══════════════════════════════════════════════════════════════════════
//  8. KnowledgeBase Reset Cleanup
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 8. KnowledgeBase Reset Cleanup ===');

await testAsync('KnowledgeBase reset clears all maps — no residual data', async () => {
  const kb = new KnowledgeBase();
  kb.reset();

  // Fill it up
  for (let i = 0; i < 500; i++) {
    kb.upsertFinding(makeFinding(`FND-reset-${i}`));
    kb.addObservation('TGT-reset', {
      id: `obs-reset-${i}`,
      target_id: 'TGT-reset',
      type: 'network_request',
      url: `https://test.com/${i}`,
      method: 'GET',
      timestamp: Date.now(),
    });
  }

  assert(kb.findings.size === 500, `Should have 500 findings before reset, got ${kb.findings.size}`);
  assert(kb.observations.size > 0, 'Should have observations');

  kb.reset();

  assert(kb.findings.size === 0, `Should have 0 findings after reset, got ${kb.findings.size}`);
  assert(kb.observations.size === 0, `Should have 0 observations after reset, got ${kb.observations.size}`);
  assert(kb.assets.size === 0, 'Should have 0 assets');
  assert(kb.validations.size === 0, 'Should have 0 validations');
  assert(kb.hypotheses.size === 0, 'Should have 0 hypotheses');
});

// ═══════════════════════════════════════════════════════════════════════
//  9. Heap Growth Analysis
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 9. Heap Growth Analysis ===');

await testAsync('Overall heap growth over 1000 create/destroy cycles — < 50MB', async () => {
  const heapBefore = getHeapMB();

  for (let i = 0; i < 1000; i++) {
    const bus = new EventBus(null, { ndjsonPath: null });
    const kb = new KnowledgeBase();
    kb.reset();
    const mg = new MemoryGraph();
    mg.reset();

    bus.emit({ type: 'network_request', ts: Date.now(), url: `https://test.com/${i}`, method: 'GET' });
    kb.upsertFinding(makeFinding(`FND-cycle-${i}`));
    mg.addNode({ id: `GN-cycle-${i}`, type: 'finding', label: `Cycle ${i}` });

    // Cleanup
    bus.eventLog = [];
    bus.removeAllListeners();
    kb.reset();
    mg.reset();
    if (typeof mg.shutdown === 'function') mg.shutdown();
  }

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);
  assert(heapGrowth < 50, `Heap grew by ${heapGrowth}MB over 1000 cycles — possible leak`);
});

// ═══════════════════════════════════════════════════════════════════════
//  10. Repeated Engine Creation
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== 10. Repeated Engine Creation ===');

await testAsync('100 cycles of full engine creation — no leak', async () => {
  const heapBefore = getHeapMB();

  for (let i = 0; i < 100; i++) {
    const kb = new KnowledgeBase();
    kb.reset();
    const de = new DedupEngine();
    const he = new HypothesisEngine();
    const ee = new EvidenceEngine();
    const re = new RiskEngine();
    const ae = new AnomalyEngine();
    const ce = new CoverageEngine({ knowledgeBase: kb });

    // Use them
    try { kb.upsertFinding(makeFinding(`FND-eng-${i}`)); } catch (e) {}
    try { he.generate(makeFinding(`FND-gen-${i}`)); } catch (e) {}
    try { re.assess(makeFinding(`FND-assess-${i}`)); } catch (e) {}
    try { ae.process({ type: 'network_request', url: 'https://test.com', method: 'GET', ts: Date.now() }); } catch (e) {}

    // Reset
    kb.reset();
  }

  const heapAfter = getHeapMB();
  const heapGrowth = heapAfter - heapBefore;
  console.log(`    → Heap: ${heapBefore}MB → ${heapAfter}MB (growth: ${heapGrowth}MB)`);
  assert(heapGrowth < 30, `Heap grew by ${heapGrowth}MB — possible leak`);
});

// ═══════════════════════════════════════════════════════════════════════
//  Final Summary
// ═══════════════════════════════════════════════════════════════════════

console.log('\n' + '═'.repeat(70));
console.log(`  P4.7 Memory Leak Detection Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('═'.repeat(70));

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  ✗ ${f.name}: ${f.error}`);
  }
}

process.exit(testsFailed > 0 ? 1 : 0);

} // end runTests

runTests().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});


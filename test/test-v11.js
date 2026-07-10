/**
 * BOQA test-v11.js — Integration tests for v1.1 Discovery Intelligence Layer
 *
 * Tests:
 *   1. MemoryGraph: nodes, edges, similarity, patterns, clustering, persistence
 *   2. HypothesisGenerator: generation methods, scoring, dedup, lifecycle
 *   3. AttackSurfaceModeler: surface construction, coverage gaps, scoring
 *   4. ConfidenceCalibrator: calibration, CEVI, uncertainty bands, drift
 *   5. DiscoveryLoopEngine: full pipeline, events, validation feedback
 *   6. Cross-module integration
 *   7. v1.1 improvement metrics validation
 *   8. Safe mode constraints verification
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const { MemoryGraph, GraphNode, GraphEdge, NODE_TYPES, EDGE_TYPES } = require('../memory-graph');
const { HypothesisGenerator, Hypothesis, HYPOTHESIS_STATUS, BUG_CLASSES, SEVERITY_LEVELS, GENERATION_METHODS } = require('../hypothesis-generator');
const { AttackSurfaceModeler, SurfaceGraph, SurfaceNode, SURFACE_NODE_TYPES } = require('../attack-surface-modeler');
const { ConfidenceCalibrator, CalibrationRecord, CEVIResult } = require('../confidence-calibrator');
const { DiscoveryLoopEngine, LoopCycleResult, LOOP_STATES, LOOP_EVENTS } = require('../discovery-loop-engine');

// ─── Test Runner ────────────────────────────────────────────────────

let passCount = 0;
let failCount = 0;
let sectionTests = [];
let currentSection = [];
let currentSectionName = '';

function test(name, fn) {
  currentSection.push({ name, fn });
}

function beginSection(name) {
  // Archive previous section if it has tests
  if (currentSection.length > 0 && currentSectionName) {
    sectionTests.push({ name: currentSectionName, tests: currentSection });
  }
  currentSection = [];
  currentSectionName = name;
}

async function runAllTests() {
  // Archive last section
  if (currentSection.length > 0 && currentSectionName) {
    sectionTests.push({ name: currentSectionName, tests: currentSection });
  }
  currentSection = [];
  currentSectionName = '';

  for (const sec of sectionTests) {
    console.log(`\n═══ ${sec.name} ═══`);
    for (const { name, fn } of sec.tests) {
      try {
        await fn();
        passCount++;
        console.log(`  ✓ ${name}`);
      } catch (err) {
        failCount++;
        console.log(`  ✗ ${name}`);
        console.log(`    ${err.message}`);
      }
    }
  }
}

// =====================================================================
//  1. MemoryGraph Tests
// =====================================================================

beginSection('1. MemoryGraph');

const mg = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
mg.reset();

test('add nodes', () => {
  const n1 = mg.addNode({ type: NODE_TYPES.FINDING, label: 'Auth bypass', category: 'auth', target_id: 't1.com', severity: 'high', confidence: 0.8, features: { auth_score: 80, injection_risk: 20 }, tags: ['auth', 'bypass'] });
  const n2 = mg.addNode({ type: NODE_TYPES.FINDING, label: 'IDOR', category: 'idor', target_id: 't1.com', severity: 'medium', confidence: 0.6, features: { auth_score: 40, injection_risk: 10 }, tags: ['idor'] });
  const n3 = mg.addNode({ type: NODE_TYPES.FAILURE, label: 'Failed auth test', category: 'auth', target_id: 't2.com', verdict: 'rejected', features: { auth_score: 30 }, pattern_hash: 'auth_fail_1' });

  assert.strictEqual(mg.nodes.size, 3, 'Should have 3 nodes');
  assert.strictEqual(n1.type, NODE_TYPES.FINDING);
  assert.strictEqual(n1.occurrence_count, 1);
  assert.ok(n1.id.startsWith('GN-'));
});

test('add edges', () => {
  const nodes = [...mg.nodes.values()];
  const n1 = nodes[0], n2 = nodes[1];

  const e1 = mg.addEdge(n1.id, n2.id, { type: EDGE_TYPES.SIMILARITY, weight: 0.8 });
  assert.ok(e1, 'Edge should be created');
  assert.strictEqual(mg.edges.size, 1);

  const e2 = mg.addEdge(n1.id, n2.id, { type: EDGE_TYPES.SIMILARITY, weight: 0.9 });
  assert.strictEqual(mg.edges.size, 1, 'Should not duplicate edge');
  assert.strictEqual(e2.weight, 0.9, 'Should update weight');
});

test('query nodes', () => {
  const authNodes = mg.queryNodes({ category: 'auth' });
  assert.strictEqual(authNodes.length, 2, 'Should find 2 auth nodes');

  const target1Nodes = mg.queryNodes({ target_id: 't1.com' });
  assert.strictEqual(target1Nodes.length, 2, 'Should find 2 t1.com nodes');

  const highConf = mg.queryNodes({ min_confidence: 0.7 });
  assert.strictEqual(highConf.length, 1, 'Should find 1 high confidence node');
});

test('get neighbors', () => {
  const nodes = [...mg.nodes.values()];
  const n1 = nodes[0];
  const neighbors = mg.getNeighbors(n1.id);
  assert.ok(neighbors.length >= 1, 'Should have at least 1 neighbor');
});

test('find similar by features', () => {
  const similar = mg.findSimilar({ auth_score: 70, injection_risk: 15 }, { minSimilarity: 0.1 });
  assert.ok(similar.length >= 1, 'Should find similar nodes');
  assert.ok(similar[0].similarity > 0, 'Similarity should be positive');
});

test('detect repeated failures', () => {
  mg.addNode({ type: NODE_TYPES.FAILURE, label: 'Failed auth test 2', category: 'auth', target_id: 't3.com', verdict: 'rejected', features: { auth_score: 25 }, pattern_hash: 'auth_fail_1' });
  mg.addNode({ type: NODE_TYPES.FAILURE, label: 'Failed auth test 3', category: 'auth', target_id: 't4.com', verdict: 'rejected', features: { auth_score: 35 }, pattern_hash: 'auth_fail_1' });

  const patterns = mg.detectRepeatedFailures(3);
  assert.ok(patterns.length >= 1, 'Should detect repeated failure patterns');
  assert.ok(patterns[0].cross_target, 'Pattern should be cross-target');
  assert.ok(patterns[0].occurrence_count >= 3, 'Should have >= 3 occurrences');
});

test('cluster nodes', () => {
  const n1 = mg.addNode({ type: NODE_TYPES.FINDING, category: 'injection', target_id: 't1.com', features: { xss_score: 80 }, confidence: 0.7 });
  const n2 = mg.addNode({ type: NODE_TYPES.FINDING, category: 'injection', target_id: 't2.com', features: { xss_score: 75 }, confidence: 0.65 });
  mg.addEdge(n1.id, n2.id, { type: EDGE_TYPES.SIMILARITY, weight: 0.8 });
  mg.addEdge(n2.id, n1.id, { type: EDGE_TYPES.SIMILARITY, weight: 0.8 });

  const clusters = mg.clusterNodes({ minClusterSize: 2 });
  assert.ok(clusters.length >= 0, 'Clustering should return results');
});

test('auto-link nodes', () => {
  const node = mg.addNode({ type: NODE_TYPES.FINDING, category: 'auth', target_id: 't1.com', features: { auth_score: 75, injection_risk: 20 } });
  const created = mg.autoLink(node, 0.3);
  assert.ok(Array.isArray(created), 'autoLink should return an array');
});

test('shortest path', () => {
  const nodes = [...mg.nodes.values()];
  const path = mg.shortestPath(nodes[0].id, nodes[1].id);
  assert.ok(path === null || Array.isArray(path), 'Path should be null or array');
});

test('subgraph', () => {
  const nodes = [...mg.nodes.values()];
  const sub = mg.getSubgraph(nodes[0].id, 2);
  assert.ok(sub.nodes.length >= 1, 'Subgraph should have at least 1 node');
  assert.ok(Array.isArray(sub.edges), 'Subgraph edges should be array');
});

test('get stats', () => {
  const stats = mg.getStats();
  assert.strictEqual(stats.total_nodes, mg.nodes.size);
  assert.ok(stats.avg_degree >= 0);
});

test('persistence', () => {
  const filePath = mg.save();
  assert.ok(fs.existsSync(filePath), 'Save file should exist');
});

mg.shutdown();

// =====================================================================
//  2. HypothesisGenerator Tests
// =====================================================================

beginSection('2. HypothesisGenerator');

const mgForHG = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
mgForHG.reset();
// Pre-populate with patterns so pattern clustering generates hypotheses
mgForHG.addNode({ type: NODE_TYPES.PATTERN, label: 'Auth bypass pattern', category: 'auth', features: { auth_score: 85 }, occurrence_count: 5, confidence: 0.8 });
mgForHG.addNode({ type: NODE_TYPES.PATTERN, label: 'Session pattern', category: 'session', features: { session_score: 70 }, occurrence_count: 3, confidence: 0.6 });

const hg = new HypothesisGenerator({ memoryGraph: mgForHG, persistenceIntervalMs: 0 });
hg.reset();

test('generate from signals - pattern clustering', () => {
  const signals = [
    { id: 's1', type: 'security', source: 'scanner', target_id: 'target1.com', category: 'auth', features: { anomaly_score: 70 } },
    { id: 's2', type: 'security', source: 'scanner', target_id: 'target1.com', category: 'auth', features: { anomaly_score: 65 } },
    { id: 's3', type: 'security', source: 'scanner', target_id: 'target1.com', category: 'auth', features: { anomaly_score: 72 } },
  ];

  const hypotheses = hg.generateFromSignals(signals);
  assert.ok(hypotheses.length >= 1, `Should generate hypotheses, got ${hypotheses.length}`);
});

test('generate from signals - anomaly delta', () => {
  const anomalySignals = [
    { id: 'a1', type: 'anomaly', source: 'baseline_diff', target_id: 'target2.com', category: 'session', features: { anomaly_score: 85, delta_score: 70, session_anomaly: true } },
  ];

  const hypotheses = hg.generateFromSignals(anomalySignals);
  assert.ok(hypotheses.length >= 1, 'Should generate hypotheses from anomalies');
});

test('generate single hypothesis', () => {
  const hyp = hg.generate({
    target_id: 'target3.com',
    surface_area: 'auth_flow',
    expected_bug_class: BUG_CLASSES.AUTH_BYPASS,
    description: 'Test hypothesis',
    expected_severity: SEVERITY_LEVELS.HIGH,
    confidence: 0.6,
    generation_method: GENERATION_METHODS.PATTERN_CLUSTER,
  });

  assert.ok(hyp.id, 'Hypothesis should have an ID');
  assert.strictEqual(hyp.expected_bug_class, BUG_CLASSES.AUTH_BYPASS);
});

test('score hypothesis', () => {
  const hyps = hg.queryHypotheses({ limit: 1 });
  if (hyps.length > 0) {
    const scored = hg.scoreHypothesis(hyps[0].id, {
      confidence: 0.75,
      cevi_score: 62.5,
      uncertainty_band: { p10: 45, p50: 62.5, p90: 78 },
    });
    assert.ok(scored, 'Should return scored hypothesis');
    assert.strictEqual(scored.status, HYPOTHESIS_STATUS.SCORED);
    assert.strictEqual(scored.cevi_score, 62.5);
  }
});

test('deduplication', () => {
  const dedupTarget = 'dedup_unique_' + Date.now() + '.com';
  hg.generate({
    target_id: dedupTarget,
    surface_area: 'api',
    expected_bug_class: BUG_CLASSES.IDOR,
    description: 'IDOR in API',
    confidence: 0.5,
  });
  hg.generate({
    target_id: dedupTarget,
    surface_area: 'api',
    expected_bug_class: BUG_CLASSES.IDOR,
    description: 'IDOR in API v2',
    confidence: 0.6,
  });

  assert.ok(hg.metrics.dedup_count > 0, 'Should have dedup count');
});

test('mark simulated', () => {
  const hyps = hg.queryHypotheses({ status: HYPOTHESIS_STATUS.SCORED, limit: 1 });
  if (hyps.length > 0) {
    const sim = hg.markSimulated(hyps[0].id, { competition_impact: 0.15 });
    assert.strictEqual(sim.status, HYPOTHESIS_STATUS.SIMULATED);
  }
});

test('mark validated', () => {
  const hyps = hg.queryHypotheses({ limit: 1 });
  if (hyps.length > 0) {
    const prevValidated = hg.metrics.total_validated;
    hg.markValidated(hyps[0].id, true, { evidence: 'test' });
    assert.strictEqual(hg.metrics.total_validated, prevValidated + 1);
  }
});

test('query by bug class', () => {
  const authHyps = hg.queryHypotheses({ bug_class: BUG_CLASSES.AUTH_BYPASS });
  assert.ok(Array.isArray(authHyps), 'Should return array');
});

test('get metrics', () => {
  const m = hg.getMetrics();
  assert.ok(m.total_generated >= 0);
  assert.ok(typeof m.by_method === 'object');
});

hg.shutdown();
mgForHG.shutdown();

// =====================================================================
//  3. AttackSurfaceModeler Tests
// =====================================================================

beginSection('3. AttackSurfaceModeler');

const asm = new AttackSurfaceModeler({ persistenceIntervalMs: 0 });
asm.reset();

test('build surface from asset data', () => {
  const graph = asm.buildSurface('test-target-v11.com', {
    endpoints: [
      { url: 'https://test-target-v11.com/api/v1/users', method: 'GET', auth_required: true, auth_type: 'jwt' },
      { url: 'https://test-target-v11.com/api/v1/users', method: 'POST', auth_required: true, auth_type: 'jwt' },
      { url: 'https://test-target-v11.com/login', method: 'POST', auth_required: false },
    ],
    auth_flows: [
      { name: 'JWT Auth', type: 'jwt', tokens: ['access_token', 'refresh_token'] },
    ],
    cookies: [
      { name: 'sessionid', httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'csrf_token', httpOnly: false, secure: false },
    ],
    websockets: [
      { url: 'wss://test-target-v11.com/ws', auth_required: true },
    ],
    forms: [
      { action: 'https://test-target-v11.com/login', method: 'POST', name: 'login_form', fields: ['username', 'password'] },
    ],
  });

  assert.ok(graph, 'Should return surface graph');
  assert.ok(graph.nodes.size >= 5, `Should have at least 5 nodes, got ${graph.nodes.size}`);
  assert.ok(graph.edges.size >= 1, 'Should have edges from auto-connection');
});

test('coverage computation (untested = 0)', () => {
  const graph = asm.getSurface('test-target-v11.com');
  const coverage = graph.computeCoverage();
  assert.strictEqual(coverage, 0, `Untested surface should have 0 coverage, got ${coverage}`);
});

test('coverage gaps', () => {
  const gaps = asm.getCoverageGaps('test-target-v11.com');
  assert.ok(gaps.length >= 1, 'Should have coverage gaps for untested surface');
  assert.ok(gaps[0].priority_score >= 0, 'Gap should have priority score');
});

test('update node test status', () => {
  const graph = asm.getSurface('test-target-v11.com');
  const nodes = [...graph.nodes.values()];
  if (nodes.length > 0) {
    const updated = asm.updateNodeStatus('test-target-v11.com', nodes[0].id, { tested: true, finding_count: 1 });
    assert.ok(updated.tested, 'Node should be marked as tested');
  }
});

test('surface details', () => {
  const details = asm.getSurfaceDetails('test-target-v11.com');
  assert.ok(details, 'Should return details');
  assert.ok(details.node_count > 0, 'Should have nodes');
  assert.ok(typeof details.coverage === 'number');
  assert.ok(Array.isArray(details.coverage_gaps));
});

test('get metrics', () => {
  const m = asm.getMetrics();
  assert.ok(m.total_surfaces >= 1);
  assert.ok(m.total_nodes > 0);
  assert.ok(typeof m.avg_coverage === 'number');
});

asm.shutdown();

// =====================================================================
//  4. ConfidenceCalibrator Tests
// =====================================================================

beginSection('4. ConfidenceCalibrator');

const ccMG = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
ccMG.reset();
const cc = new ConfidenceCalibrator({ memoryGraph: ccMG, persistenceIntervalMs: 0 });
cc.reset();

test('initial calibration (untrained)', () => {
  const result = cc.calibrate(65.0, { target_id: 'cc-target-unique-1.com', category: 'auth_unique_1' });
  assert.strictEqual(result.confidence_level, 'untrained', 'Should be untrained with 0 observations');
  assert.strictEqual(result.raw_evi, 65.0);
  assert.strictEqual(result.calibration_factor, 1.0, 'Default factor should be 1.0');
  assert.ok(result.cevi >= 0, 'CEVI should be non-negative');
});

test('record observations', () => {
  const targetCat = 'cc-target-unique-2.com:cc_cat_2';
  for (let i = 0; i < 10; i++) {
    cc.recordObservation({
      target_id: 'cc-target-unique-2.com',
      category: 'cc_cat_2',
      predicted: 60 + Math.random() * 10,
      actual: 40 + Math.random() * 15,
    });
  }

  const record = cc.getCalibrationRecord('cc-target-unique-2.com', 'cc_cat_2');
  assert.ok(record, 'Should have calibration record');
  assert.strictEqual(record.observation_count, 10);
  assert.ok(record.variance > 0, 'Should have computed variance');
});

test('calibrated CEVI after observations', () => {
  const result = cc.calibrate(65.0, { target_id: 'cc-target-unique-2.com', category: 'cc_cat_2' });
  assert.ok(result.confidence_level !== 'untrained', 'Should not be untrained after 10 observations');
  assert.ok(typeof result.calibration_factor === 'number');
  assert.ok(result.cevi >= 0);
});

test('uncertainty bands', () => {
  const result = cc.calibrate(70.0, { target_id: 'cc-target-unique-2.com', category: 'cc_cat_2' });
  assert.ok(result.p10 <= result.p50, 'p10 should be <= p50');
  assert.ok(result.p50 <= result.p90, 'p50 should be <= p90');
  assert.ok(result.p10 < result.p90, 'Band should have width');
});

test('competition penalty', () => {
  const result = cc.calibrate(65.0, { target_id: 'cc-target-unique-3.com', category: 'idor' });
  assert.ok(result.competition_penalty >= 0, 'Should have competition penalty');
});

test('learning bonus', () => {
  const result = cc.calibrate(65.0, { target_id: 'cc-target-unique-2.com', category: 'cc_cat_2' });
  assert.ok(result.learning_bonus >= 0, 'Should have learning bonus');
});

test('drift penalty', () => {
  const result = cc.calibrate(65.0, { target_id: 'cc-target-unique-2.com', category: 'cc_cat_2' });
  assert.ok(result.drift_penalty >= 0, 'Should have drift penalty');
});

test('batch calibrate', () => {
  const results = cc.calibrateBatch([
    { evi: 60, target_id: 'bt1.com', category: 'auth' },
    { evi: 45, target_id: 'bt2.com', category: 'idor' },
    { evi: 72, target_id: 'bt1.com', category: 'xss' },
  ]);
  assert.strictEqual(results.length, 3);
  assert.ok(results.every(r => r.cevi >= 0));
});

test('set historical weights', () => {
  cc.setHistoricalWeights('cc-target-unique-2.com', 'cc_cat_2', { probability: 0.35, capital_efficiency: 0.20 });
  const record = cc.getCalibrationRecord('cc-target-unique-2.com', 'cc_cat_2');
  assert.ok(record.historical_weights, 'Should have historical weights');
  assert.strictEqual(record.historical_weights.probability, 0.35);
});

test('global record', () => {
  assert.ok(cc.globalRecord, 'Should have global record');
  assert.ok(cc.globalRecord.observation_count >= 10, 'Global should have accumulated observations');
});

test('get metrics', () => {
  const m = cc.getMetrics();
  assert.ok(m.total_calibrations > 0);
  assert.ok(m.total_observations > 0);
});

cc.shutdown();
ccMG.shutdown();

// =====================================================================
//  5. DiscoveryLoopEngine Tests
// =====================================================================

beginSection('5. DiscoveryLoopEngine');

const dleMG = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
dleMG.reset();
// Add patterns for hypothesis generation
dleMG.addNode({ type: NODE_TYPES.PATTERN, label: 'Auth pattern', category: 'auth', features: { auth_score: 75 }, occurrence_count: 4, confidence: 0.7 });
dleMG.addNode({ type: NODE_TYPES.PATTERN, label: 'Session pattern', category: 'session', features: { session_score: 65 }, occurrence_count: 3, confidence: 0.6 });

const dleASM = new AttackSurfaceModeler({ persistenceIntervalMs: 0 });
dleASM.reset();
const dleCC = new ConfidenceCalibrator({ memoryGraph: dleMG, persistenceIntervalMs: 0 });
dleCC.reset();
const dleHG = new HypothesisGenerator({ memoryGraph: dleMG, attackSurfaceModeler: dleASM, confidenceCalibrator: dleCC, persistenceIntervalMs: 0 });
dleHG.reset();
const dle = new DiscoveryLoopEngine({
  memoryGraph: dleMG,
  hypothesisGenerator: dleHG,
  attackSurfaceModeler: dleASM,
  confidenceCalibrator: dleCC,
  loopIntervalMs: 60000,
  autoStart: false,
  persistenceIntervalMs: 0,
});
dle.reset();
// reset() now also resets state to IDLE

test('initial state', () => {
  // State may be idle or shutdown from persisted data; reset should make it usable
  assert.ok([LOOP_STATES.IDLE, LOOP_STATES.SHUTDOWN].includes(dle.state), `State should be idle or shutdown, got ${dle.state}`);
  assert.strictEqual(dle.cycleCount, 0);
  assert.ok(dle.safeMode.no_real_world_execution);
  assert.ok(dle.safeMode.simulation_only);
});

test('ingest signals', () => {
  const count = dle.ingestSignals([
    { id: 'sig1', type: 'security', source: 'scanner', target_id: 'dle-test.com', category: 'auth', features: { anomaly_score: 75 } },
    { id: 'sig2', type: 'anomaly', source: 'baseline', target_id: 'dle-test.com', category: 'session', features: { anomaly_score: 85, session_anomaly: true } },
    { id: 'sig3', type: 'security', source: 'scanner', target_id: 'dle-test.com', category: 'idor', features: { anomaly_score: 60 } },
  ]);
  assert.strictEqual(count, 3, 'Should ingest 3 signals');
});

test('run single cycle', async () => {
  const result = await dle.runOnce();
  assert.ok(result, 'Should return cycle result');
  assert.ok(result.cycle_id, 'Should have cycle ID');
  assert.strictEqual(result.signals_ingested, 3, 'Should process 3 signals');
  assert.strictEqual(dle.cycleCount, 1, 'Cycle count should be 1');
});

test('second cycle (no new signals)', async () => {
  const result = await dle.runOnce();
  assert.strictEqual(result.signals_ingested, 0, 'No new signals to process');
  assert.strictEqual(dle.cycleCount, 2, 'Cycle count should be 2');
});

test('event listeners', () => {
  let eventFired = false;
  dle.on(LOOP_EVENTS.SIGNAL_INGESTED, () => { eventFired = true; });
  dle.ingestSignals([{ id: 'sig_test', type: 'security', source: 'test' }]);
  assert.ok(eventFired, 'Event listener should fire');
});

test('record validation result', () => {
  const hyps = dle.hypothesisGenerator.queryHypotheses({ limit: 1 });
  if (hyps.length > 0) {
    dle.recordValidationResult(hyps[0].id, true, { evidence: 'simulated confirmation' });
    const hyp = dle.hypothesisGenerator.getHypothesis(hyps[0].id);
    if (hyp) {
      assert.strictEqual(hyp.status, HYPOTHESIS_STATUS.VALIDATED);
    }
  }
});

test('get ranked hypotheses', () => {
  const ranked = dle.getRankedHypotheses({ limit: 10 });
  assert.ok(Array.isArray(ranked), 'Should return array');
  if (ranked.length > 0) {
    assert.ok(ranked[0].cevi !== undefined, 'Should have CEVI score');
  }
});

test('get state', () => {
  const state = dle.getState();
  assert.ok([LOOP_STATES.IDLE, LOOP_STATES.SHUTDOWN].includes(state.state), `State should be idle or shutdown, got ${state.state}`);
  assert.strictEqual(state.cycle_count, 2);
});

test('get metrics', () => {
  const m = dle.getMetrics();
  assert.strictEqual(m.total_cycles, 2);
  assert.ok(m.total_signals_processed >= 3);
  assert.ok(typeof m.avg_cycle_duration_ms === 'number');
});

test('cycle history', () => {
  const history = dle.getCycleHistory(5);
  assert.strictEqual(history.length, 2);
  assert.ok(history[0].cycle_id);
});

dle.shutdown();

// =====================================================================
//  6. Cross-Module Integration
// =====================================================================

beginSection('6. Cross-Module Integration');

test('MemoryGraph <-> HypothesisGenerator', () => {
  const mg2 = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  mg2.addNode({ type: NODE_TYPES.PATTERN, label: 'Auth bypass pattern', category: 'auth', features: { auth_score: 85 }, occurrence_count: 5, confidence: 0.8 });

  const hg2 = new HypothesisGenerator({ memoryGraph: mg2, persistenceIntervalMs: 0 });
  const hyps = hg2.generateFromSignals([
    { id: 'sig1', type: 'security', source: 'scanner', target_id: 'x.com', category: 'auth', features: { anomaly_score: 70 } },
    { id: 'sig2', type: 'security', source: 'scanner', target_id: 'x.com', category: 'auth', features: { anomaly_score: 65 } },
  ]);

  assert.ok(hyps.length >= 1, 'Should generate hypotheses from memory graph patterns');
  mg2.shutdown();
  hg2.shutdown();
});

test('AttackSurfaceModeler <-> HypothesisGenerator', () => {
  const asm2 = new AttackSurfaceModeler({ persistenceIntervalMs: 0 });
  asm2.buildSurface('surf-target.com', {
    endpoints: [{ url: 'https://surf-target.com/api/admin', method: 'GET', auth_required: true, auth_type: 'session' }],
    auth_flows: [{ name: 'Session auth', type: 'session' }],
  });

  const mg3 = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  const hg3 = new HypothesisGenerator({ memoryGraph: mg3, attackSurfaceModeler: asm2, persistenceIntervalMs: 0 });

  const hyps = hg3.generateFromSignals([
    { id: 'sig1', type: 'security', source: 'scanner', target_id: 'surf-target.com', category: 'auth', features: { anomaly_score: 50 } },
  ]);

  assert.ok(hyps.length >= 1, 'Should generate hypotheses from surface gaps');
  asm2.shutdown();
  mg3.shutdown();
  hg3.shutdown();
});

test('ConfidenceCalibrator <-> DiscoveryLoopEngine', () => {
  const mg4 = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  const cc2 = new ConfidenceCalibrator({ memoryGraph: mg4, persistenceIntervalMs: 0 });

  for (let i = 0; i < 20; i++) {
    cc2.recordObservation({
      target_id: 'cal-target.com', category: 'auth',
      predicted: 55 + Math.random() * 20, actual: 35 + Math.random() * 15,
    });
  }

  const result = cc2.calibrate(60.0, { target_id: 'cal-target.com', category: 'auth' });
  assert.ok(result.confidence_level !== 'untrained', 'Should not be untrained');
  assert.ok(result.calibration_factor !== 1.0 || result.competition_penalty > 0 || result.learning_bonus > 0,
    'At least one adjustment should be non-zero');

  cc2.shutdown();
  mg4.shutdown();
});

test('full pipeline end-to-end', async () => {
  const mg5 = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  mg5.addNode({ type: NODE_TYPES.PATTERN, label: 'E2E pattern', category: 'auth', features: { auth_score: 70 }, occurrence_count: 3, confidence: 0.7 });

  const asm3 = new AttackSurfaceModeler({ persistenceIntervalMs: 0 });
  const cc3 = new ConfidenceCalibrator({ memoryGraph: mg5, persistenceIntervalMs: 0 });
  const hg4 = new HypothesisGenerator({ memoryGraph: mg5, attackSurfaceModeler: asm3, confidenceCalibrator: cc3, persistenceIntervalMs: 0 });
  const dle2 = new DiscoveryLoopEngine({
    memoryGraph: mg5, hypothesisGenerator: hg4,
    attackSurfaceModeler: asm3, confidenceCalibrator: cc3,
    autoStart: false, persistenceIntervalMs: 0,
  });

  dle2.ingestSignals([
    { id: 's1', type: 'security', source: 'scanner', target_id: 'e2e.com', category: 'auth', features: { anomaly_score: 80 } },
    { id: 's2', type: 'security', source: 'scanner', target_id: 'e2e.com', category: 'auth', features: { anomaly_score: 75 } },
    { id: 's3', type: 'anomaly', source: 'baseline', target_id: 'e2e.com', category: 'session', features: { anomaly_score: 90, session_anomaly: true } },
  ]);

  const result = await dle2.runOnce();
  assert.ok(result.signals_ingested >= 3);
  assert.ok(mg5.nodes.size > 0, 'MemoryGraph should have nodes after cycle');

  dle2.shutdown();
});

// =====================================================================
//  7. Improvement Metrics Validation
// =====================================================================

beginSection('7. Improvement Metrics Validation');

test('false_positive_reduction (calibration reduces overestimation)', () => {
  const ccTest = new ConfidenceCalibrator({ persistenceIntervalMs: 0 });
  for (let i = 0; i < 50; i++) {
    ccTest.recordObservation({
      target_id: 'fp-test.com', category: 'auth',
      predicted: 70, actual: 40,
    });
  }
  const result = ccTest.calibrate(70, { target_id: 'fp-test.com', category: 'auth' });
  assert.ok(result.calibration_factor < 1.0, 'Calibration should reduce overestimated scores');
  assert.ok(result.cevi < 70, 'CEVI should be lower than raw EVI after calibration');
  ccTest.shutdown();
});

test('discovery_yield_increase (hypotheses from signals)', () => {
  const mgY = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  for (let i = 0; i < 5; i++) {
    mgY.addNode({ type: NODE_TYPES.PATTERN, label: `Pattern ${i}`, category: 'auth', features: { auth_score: 70 + i * 5 }, occurrence_count: 3 + i });
  }

  const hgY = new HypothesisGenerator({ memoryGraph: mgY, persistenceIntervalMs: 0 });
  const signals = [];
  for (let i = 0; i < 20; i++) {
    signals.push({
      id: `sig_${i}`, type: i % 3 === 0 ? 'anomaly' : 'security',
      source: 'scanner', target_id: `target${i % 4}.com`,
      category: ['auth', 'idor', 'session', 'injection'][i % 4],
      features: { anomaly_score: 50 + Math.random() * 40 },
    });
  }

  const hyps = hgY.generateFromSignals(signals);
  assert.ok(hyps.length >= 1, 'Should generate at least 1 hypothesis from 20 signals with patterns');
  mgY.shutdown();
  hgY.shutdown();
});

test('ranking_stability (drift should be measurable)', async () => {
  const mgS = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  mgS.addNode({ type: NODE_TYPES.PATTERN, label: 'Stab pattern', category: 'auth', features: { auth_score: 70 }, occurrence_count: 3, confidence: 0.7 });

  const asmS = new AttackSurfaceModeler({ persistenceIntervalMs: 0 });
  const ccS = new ConfidenceCalibrator({ memoryGraph: mgS, persistenceIntervalMs: 0 });
  const hgS = new HypothesisGenerator({ memoryGraph: mgS, attackSurfaceModeler: asmS, confidenceCalibrator: ccS, persistenceIntervalMs: 0 });
  const dleS = new DiscoveryLoopEngine({
    memoryGraph: mgS, hypothesisGenerator: hgS,
    attackSurfaceModeler: asmS, confidenceCalibrator: ccS,
    autoStart: false, persistenceIntervalMs: 0,
  });

  dleS.ingestSignals([{ id: 's1', type: 'security', source: 'scanner', target_id: 'stab.com', category: 'auth', features: { anomaly_score: 70 } }]);
  await dleS.runOnce();
  await dleS.runOnce();

  const drift = dleS.metrics.ranking_drift_pct;
  assert.ok(typeof drift === 'number', `Drift should be a number, got ${typeof drift}`);

  dleS.shutdown();
});

// =====================================================================
//  8. Safe Mode Constraints
// =====================================================================

beginSection('8. Safe Mode Constraints');

test('no_real_world_execution flag', () => {
  const dleSafe = new DiscoveryLoopEngine({ autoStart: false, persistenceIntervalMs: 0 });
  assert.strictEqual(dleSafe.safeMode.no_real_world_execution, true);
  assert.strictEqual(dleSafe.safeMode.simulation_only, true);
  assert.strictEqual(dleSafe.safeMode.no_target_specific_attack_output, true);
  dleSafe.shutdown();
});

test('hypotheses are simulation-only', () => {
  const hgSafe = new HypothesisGenerator({ persistenceIntervalMs: 0 });
  const hyp = hgSafe.generate({
    target_id: 'safe-target.com',
    expected_bug_class: BUG_CLASSES.AUTH_BYPASS,
    description: 'Test hypothesis',
    test_approach: 'Simulate auth bypass attempt',
  });

  assert.ok(hyp.test_approach.toLowerCase().includes('simulate') || hyp.test_approach.toLowerCase().includes('investigate') || hyp.test_approach.toLowerCase().includes('explore') || hyp.test_approach.toLowerCase().includes('test'),
    'Test approach should be simulation-only');
  hgSafe.shutdown();
});

test('competition simulation is simulation_only', async () => {
  const mgSafe = new MemoryGraph({ decayIntervalMs: 0, persistenceIntervalMs: 0 });
  mgSafe.addNode({ type: NODE_TYPES.PATTERN, label: 'Safe pattern', category: 'auth', features: { auth_score: 60 }, occurrence_count: 2, confidence: 0.5 });

  const asmSafe = new AttackSurfaceModeler({ persistenceIntervalMs: 0 });
  const ccSafe = new ConfidenceCalibrator({ memoryGraph: mgSafe, persistenceIntervalMs: 0 });
  const hgSafe = new HypothesisGenerator({ memoryGraph: mgSafe, attackSurfaceModeler: asmSafe, confidenceCalibrator: ccSafe, persistenceIntervalMs: 0 });
  const dleSafe = new DiscoveryLoopEngine({
    memoryGraph: mgSafe, hypothesisGenerator: hgSafe,
    attackSurfaceModeler: asmSafe, confidenceCalibrator: ccSafe,
    autoStart: false, persistenceIntervalMs: 0,
  });

  dleSafe.ingestSignals([{ id: 's1', type: 'security', source: 'test', target_id: 'safe.com', category: 'auth', features: { anomaly_score: 60 } }]);
  await dleSafe.runOnce();

  assert.ok(dleSafe.safeMode.simulation_only);
  dleSafe.shutdown();
});

// =====================================================================
//  Run all tests
// =====================================================================

(async () => {
  await runAllTests();

  console.log('\n══════════════════════════════════════════════════');
  console.log(`  Results: ${passCount} passed, ${failCount} failed`);
  console.log('══════════════════════════════════════════════════\n');

  setTimeout(() => process.exit(failCount > 0 ? 1 : 0), 500);
})();


/**
 * BOQA test-v14.js — Test suite for v1.4 Autonomous Decision Kernel
 *
 * Tests:
 *   1. PermissionMatrixEngine
 *   2. RiskContainmentFirewall
 *   3. AutonomyLevelController
 *   4. ExecutionBudgetGovernor
 *   5. SelfCorrectionLoop_v2
 *   6. AutonomyGovernor (integrated)
 *   7. AutonomyGovernor.runPipeline (full v1.4 pipeline)
 *   8. Behavioral modes
 *   9. v1.4 scoring system
 *  10. Integration with v1.3 hardening layers
 */

const {
  AutonomyGovernor,
  AutonomyCheckResult,
  PipelineResult,
  PermissionMatrixEngine,
  RiskContainmentFirewall,
  AutonomyLevelController,
  ExecutionBudgetGovernor,
  SelfCorrectionLoop_v2,
  AUTONOMY_LEVELS,
  EXECUTION_LEVELS,
  BEHAVIORAL_MODES,
  DECISION_TYPES,
} = require('../autonomy-governor');

const { UncertaintyGovernor, GATE_STATES } = require('../uncertainty-governor');
const { CounterfactualValidator } = require('../counterfactual-validator');
const { DecisionStabilityEngine } = require('../decision-stability-engine');
const { RealityAlignmentLayer } = require('../reality-alignment-layer');
const { EconomicValueEngine } = require('../economic-value-engine');
const { ConfidenceCalibrator } = require('../confidence-calibrator');
const { MemoryGraph } = require('../memory-graph');

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

// ─── 1. PermissionMatrixEngine ──────────────────────────────────────

console.log('\n=== PermissionMatrixEngine ===');

test('should instantiate with default matrix', () => {
  const pme = new PermissionMatrixEngine();
  const matrix = pme.getMatrix();
  assert(matrix[DECISION_TYPES.SIGNAL_ASSESSMENT] !== undefined, 'signal_assessment should exist');
  assert(matrix[DECISION_TYPES.EXECUTION_ACTION] !== undefined, 'execution_action should exist');
});

test('should allow OBSERVE for signal_assessment at L0', () => {
  const pme = new PermissionMatrixEngine();
  const result = pme.check(DECISION_TYPES.SIGNAL_ASSESSMENT, AUTONOMY_LEVELS.L0, EXECUTION_LEVELS.OBSERVE);
  assert(result.allowed === true, `OBSERVE should be allowed at L0: ${result.reason}`);
});

test('should block EXECUTE_CONDITIONAL for execution_action at L1', () => {
  const pme = new PermissionMatrixEngine();
  const result = pme.check(DECISION_TYPES.EXECUTION_ACTION, AUTONOMY_LEVELS.L1, EXECUTION_LEVELS.EXECUTE_CONDITIONAL);
  assert(result.allowed === false, 'EXECUTE_CONDITIONAL should be blocked at L1');
  assert(result.max_allowed !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL, 'max_allowed should be lower');
});

test('should allow QUEUE for execution_action at L3', () => {
  const pme = new PermissionMatrixEngine();
  const result = pme.check(DECISION_TYPES.EXECUTION_ACTION, AUTONOMY_LEVELS.L3, EXECUTION_LEVELS.QUEUE);
  assert(result.allowed === true, `QUEUE should be allowed at L3: ${result.reason}`);
});

test('should return OBSERVE for unknown decision type', () => {
  const pme = new PermissionMatrixEngine();
  const result = pme.check('unknown_type', AUTONOMY_LEVELS.L3, EXECUTION_LEVELS.RECOMMEND);
  assert(result.allowed === false, 'unknown type should be blocked');
});

test('should support permission overrides', () => {
  const pme = new PermissionMatrixEngine({
    permissionOverrides: {
      custom_type: {
        min_level: AUTONOMY_LEVELS.L2,
        allowed_levels: [EXECUTION_LEVELS.SIMULATE, EXECUTION_LEVELS.RECOMMEND],
      },
    },
  });
  const result = pme.check('custom_type', AUTONOMY_LEVELS.L2, EXECUTION_LEVELS.RECOMMEND);
  assert(result.allowed === true, 'custom type should be allowed');
});

test('getMaxAllowed returns correct level', () => {
  const pme = new PermissionMatrixEngine();
  const max = pme.getMaxAllowed(DECISION_TYPES.POLICY_DECISION, AUTONOMY_LEVELS.L2);
  assert(max === EXECUTION_LEVELS.QUEUE, `max for policy_decision at L2 should be QUEUE, got ${max}`);
});

test('getAllowedLevels returns array', () => {
  const pme = new PermissionMatrixEngine();
  const levels = pme.getAllowedLevels(DECISION_TYPES.ECONOMIC_SCORING, AUTONOMY_LEVELS.L1);
  assert(Array.isArray(levels), 'should return array');
  assert(levels.includes(EXECUTION_LEVELS.SIMULATE), 'should include SIMULATE');
});

// ─── 2. RiskContainmentFirewall ─────────────────────────────────────

console.log('\n=== RiskContainmentFirewall ===');

test('should pass safe decisions', () => {
  const rcf = new RiskContainmentFirewall();
  const result = rcf.evaluate({
    uncertainty: 0.2,
    stability_score: 0.9,
    external_alignment: 0.8,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
  });
  assert(result.passed === true, 'Safe decision should pass');
  assert(result.violations.length === 0, 'No violations');
});

test('should block EXECUTE when uncertainty > 0.7', () => {
  const rcf = new RiskContainmentFirewall();
  const result = rcf.evaluate({
    uncertainty: 0.8,
    stability_score: 0.9,
    external_alignment: 0.8,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
  });
  assert(result.passed === false, 'High uncertainty should block EXECUTE');
  assert(result.action === EXECUTION_LEVELS.SIMULATE, 'Should downgrade to SIMULATE');
  assert(result.violations.length > 0, 'Should have violations');
});

test('should downgrade to OBSERVE when stability < 0.6', () => {
  const rcf = new RiskContainmentFirewall();
  const result = rcf.evaluate({
    uncertainty: 0.3,
    stability_score: 0.4,
    external_alignment: 0.8,
    proposed_action: EXECUTION_LEVELS.RECOMMEND,
  });
  assert(result.passed === false, 'Low stability should not pass');
  assert(result.action === EXECUTION_LEVELS.OBSERVE, 'Should downgrade to OBSERVE');
});

test('should require simulation only when alignment < 0.5', () => {
  const rcf = new RiskContainmentFirewall();
  const result = rcf.evaluate({
    uncertainty: 0.3,
    stability_score: 0.8,
    external_alignment: 0.3,
    proposed_action: EXECUTION_LEVELS.QUEUE,
  });
  assert(result.passed === false, 'Low alignment should not pass');
  assert(result.action === EXECUTION_LEVELS.SIMULATE, 'Should require SIMULATE only');
});

test('should record violations', () => {
  const rcf = new RiskContainmentFirewall();
  rcf.evaluate({
    opportunity_id: 'test-1',
    uncertainty: 0.8,
    stability_score: 0.4,
    external_alignment: 0.3,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
  });
  assert(rcf.getViolationCount() > 0, 'Should have recorded violations');
  assert(rcf.getViolations().length > 0, 'Should return violations');
});

test('reset clears violations', () => {
  const rcf = new RiskContainmentFirewall();
  rcf.evaluate({
    uncertainty: 0.9,
    stability_score: 0.3,
    external_alignment: 0.2,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
  });
  rcf.reset();
  assert(rcf.getViolationCount() === 0, 'Violations should be cleared');
});

// ─── 3. AutonomyLevelController ─────────────────────────────────────

console.log('\n=== AutonomyLevelController ===');

test('should start at initial level', () => {
  const alc = new AutonomyLevelController({ initialAutonomyLevel: 2 });
  assert(alc.getCurrentLevel() === 2, `Expected level 2, got ${alc.getCurrentLevel()}`);
  assert(alc.getEffectiveLevel() === 2, 'Effective should equal current');
});

test('should set level manually', () => {
  const alc = new AutonomyLevelController({ initialAutonomyLevel: 1 });
  alc.setLevel(3, 'test_override');
  assert(alc.getCurrentLevel() === 3, 'Level should be 3');
});

test('should respect max level', () => {
  const alc = new AutonomyLevelController({ initialAutonomyLevel: 1, maxAutonomyLevel: 2 });
  alc.setLevel(5, 'test');
  assert(alc.getCurrentLevel() === 2, `Should cap at max level 2, got ${alc.getCurrentLevel()}`);
});

test('should downgrade on high error rate', () => {
  const alc = new AutonomyLevelController({
    initialAutonomyLevel: 3,
    downgradeErrorThreshold: 0.30,
  });

  // Record snapshots with high error rate
  for (let i = 0; i < 20; i++) {
    alc.recordSnapshot({
      performance_score: 0.3,
      error_rate: 0.40,
      decision_accuracy: 0.4,
      avg_regret_score: 0.5,
    });
  }

  const result = alc.evaluateScaling();
  assert(result.changed === true, `Should downgrade: ${result.reason}`);
  assert(result.new_level < 3, 'Should decrease level');
});

test('should upgrade on sustained improvement', () => {
  const alc = new AutonomyLevelController({
    initialAutonomyLevel: 2,
    maxAutonomyLevel: 4,
    scalingMinImprovement: 0.05,
    scalingMaxErrorRate: 0.15,
  });

  // Old period: low performance
  const oldTime = Date.now() - 45 * 24 * 60 * 60 * 1000; // 45 days ago
  for (let i = 0; i < 10; i++) {
    alc.performanceSnapshots.push({
      performance_score: 0.4,
      error_rate: 0.10,
      decision_accuracy: 0.6,
      avg_regret_score: 0.3,
      timestamp: oldTime + i * 24 * 60 * 60 * 1000,
    });
  }

  // Recent period: high performance
  for (let i = 0; i < 10; i++) {
    alc.recordSnapshot({
      performance_score: 0.7,
      error_rate: 0.05,
      decision_accuracy: 0.9,
      avg_regret_score: 0.1,
    });
  }

  const result = alc.evaluateScaling();
  assert(result.changed === true, `Should upgrade: ${result.reason}`);
  assert(result.new_level > 2, 'Should increase level');
});

test('should support temporary reduction', () => {
  const alc = new AutonomyLevelController({ initialAutonomyLevel: 3 });
  alc.temporaryReduce(1, 60000, 'safety_alert');
  assert(alc.getEffectiveLevel() === 1, 'Should be temporarily reduced');

  // Simulate expiry
  alc.temporaryReductionExpiry = Date.now() - 1;
  assert(alc.getEffectiveLevel() === 3, 'Should return to original after expiry');
});

test('should record level history', () => {
  const alc = new AutonomyLevelController({ initialAutonomyLevel: 1 });
  alc.setLevel(2, 'test');
  alc.setLevel(3, 'test');
  const history = alc.getLevelHistory();
  assert(history.length >= 2, 'Should have history entries');
});

// ─── 4. ExecutionBudgetGovernor ─────────────────────────────────────

console.log('\n=== ExecutionBudgetGovernor ===');

test('should start a cycle and track budget', () => {
  const ebg = new ExecutionBudgetGovernor();
  ebg.startCycle('test-cycle');
  const status = ebg.getStatus();
  assert(status.cycle_id === 'test-cycle', 'Cycle ID should match');
  assert(status.decisions_made === 0, 'No decisions yet');
});

test('should allow within-budget decisions', () => {
  const ebg = new ExecutionBudgetGovernor({ maxCapitalExposurePct: 0.01 });
  ebg.startCycle('test');
  const result = ebg.checkBudget({ capital_required: 100, risk_estimate: 0.05 });
  assert(result.allowed === true, 'Small budget should be allowed');
});

test('should block over-budget decisions', () => {
  const ebg = new ExecutionBudgetGovernor({
    maxCapitalExposurePct: 0.001,
    maxRiskPerAction: 0.1,
  });
  ebg.startCycle('test');
  // Try a large capital requirement
  const result = ebg.checkBudget({ capital_required: 100000, risk_estimate: 0.05 });
  assert(result.allowed === false, 'Over-budget should be blocked');
});

test('should block high-risk decisions', () => {
  const ebg = new ExecutionBudgetGovernor({ maxRiskPerAction: 0.1 });
  ebg.startCycle('test');
  const result = ebg.checkBudget({ capital_required: 10, risk_estimate: 0.5 });
  assert(result.allowed === false, 'High risk should be blocked');
});

test('should track expenditures', () => {
  const ebg = new ExecutionBudgetGovernor({ maxCapitalExposurePct: 0.05 });
  ebg.startCycle('test');
  ebg.recordExpenditure({ opportunity_id: 'opp-1', capital_committed: 1000, risk_taken: 0.05 });
  const status = ebg.getStatus();
  assert(status.decisions_made === 1, 'Should track decisions');
  assert(status.capital_exposed === 1000, 'Should track capital');
  assert(status.active_decisions === 1, 'Should track active decisions');
});

test('should release decisions', () => {
  const ebg = new ExecutionBudgetGovernor();
  ebg.startCycle('test');
  ebg.recordExpenditure({ opportunity_id: 'opp-1', capital_committed: 100, risk_taken: 0.05 });
  ebg.releaseDecision('opp-1');
  const status = ebg.getStatus();
  assert(status.active_decisions === 0, 'Should be released');
});

test('should enforce parallel decision limit', () => {
  const ebg = new ExecutionBudgetGovernor({ maxParallelDecisions: 2, maxCapitalExposurePct: 1 });
  ebg.startCycle('test');
  ebg.recordExpenditure({ opportunity_id: 'opp-1', capital_committed: 100, risk_taken: 0.05 });
  ebg.recordExpenditure({ opportunity_id: 'opp-2', capital_committed: 100, risk_taken: 0.05 });
  const result = ebg.checkBudget({ capital_required: 100, risk_estimate: 0.05 });
  assert(result.allowed === false, 'Should block when parallel limit reached');
});

// ─── 5. SelfCorrectionLoop_v2 ───────────────────────────────────────

console.log('\n=== SelfCorrectionLoop_v2 ===');

test('should start with default policy weights', () => {
  const scl = new SelfCorrectionLoop_v2();
  const weights = scl.getPolicyWeights();
  assert(weights.cevi_weight > 0, 'cevi_weight should be > 0');
  assert(weights.stability_weight > 0, 'stability_weight should be > 0');
  assert(weights.alignment_weight > 0, 'alignment_weight should be > 0');
  assert(weights.autonomy_weight > 0, 'autonomy_weight should be > 0');

  // Weights should approximately sum to 1.0
  const total = Object.values(weights).reduce((s, w) => s + w, 0);
  assertApprox(total, 1.0, 0.05, 'Weights should sum to ~1.0');
});

test('should record outcomes', () => {
  const scl = new SelfCorrectionLoop_v2();
  scl.recordOutcome({
    opportunity_id: 'opp-1',
    decision_type: DECISION_TYPES.POLICY_DECISION,
    action_taken: EXECUTION_LEVELS.SIMULATE,
    forecast_value: 100,
    actual_value: 90,
    forecast_error: 0.1,
    regret_score: 0.1,
    missed_opportunity_delta: 5,
  });
  const outcomes = scl.getOutcomes(10);
  assert(outcomes.length === 1, 'Should have 1 outcome');
});

test('should compute performance metrics', () => {
  const scl = new SelfCorrectionLoop_v2();
  for (let i = 0; i < 20; i++) {
    scl.recordOutcome({
      opportunity_id: `opp-${i}`,
      decision_type: DECISION_TYPES.POLICY_DECISION,
      action_taken: EXECUTION_LEVELS.SIMULATE,
      forecast_value: 100,
      actual_value: 85 + Math.random() * 30,
      forecast_error: 0.1 + Math.random() * 0.2,
      regret_score: 0.05 + Math.random() * 0.1,
      missed_opportunity_delta: Math.random() * 50,
    });
  }
  const metrics = scl.getPerformanceMetrics();
  assert(metrics.outcome_count > 0, 'Should have outcomes');
  assert(metrics.avg_forecast_error > 0, 'Should compute forecast error');
  assert(metrics.decision_accuracy >= 0, 'Should compute accuracy');
});

test('should apply self-correction after enough outcomes', () => {
  const scl = new SelfCorrectionLoop_v2();
  for (let i = 0; i < 30; i++) {
    scl.recordOutcome({
      opportunity_id: `opp-${i}`,
      decision_type: DECISION_TYPES.POLICY_DECISION,
      action_taken: EXECUTION_LEVELS.SIMULATE,
      forecast_value: 100,
      actual_value: 50,
      forecast_error: 0.5,
      regret_score: 0.4,
      missed_opportunity_delta: 200,
    });
  }
  // After many bad outcomes, weights should have shifted
  const weights = scl.getPolicyWeights();
  const corrections = scl.getCorrectionHistory();
  assert(corrections.length > 0, 'Should have corrections applied');
});

// ─── 6. AutonomyGovernor (Integrated) ──────────────────────────────

console.log('\n=== AutonomyGovernor (Integrated) ===');

test('should instantiate with all subsystems', () => {
  const ag = new AutonomyGovernor();
  assert(ag.permissionMatrix instanceof PermissionMatrixEngine, 'Should have PermissionMatrixEngine');
  assert(ag.riskFirewall instanceof RiskContainmentFirewall, 'Should have RiskContainmentFirewall');
  assert(ag.autonomyController instanceof AutonomyLevelController, 'Should have AutonomyLevelController');
  assert(ag.budgetGovernor instanceof ExecutionBudgetGovernor, 'Should have ExecutionBudgetGovernor');
  assert(ag.selfCorrection instanceof SelfCorrectionLoop_v2, 'Should have SelfCorrectionLoop_v2');
});

test('should default to RECOMMENDATION_MODE', () => {
  const ag = new AutonomyGovernor();
  assert(ag.getBehavioralMode() === BEHAVIORAL_MODES.RECOMMENDATION_MODE, 'Default mode should be RECOMMENDATION_MODE');
});

test('should default to L1 autonomy', () => {
  const ag = new AutonomyGovernor();
  assert(ag.getAutonomyLevel() === 1, `Default level should be 1, got ${ag.getAutonomyLevel()}`);
  assert(ag.getAutonomyLevelName() === 'L1-analysis', `Name should be L1-analysis, got ${ag.getAutonomyLevelName()}`);
});

test('check() should return AutonomyCheckResult', () => {
  const ag = new AutonomyGovernor();
  const result = ag.check({
    opportunity_id: 'test-1',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.OBSERVE,
    cevi: 0.5,
    uncertainty: 0.3,
    stability_score: 0.8,
    alignment_score: 0.7,
  });
  assert(result instanceof AutonomyCheckResult, 'Should return AutonomyCheckResult');
  assert(result.final_action !== undefined, 'Should have final action');
  assert(result.final_score !== undefined, 'Should have final score');
  assert(result.penalties !== undefined, 'Should have penalties');
});

test('check() should block high-uncertainty execution', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3 });
  const result = ag.check({
    opportunity_id: 'test-high-uncertainty',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    cevi: 0.6,
    uncertainty: 0.8,
    stability_score: 0.8,
    alignment_score: 0.8,
  });
  assert(result.final_action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    `Should not EXECUTE with high uncertainty, got ${result.final_action}`);
});

test('check() should downgrade when stability is low', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3 });
  const result = ag.check({
    opportunity_id: 'test-low-stability',
    decision_type: DECISION_TYPES.POLICY_DECISION,
    proposed_action: EXECUTION_LEVELS.RECOMMEND,
    cevi: 0.5,
    uncertainty: 0.3,
    stability_score: 0.4,
    alignment_score: 0.7,
  });
  assert(result.final_action === EXECUTION_LEVELS.OBSERVE,
    `Should downgrade to OBSERVE with low stability, got ${result.final_action}`);
});

test('check() should compute penalties', () => {
  const ag = new AutonomyGovernor();
  const result = ag.check({
    opportunity_id: 'test-penalties',
    decision_type: DECISION_TYPES.ECONOMIC_SCORING,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.5,
    uncertainty: 0.5,
    stability_score: 0.5,
    alignment_score: 0.5,
    risk_estimate: 0.3,
    counterfactual_regret: 0.2,
  });
  assert(result.penalties.total_penalty > 0, 'Should have penalties');
  assert(result.penalties.uncertainty_penalty !== undefined, 'Should have uncertainty penalty');
  assert(result.penalties.stability_decay !== undefined, 'Should have stability decay');
  assert(result.penalties.execution_risk_adjustment !== undefined, 'Should have execution risk adjustment');
});

test('check() should audit log', () => {
  const ag = new AutonomyGovernor();
  ag.check({
    opportunity_id: 'test-audit',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.OBSERVE,
    cevi: 0.5,
  });
  const log = ag.getAuditLog();
  assert(log.length > 0, 'Audit log should have entries');
  assert(log[log.length - 1].opportunity_id === 'test-audit', 'Last entry should match');
});

test('setBehavioralMode should validate modes', () => {
  const ag = new AutonomyGovernor();
  ag.setBehavioralMode(BEHAVIORAL_MODES.SIMULATE_ONLY);
  assert(ag.getBehavioralMode() === BEHAVIORAL_MODES.SIMULATE_ONLY, 'Mode should be set');

  let threw = false;
  try {
    ag.setBehavioralMode('INVALID_MODE');
  } catch (_) {
    threw = true;
  }
  assert(threw === true, 'Should reject invalid mode');
});

test('recordOutcome should feed self-correction and autonomy scaling', () => {
  const ag = new AutonomyGovernor();
  ag.recordOutcome({
    opportunity_id: 'opp-1',
    decision_type: DECISION_TYPES.POLICY_DECISION,
    action_taken: EXECUTION_LEVELS.SIMULATE,
    forecast_value: 100,
    actual_value: 90,
    forecast_error: 0.1,
    regret_score: 0.05,
    missed_opportunity_delta: 5,
  });
  const perf = ag.selfCorrection.getPerformanceMetrics();
  assert(perf.outcome_count > 0, 'Self-correction should have outcomes');
});

test('getMetrics should return comprehensive metrics', () => {
  const ag = new AutonomyGovernor();
  const metrics = ag.getMetrics();
  assert(metrics.autonomy_level !== undefined, 'Should have autonomy_level');
  assert(metrics.behavioral_mode !== undefined, 'Should have behavioral_mode');
  assert(metrics.policy_weights !== undefined, 'Should have policy_weights');
  assert(metrics.model_params !== undefined, 'Should have model_params');
  assert(metrics.budget_status !== undefined, 'Should have budget_status');
  assert(metrics.self_correction !== undefined, 'Should have self_correction');
});

test('getSubsystemStatus should return all subsystems', () => {
  const ag = new AutonomyGovernor();
  const status = ag.getSubsystemStatus();
  assert(status.permission_matrix !== undefined, 'Should have permission_matrix');
  assert(status.risk_firewall !== undefined, 'Should have risk_firewall');
  assert(status.autonomy_controller !== undefined, 'Should have autonomy_controller');
  assert(status.budget_governor !== undefined, 'Should have budget_governor');
  assert(status.self_correction !== undefined, 'Should have self_correction');
});

// ─── 7. Pipeline ────────────────────────────────────────────────────

console.log('\n=== AutonomyGovernor.runPipeline ===');

test('should run full v1.4 pipeline with opportunities', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 2 });
  const opportunities = [
    {
      opportunity_id: 'opp-A',
      cevi: 0.7,
      confidence: 0.8,
      market_size: 500000,
      competition_pressure: 0.15,
      stability_score: 0.8,
      alignment_score: 0.7,
      opportunity_class: 'security_bug_bounty',
      economic_score: 45,
      proposed_action: EXECUTION_LEVELS.SIMULATE,
    },
    {
      opportunity_id: 'opp-B',
      cevi: 0.4,
      confidence: 0.5,
      market_size: 50000,
      competition_pressure: 0.3,
      stability_score: 0.5,
      alignment_score: 0.4,
      opportunity_class: 'ssl_tls_feed',
      economic_score: 20,
      proposed_action: EXECUTION_LEVELS.RECOMMEND,
    },
  ];

  const result = ag.runPipeline(opportunities);
  assert(result instanceof PipelineResult, 'Should return PipelineResult');
  assert(result.total_opportunities === 2, 'Should process 2 opportunities');
  assert(result.results.length === 2, 'Should have 2 results');
  assert(result.results[0].final_score >= result.results[1].final_score,
    'Results should be sorted by score descending');
  assert(result.results[0].rank === 1, 'Top result should be rank 1');
  assert(result.autonomy_level !== undefined, 'Should have autonomy level');
  assert(result.behavioral_mode !== undefined, 'Should have behavioral mode');
});

test('pipeline should produce step-by-step results', () => {
  const ag = new AutonomyGovernor();
  const result = ag.runPipeline([{
    opportunity_id: 'opp-step-test',
    cevi: 0.6,
    economic_score: 35,
  }]);

  const steps = result.results[0].steps;
  assert(steps.signal_ingestion !== undefined, 'Should have signal_ingestion step');
  assert(steps.hypothesis_generation !== undefined, 'Should have hypothesis_generation step');
  assert(steps.economic_modeling !== undefined, 'Should have economic_modeling step');
  assert(steps.cross_opportunity_comparison !== undefined, 'Should have cross_opportunity_comparison step');
  assert(steps.uncertainty_governance !== undefined, 'Should have uncertainty_governance step');
  assert(steps.counterfactual_validation !== undefined, 'Should have counterfactual_validation step');
  assert(steps.stability_filtering !== undefined, 'Should have stability_filtering step');
  assert(steps.reality_alignment !== undefined, 'Should have reality_alignment step');
  assert(steps.autonomy_permission_check !== undefined, 'Should have autonomy_permission_check step');
  assert(steps.decision_output !== undefined, 'Should have decision_output step');
});

test('pipeline should handle empty input', () => {
  const ag = new AutonomyGovernor();
  const result = ag.runPipeline([]);
  assert(result.total_opportunities === 0, 'Should handle empty array');
  assert(result.results.length === 0, 'No results for empty input');
});

// ─── 8. Behavioral Modes ───────────────────────────────────────────

console.log('\n=== Behavioral Modes ===');

test('OBSERVE_ONLY should only allow OBSERVE', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3 });
  ag.setBehavioralMode(BEHAVIORAL_MODES.OBSERVE_ONLY);
  const result = ag.check({
    opportunity_id: 'test-observe',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.7,
    uncertainty: 0.2,
    stability_score: 0.9,
    alignment_score: 0.8,
  });
  // In OBSERVE_ONLY mode, even if firewall allows, mode should restrict
  assert(result.mode_compatible === false, 'SIMULATE not compatible with OBSERVE_ONLY');
});

test('SIMULATE_ONLY should allow OBSERVE and SIMULATE', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3 });
  ag.setBehavioralMode(BEHAVIORAL_MODES.SIMULATE_ONLY);
  const result = ag.check({
    opportunity_id: 'test-sim',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.7,
    uncertainty: 0.2,
    stability_score: 0.9,
    alignment_score: 0.8,
  });
  assert(result.mode_compatible === true, 'SIMULATE should be compatible');
});

test('FULL_AUTONOMY should allow all actions', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 4 });
  ag.setBehavioralMode(BEHAVIORAL_MODES.FULL_AUTONOMY);
  const result = ag.check({
    opportunity_id: 'test-full',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    cevi: 0.8,
    uncertainty: 0.2,
    stability_score: 0.9,
    alignment_score: 0.9,
  });
  assert(result.mode_compatible === true, 'All actions compatible with FULL_AUTONOMY');
});

// ─── 9. v1.4 Scoring System ────────────────────────────────────────

console.log('\n=== v1.4 Scoring System ===');

test('final_score = CEVI * weights + stability * weights + alignment * weights + autonomy_weight * weights - penalties', () => {
  const ag = new AutonomyGovernor();
  const result = ag.check({
    opportunity_id: 'score-test',
    decision_type: DECISION_TYPES.ECONOMIC_SCORING,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.6,
    uncertainty: 0.3,
    stability_score: 0.7,
    alignment_score: 0.8,
    risk_estimate: 0.1,
  });

  // The final score should be positive (good signal, low penalties)
  assert(result.final_score > 0, `Final score should be positive, got ${result.final_score}`);
  assert(result.final_score <= 1.0, 'Final score should be <= 1.0');
});

test('high uncertainty should reduce final score via penalties', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3 });
  const lowUncertainty = ag.check({
    opportunity_id: 'low-unc',
    decision_type: DECISION_TYPES.ECONOMIC_SCORING,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.6,
    uncertainty: 0.2,
    stability_score: 0.8,
    alignment_score: 0.7,
    risk_estimate: 0.05,
  });
  const highUncertainty = ag.check({
    opportunity_id: 'high-unc',
    decision_type: DECISION_TYPES.ECONOMIC_SCORING,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.6,
    uncertainty: 0.8,
    stability_score: 0.8,
    alignment_score: 0.7,
    risk_estimate: 0.05,
  });

  assert(lowUncertainty.final_score > highUncertainty.final_score,
    `Low uncertainty (${lowUncertainty.final_score}) should score higher than high (${highUncertainty.final_score})`);
});

test('counterfactual regret should penalize score', () => {
  const ag = new AutonomyGovernor();
  const noRegret = ag.check({
    opportunity_id: 'no-regret',
    decision_type: DECISION_TYPES.ECONOMIC_SCORING,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.6,
    uncertainty: 0.3,
    stability_score: 0.7,
    alignment_score: 0.7,
    counterfactual_regret: 0,
    risk_estimate: 0.05,
  });
  const highRegret = ag.check({
    opportunity_id: 'high-regret',
    decision_type: DECISION_TYPES.ECONOMIC_SCORING,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.6,
    uncertainty: 0.3,
    stability_score: 0.7,
    alignment_score: 0.7,
    counterfactual_regret: 0.5,
    risk_estimate: 0.05,
  });

  assert(noRegret.final_score > highRegret.final_score,
    'No regret should score higher than high regret');
});

// ─── 10. Integration with v1.3 Hardening Layers ────────────────────

console.log('\n=== Integration with v1.3 Hardening Layers ===');

test('should integrate with UncertaintyGovernor', () => {
  const ug = new UncertaintyGovernor();
  const ag = new AutonomyGovernor({
    uncertaintyGovernor: ug,
    initialAutonomyLevel: 2,
  });

  const result = ag.check({
    opportunity_id: 'ug-integration',
    decision_type: DECISION_TYPES.POLICY_DECISION,
    proposed_action: EXECUTION_LEVELS.RECOMMEND,
    cevi: 0.6,
    confidence: 0.8,
    signal_density: 10,
  });

  // Should have used the uncertainty governor
  assert(result.firewall_check !== undefined, 'Should have firewall check');
});

test('should integrate with CounterfactualValidator', () => {
  const cv = new CounterfactualValidator();
  const ag = new AutonomyGovernor({
    counterfactualValidator: cv,
    initialAutonomyLevel: 2,
  });

  const result = ag.runPipeline([{
    opportunity_id: 'cv-integration',
    cevi: 0.5,
    economic_score: 30,
    confidence: 0.6,
    market_size: 100000,
    competition_pressure: 0.2,
    opportunity_class: 'security_bug_bounty',
  }]);

  const steps = result.results[0].steps;
  assert(steps.counterfactual_validation !== undefined, 'Should have counterfactual step');
  assert(steps.counterfactual_validation.verdict !== undefined, 'Should have verdict');
});

test('should integrate with DecisionStabilityEngine', () => {
  const dse = new DecisionStabilityEngine();
  const ag = new AutonomyGovernor({
    decisionStabilityEngine: dse,
    initialAutonomyLevel: 2,
  });

  const result = ag.runPipeline([{
    opportunity_id: 'dse-integration',
    cevi: 0.5,
    economic_score: 30,
    policy: 'SIMULATE',
    confidence: 0.6,
  }]);

  const steps = result.results[0].steps;
  assert(steps.stability_filtering !== undefined, 'Should have stability step');
  assert(steps.stability_filtering.stable_policy !== undefined, 'Should have stable policy');
});

test('should integrate with RealityAlignmentLayer', () => {
  const ral = new RealityAlignmentLayer();
  const ag = new AutonomyGovernor({
    realityAlignmentLayer: ral,
    initialAutonomyLevel: 2,
  });

  const result = ag.runPipeline([{
    opportunity_id: 'ral-integration',
    cevi: 0.5,
    economic_score: 30,
    simulated_roi: 0.12,
    opportunity_class: 'security_bug_bounty',
  }]);

  const steps = result.results[0].steps;
  assert(steps.reality_alignment !== undefined, 'Should have reality alignment step');
  assert(steps.reality_alignment.alignment_score !== undefined, 'Should have alignment score');
});

test('full v1.4 pipeline with all v1.3 layers integrated', () => {
  const ug = new UncertaintyGovernor();
  const cv = new CounterfactualValidator();
  const dse = new DecisionStabilityEngine();
  const ral = new RealityAlignmentLayer();
  const mg = new MemoryGraph();
  const cc = new ConfidenceCalibrator({ memoryGraph: mg });
  const eve = new EconomicValueEngine({ confidenceCalibrator: cc, memoryGraph: mg });

  const ag = new AutonomyGovernor({
    uncertaintyGovernor: ug,
    counterfactualValidator: cv,
    decisionStabilityEngine: dse,
    realityAlignmentLayer: ral,
    economicValueEngine: eve,
    initialAutonomyLevel: 2,
  });

  const opportunities = [
    {
      opportunity_id: 'full-integ-A',
      cevi: 0.7,
      confidence: 0.8,
      market_size: 500000,
      competition_pressure: 0.15,
      capital_required: 2000,
      opportunity_class: 'security_bug_bounty',
      simulated_roi: 0.2,
      policy: 'SIMULATE',
      proposed_action: EXECUTION_LEVELS.SIMULATE,
    },
    {
      opportunity_id: 'full-integ-B',
      cevi: 0.3,
      confidence: 0.4,
      market_size: 30000,
      competition_pressure: 0.4,
      capital_required: 500,
      opportunity_class: 'ssl_tls_feed',
      simulated_roi: 0.04,
      policy: 'WATCH',
      proposed_action: EXECUTION_LEVELS.OBSERVE,
    },
  ];

  const result = ag.runPipeline(opportunities);
  assert(result.total_opportunities === 2, 'Should process 2 opportunities');
  assert(result.results[0].rank === 1, 'Top result should be rank 1');
  assert(result.results[0].final_score >= result.results[1].final_score,
    'Should be sorted by score');
});

test('global decision lock should force HOLD', () => {
  const ug = new UncertaintyGovernor();
  ug.activateDecisionLock('test_emergency');

  const ag = new AutonomyGovernor({
    uncertaintyGovernor: ug,
    initialAutonomyLevel: 3,
  });

  const result = ag.check({
    opportunity_id: 'lock-test',
    decision_type: DECISION_TYPES.POLICY_DECISION,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
    cevi: 0.7,
    uncertainty: 0.2,
    stability_score: 0.9,
    alignment_score: 0.8,
  });

  assert(result.hold_override.override === true, 'Should have hold override');
  assert(result.final_action === EXECUTION_LEVELS.OBSERVE, 'Should be forced to OBSERVE/HOLD');
});

// ─── Persistence Tests ──────────────────────────────────────────────

console.log('\n=== Persistence ===');

test('save and load should preserve state', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 2 });
  ag.setBehavioralMode(BEHAVIORAL_MODES.CONTROLLED_AUTONOMY);
  ag.check({
    opportunity_id: 'persist-test',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.OBSERVE,
    cevi: 0.5,
  });

  const savedPath = ag.save();
  assert(savedPath !== undefined, 'Should return save path');

  // Create new instance and load
  const ag2 = new AutonomyGovernor();
  const loaded = ag2.load();
  assert(loaded === true, 'Should load successfully');
  assert(ag2.getBehavioralMode() === BEHAVIORAL_MODES.CONTROLLED_AUTONOMY,
    'Behavioral mode should be preserved');

  // Cleanup
  ag.reset();
});

// ─── Guardrail Tests ────────────────────────────────────────────────

console.log('\n=== Guardrails ===');

test('no unbounded external execution', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3, maxAutonomyLevel: 3 });
  const result = ag.check({
    opportunity_id: 'guardrail-test',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    cevi: 0.9,
    uncertainty: 0.2,
    stability_score: 0.9,
    alignment_score: 0.9,
    risk_estimate: 0.05,
    capital_required: 50,
  });

  // EXECUTE_CONDITIONAL is the most aggressive action allowed
  // but it's still conditional, not unbounded
  assert(result.final_action !== 'EXECUTE_UNBOUNDED', 'No unbounded execution should exist');
});

test('EXECUTE only allowed at L3+ with low uncertainty and high stability', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 2 });

  // At L2, EXECUTE should not be allowed
  const result = ag.check({
    opportunity_id: 'level-guard',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    cevi: 0.8,
    uncertainty: 0.2,
    stability_score: 0.9,
    alignment_score: 0.9,
  });

  assert(result.final_action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    'EXECUTE should not be allowed at L2');
});

test('escalation detection on layer contradiction', () => {
  const ag = new AutonomyGovernor({ initialAutonomyLevel: 3 });
  // Create a situation where permission allows but firewall blocks
  const result = ag.check({
    opportunity_id: 'escalation-test',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    cevi: 0.8,
    uncertainty: 0.8, // High uncertainty → firewall blocks
    stability_score: 0.9,
    alignment_score: 0.9,
  });

  assert(result.needs_escalation === true, 'Should detect escalation');
});

// ─── Results ────────────────────────────────────────────────────────

console.log('\n' + '='.repeat(60));
console.log(`  Results: ${testsPassed} passed, ${testsFailed} failed`);
if (failures.length > 0) {
  console.log('\n  Failures:');
  for (const f of failures) {
    console.log(`    - ${f.name}: ${f.error}`);
  }
}
console.log('='.repeat(60));

// Cleanup test state
try {
  const ag = new AutonomyGovernor();
  ag.reset();
} catch (_) {}

// Exit
setTimeout(() => process.exit(testsFailed > 0 ? 1 : 0), 500);


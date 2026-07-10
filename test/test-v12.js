/**
 * BOQA test-v12.js — Integration tests for v1.2 Decision Evolution Layer
 *
 * Tests:
 *   1. EconomicValueEngine: scoring, market factors, risk adjustments, portfolio
 *   2. OpportunityComparator: Pareto frontier, cross-class comparison, profiles
 *   3. DecisionPolicyEngine: policy modes, human approval gate, audit log
 *   4. CapitalAllocatorSim: Monte Carlo, optimization, return surface
 *   5. LiveDecisionRunner: full pipeline, trace graph, dry-run enforcement
 *   6. Cross-module integration: EVM → Comparator → Policy → Allocation → Runner
 *   7. v1.2 guardrails: simulation-only, human gate, audit logging
 *   8. Safe mode constraints verification
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const { EconomicValueEngine, EconomicScore, Opportunity, MARKET_SIZE_BANDS, COMPETITION_LEVELS, OPPORTUNITY_CLASSES } = require('../economic-value-engine');
const { OpportunityComparator, NormalizedOpportunity, ComparisonMatrix, COMPARISON_DIMENSIONS, DECISION_PROFILES } = require('../opportunity-comparator');
const { DecisionPolicyEngine, PolicyDecision, POLICY_MODES, DEFAULT_POLICY_RULES } = require('../decision-policy-engine');
const { CapitalAllocatorSim, AllocationCandidate, AllocationResult, SIM_STATUS } = require('../capital-allocator-sim');
const { LiveDecisionRunner, DecisionRunResult, DecisionTraceGraph, TraceNode, TraceEdge, RUNNER_MODES, TRACE_NODE_TYPES, RUN_STATES } = require('../live-decision-runner');

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
  if (currentSection.length > 0 && currentSectionName) {
    sectionTests.push({ name: currentSectionName, tests: currentSection });
  }
  currentSection = [];
  currentSectionName = name;
}

async function runAll() {
  console.log(`\n╔═══════════════════════════════════════════════════════════════╗`);
  console.log(`║   BOQA v1.2 Decision Evolution Layer — Integration Tests     ║`);
  console.log(`╚═══════════════════════════════════════════════════════════════╝\n`);

  // Archive last section
  if (currentSection.length > 0 && currentSectionName) {
    sectionTests.push({ name: currentSectionName, tests: currentSection });
  }

  const startTime = Date.now();

  for (const section of sectionTests) {
    console.log(`\n── ${section.name} ──`);
    for (const t of section.tests) {
      try {
        await t.fn();
        passCount++;
        console.log(`  ✓ ${t.name}`);
      } catch (err) {
        failCount++;
        console.log(`  ✗ ${t.name}`);
        console.log(`    ${err.message}`);
        if (err.stack) {
          const line = err.stack.split('\n').find(l => l.includes('test-v12'));
          if (line) console.log(`    ${line.trim()}`);
        }
      }
    }
  }

  const duration = Date.now() - startTime;
  console.log(`\n═══════════════════════════════════════════════════════════════`);
  console.log(`  Results: ${passCount} passed, ${failCount} failed (${duration}ms)`);
  console.log(`═══════════════════════════════════════════════════════════════\n`);

  // Cleanup: shutdown all modules to stop timers
  setTimeout(() => process.exit(failCount > 0 ? 1 : 0), 500);
}

// Helper
function approx(a, b, eps = 0.01) {
  return Math.abs(a - b) <= eps;
}

// ═══════════════════════════════════════════════════════════════════════
//  1. EconomicValueEngine
// ═══════════════════════════════════════════════════════════════════════

beginSection('1. EconomicValueEngine');

test('should create engine with defaults', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  assert(eve instanceof EconomicValueEngine);
  assert.strictEqual(eve.metrics.total_opportunities, 0);
  eve.shutdown();
});

test('should register opportunity', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  const opp = eve.registerOpportunity({
    opportunity_class: OPPORTUNITY_CLASSES.SECURITY_BUG_BOUNTY,
    cevi: 65,
    market_size: 100000,
    competition_level: 'MODERATE',
    capital_required: 2000,
    confidence: 0.6,
  });
  assert(opp.id);
  assert.strictEqual(opp.opportunity_class, OPPORTUNITY_CLASSES.SECURITY_BUG_BOUNTY);
  assert.strictEqual(opp.cevi, 65);
  eve.shutdown();
});

test('should register batch of opportunities', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  const opps = eve.registerBatch([
    { cevi: 50, market_size: 50000 },
    { cevi: 70, market_size: 200000 },
    { cevi: 30, market_size: 10000 },
  ]);
  assert.strictEqual(opps.length, 3);
  assert.strictEqual(eve.opportunities.size, 3);
  eve.shutdown();
});

test('should score opportunity with all components', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  const opp = eve.registerOpportunity({
    opportunity_class: OPPORTUNITY_CLASSES.MORPHO_LIQUIDATION,
    cevi: 60,
    market_size: 500000,
    competition_level: 'LOW',
    competition_pressure: 0.05,
    capital_required: 5000,
    time_to_revenue_days: 7,
    confidence: 0.7,
    signal_quality: 0.8,
    coverage: 0.6,
    data_availability: 0.7,
    historical_volatility: 0.2,
    tail_risk: 0.05,
  });
  const score = eve.score(opp.id);

  assert(score instanceof EconomicScore);
  assert(score.normalized_score > 0, `normalized_score should be > 0, got ${score.normalized_score}`);
  assert(score.expected_value > 0, `expected_value should be > 0, got ${score.expected_value}`);
  assert(score.market_factor > 0, 'market_factor should be > 0');
  assert(score.risk_adjusted_penalty >= 0, 'risk_adjusted_penalty should be >= 0');
  assert(score.liquidity_bonus > 0, `liquidity_bonus should be > 0 for ttr=7, got ${score.liquidity_bonus}`);
  assert(score.var_95 >= 0, 'var_95 should be >= 0');
  assert(score.sharpe_ratio !== undefined, 'sharpe_ratio should be defined');
  eve.shutdown();
});

test('should compute market factor from size bands', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });

  const micro = eve.registerOpportunity({ cevi: 50, market_size: 5000 });
  const mega  = eve.registerOpportunity({ cevi: 50, market_size: 50000000 });
  const sMicro = eve.score(micro.id);
  const sMega  = eve.score(mega.id);

  assert(sMega.market_factor > sMicro.market_factor,
    `Mega market factor ${sMega.market_factor} should be > micro ${sMicro.market_factor}`);
  eve.shutdown();
});

test('should apply risk penalty for high volatility', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });

  const safe = eve.registerOpportunity({ cevi: 50, historical_volatility: 0.1, tail_risk: 0.02 });
  const risky = eve.registerOpportunity({ cevi: 50, historical_volatility: 0.8, tail_risk: 0.3 });
  const sSafe = eve.score(safe.id);
  const sRisky = eve.score(risky.id);

  assert(sRisky.risk_adjusted_penalty > sSafe.risk_adjusted_penalty,
    'Risky opportunity should have higher risk penalty');
  eve.shutdown();
});

test('should give liquidity bonus for fast TTR', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });

  const fast = eve.registerOpportunity({ cevi: 50, time_to_revenue_days: 3 });
  const slow = eve.registerOpportunity({ cevi: 50, time_to_revenue_days: 120 });
  const sFast = eve.score(fast.id);
  const sSlow = eve.score(slow.id);

  assert(sFast.liquidity_bonus > sSlow.liquidity_bonus,
    `Fast TTR bonus ${sFast.liquidity_bonus} should be > slow ${sSlow.liquidity_bonus}`);
  eve.shutdown();
});

test('should score all opportunities and rank', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  eve.registerBatch([
    { cevi: 80, market_size: 1000000, competition_level: 'LOW', confidence: 0.8 },
    { cevi: 40, market_size: 50000, competition_level: 'HIGH', confidence: 0.3 },
    { cevi: 60, market_size: 200000, competition_level: 'MODERATE', confidence: 0.6 },
  ]);

  const ranked = eve.scoreAll();
  assert.strictEqual(ranked.length, 3);
  assert(ranked[0].normalized_score >= ranked[1].normalized_score);
  assert(ranked[1].normalized_score >= ranked[2].normalized_score);
  eve.shutdown();
});

test('should compute portfolio summary', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  eve.registerBatch([
    { cevi: 70, market_size: 500000, competition_level: 'LOW', capital_required: 3000 },
    { cevi: 50, market_size: 200000, competition_level: 'MODERATE', capital_required: 2000 },
  ]);
  eve.scoreAll();

  const summary = eve.getPortfolioSummary();
  assert.strictEqual(summary.total_opportunities, 2);
  assert(summary.total_expected_value > 0);
  assert(summary.total_capital_required > 0);
  assert(summary.portfolio_var_95 >= 0);
  eve.shutdown();
});

test('should record outcome and provide feedback', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  const opp = eve.registerOpportunity({ cevi: 60, market_size: 100000 });
  const score = eve.score(opp.id);

  const feedback = eve.recordOutcome(opp.id, { actual_return: 400, actual_cost: 2000 });
  assert(feedback);
  assert.strictEqual(feedback.predicted_ev, score.expected_value);
  assert.strictEqual(feedback.actual_return, 400);
  eve.shutdown();
});

test('should persist and load state', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.registerOpportunity({ cevi: 55, market_size: 75000 });
  eve.scoreAll();
  eve.save();

  const eve2 = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  assert(eve2.opportunities.size >= 1);
  eve.shutdown();
  eve2.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  2. OpportunityComparator
// ═══════════════════════════════════════════════════════════════════════

beginSection('2. OpportunityComparator');

test('should create comparator with defaults', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });
  oc.reset();
  assert.strictEqual(oc.activeProfile, 'BALANCED');
  oc.shutdown();
});

test('should list decision profiles', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });
  const profiles = oc.listProfiles();
  assert(profiles.length >= 5);
  assert(profiles.some(p => p.name === 'BALANCED'));
  assert(profiles.some(p => p.name === 'AGGRESSIVE'));
  oc.shutdown();
});

test('should compare opportunities across classes', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });

  const scores = [
    { opportunity_id: 'opp1', opportunity_class: 'bug_bounty', target_id: 't1',
      expected_value: 5000, risk_adjusted_yield: 1.5, capital_required: 2000,
      time_to_revenue_days: 14, competition_pressure: 0.1, confidence: 0.7 },
    { opportunity_id: 'opp2', opportunity_class: 'defi_yield', target_id: 't2',
      expected_value: 3000, risk_adjusted_yield: 2.0, capital_required: 1000,
      time_to_revenue_days: 7, competition_pressure: 0.05, confidence: 0.8 },
    { opportunity_id: 'opp3', opportunity_class: 'data_api', target_id: 't3',
      expected_value: 8000, risk_adjusted_yield: 0.8, capital_required: 5000,
      time_to_revenue_days: 60, competition_pressure: 0.25, confidence: 0.5 },
  ];

  const matrix = oc.compare(scores);
  assert.strictEqual(matrix.opportunities.length, 3);
  assert(matrix.pareto_frontier.length >= 1, 'Should have at least 1 Pareto optimal');
  assert(matrix.computed_at);
  oc.shutdown();
});

test('should identify Pareto frontier correctly', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });

  // Create a clearly dominant opportunity
  const scores = [
    { opportunity_id: 'dominant', opportunity_class: 'test', target_id: 't1',
      expected_value: 10000, risk_adjusted_yield: 3.0, capital_required: 1000,
      time_to_revenue_days: 3, competition_pressure: 0.02, confidence: 0.95 },
    { opportunity_id: 'weak', opportunity_class: 'test', target_id: 't2',
      expected_value: 500, risk_adjusted_yield: 0.2, capital_required: 5000,
      time_to_revenue_days: 120, competition_pressure: 0.35, confidence: 0.2 },
  ];

  const matrix = oc.compare(scores);
  const dominant = matrix.opportunities.find(o => o.opportunity_id === 'dominant');
  const weak = matrix.opportunities.find(o => o.opportunity_id === 'weak');

  assert(dominant.is_pareto_optimal, 'Dominant should be Pareto optimal');
  assert.strictEqual(dominant.rank, 1);
  assert(dominant.composite_score > weak.composite_score);
  oc.shutdown();
});

test('should compare with different profiles', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });

  const scores = [
    { opportunity_id: 'opp1', opportunity_class: 'test', target_id: 't1',
      expected_value: 5000, risk_adjusted_yield: 0.5, capital_required: 2000,
      time_to_revenue_days: 60, competition_pressure: 0.2, confidence: 0.3 },
    { opportunity_id: 'opp2', opportunity_class: 'test', target_id: 't2',
      expected_value: 2000, risk_adjusted_yield: 2.0, capital_required: 1000,
      time_to_revenue_days: 7, competition_pressure: 0.05, confidence: 0.9 },
  ];

  const conservativeMatrix = oc.compare(scores, 'CONSERVATIVE');
  const aggressiveMatrix = oc.compare(scores, 'AGGRESSIVE');

  // Conservative should weight confidence/risk more, aggressive should weight EV more
  assert(conservativeMatrix.opportunities.length === 2);
  assert(aggressiveMatrix.opportunities.length === 2);
  oc.shutdown();
});

test('should compare across all profiles', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });

  const scores = [
    { opportunity_id: 'opp1', opportunity_class: 'test', target_id: 't1',
      expected_value: 5000, risk_adjusted_yield: 1.5, capital_required: 2000,
      time_to_revenue_days: 14, competition_pressure: 0.1, confidence: 0.7 },
  ];

  const results = oc.compareAcrossProfiles(scores);
  assert(Object.keys(results).length >= 5);
  oc.shutdown();
});

test('should set active profile', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });
  const changed = oc.setProfile('AGGRESSIVE');
  assert(changed);
  assert.strictEqual(oc.getActiveProfile().name, 'AGGRESSIVE');

  const invalid = oc.setProfile('NONEXISTENT');
  assert(!invalid);
  oc.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  3. DecisionPolicyEngine
// ═══════════════════════════════════════════════════════════════════════

beginSection('3. DecisionPolicyEngine');

test('should create engine with default rules', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.reset();
  assert(dpe.policyRules.simulation_only_mode === true);
  assert(dpe.policyRules.human_approval_required_for_deploy === true);
  dpe.shutdown();
});

test('should decide IGNORE or HOLD for low-score opportunities', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.reset();
  const decision = dpe.decide({
    opportunity_id: 'low-opp',
    economic_score: 10,
    risk_score: 5,
    confidence: 0.2,
    competition_level: 'HIGH',
  });
  // v1.3 hardening: low confidence forces HOLD or IGNORE
  assert(['IGNORE', 'HOLD', 'WATCH'].includes(decision.policy),
    `Expected IGNORE/HOLD/WATCH for low score + low confidence, got ${decision.policy}`);
  dpe.shutdown();
});

test('should decide SIMULATE for moderate opportunities (simulation_only_mode)', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.reset();
  const decision = dpe.decide({
    opportunity_id: 'mod-opp',
    economic_score: 55,
    risk_score: 10,
    confidence: 0.6,
    competition_level: 'MODERATE',
  });
  // simulation_only_mode is on, so BUILD/DEPLOY downgrade to SIMULATE
  assert(decision.policy === POLICY_MODES.SIMULATE || decision.policy === POLICY_MODES.WATCH);
  dpe.shutdown();
});

test('should decide WATCH for low-confidence opportunities', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  const decision = dpe.decide({
    opportunity_id: 'watch-opp',
    economic_score: 30,
    risk_score: 5,
    confidence: 0.25,
    competition_level: 'LOW',
  });
  assert(decision.policy === POLICY_MODES.WATCH || decision.policy === POLICY_MODES.SIMULATE);
  dpe.shutdown();
});

test('should enforce human approval gate for DEPLOY', () => {
  const dpe = new DecisionPolicyEngine({
    persistenceIntervalMs: 0,
    policyRules: { ...DEFAULT_POLICY_RULES, simulation_only_mode: false, forbid_autonomous_deploy: false, forbid_live_execution: false },
  });
  dpe.reset();
  dpe.policyRules.simulation_only_mode = false;
  dpe.policyRules.human_approval_required_for_deploy = true;
  dpe.policyRules.forbid_autonomous_deploy = false;
  dpe.policyRules.forbid_live_execution = false;
  dpe.policyRules.min_confidence_for_any_action = 0.0; // Allow all confidence levels for this v1.2 test

  // Without approval — should downgrade
  const withoutApproval = dpe.decide({
    opportunity_id: 'deploy-opp',
    economic_score: 80,
    risk_score: 3,
    confidence: 0.9,
    competition_level: 'LOW',
    var_95: 500,
    human_approval: false,
  });
  assert(withoutApproval.policy !== POLICY_MODES.DEPLOY,
    `Should not DEPLOY without approval, got ${withoutApproval.policy}`);
  assert(withoutApproval.conditions_failed.includes('human_approval') || withoutApproval.constraints.includes('human_approval_required'));

  // With approval — should deploy
  const withApproval = dpe.decide({
    opportunity_id: 'deploy-opp2',
    economic_score: 80,
    risk_score: 3,
    confidence: 0.9,
    competition_level: 'LOW',
    var_95: 500,
    human_approval: true,
  });
  assert.strictEqual(withApproval.policy, POLICY_MODES.DEPLOY,
    `Expected DEPLOY with approval, got ${withApproval.policy}. constraints: ${withApproval.constraints}`);
  dpe.shutdown();
});

test('should grant and revoke human approval', () => {
  const dpe = new DecisionPolicyEngine({
    persistenceIntervalMs: 0,
    policyRules: { ...DEFAULT_POLICY_RULES, simulation_only_mode: false },
  });
  dpe.reset();
  dpe.policyRules.simulation_only_mode = false;
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  dpe.economicValueEngine = eve;

  const opp = eve.registerOpportunity({ cevi: 80, market_size: 500000 });
  eve.score(opp.id);

  dpe.decide({
    opportunity_id: opp.id,
    economic_score: 80,
    risk_score: 3,
    confidence: 0.9,
    competition_level: 'LOW',
    var_95: 500,
  });

  const approved = dpe.grantApproval(opp.id, 'test_operator');
  assert(approved, 'grantApproval should return a decision');
  assert(approved.human_approval, 'Should have human_approval = true');
  assert.strictEqual(approved.approved_by, 'test_operator');

  const revoked = dpe.revokeApproval(opp.id);
  assert(!revoked.human_approval);
  assert(revoked.policy !== POLICY_MODES.DEPLOY);

  eve.shutdown();
  dpe.shutdown();
});

test('should maintain audit log', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.decide({ opportunity_id: 'a1', economic_score: 50, risk_score: 5, confidence: 0.5 });
  dpe.decide({ opportunity_id: 'a2', economic_score: 60, risk_score: 5, confidence: 0.6 });

  const log = dpe.getAuditLog();
  assert(log.length >= 2);
  dpe.shutdown();
});

test('should decide batch', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  const decisions = dpe.decideBatch([
    { opportunity_id: 'b1', economic_score: 10, risk_score: 5, confidence: 0.2 },
    { opportunity_id: 'b2', economic_score: 60, risk_score: 8, confidence: 0.65 },
    { opportunity_id: 'b3', economic_score: 85, risk_score: 3, confidence: 0.9 },
  ]);
  assert.strictEqual(decisions.length, 3);
  dpe.shutdown();
});

test('should produce ranked action portfolio', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.reset();
  dpe.decideBatch([
    { opportunity_id: 'p1', economic_score: 30, risk_score: 5, confidence: 0.3, opportunity_class: 'bug_bounty' },
    { opportunity_id: 'p2', economic_score: 60, risk_score: 8, confidence: 0.65, opportunity_class: 'defi_yield' },
    { opportunity_id: 'p3', economic_score: 10, risk_score: 15, confidence: 0.1, opportunity_class: 'data_api' },
  ]);

  const portfolio = dpe.getRankedActionPortfolio();
  assert.strictEqual(portfolio.length, 3);
  assert('opportunity_id' in portfolio[0]);
  assert('decision' in portfolio[0]);
  assert('economic_score' in portfolio[0]);
  dpe.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  4. CapitalAllocatorSim
// ═══════════════════════════════════════════════════════════════════════

beginSection('4. CapitalAllocatorSim');

test('should create simulator with defaults', () => {
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0 });
  assert.strictEqual(cas.simStatus, SIM_STATUS.IDLE);
  assert.strictEqual(cas.options.monteCarloRounds, 1000);
  cas.shutdown();
});

test('should add allocation candidates', () => {
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0 });
  cas.reset();
  cas.addCandidate({
    opportunity_id: 'c1',
    expected_return: 0.15,
    volatility: 0.3,
    capital_required: 5000,
    liquidity_days: 14,
  });
  assert.strictEqual(cas.candidates.size, 1);
  cas.shutdown();
});

test('should run Monte Carlo simulation', () => {
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, monteCarloRounds: 100 });
  cas.addCandidate({ opportunity_id: 'mc1', expected_return: 0.12, volatility: 0.25, capital_required: 3000 });
  cas.addCandidate({ opportunity_id: 'mc2', expected_return: 0.08, volatility: 0.15, capital_required: 2000 });

  const result = cas.simulate(null, 100);
  assert(result.scenarios.length === 100);
  assert(result.summary instanceof AllocationResult);
  assert(result.summary.simulation_rounds === 100);
  cas.shutdown();
});

test('should produce portfolio metrics', () => {
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, monteCarloRounds: 200 });
  cas.addCandidate({ opportunity_id: 'pm1', expected_return: 0.15, volatility: 0.3, capital_required: 5000 });
  cas.addCandidate({ opportunity_id: 'pm2', expected_return: 0.10, volatility: 0.2, capital_required: 3000 });
  cas.addCandidate({ opportunity_id: 'pm3', expected_return: 0.20, volatility: 0.4, capital_required: 2000 });

  const result = cas.simulate(null, 200);
  const summary = result.summary;

  assert(typeof summary.expected_portfolio_return === 'number');
  assert(typeof summary.portfolio_var_95 === 'number');
  assert(typeof summary.portfolio_sharpe === 'number');
  assert(summary.concentration_score >= 0 && summary.concentration_score <= 1);
  assert(summary.opportunity_count > 0);
  cas.shutdown();
});

test('should optimize allocation', () => {
  const cas = new CapitalAllocatorSim({
    persistenceIntervalMs: 0,
    monteCarloRounds: 50,
    maxOptimizationSteps: 10,
  });
  cas.addCandidate({ opportunity_id: 'opt1', expected_return: 0.15, volatility: 0.25, capital_required: 3000 });
  cas.addCandidate({ opportunity_id: 'opt2', expected_return: 0.10, volatility: 0.15, capital_required: 2000 });

  const result = cas.optimize(5);
  assert(result instanceof AllocationResult);
  assert(Object.keys(result.allocations).length > 0);
  assert.strictEqual(cas.simStatus, SIM_STATUS.COMPLETED);
  cas.shutdown();
});

test('should compute return surface', () => {
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, monteCarloRounds: 50 });
  cas.addCandidate({ opportunity_id: 'rs1', expected_return: 0.15, volatility: 0.3, capital_required: 3000 });
  cas.addCandidate({ opportunity_id: 'rs2', expected_return: 0.08, volatility: 0.1, capital_required: 2000 });

  const surface = cas.computeReturnSurface(5);
  assert.strictEqual(surface.length, 5);
  assert(surface[0].risk_level === 0);
  assert(surface[4].risk_level === 1);
  assert('expected_return' in surface[0]);
  assert('var_95' in surface[0]);
  cas.shutdown();
});

test('should load candidates from EconomicValueEngine', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  eve.registerBatch([
    { cevi: 60, market_size: 100000, capital_required: 3000 },
    { cevi: 70, market_size: 500000, capital_required: 5000 },
  ]);
  eve.scoreAll();

  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, economicValueEngine: eve });
  cas.reset();
  const count = cas.loadFromEngine();
  assert.strictEqual(count, 2);

  eve.shutdown();
  cas.shutdown();
});

test('should apply concentration constraints', () => {
  const cas = new CapitalAllocatorSim({
    persistenceIntervalMs: 0,
    monteCarloRounds: 50,
    maxConcentrationPct: 0.40,
  });
  cas.addCandidate({ opportunity_id: 'cc1', expected_return: 0.15, volatility: 0.3, capital_required: 3000 });
  cas.addCandidate({ opportunity_id: 'cc2', expected_return: 0.10, volatility: 0.2, capital_required: 2000 });

  const result = cas.simulate(null, 50);
  // Check no single allocation exceeds concentration limit
  const weights = result.summary.allocations;
  for (const w of Object.values(weights)) {
    assert(w <= 0.40 + 0.01, `Weight ${w} exceeds concentration limit`);
  }
  cas.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  5. LiveDecisionRunner
// ═══════════════════════════════════════════════════════════════════════

beginSection('5. LiveDecisionRunner');

test('should create runner in DRY_RUN_ONLY mode', () => {
  const runner = new LiveDecisionRunner({ persistenceIntervalMs: 0 });
  assert.strictEqual(runner.metrics.mode, RUNNER_MODES.DRY_RUN);
  runner.shutdown();
});

test('should execute a full decision run', async () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0, economicValueEngine: eve });
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0, economicValueEngine: eve, opportunityComparator: oc });
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, economicValueEngine: eve, monteCarloRounds: 50, maxOptimizationSteps: 3 });
  const runner = new LiveDecisionRunner({
    persistenceIntervalMs: 0,
    economicValueEngine: eve,
    opportunityComparator: oc,
    decisionPolicyEngine: dpe,
    capitalAllocatorSim: cas,
  });

  const opportunitySet = [
    { id: 'run1', opportunity_class: OPPORTUNITY_CLASSES.SECURITY_BUG_BOUNTY,
      cevi: 65, market_size: 100000, competition_level: 'LOW',
      capital_required: 3000, confidence: 0.7 },
    { id: 'run2', opportunity_class: OPPORTUNITY_CLASSES.MORPHO_LIQUIDATION,
      cevi: 45, market_size: 50000, competition_level: 'MODERATE',
      capital_required: 2000, confidence: 0.5 },
  ];

  const result = await runner.run(opportunitySet);
  assert(result instanceof DecisionRunResult);
  assert.strictEqual(result.state, RUN_STATES.COMPLETED);
  assert.strictEqual(result.mode, RUNNER_MODES.DRY_RUN);
  assert(result.opportunities_scored > 0);
  assert(result.ranked_portfolio.length > 0);
  assert(result.trace_graph instanceof DecisionTraceGraph);
  assert(result.duration_ms >= 0);

  eve.shutdown(); oc.shutdown(); dpe.shutdown(); cas.shutdown(); runner.shutdown();
});

test('should produce trace graph with correct node types', async () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0, economicValueEngine: eve });
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0, economicValueEngine: eve, opportunityComparator: oc });
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, economicValueEngine: eve, monteCarloRounds: 30, maxOptimizationSteps: 2 });
  const runner = new LiveDecisionRunner({
    persistenceIntervalMs: 0,
    economicValueEngine: eve,
    opportunityComparator: oc,
    decisionPolicyEngine: dpe,
    capitalAllocatorSim: cas,
  });

  const result = await runner.run([
    { id: 'trace1', opportunity_class: 'test', cevi: 55, market_size: 80000, confidence: 0.6 },
  ]);

  const tg = result.trace_graph;
  assert(tg.nodes.size > 0);
  assert(tg.edges.size > 0);

  const inputNodes = tg.getInputNodes();
  const outputNodes = tg.getOutputNodes();
  assert(inputNodes.length > 0, 'Should have input nodes');
  assert(outputNodes.length > 0, 'Should have output nodes');

  // Check trace back from output
  const tracePath = tg.traceBack(outputNodes[0].id);
  assert(tracePath.length > 0, 'Should be able to trace back from output');

  eve.shutdown(); oc.shutdown(); dpe.shutdown(); cas.shutdown(); runner.shutdown();
});

test('should always run in DRY_RUN_ONLY mode', async () => {
  const runner = new LiveDecisionRunner({ persistenceIntervalMs: 0 });
  const result = await runner.run([
    { id: 'dry1', cevi: 80, market_size: 500000, confidence: 0.9 },
  ]);
  assert.strictEqual(result.mode, RUNNER_MODES.DRY_RUN);
  runner.shutdown();
});

test('should store run history', async () => {
  const runner = new LiveDecisionRunner({ persistenceIntervalMs: 0 });
  await runner.run([{ id: 'h1', cevi: 50, market_size: 50000 }]);
  await runner.run([{ id: 'h2', cevi: 60, market_size: 60000 }]);

  const history = runner.getRunHistory();
  assert(history.length >= 2);

  const latest = runner.getLatestRun();
  assert(latest);
  runner.shutdown();
});

test('should handle empty opportunity set', async () => {
  const runner = new LiveDecisionRunner({ persistenceIntervalMs: 0 });
  const result = await runner.run([]);
  assert.strictEqual(result.state, RUN_STATES.COMPLETED);
  assert.strictEqual(result.opportunities_scored, 0);
  runner.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  6. Cross-Module Integration
// ═══════════════════════════════════════════════════════════════════════

beginSection('6. Cross-Module Integration');

test('should run full v1.2 decision pipeline', async () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.reset();
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0, economicValueEngine: eve });
  oc.reset();
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0, economicValueEngine: eve, opportunityComparator: oc });
  dpe.reset();
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, economicValueEngine: eve, monteCarloRounds: 50, maxOptimizationSteps: 3 });
  cas.reset();
  const runner = new LiveDecisionRunner({
    persistenceIntervalMs: 0,
    economicValueEngine: eve,
    opportunityComparator: oc,
    decisionPolicyEngine: dpe,
    capitalAllocatorSim: cas,
  });

  // Full pipeline: register → score → compare → decide → allocate → run
  const oppSet = [
    { id: 'pipe1', opportunity_class: OPPORTUNITY_CLASSES.POLYEDGE_PREDICTION,
      cevi: 75, market_size: 500000, competition_level: 'LOW', competition_pressure: 0.05,
      capital_required: 5000, time_to_revenue_days: 14, confidence: 0.8,
      signal_quality: 0.8, coverage: 0.7, data_availability: 0.9 },
    { id: 'pipe2', opportunity_class: OPPORTUNITY_CLASSES.MORPHO_LIQUIDATION,
      cevi: 55, market_size: 200000, competition_level: 'MODERATE', competition_pressure: 0.15,
      capital_required: 2000, time_to_revenue_days: 3, confidence: 0.6,
      signal_quality: 0.7, coverage: 0.5, data_availability: 0.6 },
    { id: 'pipe3', opportunity_class: OPPORTUNITY_CLASSES.SEC_ANOMALY_WEBHOOK,
      cevi: 30, market_size: 50000, competition_level: 'HIGH', competition_pressure: 0.25,
      capital_required: 1000, time_to_revenue_days: 60, confidence: 0.35,
      signal_quality: 0.4, coverage: 0.3, data_availability: 0.4 },
  ];

  // Step 1: Score
  for (const opp of oppSet) {
    eve.registerOpportunity(opp);
  }
  const scores = eve.scoreAll();
  assert.strictEqual(scores.length, 3);

  // Step 2: Compare
  const matrix = oc.compare(scores);
  assert(matrix.pareto_frontier.length >= 1);

  // Step 3: Decide policies
  const decisions = dpe.decideBatch(scores.map(s => ({
    opportunity_id: s.opportunity_id,
    economic_score: s.normalized_score,
    risk_score: s.risk_adjusted_penalty,
    confidence: s.confidence,
    competition_level: s.competition_pressure <= 0.05 ? 'LOW' : s.competition_pressure <= 0.15 ? 'MODERATE' : 'HIGH',
    opportunity_class: s.opportunity_class,
    target_id: s.target_id,
  })));
  assert.strictEqual(decisions.length, 3);

  // Step 4: Allocate
  cas.loadFromEngine();
  const allocation = cas.optimize(3);
  assert(allocation.allocations);

  // Step 5: Full run via runner
  const runResult = await runner.run(oppSet);
  assert.strictEqual(runResult.state, RUN_STATES.COMPLETED);
  assert(runResult.ranked_portfolio.length > 0);

  // Pipeline metrics
  assert(eve.metrics.total_scored >= 3, `EVE scored: ${eve.metrics.total_scored}`);
  assert(oc.metrics.total_comparisons >= 1, `OC comparisons: ${oc.metrics.total_comparisons}`);
  assert(dpe.metrics.total_decisions >= 3, `DPE decisions: ${dpe.metrics.total_decisions}`);
  assert(cas.metrics.total_simulations >= 1, `CAS simulations: ${cas.metrics.total_simulations}`);
  assert(runner.metrics.total_runs >= 1, `Runner runs: ${runner.metrics.total_runs}`);

  eve.shutdown(); oc.shutdown(); dpe.shutdown(); cas.shutdown(); runner.shutdown();
});

test('EVE outcome feedback should flow to ConfidenceCalibrator', () => {
  const cal = new (require('../confidence-calibrator')).ConfidenceCalibrator({ persistenceIntervalMs: 0 });
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0, confidenceCalibrator: cal });

  const opp = eve.registerOpportunity({ cevi: 60, market_size: 100000 });
  eve.score(opp.id);
  eve.recordOutcome(opp.id, { actual_return: 500, actual_cost: 2000 });

  // ConfidenceCalibrator should have received an observation
  assert(cal.metrics.total_observations > 0,
    `Expected observations > 0, got ${cal.metrics.total_observations}`);

  eve.shutdown(); cal.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  7. v1.2 Guardrails
// ═══════════════════════════════════════════════════════════════════════

beginSection('7. v1.2 Guardrails');

test('simulation_only_mode should prevent BUILD and DEPLOY', () => {
  const dpe = new DecisionPolicyEngine({
    persistenceIntervalMs: 0,
    policyRules: { ...DEFAULT_POLICY_RULES, simulation_only_mode: true },
  });
  dpe.reset();
  dpe.policyRules.simulation_only_mode = true;

  const highScore = dpe.decide({
    opportunity_id: 'guard1',
    economic_score: 90,
    risk_score: 2,
    confidence: 0.95,
    competition_level: 'NONE',
    var_95: 100,
    human_approval: true,
  });

  assert(highScore.policy !== POLICY_MODES.BUILD, `Should not BUILD in sim-only mode, got ${highScore.policy}`);
  assert(highScore.policy !== POLICY_MODES.DEPLOY, `Should not DEPLOY in sim-only mode, got ${highScore.policy}`);
  assert(highScore.constraints.includes('simulation_only_mode'));
  dpe.shutdown();
});

test('DEPLOY always requires human approval', () => {
  const dpe = new DecisionPolicyEngine({
    persistenceIntervalMs: 0,
    policyRules: { ...DEFAULT_POLICY_RULES, simulation_only_mode: false, human_approval_required_for_deploy: true },
  });

  const noApproval = dpe.decide({
    opportunity_id: 'deploy-check',
    economic_score: 85,
    risk_score: 3,
    confidence: 0.9,
    competition_level: 'LOW',
    var_95: 200,
  });

  if (noApproval.policy === POLICY_MODES.DEPLOY) {
    assert(noApproval.human_approval === true, 'DEPLOY without approval should not happen');
  } else {
    assert(noApproval.conditions_failed.includes('human_approval') || noApproval.constraints.includes('human_approval_required'));
  }
  dpe.shutdown();
});

test('LiveDecisionRunner should always be DRY_RUN_ONLY', () => {
  const runner = new LiveDecisionRunner({ persistenceIntervalMs: 0 });
  assert.strictEqual(RUNNER_MODES.DRY_RUN, 'dry_run_only');
  // There is no way to set any other mode
  assert(!runner.options.mode || runner.options.mode === RUNNER_MODES.DRY_RUN);
  runner.shutdown();
});

test('audit log should be maintained for all decisions', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.decide({ opportunity_id: 'a1', economic_score: 50, risk_score: 5, confidence: 0.5 });
  dpe.decide({ opportunity_id: 'a2', economic_score: 70, risk_score: 3, confidence: 0.8 });

  const log = dpe.getAuditLog();
  assert(log.length >= 2);

  for (const entry of log) {
    assert(entry.action);
    assert(entry.timestamp);
  }
  dpe.shutdown();
});

test('all v1.2 modules should persist and reload', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.registerOpportunity({ cevi: 55, market_size: 75000 });
  eve.scoreAll();
  eve.save();

  const eve2 = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  assert(eve2.opportunities.size >= 1);
  assert(eve2.scores.size >= 1);

  eve.shutdown(); eve2.shutdown();
});

// ═══════════════════════════════════════════════════════════════════════
//  8. v1.2 Expected Metrics Validation
// ═══════════════════════════════════════════════════════════════════════

beginSection('8. v1.2 Expected Metrics Validation');

test('economic scoring should produce normalized scores in [0, 100]', () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  eve.registerBatch([
    { cevi: 90, market_size: 5000000, competition_level: 'NONE', confidence: 0.95 },
    { cevi: 10, market_size: 5000, competition_level: 'SATURATED', confidence: 0.1 },
    { cevi: 50, market_size: 100000, competition_level: 'MODERATE', confidence: 0.5 },
  ]);
  const scores = eve.scoreAll();
  for (const s of scores) {
    assert(s.normalized_score >= 0 && s.normalized_score <= 100,
      `Score ${s.normalized_score} out of range for ${s.opportunity_id}`);
  }
  eve.shutdown();
});

test('Pareto frontier should be subset of all opportunities', () => {
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0 });
  const scores = [
    { opportunity_id: 'm1', opportunity_class: 'test', target_id: 't1',
      expected_value: 3000, risk_adjusted_yield: 1.5, capital_required: 2000,
      time_to_revenue_days: 14, competition_pressure: 0.1, confidence: 0.7 },
    { opportunity_id: 'm2', opportunity_class: 'test', target_id: 't2',
      expected_value: 5000, risk_adjusted_yield: 2.0, capital_required: 1000,
      time_to_revenue_days: 7, competition_pressure: 0.05, confidence: 0.9 },
  ];

  const matrix = oc.compare(scores);
  for (const p of matrix.pareto_frontier) {
    assert(matrix.opportunities.some(o => o.opportunity_id === p.opportunity_id));
  }
  oc.shutdown();
});

test('policy distribution should cover all decided policies', () => {
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0 });
  dpe.reset();
  dpe.decideBatch([
    { opportunity_id: 'd1', economic_score: 10, risk_score: 15, confidence: 0.1 },
    { opportunity_id: 'd2', economic_score: 40, risk_score: 5, confidence: 0.35 },
    { opportunity_id: 'd3', economic_score: 65, risk_score: 8, confidence: 0.7 },
  ]);

  const metrics = dpe.getMetrics();
  assert.strictEqual(metrics.total_decisions, 3);
  assert(Object.keys(metrics.policy_distribution).length > 0);
  dpe.shutdown();
});

test('capital allocation should respect concentration limits', () => {
  const cas = new CapitalAllocatorSim({
    persistenceIntervalMs: 0,
    monteCarloRounds: 50,
    maxConcentrationPct: 0.30,
  });

  // Add 5 candidates
  for (let i = 0; i < 5; i++) {
    cas.addCandidate({
      opportunity_id: `cl${i}`,
      expected_return: 0.10 + Math.random() * 0.1,
      volatility: 0.2 + Math.random() * 0.1,
      capital_required: 2000,
    });
  }

  const result = cas.simulate(null, 50);
  for (const [id, weight] of Object.entries(result.summary.allocations)) {
    assert(weight <= 0.30 + 0.01, `Allocation ${id} = ${weight} exceeds 30% limit`);
  }
  cas.shutdown();
});

test('decision run should produce portfolio with correct output format', async () => {
  const eve = new EconomicValueEngine({ persistenceIntervalMs: 0 });
  const oc = new OpportunityComparator({ persistenceIntervalMs: 0, economicValueEngine: eve });
  const dpe = new DecisionPolicyEngine({ persistenceIntervalMs: 0, economicValueEngine: eve, opportunityComparator: oc });
  const cas = new CapitalAllocatorSim({ persistenceIntervalMs: 0, economicValueEngine: eve, monteCarloRounds: 30, maxOptimizationSteps: 2 });
  const runner = new LiveDecisionRunner({
    persistenceIntervalMs: 0,
    economicValueEngine: eve, opportunityComparator: oc,
    decisionPolicyEngine: dpe, capitalAllocatorSim: cas,
  });

  const result = await runner.run([
    { id: 'fmt1', opportunity_class: OPPORTUNITY_CLASSES.DATA_API_MARKETPLACE,
      cevi: 60, market_size: 200000, confidence: 0.65 },
  ]);

  assert(result.ranked_portfolio.length > 0);
  const entry = result.ranked_portfolio[0];
  assert('opportunity_id' in entry);
  assert('economic_score' in entry);
  assert('risk_score' in entry);
  assert('capital_required' in entry);
  assert('competition_level' in entry);
  assert('time_to_revenue' in entry);
  assert('decision' in entry);
  assert('confidence' in entry);

  eve.shutdown(); oc.shutdown(); dpe.shutdown(); cas.shutdown(); runner.shutdown();
});

// ─── Run ──────────────────────────────────────────────────────────────

runAll();


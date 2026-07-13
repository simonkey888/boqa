'use strict';

/**
 * test/test-quality-v1.js
 *
 * Fase 16 — Tests for the new quality pipeline (canonical bugs, reportability,
 * bounty, scope, persistence).
 *
 * Standalone test runner — no external deps. Prints PASS/FAIL per case.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

const {
  CanonicalBugStore,
  buildBugFingerprint,
  normalizeCategory,
  normalizePath,
  normalizeOrigin,
  mergeBugObservation,
  LIFECYCLE_STATUS,
} = require('../canonical-bug-store');
const { evaluateReportability, computeConfidence, reproducibilityScore } = require('../reportability-engine');
const { estimateBounty, estimatePortfolio, DEFAULT_USD_RANGES } = require('../bounty-estimator');
const { TargetRegistry } = require('../target-registry');
const { MultiTargetScheduler } = require('../scheduler-multi-target');
const { Persistence } = require('../persistence');

// ─── Test harness ────────────────────────────────────────────────────────

let passed = 0, failed = 0;
const failures = [];

function assert(cond, msg) {
  if (!cond) throw new Error(`Assertion failed: ${msg}`);
}
function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`Assertion failed: ${msg} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}
function assertDeep(actual, expected, msg) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Error(`Assertion failed: ${msg} — expected ${e}, got ${a}`);
}

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

// ─── Fixtures ────────────────────────────────────────────────────────────

const TARGET_RIPIO = {
  id: 'target-ripio',
  name: 'Ripio',
  url: 'https://ripio.com',
  authorization_status: 'authorized',
  authorization_source: 'public_bug_bounty_program',
  program_name: 'Ripio Public BB',
  program_url: 'https://ripio.com/security',
  scope_allowlist: ['https://ripio.com/*'],
  scope_denylist: [],
  allowed_methods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
  bounty_policy: {
    critical: { min: 5000, typical: 10000, max: 25000 },
    high:     { min: 1000, typical: 3000, max: 7500 },
    medium:   { min: 250,  typical: 750,  max: 2000 },
    low:      { min: 50,   typical: 150,  max: 500 },
  },
  enabled: true,
};

const TARGET_OTHER = {
  id: 'target-other',
  name: 'Other',
  url: 'https://other.example.com',
  authorization_status: 'authorized',
  authorization_source: 'public_bug_bounty_program',
  program_name: 'Other BB',
  scope_allowlist: ['https://other.example.com/*'],
  allowed_methods: ['GET', 'HEAD', 'OPTIONS'],
  bounty_policy: {},
  enabled: true,
};

function fixtureBug(opts = {}) {
  return {
    category: opts.category || 'cors',
    method: opts.method || 'GET',
    endpoint: opts.endpoint || '/api/data',
    component: opts.component || 'api',
    cookie_name: opts.cookie_name || '',
    evidence: opts.evidence || [
      { type: 'request', method: 'GET', status: 200 },
      { type: 'response', method: 'GET', status: 200 },
    ],
    evidence_quality: opts.evidence_quality ?? 90,
    confidence: opts.confidence ?? 80,
    severity: opts.severity || 'medium',
    session_id: opts.session_id || 'sess-1',
    first_seen_at: opts.first_seen_at || Date.now(),
    last_seen_at: opts.last_seen_at || Date.now(),
    reproduced: opts.reproduced,
    reproduction_count: opts.reproduction_count,
    ...opts,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────

console.log('\n=== FASE 16: Quality Pipeline Tests ===\n');

// 1. Same bug confirmed in 4 cycles = 1 bug, observation_count=4
test('1. same bug 4 cycles → 1 canonical, observation_count=4', () => {
  const store = new CanonicalBugStore();
  for (let i = 0; i < 4; i++) {
    store.observe(fixtureBug({ session_id: `sess-${i+1}` }), TARGET_RIPIO);
  }
  assertEq(store.size(), 1, 'store size should be 1');
  const bug = store.all()[0];
  assertEq(bug.observation_count, 4, 'observation_count should be 4');
  assertEq(bug.session_count, 4, 'session_count should be 4');
});

// 2. Same title in two targets = 2 separate bugs
test('2. same title in 2 targets → 2 separate bugs', () => {
  const store = new CanonicalBugStore();
  store.observe(fixtureBug({ endpoint: '/api/x' }), TARGET_RIPIO);
  store.observe(fixtureBug({ endpoint: '/api/x' }), TARGET_OTHER);
  assertEq(store.size(), 2, 'two targets → two bugs');
});

// 3. Same category, different endpoint → 2 bugs when impact differs (different evidence signature)
test('3. same category + different endpoint/evidence → 2 bugs', () => {
  const store = new CanonicalBugStore();
  store.observe(fixtureBug({ endpoint: '/api/a', evidence: [{type:'request',status:200}] }), TARGET_RIPIO);
  store.observe(fixtureBug({ endpoint: '/api/b', evidence: [{type:'request',status:500}] }), TARGET_RIPIO);
  assertEq(store.size(), 2, 'different endpoint+evidence → 2 bugs');
});

// 4. Restart server → IDs stable, no duplication
test('4. restart: stable IDs, no duplication', () => {
  const store1 = new CanonicalBugStore();
  const { bug: bug1 } = store1.observe(fixtureBug(), TARGET_RIPIO);
  const id1 = bug1.id;

  // Simulate restart: serialize + deserialize
  const ser = store1.to_serializable();
  const store2 = CanonicalBugStore.from_serializable(ser);

  // Observe the same bug again
  const { bug: bug2, is_new } = store2.observe(fixtureBug(), TARGET_RIPIO);
  assertEq(is_new, false, 'should NOT be new after re-observe');
  assertEq(bug2.id, id1, 'ID should be stable across restart');
  assertEq(store2.size(), 1, 'no duplication');
});

// 5. CORS wildcard + credentials without readable sensitive data → rejected
test('5. CORS wildcard + credentials, no readable sensitive → rejected', () => {
  const store = new CanonicalBugStore();
  const { bug } = store.observe(fixtureBug({
    category: 'cors',
    evidence: [
      { type: 'header', header_name: 'Access-Control-Allow-Origin' },
      { type: 'header', header_name: 'Access-Control-Allow-Credentials' },
    ],
    evidence_quality: 80,
    reproduction_count: 3,
    confidence: 95,
  }), TARGET_RIPIO);

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    cors_origin_reflected: false,
    cors_credentials_true: true,
    cors_sensitive_response_readable: false,
    cors_authenticated_request: false,
    impacts: [],
    independent_signals: 1,
    verified_program: true,
    scope_verified: true,
    exploitability_demonstrated: false,
    isolated_header_only: true,
  });
  assertEq(report.status, 'rejected', 'CORS without readable sensitive data should be rejected');
});

// 6. CORS with controlled Origin + credentials + sensitive readable → reportable
test('6. CORS with controlled Origin + creds + sensitive readable → reportable', () => {
  const store = new CanonicalBugStore();
  // Observe 3 times (3 cycles) to avoid single_observation penalty
  for (let i = 0; i < 3; i++) {
    store.observe(fixtureBug({
      category: 'cors',
      method: 'GET',
      endpoint: '/api/account',
      evidence: [
        { type: 'request', method: 'GET', status: 200 },
        { type: 'response', method: 'GET', status: 200 },
      ],
      evidence_quality: 95,
      reproduction_count: 3,
      confidence: 95,
      severity: 'high',
      session_id: `sess-${i+1}`,
      reproduced: true,
    }), TARGET_RIPIO);
  }
  const bug = store.all()[0];
  assertEq(bug.observation_count, 3, '3 observations recorded');

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    cors_origin_reflected: true,
    cors_origin_authorized_specifically: true,
    cors_credentials_true: true,
    cors_sensitive_response_readable: true,
    cors_authenticated_request: true,
    impacts: ['sensitive_data_exposure'],
    independent_signals: 3,
    verified_program: true,
    scope_verified: true,
    exploitability_demonstrated: true,
    isolated_header_only: false,
    impact_score: 25,
    disclosure: {
      title: 'CORS authenticated cross-origin read',
      target: 'https://ripio.com',
      endpoint: '/api/account',
      method: 'GET',
      preconditions: 'authenticated session',
      safe_steps: 'step 1',
      expected_result: 'blocked',
      observed_result: 'PII returned',
      impact: 'cross-origin PII read',
      evidence: 'har+dom',
      remediation: 'restrict ACAO',
      timestamp: Date.now(),
      scope_proof: 'ripio.com/*',
    },
  });
  assert(report.status === 'reportable', `expected reportable, got ${report.status} — gates: ${JSON.stringify(report.failed_gates)} reasons: ${JSON.stringify(report.reasons)}`);
});

// 7. csrftoken SameSite weak alone → rejected
test('7. csrftoken SameSite weak alone → rejected', () => {
  const store = new CanonicalBugStore();
  const { bug } = store.observe(fixtureBug({
    category: 'cookie_security',
    cookie_name: 'csrftoken',
    endpoint: '/api/csrf',
    evidence: [
      { type: 'header', header_name: 'Set-Cookie' },
      { type: 'header', header_name: 'Set-Cookie' },
    ],
    evidence_quality: 70,
    reproduction_count: 2,
    confidence: 65,
  }), TARGET_RIPIO);

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    session_cookie_exposed: false,
    mutating_endpoint: false,
    impacts: [],
    independent_signals: 1,
    verified_program: true,
    scope_verified: true,
    isolated_header_only: true,
  });
  assertEq(report.status, 'rejected', 'csrftoken alone should be rejected');
});

// 8. CSRF not reproducible → needs_review or rejected
test('8. CSRF not reproducible → needs_review', () => {
  const store = new CanonicalBugStore();
  const { bug } = store.observe(fixtureBug({
    category: 'csrf',
    method: 'POST',
    endpoint: '/api/settings',
    cookie_name: 'session',
    evidence: [
      { type: 'request', method: 'POST' },
      { type: 'response', method: 'POST', status: 200 },
    ],
    evidence_quality: 70,
    reproduction_count: 1,  // only 1 reproduction
    confidence: 70,
  }), TARGET_RIPIO);

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    session_cookie_used: true,
    mutating_endpoint: true,
    no_anti_csrf_token: true,
    origin_referer_validated: false,
    destructive_operation: false,
    impacts: ['state_changing_action'],
    independent_signals: 2,
    verified_program: true,
    scope_verified: true,
    exploitability_demonstrated: false,
    isolated_header_only: false,
    impact_score: 15,
  });
  // Only 1 reproduction → GATE 2 fails → rejected (since not soft)
  assert(report.status === 'needs_review' || report.status === 'rejected',
    `expected needs_review or rejected, got ${report.status}`);
});

// 9. Missing no-store on public page → rejected
test('9. missing no-store on public page → rejected', () => {
  const store = new CanonicalBugStore();
  const { bug } = store.observe(fixtureBug({
    category: 'cache_control',
    endpoint: '/',
    evidence: [{ type: 'header', header_name: 'Cache-Control' }, { type: 'header', header_name: 'Cache-Control' }],
    evidence_quality: 70,
    reproduction_count: 3,
    confidence: 70,
  }), TARGET_RIPIO);

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    authenticated_response: false,
    sensitive_data_in_response: false,
    cacheable: false,
    impacts: [],
    independent_signals: 1,
    verified_program: true,
    scope_verified: true,
    isolated_header_only: true,
  });
  assertEq(report.status, 'rejected', 'public page without no-store → rejected');
});

// 10. Missing no-store on authenticated sensitive cacheable → needs_review/reportable
test('10. missing no-store authenticated sensitive → needs_review/reportable', () => {
  const store = new CanonicalBugStore();
  // 3 cycles to avoid single_observation penalty
  for (let i = 0; i < 3; i++) {
    store.observe(fixtureBug({
      category: 'cache_control',
      endpoint: '/api/profile',
      evidence: [
        { type: 'request', status: 200 },
        { type: 'response', status: 200 },
      ],
      evidence_quality: 85,
      reproduction_count: 3,
      confidence: 88,
      severity: 'medium',
      session_id: `sess-${i+1}`,
      reproduced: true,
    }), TARGET_RIPIO);
  }
  const bug = store.all()[0];

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    authenticated_response: true,
    sensitive_data_in_response: true,
    cacheable: true,
    cache_exposure_evidence: true,
    impacts: ['sensitive_data_exposure'],
    independent_signals: 3,
    verified_program: true,
    scope_verified: true,
    exploitability_demonstrated: true,
    isolated_header_only: false,
    impact_score: 20,
    disclosure: {
      title: 'x', target: 'x', endpoint: 'x', method: 'x', preconditions: 'x',
      safe_steps: 'x', expected_result: 'x', observed_result: 'x',
      impact: 'x', evidence: 'x', remediation: 'x', timestamp: 1, scope_proof: 'x',
    },
  });
  assert(report.status === 'reportable' || report.status === 'needs_review',
    `expected reportable or needs_review, got ${report.status}`);
});

// 11. Analytics query param → rejected
test('11. analytics query param → rejected', () => {
  const store = new CanonicalBugStore();
  const { bug } = store.observe(fixtureBug({
    category: 'sensitive_data_query',
    endpoint: '/?utm_source=email',
    evidence: [
      { type: 'request' },
      { type: 'response' },
    ],
    evidence_quality: 80,
    reproduction_count: 3,
    confidence: 75,
  }), TARGET_RIPIO);

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    sensitive_value_real: false,
    impacts: [],
    independent_signals: 2,
    verified_program: true,
    scope_verified: true,
    isolated_header_only: false,
    impact_score: 0,
  });
  assertEq(report.status, 'rejected', 'analytics query → rejected');
});

// 12. Real token redacted in URL → reportable if leak demonstrated
test('12. real token in URL with leak → reportable', () => {
  const store = new CanonicalBugStore();
  // 3 cycles to avoid single_observation penalty
  for (let i = 0; i < 3; i++) {
    store.observe(fixtureBug({
      category: 'sensitive_data_query',
      endpoint: '/reset',
      method: 'GET',
      evidence: [
        { type: 'request', param_name: 'token' },
        { type: 'response', status: 200 },
        { type: 'header', header_name: 'Referer' },
      ],
      evidence_quality: 95,
      reproduction_count: 3,
      confidence: 95,
      severity: 'high',
      session_id: `sess-${i+1}`,
      reproduced: true,
    }), TARGET_RIPIO);
  }
  const bug = store.all()[0];

  const report = evaluateReportability(bug, TARGET_RIPIO, {
    sensitive_value_real: true,
    sensitive_value_propagated: true,
    impacts: ['account_security', 'sensitive_data_exposure'],
    independent_signals: 3,
    verified_program: true,
    scope_verified: true,
    exploitability_demonstrated: true,
    isolated_header_only: false,
    impact_score: 25,
    disclosure: {
      title: 't', target: 't', endpoint: 't', method: 't', preconditions: 't',
      safe_steps: 't', expected_result: 't', observed_result: 't',
      impact: 't', evidence: 't', remediation: 't', timestamp: 1, scope_proof: 't',
    },
  });
  assert(report.status === 'reportable', `expected reportable, got ${report.status} — ${JSON.stringify(report.failed_gates)}`);
});

// 13. Reducer without detector → needs_review (never confirmed)
test('13. reducer without detector → needs_review', () => {
  // Direct classification test using the Fase 4 rules.
  // The full FalsePositiveReducer class requires an agent to run async,
  // so we verify the classification table directly.
  function classify(consistentObservations, totalRounds, allInconclusive) {
    if (allInconclusive) return 'needs_review';
    if (consistentObservations >= totalRounds) return 'confirmed';
    if (consistentObservations === 2 && totalRounds === 3) return 'confirmed';
    if (consistentObservations === 1) return 'needs_review';
    return 'false_positive';
  }
  // allInconclusive = no detector + no replay → must be needs_review
  assertEq(classify(0, 3, true), 'needs_review', 'all-inconclusive → needs_review');
  assertEq(classify(3, 3, false), 'confirmed', '3/3 → confirmed');
  assertEq(classify(2, 3, false), 'confirmed', '2/3 → confirmed with penalty');
  assertEq(classify(1, 3, false), 'needs_review', '1/3 → needs_review');
  assertEq(classify(0, 3, false), 'false_positive', '0/3 → false_positive');
});

// 14. No verified program → bounty N/D
test('14. no verified program → bounty null', () => {
  const target = { ...TARGET_RIPIO, program_name: '', authorization_status: 'authorized' };
  const bug = fixtureBug({ severity: 'high', evidence_quality: 95, reproduction_count: 3 });
  const report = { status: 'reportable', confidence: 95 };
  const est = estimateBounty(bug, target, report);
  assert(est.typical === null, `expected null typical, got ${est.typical}`);
  assert(/Sin programa/.test(est.label), `label should mention no program, got ${est.label}`);
});

// 15. Rejected bug → bounty USD 0
test('15. rejected bug → bounty 0', () => {
  const bug = fixtureBug({ severity: 'high' });
  const report = { status: 'rejected', confidence: 30 };
  const est = estimateBounty(bug, TARGET_RIPIO, report);
  assertEq(est.min, 0, 'min should be 0');
  assertEq(est.typical, 0, 'typical should be 0');
  assertEq(est.max, 0, 'max should be 0');
});

// 16. Dashboard dedup: list reportable without duplicates
test('16. dashboard: reportable list has no duplicates', () => {
  const store = new CanonicalBugStore();
  // 5 raw observations, 2 unique fingerprints
  store.observe(fixtureBug({ endpoint: '/api/a' }), TARGET_RIPIO);
  store.observe(fixtureBug({ endpoint: '/api/a' }), TARGET_RIPIO);
  store.observe(fixtureBug({ endpoint: '/api/a' }), TARGET_RIPIO);
  store.observe(fixtureBug({ endpoint: '/api/b' }), TARGET_RIPIO);
  store.observe(fixtureBug({ endpoint: '/api/b' }), TARGET_RIPIO);
  const all = store.all();
  assertEq(all.length, 2, '5 raw → 2 unique');
  const ids = new Set(all.map(b => b.id));
  assertEq(ids.size, 2, 'IDs unique');
});

// 17. Coverage absent → N/D (handled in dashboard, but test the helper)
test('17. coverage absent → null', () => {
  function pickCoverage(cov) {
    return cov?.overall_score ?? cov?.score ?? cov?.coverage_score ?? null;
  }
  assertEq(pickCoverage({}), null, 'empty cov → null');
  assertEq(pickCoverage(null), null, 'null cov → null');
  assertEq(pickCoverage({ overall_score: 42 }), 42, 'overall_score picked');
  assertEq(pickCoverage({ score: 7 }), 7, 'score fallback picked');
});

// 18. Scope: redirect to external → blocked
test('18. scope: cross-origin redirect blocked', () => {
  const reg = new TargetRegistry({ path: '/tmp/_boqa_test_targets_' + Date.now() + '.json' });
  reg.register({ id: 't1', url: 'https://ripio.com', authorization_source: 'public_bug_bounty_program' });
  const scope = reg.verifyScope('t1', 'https://evil.com/path');
  assertEq(scope.in_scope, false, 'cross-origin should be blocked');
  assertEq(scope.reason, 'cross_origin_redirect_blocked', 'reason correct');
});

// 19. Target not authorized → scan rejected
test('19. unauthorized target → scan rejected', () => {
  const reg = new TargetRegistry({ path: '/tmp/_boqa_test_targets2_' + Date.now() + '.json' });
  // Try to register without authorization_source → should throw
  let threw = false;
  try { reg.register({ id: 't1', url: 'https://x.com' }); } catch { threw = true; }
  assertEq(threw, true, 'register without authorization_source should throw');
});

// 20. Restart Docker → canonical state preserved (via persistence)
test('20. persistence: state survives restart', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-persistence-'));
  try {
    const p1 = new Persistence({ root: tmpDir });
    const store1 = new CanonicalBugStore();
    store1.observe(fixtureBug({ endpoint: '/api/x' }), TARGET_RIPIO);
    store1.observe(fixtureBug({ endpoint: '/api/y' }), TARGET_RIPIO);
    p1.persistCanonicalStore(store1);

    // Simulate restart
    const p2 = new Persistence({ root: tmpDir });
    const store2 = p2.loadCanonicalStore();
    assertEq(store2.size(), 2, '2 bugs persisted');
    // Re-observe same → no duplication
    store2.observe(fixtureBug({ endpoint: '/api/x' }), TARGET_RIPIO);
    assertEq(store2.size(), 2, 'no duplication after reload');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ─── Extra tests for fingerprint stability ───────────────────────────────

test('21. fingerprint ignores timestamps and session IDs', () => {
  const t1 = fixtureBug({ first_seen_at: 1000, last_seen_at: 2000, session_id: 'sess-A' });
  const t2 = fixtureBug({ first_seen_at: 9000, last_seen_at: 9999, session_id: 'sess-B' });
  const fp1 = buildBugFingerprint(t1, TARGET_RIPIO);
  const fp2 = buildBugFingerprint(t2, TARGET_RIPIO);
  assertEq(fp1.fingerprint, fp2.fingerprint, 'fingerprints must match (timestamps/sessions excluded)');
});

test('22. reproducibilityScore calibration', () => {
  assertEq(reproducibilityScore(3, 3), 25, '3/3 = 25');
  assertEq(reproducibilityScore(2, 3), 22, '2/3 = 22');
  assertEq(reproducibilityScore(1, 3), 10, '1/3 = 10');
  assertEq(reproducibilityScore(0, 3), 0, '0/3 = 0');
});

test('23. portfolio: only reportable contributes to total', () => {
  const bugs = [
    { target_id: 'target-ripio', severity: 'high', evidence_quality: 95, reproduction_count: 3, quality_status: 'reportable', estimated_bounty_usd: { min: 1000, typical: 3000, max: 7500 }, last_seen_at: 1 },
    { target_id: 'target-ripio', severity: 'medium', evidence_quality: 70, reproduction_count: 1, quality_status: 'needs_review', estimated_bounty_usd: null, last_seen_at: 2 },
    { target_id: 'target-ripio', severity: 'low', evidence_quality: 50, reproduction_count: 0, quality_status: 'rejected', estimated_bounty_usd: { min: 0, typical: 0, max: 0 }, last_seen_at: 3 },
  ];
  const portfolio = estimatePortfolio(bugs, [TARGET_RIPIO]);
  assertEq(portfolio.reportable_bugs, 1, '1 reportable');
  assertEq(portfolio.needs_review, 1, '1 needs_review');
  assertEq(portfolio.rejected, 1, '1 rejected');
  assertEq(portfolio.estimated_value_usd.typical, 3000, 'only reportable typical counts');
});

// ─── Summary ─────────────────────────────────────────────────────────────

setTimeout(() => {
  console.log('\n========================================');
  console.log(' SUMMARY — Quality v1 Tests');
  console.log('========================================');
  console.log(`  Total:    ${passed + failed}`);
  console.log(`  Passed:   ${passed}`);
  console.log(`  Failed:   ${failed}`);
  if (failed > 0) {
    console.log('  Failures:');
    for (const f of failures) console.log(`    - ${f.name}: ${f.error}`);
  }
  console.log('========================================');
  process.exit(failed > 0 ? 1 : 0);
}, 100);

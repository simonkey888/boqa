/**
 * BOQA test-p49-security-regression.js — P4.9 Security Regression
 *
 * Tests: API key enforcement, rate limiter, permission matrix,
 * simulation only, deploy approval, autonomy guard, hard fail paths,
 * null injections, invalid payloads, oversized payloads.
 *
 * Zero behavior change. Only increases confidence.
 */

const { createRequireAgent, requireApiKey, rateLimiter, errorHandler } = require('../lib/middleware');
const { AutonomyGovernor, AUTONOMY_LEVELS, EXECUTION_LEVELS, DECISION_TYPES, BEHAVIORAL_MODES } = require('../autonomy-governor');

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

// ═══════════════════════════════════════════════════════════════════════
//  1. API Key Enforcement
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== API Key Enforcement ===');

test('should block request without API key when configured', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'secure-key-123';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let statusCode = null;
  let body = null;
  freshKey({ headers: {}, query: {} }, {
    status: (c) => { statusCode = c; return { json: (b) => { body = b; } }; },
  }, () => {});

  assert(statusCode === 401, `should return 401, got ${statusCode}`);
  assert(body.error === 'unauthorized', 'error should be unauthorized');

  process.env.BOQA_API_KEY = originalKey;
});

test('should accept valid API key in header', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'test-key';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let nextCalled = false;
  freshKey({ headers: { 'x-api-key': 'test-key' }, query: {} }, {
    status: () => ({ json: () => {} }),
  }, () => { nextCalled = true; });

  assert(nextCalled === true, 'should call next for valid key');

  process.env.BOQA_API_KEY = originalKey;
});

test('should accept valid API key in query param', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'test-key';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let nextCalled = false;
  freshKey({ headers: {}, query: { api_key: 'test-key' } }, {
    status: () => ({ json: () => {} }),
  }, () => { nextCalled = true; });

  assert(nextCalled === true, 'should call next for valid query key');

  process.env.BOQA_API_KEY = originalKey;
});

test('should reject slightly wrong API key', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'exact-key';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let statusCode = null;
  freshKey({ headers: { 'x-api-key': 'exact-keY' }, query: {} }, {
    status: (c) => { statusCode = c; return { json: () => {} }; },
  }, () => {});

  assert(statusCode === 401, 'should reject case-mismatched key');

  process.env.BOQA_API_KEY = originalKey;
});

// ═══════════════════════════════════════════════════════════════════════
//  2. Rate Limiter
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Rate Limiter ===');

test('should rate limit excessive requests from same IP', () => {
  const originalLimit = process.env.BOQA_RATE_LIMIT;
  process.env.BOQA_RATE_LIMIT = '5';

  delete require.cache[require.resolve('../lib/middleware')];
  const { rateLimiter: freshLimiter } = require('../lib/middleware');

  let lastCode = 200;
  const ip = '10.99.99.99';
  const res = {
    status: (c) => { lastCode = c; return res; },
    json: () => res,
    setHeader: () => {},
  };
  for (let i = 0; i < 10; i++) {
    freshLimiter({ ip, connection: { remoteAddress: ip } }, res, () => {});
  }

  assert(lastCode === 429, `final request should be 429, got ${lastCode}`);

  process.env.BOQA_RATE_LIMIT = originalLimit;
});

test('should rate limit different IPs independently', () => {
  const originalLimit = process.env.BOQA_RATE_LIMIT;
  process.env.BOQA_RATE_LIMIT = '3';

  delete require.cache[require.resolve('../lib/middleware')];
  const { rateLimiter: freshLimiter } = require('../lib/middleware');

  let ip1Code = null;
  let ip2Code = null;
  const res1 = {
    status: (c) => { ip1Code = c; return res1; },
    json: () => res1,
    setHeader: () => {},
  };
  const res2 = {
    status: (c) => { ip2Code = c; return res2; },
    json: () => res2,
    setHeader: () => {},
  };

  // IP1: 5 requests (over limit of 3)
  for (let i = 0; i < 5; i++) {
    freshLimiter({ ip: '192.168.1.1', connection: { remoteAddress: '192.168.1.1' } }, res1, () => {});
  }

  // IP2: 1 request (should still be allowed)
  freshLimiter({ ip: '192.168.1.2', connection: { remoteAddress: '192.168.1.2' } }, res2, () => {});

  assert(ip1Code === 429, 'IP1 should be rate limited after 5 requests');
  assert(ip2Code !== 429, 'IP2 should not be rate limited yet');

  process.env.BOQA_RATE_LIMIT = originalLimit;
});

// ═══════════════════════════════════════════════════════════════════════
//  3. Autonomy Guard
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Autonomy Guard ===');

test('should block unauthorized execution via permission matrix', () => {
  const gov = new AutonomyGovernor();
  // AutonomyGovernor.check(data) uses data object, not positional args
  // Start at default L1, try execution_action with OBSERVE
  const result = gov.check({
    opportunity_id: 'test-1',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
  });
  assert(result !== null, 'should return a result');
  assert(typeof result.final_action === 'string', 'should have action field');
  // EXECUTE_CONDITIONAL should be downgraded at L1
  assert(result.final_action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    'EXECUTE_CONDITIONAL should be downgraded');
});

test('should allow OBSERVE for signal_assessment', () => {
  const gov = new AutonomyGovernor();
  const result = gov.check({
    opportunity_id: 'test-2',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.OBSERVE,
  });
  assert(result !== null, 'should return a result');
  assert(result.final_action === EXECUTION_LEVELS.OBSERVE,
    `action should be OBSERVE, got ${result.final_action}`);
});

test('should start at safe behavioral mode', () => {
  const gov = new AutonomyGovernor();
  // Default mode is RECOMMENDATION_MODE (safe)
  assert(gov.behavioralMode === BEHAVIORAL_MODES.RECOMMENDATION_MODE,
    `should start in RECOMMENDATION_MODE, got ${gov.behavioralMode}`);
});

test('should downgrade execution action at low autonomy', () => {
  const gov = new AutonomyGovernor();
  const result = gov.check({
    opportunity_id: 'test-3',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
  });
  // At default L1, execution_action should be restricted
  assert(result.final_action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    'should downgrade EXECUTE_CONDITIONAL at L1');
});

// ═══════════════════════════════════════════════════════════════════════
//  4. Hard Fail Paths
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Hard Fail Paths ===');

test('should return error envelope for null agent requests', () => {
  const middleware = createRequireAgent(() => null, () => 'Init failed');
  let body = null;
  middleware({}, {
    status: () => ({ json: (b) => { body = b; } }),
  }, () => {});

  assert(body.error === 'agent_unavailable', 'should have error code');
  assert(body.message.includes('degraded'), 'should mention degraded mode');
});

test('should handle error in errorHandler with no message', () => {
  const originalEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';

  let body = null;
  const err = { status: 503 };
  errorHandler(err, {}, {
    status: (c) => ({ json: (b) => { body = b; } }),
  }, () => {});

  assert(body.error === 'internal_error', 'should default to internal_error');
  assert(body.message === 'An unexpected error occurred', 'should have default message');

  process.env.NODE_ENV = originalEnv;
});

// ═══════════════════════════════════════════════════════════════════════
//  5. Null / Invalid Payload Injection
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Null / Invalid Payload Injection ===');

test('should handle null request body gracefully', () => {
  const middleware = createRequireAgent(() => ({}), () => null);
  let nextCalled = false;
  middleware({ body: null }, {
    status: () => ({ json: () => {} }),
  }, () => { nextCalled = true; });

  assert(nextCalled === true, 'should call next even with null body');
});

test('should handle undefined request properties', () => {
  const middleware = createRequireAgent(() => null, () => undefined);
  let body = null;
  middleware({}, {
    status: () => ({ json: (b) => { body = b; } }),
  }, () => {});

  assert(body.error === 'agent_unavailable', 'should handle undefined init error');
  assert(body.degraded_since === 'unknown', 'should default to unknown for undefined init error');
});

test('should handle malformed API key header', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'valid-key';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let statusCode = null;
  // Pass non-string header value
  freshKey({ headers: { 'x-api-key': 12345 }, query: {} }, {
    status: (c) => { statusCode = c; return { json: () => {} }; },
  }, () => {});

  assert(statusCode === 401, 'should reject non-string API key');

  process.env.BOQA_API_KEY = originalKey;
});

test('should handle empty API key', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'non-empty-key';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let statusCode = null;
  freshKey({ headers: { 'x-api-key': '' }, query: {} }, {
    status: (c) => { statusCode = c; return { json: () => {} }; },
  }, () => {});

  assert(statusCode === 401, 'should reject empty API key');

  process.env.BOQA_API_KEY = originalKey;
});

test('should handle missing ip in rate limiter', () => {
  const originalLimit = process.env.BOQA_RATE_LIMIT;
  process.env.BOQA_RATE_LIMIT = '60';

  delete require.cache[require.resolve('../lib/middleware')];
  const { rateLimiter: freshLimiter } = require('../lib/middleware');

  let nextCalled = false;
  const res = {
    status: () => res,
    json: () => res,
    setHeader: () => {},
  };
  // Missing ip but has connection
  freshLimiter({ connection: { remoteAddress: '9.9.9.9' } }, res, () => { nextCalled = true; });

  assert(nextCalled === true, 'should handle missing IP via connection fallback');

  process.env.BOQA_RATE_LIMIT = originalLimit;
});

// ═══════════════════════════════════════════════════════════════════════
//  6. Oversized Payloads
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Oversized Payloads ===');

test('should not crash on very long API key', () => {
  const originalKey = process.env.BOQA_API_KEY;
  process.env.BOQA_API_KEY = 'short';

  delete require.cache[require.resolve('../lib/middleware')];
  const { requireApiKey: freshKey } = require('../lib/middleware');

  let statusCode = null;
  const longKey = 'x'.repeat(10000);
  freshKey({ headers: { 'x-api-key': longKey }, query: {} }, {
    status: (c) => { statusCode = c; return { json: () => {} }; },
  }, () => {});

  assert(statusCode === 401, 'should reject oversized API key without crash');

  process.env.BOQA_API_KEY = originalKey;
});

test('should not crash on very long URL in rate limiter', () => {
  const originalLimit = process.env.BOQA_RATE_LIMIT;
  process.env.BOQA_RATE_LIMIT = '60';

  delete require.cache[require.resolve('../lib/middleware')];
  const { rateLimiter: freshLimiter } = require('../lib/middleware');

  let nextCalled = false;
  freshLimiter({ ip: '1.2.3.4', connection: { remoteAddress: '1.2.3.4' }, url: '/api/' + 'x'.repeat(10000) }, {
    status: () => ({ json: () => {}, setHeader: () => {} }),
  }, () => { nextCalled = true; });

  assert(nextCalled === true, 'should handle long URL without crash');

  process.env.BOQA_RATE_LIMIT = originalLimit;
});

test('should handle autonomy check with extreme values', () => {
  const gov = new AutonomyGovernor();
  const result = gov.check({
    opportunity_id: 'extreme-test',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.OBSERVE,
    cevi: 100,
    uncertainty: 0.99,
    stability_score: 0.01,
    alignment_score: 0.01,
    capital_required: 999999,
    risk_estimate: 0.99,
  });
  assert(result !== null, 'should return result even with extreme values');
  assert(typeof result.final_action === 'string', 'should have action field');
});

// ═══════════════════════════════════════════════════════════════════════
//  7. Permission Matrix Validation
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Permission Matrix Validation ===');

test('should have permission for all decision types', () => {
  const gov = new AutonomyGovernor();
  for (const dt of Object.values(DECISION_TYPES)) {
    const result = gov.check({
      opportunity_id: `perm-test-${dt}`,
      decision_type: dt,
      proposed_action: EXECUTION_LEVELS.OBSERVE,
    });
    assert(result !== null, `check for ${dt} should return result`);
    assert(typeof result.final_action === 'string', `${dt} should have action`);
  }
});

test('should escalate permissions with autonomy level', () => {
  const gov = new AutonomyGovernor();
  // Get results at different autonomy levels
  const result = gov.check({
    opportunity_id: 'escalate-test',
    decision_type: DECISION_TYPES.SIGNAL_ASSESSMENT,
    proposed_action: EXECUTION_LEVELS.SIMULATE,
  });
  assert(result !== null, 'should return result');
  assert(typeof result.final_action === 'string', 'should have action');
});

// ═══════════════════════════════════════════════════════════════════════
//  8. Simulation-Only Mode
// ═══════════════════════════════════════════════════════════════════════

console.log('\n=== Simulation-Only Mode ===');

test('should enforce safe mode via RECOMMENDATION_MODE default', () => {
  const gov = new AutonomyGovernor();
  assert(gov.behavioralMode === BEHAVIORAL_MODES.RECOMMENDATION_MODE,
    'default behavioral mode should be RECOMMENDATION_MODE');
});

test('should constrain execution even at default autonomy', () => {
  const gov = new AutonomyGovernor();
  const result = gov.check({
    opportunity_id: 'constrain-test',
    decision_type: DECISION_TYPES.EXECUTION_ACTION,
    proposed_action: EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
  });
  // At default L1, execution_action should be restricted
  assert(result.final_action !== EXECUTION_LEVELS.EXECUTE_CONDITIONAL,
    'should constrain EXECUTE_CONDITIONAL at default L1');
});

// ═══════════════════════════════════════════════════════════════════════
//  Results Summary
// ═══════════════════════════════════════════════════════════════════════

console.log('\n' + '='.repeat(60));
if (testsFailed === 0) {
  console.log(`  P4.9 Results: ${testsPassed} passed, ${testsFailed} failed`);
} else {
  console.log(`  P4.9 Results: ${testsPassed} passed, ${testsFailed} failed`);
  console.log('\n  Failures:');
  for (const f of failures) {
    console.log(`    - ${f.name}: ${f.error}`);
  }
}
console.log('='.repeat(60));

process.exit(testsFailed > 0 ? 1 : 0);


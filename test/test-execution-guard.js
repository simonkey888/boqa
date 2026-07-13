'use strict';

/**
 * test/test-execution-guard.js
 *
 * P0 SECURITY: Tests for ExecutionAuthorizationGuard + admin gate.
 * All tests use mocks — no real network requests.
 */

const path = require('path');
const { TargetRegistry } = require('../target-registry');
const guard = require('../lib/execution-authorization-guard');
const { createAdminGate } = require('../lib/admin-gate');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); passed++; }
  catch (e) { console.log(`  ✗ ${name}\n    ${e.message}`); failures.push({ name, error: e.message }); failed++; }
}
function assertEq(a, e, m) { if (a !== e) throw new Error(`${m}: expected ${JSON.stringify(e)}, got ${JSON.stringify(a)}`); }
function assert(c, m) { if (!c) throw new Error(m); }

console.log('\n=== Execution Authorization Guard Tests ===\n');

// ─── Fixtures ───────────────────────────────────────────────────────────

function makeRegistry() {
  const reg = new TargetRegistry({ path: '/tmp/_boqa_guard_test_' + Date.now() + '.json' });
  reg.register({
    id: 'target-authorized',
    url: 'https://example.com',
    authorization_status: 'authorized',
    authorization_source: 'public_bug_bounty_program',
    authorization_source_url: 'https://example.com/security',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://example.com/*'],
    allowed_methods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
    enabled: true,
    execution_authorized: true,
  });
  reg.register({
    id: 'target-pending',
    url: 'https://pending.com',
    // pending_verification — no auth fields
  });
  reg.register({
    id: 'target-disabled',
    url: 'https://disabled.com',
    authorization_status: 'authorized',
    authorization_source: 'public_bug_bounty_program',
    authorization_source_url: 'https://disabled.com/security',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://disabled.com/*'],
    enabled: false,
    execution_authorized: true,
  });
  reg.register({
    id: 'target-no-exec',
    url: 'https://noexec.com',
    authorization_status: 'authorized',
    authorization_source: 'public_bug_bounty_program',
    authorization_source_url: 'https://noexec.com/security',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://noexec.com/*'],
    enabled: true,
    execution_authorized: false,
  });
  return reg;
}

// ─── Target authorization ───────────────────────────────────────────────

test('target inexistente → reject', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget('nonexistent', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TARGET_NOT_FOUND', 'code');
});

test('target pending → reject', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget('target-pending', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TARGET_NOT_AUTHORIZED', 'code');
});

test('target disabled → reject', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget('target-disabled', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TARGET_DISABLED', 'code');
});

test('execution_authorized=false → reject', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget('target-no-exec', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TARGET_NOT_EXECUTION_AUTHORIZED', 'code');
});

test('target authorized + enabled + exec → allow', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget('target-authorized', reg);
  assertEq(r.allowed, true, 'should allow');
});

test('target_id vacío → reject', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget('', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TARGET_REQUIRED', 'code');
});

test('target_id null → reject', () => {
  const reg = makeRegistry();
  const r = guard.authorizeTarget(null, reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TARGET_REQUIRED', 'code');
});

// ─── URL validation ─────────────────────────────────────────────────────

test('localhost → reject', () => {
  const r = guard.validateUrlStructure('http://localhost:8080/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'LOCALHOST_BLOCKED', 'code');
});

test('127.0.0.1 → reject', () => {
  const r = guard.validateUrlStructure('http://127.0.0.1/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('::1 → reject', () => {
  const r = guard.validateUrlStructure('http://[::1]/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('10.x.x.x → reject', () => {
  const r = guard.validateUrlStructure('http://10.0.0.1/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('192.168.x.x → reject', () => {
  const r = guard.validateUrlStructure('http://192.168.1.1/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('172.16.x.x → reject', () => {
  const r = guard.validateUrlStructure('http://172.16.0.1/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('169.254.x.x (metadata) → reject', () => {
  const r = guard.validateUrlStructure('http://169.254.169.254/latest/meta-data/');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('userinfo in URL → reject', () => {
  const r = guard.validateUrlStructure('http://user:pass@example.com/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'USERINFO_IN_URL', 'code');
});

test('file:// → reject', () => {
  const r = guard.validateUrlStructure('file:///etc/passwd');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'INVALID_PROTOCOL', 'code');
});

test('ftp:// → reject', () => {
  const r = guard.validateUrlStructure('ftp://example.com/file');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'INVALID_PROTOCOL', 'code');
});

test('0.0.0.0 → reject', () => {
  const r = guard.validateUrlStructure('http://0.0.0.0/test');
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'BLOCKED_IP', 'code');
});

test('valid https URL → allow (structure)', () => {
  const r = guard.validateUrlStructure('https://example.com/api/test');
  assertEq(r.allowed, true, 'should allow');
});

// ─── Scope validation ───────────────────────────────────────────────────

test('URL within scope → allow', () => {
  const reg = makeRegistry();
  const r = guard.validateUrl('target-authorized', 'https://example.com/api/test', reg);
  assertEq(r.allowed, true, 'should allow');
});

test('URL hostname out of scope → reject', () => {
  const reg = makeRegistry();
  const r = guard.validateUrl('target-authorized', 'https://evil.com/api/test', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'HOSTNAME_OUT_OF_SCOPE', 'code');
});

test('URL with target pending → reject', () => {
  const reg = makeRegistry();
  const r = guard.validateUrl('target-pending', 'https://pending.com/test', reg);
  assertEq(r.allowed, false, 'should deny');
});

// ─── Task validation ────────────────────────────────────────────────────

test('task with admin disabled → reject', () => {
  const reg = makeRegistry();
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'false';
  const r = guard.validateTask({ target_id: 'target-authorized', params: { url: 'https://example.com/test' } }, reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'ADMIN_EXECUTION_DISABLED', 'code');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('task with admin enabled + authorized target → allow', () => {
  const reg = makeRegistry();
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  const r = guard.validateTask({ target_id: 'target-authorized', params: { url: 'https://example.com/test' } }, reg);
  assertEq(r.allowed, true, 'should allow');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('task with admin enabled + pending target → reject', () => {
  const reg = makeRegistry();
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  const r = guard.validateTask({ target_id: 'target-pending', params: { url: 'https://pending.com/test' } }, reg);
  assertEq(r.allowed, false, 'should deny');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('task with request_sequence containing localhost → reject', () => {
  const reg = makeRegistry();
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  const r = guard.validateTask({
    target_id: 'target-authorized',
    params: {
      url: 'https://example.com/test',
      request_sequence: [
        { url: 'https://example.com/step1' },
        { url: 'http://localhost:8080/admin' },
      ],
    },
  }, reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'SEQUENCE_STEP_INVALID', 'code');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('task with workflow navigate to metadata → reject', () => {
  const reg = makeRegistry();
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  const r = guard.validateTask({
    target_id: 'target-authorized',
    params: {
      steps: [
        { action: 'navigate', url: 'https://example.com/page' },
        { action: 'navigate', url: 'http://169.254.169.254/meta-data' },
      ],
    },
  }, reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'WORKFLOW_STEP_INVALID', 'code');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('task null → reject', () => {
  const reg = makeRegistry();
  const r = guard.validateTask(null, reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'TASK_REQUIRED', 'code');
});

// ─── Admin gate middleware ──────────────────────────────────────────────

test('admin gate: BOQA_ADMIN_EXECUTION_ENABLED absent → 403 on POST', () => {
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  const gate = createAdminGate();
  let status = null;
  const req = { method: 'POST' };
  const res = { status(s) { status = s; return this; }, json() {} };
  gate(req, res, () => {});
  assertEq(status, 403, 'should return 403');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('admin gate: false → 403 on POST', () => {
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'false';
  const gate = createAdminGate();
  let status = null;
  const req = { method: 'POST' };
  const res = { status(s) { status = s; return this; }, json() {} };
  gate(req, res, () => {});
  assertEq(status, 403, 'should return 403');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('admin gate: true → allows POST through', () => {
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  const gate = createAdminGate();
  let called = false;
  const req = { method: 'POST' };
  const res = { status() { return this; }, json() {} };
  gate(req, res, () => { called = true; });
  assertEq(called, true, 'should call next()');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('admin gate: false → allows GET through', () => {
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'false';
  const gate = createAdminGate();
  let called = false;
  const req = { method: 'GET' };
  const res = { status() { return this; }, json() {} };
  gate(req, res, () => { called = true; });
  assertEq(called, true, 'should call next() for GET');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

// ─── Redirect validation ────────────────────────────────────────────────

test('redirect to in-scope URL → allow', () => {
  const reg = makeRegistry();
  const origEnv = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  const r = guard.validateRedirect('target-authorized', 'https://example.com/page1', 'https://example.com/page2', reg);
  assertEq(r.allowed, true, 'should allow');
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = origEnv;
});

test('redirect to out-of-scope hostname → reject', () => {
  const reg = makeRegistry();
  const r = guard.validateRedirect('target-authorized', 'https://example.com/page1', 'https://evil.com/page2', reg);
  assertEq(r.allowed, false, 'should deny');
  assertEq(r.code, 'REDIRECT_OUT_OF_SCOPE', 'code');
});

test('redirect to localhost → reject', () => {
  const reg = makeRegistry();
  const r = guard.validateRedirect('target-authorized', 'https://example.com/page1', 'http://localhost:8080/admin', reg);
  assertEq(r.allowed, false, 'should deny');
});

// ─── Summary ────────────────────────────────────────────────────────────

setTimeout(() => {
  console.log('\n========================================');
  console.log(' SUMMARY — Execution Guard Tests');
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

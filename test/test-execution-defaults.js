'use strict';

/**
 * Execution-default regression tests. Each config assertion runs in a fresh
 * process so Node's module cache and previous environment mutations cannot
 * mask the effective default.
 */

const { spawnSync } = require('child_process');
const path = require('path');
const { createAdminGate } = require('../lib/admin-gate');
const executionGuard = require('../lib/execution-authorization-guard');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (error) {
    console.log(`  ✗ ${name}\n    ${error.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function readAutoAnalyze(value) {
  const env = { ...process.env };
  if (value === undefined) delete env.BOQA_AUTO_ANALYZE;
  else env.BOQA_AUTO_ANALYZE = value;

  const script = "process.stdout.write(String(require('./lib/config').CONFIG.autoAnalyze))";
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    env,
    encoding: 'utf8',
  });
  if (result.status !== 0) throw new Error(result.stderr || `config subprocess exited ${result.status}`);
  return result.stdout.trim();
}

function adminPostStatus(value) {
  const previous = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  if (value === undefined) delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  else process.env.BOQA_ADMIN_EXECUTION_ENABLED = value;

  let status = null;
  const gate = createAdminGate();
  gate(
    { method: 'POST' },
    { status(code) { status = code; return this; }, json() {} },
    () => { status = 200; },
  );

  if (previous === undefined) delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  else process.env.BOQA_ADMIN_EXECUTION_ENABLED = previous;
  return status;
}

console.log('\n=== Automatic Execution Defaults ===\n');

test('BOQA_AUTO_ANALYZE absent defaults to false', () => {
  assertEqual(readAutoAnalyze(undefined), 'false', 'autoAnalyze default');
});

test('BOQA_AUTO_ANALYZE=false remains false', () => {
  assertEqual(readAutoAnalyze('false'), 'false', 'explicit false');
});

test('BOQA_AUTO_ANALYZE=true explicitly enables analysis', () => {
  assertEqual(readAutoAnalyze('true'), 'true', 'explicit true');
});

test('admin execution absent blocks mutating API execution', () => {
  assertEqual(adminPostStatus(undefined), 403, 'absent admin flag');
  const result = executionGuard.validateTask({ action: 'navigation', target_id: 'fixture', params: { url: 'https://fixture.invalid/' } }, null);
  assertEqual(result.code, 'ADMIN_EXECUTION_DISABLED', 'guard result');
});

test('BOQA_ADMIN_EXECUTION_ENABLED=false blocks mutating API execution', () => {
  assertEqual(adminPostStatus('false'), 403, 'explicit false admin flag');
  const result = executionGuard.validateTask(
    { action: 'navigation', target_id: 'fixture', params: { url: 'https://fixture.invalid/' } },
    null,
    { adminExecutionEnabled: false },
  );
  assertEqual(result.code, 'ADMIN_EXECUTION_DISABLED', 'guard result');
});

test('package-lock.json has no working-tree changes', () => {
  const result = spawnSync('git', ['diff', '--exit-code', '--', 'package-lock.json'], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
  assertEqual(result.status, 0, 'package-lock.json diff');
});

console.log(`\nTotal: ${passed + failed}  Passed: ${passed}  Failed: ${failed}`);
process.exit(failed ? 1 : 0);

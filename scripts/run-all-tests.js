#!/usr/bin/env node
/**
 * BOQA v1.4.0 — Test runner
 *
 * Executes every test-*.js file under test/ as a standalone Node.js process,
 * captures stdout/stderr/exit-code, and prints a summary.
 *
 * Usage:
 *   node scripts/run-all-tests.js            # run all tests
 *   node scripts/run-all-tests.js --quick    # stop on first failure
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const TEST_DIR = path.resolve(__dirname, '..', 'test');
const PROJECT_ROOT = path.resolve(__dirname, '..');

const argv = process.argv.slice(2);
const stopOnFirstFail = argv.includes('--quick') || argv.includes('--stop-on-fail');

// Discover tests
if (!fs.existsSync(TEST_DIR)) {
  console.error(`[run-all-tests] Test directory not found: ${TEST_DIR}`);
  process.exit(2);
}

const testFiles = fs
  .readdirSync(TEST_DIR)
  .filter((f) => f.startsWith('test-') && f.endsWith('.js'))
  .sort();

if (testFiles.length === 0) {
  console.error(`[run-all-tests] No test-*.js files found in ${TEST_DIR}`);
  process.exit(2);
}

console.log(`\n========================================`);
console.log(` BOQA v1.4.0 — Test Runner`);
console.log(` ${testFiles.length} tests discovered`);
console.log(`========================================\n`);

const results = [];
let passed = 0;
let failed = 0;
let errored = 0;
let skipped = 0;

const startTime = Date.now();

for (const file of testFiles) {
  const fullPath = path.join(TEST_DIR, file);
  const t0 = Date.now();
  process.stdout.write(`▶ ${file.padEnd(45)} `);

  const res = spawnSync('node', [fullPath], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
    timeout: 120000, // 2 min per test
    env: {
      ...process.env,
      NODE_ENV: 'test',
      BOQA_API_KEY: process.env.BOQA_API_KEY || 'test-key',
    },
  });

  const dt = Date.now() - t0;
  const status =
    res.status === 0 ? 'PASS' : res.status === null ? 'TIMEOUT' : res.status === 143 ? 'SKIPPED' : 'FAIL';

  // Capture last meaningful stderr/stdout line for context
  let detail = '';
  if (status !== 'PASS') {
    const tail = (res.stderr || res.stdout || '').trim().split('\n').slice(-3).join(' | ');
    detail = ` — ${tail.slice(0, 200)}`;
  }

  console.log(`[${status}] ${dt}ms${detail}`);

  results.push({ file, status, ms: dt, signal: res.signal, stderr: res.stderr || '', stdout: res.stdout || '' });

  if (status === 'PASS') passed++;
  else if (status === 'SKIPPED') skipped++;
  else if (status === 'TIMEOUT') errored++;
  else failed++;

  if (stopOnFirstFail && status === 'FAIL') {
    console.log(`\n[run-all-tests] --quick: stopping on first failure.\n`);
    break;
  }
}

const totalDt = Date.now() - startTime;

console.log(`\n========================================`);
console.log(` SUMMARY`);
console.log(`========================================`);
console.log(`  Total:    ${results.length}`);
console.log(`  Passed:   ${passed}`);
console.log(`  Failed:   ${failed}`);
console.log(`  Errored:  ${errored}`);
console.log(`  Skipped:  ${skipped}`);
console.log(`  Time:     ${(totalDt / 1000).toFixed(1)}s`);
console.log(`========================================\n`);

// Print full stderr for failures (for debugging)
if (failed > 0 || errored > 0) {
  console.log(`--- Failure details ---\n`);
  for (const r of results) {
    if (r.status === 'FAIL' || r.status === 'TIMEOUT') {
      console.log(`\n>>> ${r.file} (${r.status}, ${r.ms}ms)`);
      console.log(`--- stdout (last 30 lines) ---`);
      console.log(r.stdout.split('\n').slice(-30).join('\n'));
      console.log(`--- stderr (last 50 lines) ---`);
      console.log(r.stderr.split('\n').slice(-50).join('\n'));
    }
  }
}

process.exit(failed + errored > 0 ? 1 : 0);

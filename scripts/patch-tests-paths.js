#!/usr/bin/env node
/**
 * Patch test files to require modules from project root instead of test/ dir.
 *
 * The 8 recovered tests use `require('./memory-graph')` etc., which fails
 * because Node resolves relative to the test file's location (test/), not
 * the project root. This script rewrites those requires to
 * `require('../memory-graph')` so they resolve correctly.
 *
 * Idempotent: if a test is already patched, it's a no-op.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TEST_DIR = path.join(ROOT, 'test');

const TESTS_TO_PATCH = [
  'test-p41-legacy-modules.js',
  'test-p42-degraded-mode.js',
  'test-p43-persistence-isolation.js',
  'test-p44-api-regression.js',
  'test-p45-event-bus.js',
  'test-p46-concurrency.js',
  'test-p47-memory-leaks.js',
  'test-p48-long-running.js',
  'test-p49-security-regression.js',
  'test-p410-golden-regression.js',
  'test-p5-replay-time-machine.js',
  'test-v09.js',
  'test-v11.js',
  'test-v12.js',
  'test-v13.js',
  'test-v14.js',
];

// Match require('...') or require.resolve('...') where the path starts with ./
// but NOT ../ (already relative-up).
// Capture the inside quotes so we can rewrite.
const REQUIRE_RE = /((?:require|require\.resolve)\(\s*)['"]\.\/([^'"]+)['"](\s*\))/g;

function patchTest(file) {
  const fullPath = path.join(TEST_DIR, file);
  if (!fs.existsSync(fullPath)) {
    console.log(`  ⊘ ${file}  (not found)`);
    return false;
  }

  const original = fs.readFileSync(fullPath, 'utf8');
  let count = 0;

  const patched = original.replace(REQUIRE_RE, (match, prefix, modPath, suffix) => {
    // Skip if it's already a ../path
    if (modPath.startsWith('..')) return match;
    count++;
    return `${prefix}'../${modPath}'${suffix}`;
  });

  if (count === 0) {
    console.log(`  ✓ ${file}  (no ./requires found, already patched or no-op)`);
    return false;
  }

  fs.writeFileSync(fullPath, patched, 'utf8');
  console.log(`  ↻ ${file}  (${count} requires rewritten: ./ → ../)`);
  return true;
}

console.log(`\nPatching ${TESTS_TO_PATCH.length} test files...\n`);
let patched = 0;
for (const f of TESTS_TO_PATCH) {
  if (patchTest(f)) patched++;
}
console.log(`\nDone: ${patched} files patched.\n`);

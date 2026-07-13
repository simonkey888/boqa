'use strict';

/**
 * test/test-real-migration.js
 *
 * FASE H extra — Tests against the real (sanitized) migration input.
 * These tests verify:
 *   1. Migration produces deterministic counts across runs
 *   2. Two runs produce exactly the same result
 *   3. Input remains unchanged after migration
 *
 * The input lives at /home/z/my-project/boqa-real-migration-input
 * (downloaded from boqa-recovery:/var/lib/boqa/output-quality-work-*).
 */

const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

const INPUT_DIR = '/home/z/my-project/boqa-real-migration-input';
const REAL_INPUT_AVAILABLE = fs.existsSync(INPUT_DIR) &&
  fs.existsSync(path.join(INPUT_DIR, 'verifications'));

let passed = 0, failed = 0;
const failures = [];

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

function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`Assertion failed: ${msg} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

console.log('\n=== FASE H: Real Migration Tests ===\n');

if (!REAL_INPUT_AVAILABLE) {
  console.log('  (skipped — real migration input not present at /home/z/my-project/boqa-real-migration-input)');
  console.log('\n========================================');
  console.log(' SUMMARY — Real Migration Tests');
  console.log('========================================');
  console.log('  Skipped: 1 (no real input)');
  console.log('  Passed:  0');
  console.log('  Failed:  0');
  process.exit(0);
}

// Helper: compute aggregated hash of input dir
function aggregatedHash(dir) {
  const out = execFileSync('bash', ['-c',
    `cd "${dir}" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'`
  ]).toString().trim();
  return out;
}

// Helper: run migration dry-run
function runMigration(outputDir) {
  const args = [
    'scripts/migrate-canonical-bugs.js',
    '--input', INPUT_DIR,
    '--output', outputDir,
    '--dry-run',
  ];
  const stdout = execFileSync('node', args, { cwd: '/home/z/my-project/boqa-dev' }).toString();
  // Parse the JSON report at the end (after the [migrate] stderr lines, look for second JSON block)
  const jsonStart = stdout.lastIndexOf('{');
  const jsonEnd = stdout.lastIndexOf('}');
  if (jsonStart < 0 || jsonEnd < 0) throw new Error('could not parse JSON from migration output');
  return JSON.parse(stdout.substring(jsonStart, jsonEnd + 1));
}

test('1. migration produces expected counts on real input', () => {
  const out1 = runMigration('/tmp/boqa-migration-test-run1');
  assertEq(out1.raw_observations, 341, 'raw_observations should be 341');
  assertEq(out1.unique_candidates, 5, 'unique_candidates should be 5 (matches original 5 titles)');
  assertEq(out1.reportable, 0, 'reportable should be 0 (no authorized target)');
  assertEq(out1.duplicate_reduction_pct, 99, 'duplicate_reduction_pct should be 99');
});

test('2. two runs produce exactly the same result', () => {
  const out1 = runMigration('/tmp/boqa-migration-test-run1');
  const out2 = runMigration('/tmp/boqa-migration-test-run2');
  // Strip non-deterministic fields (migration_at timestamp, output_dir path)
  const deterministic1 = { ...out1 };
  delete deterministic1.migration_at;
  delete deterministic1.output_dir;
  const deterministic2 = { ...out2 };
  delete deterministic2.migration_at;
  delete deterministic2.output_dir;
  assertEq(JSON.stringify(deterministic1), JSON.stringify(deterministic2), 'two runs should produce identical deterministic counts');
});

test('3. input remains unchanged after migration', () => {
  const before = aggregatedHash(INPUT_DIR);
  runMigration('/tmp/boqa-migration-test-run3');
  const after = aggregatedHash(INPUT_DIR);
  assertEq(before, after, 'aggregated hash of input must not change');
});

test('4. four repetitions of same observation produce 1 canonical bug', () => {
  // Pull one of the confirmed-bugs JSON files and run it through the canonical store 4 times
  const verificationsDir = path.join(INPUT_DIR, 'verifications');
  const files = fs.readdirSync(verificationsDir).filter(f => f.startsWith('confirmed-bugs-'));
  if (files.length === 0) throw new Error('no confirmed-bugs files in real input');
  const data = JSON.parse(fs.readFileSync(path.join(verificationsDir, files[0]), 'utf-8'));
  // Extract a single bug observation
  const bugs = Array.isArray(data) ? data : (data.bugs || data.confirmed_bugs || []);
  if (bugs.length === 0) throw new Error('no bugs in first confirmed-bugs file');
  const sampleBug = bugs[0];

  const { CanonicalBugStore } = require('../canonical-bug-store');
  const store = new CanonicalBugStore();
  const target = {
    id: 'test-target',
    url: 'https://test.example.com',
    authorization_status: 'authorized',
    authorization_source: 'public_bug_bounty_program',
    authorization_source_url: 'https://test.example.com/security',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://test.example.com/*'],
    enabled: true,
  };
  for (let i = 0; i < 4; i++) {
    store.observe({ ...sampleBug, session_id: `sess-${i+1}` }, target);
  }
  assertEq(store.size(), 1, '4 observations of same bug → 1 canonical');
  const bug = store.all()[0];
  assertEq(bug.observation_count, 4, 'observation_count should be 4');
});

test('5. same finding on different targets → 2 separate bugs', () => {
  const verificationsDir = path.join(INPUT_DIR, 'verifications');
  const files = fs.readdirSync(verificationsDir).filter(f => f.startsWith('confirmed-bugs-'));
  const data = JSON.parse(fs.readFileSync(path.join(verificationsDir, files[0]), 'utf-8'));
  const bugs = Array.isArray(data) ? data : (data.bugs || data.confirmed_bugs || []);
  if (bugs.length === 0) throw new Error('no bugs available');
  const sampleBug = bugs[0];

  const { CanonicalBugStore } = require('../canonical-bug-store');
  const store = new CanonicalBugStore();
  const target1 = {
    id: 'target-a', url: 'https://a.example.com',
    authorization_status: 'authorized', authorization_source: 'x',
    authorization_source_url: 'https://a.example.com/sec',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://a.example.com/*'], enabled: true,
  };
  const target2 = {
    id: 'target-b', url: 'https://b.example.com',
    authorization_status: 'authorized', authorization_source: 'x',
    authorization_source_url: 'https://b.example.com/sec',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://b.example.com/*'], enabled: true,
  };
  store.observe(sampleBug, target1);
  store.observe(sampleBug, target2);
  assertEq(store.size(), 2, 'same bug on 2 targets → 2 canonical bugs');
});

test('6. pending_verification target → scheduler rejects', () => {
  const { TargetRegistry } = require('../target-registry');
  const reg = new TargetRegistry({ path: '/tmp/_boqa_real_test_targets_' + Date.now() + '.json' });
  reg.register({ id: 'pending-target', url: 'https://pending.example.com' });
  const target = reg.get('pending-target');
  assertEq(reg.isExecutable(target), false, 'pending_verification target must NOT be executable');

  const { MultiTargetScheduler } = require('../scheduler-multi-target');
  const sched = new MultiTargetScheduler({ registry: reg });
  // pickNext should return null because no executable targets
  const next = sched.pickNext();
  assertEq(next, null, 'pickNext should return null with no executable targets');
});

// Summary
setTimeout(() => {
  console.log('\n========================================');
  console.log(' SUMMARY — Real Migration Tests');
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

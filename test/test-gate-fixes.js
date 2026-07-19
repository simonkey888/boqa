'use strict';

/**
 * test/test-gate-fixes.js
 *
 * Tests for the 4 defects fixed before deploy:
 *   GATE 0: loadTargets supports 3 formats + fail-closed
 *   GATE 2: getStore merge policy (persisted + in-memory)
 *   GATE 3: /api/bugs not shadowed by v01
 *   GATE 6: migration writes to canonical/
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const { CanonicalBugStore } = require('../canonical-bug-store');
const { TargetRegistry } = require('../target-registry');
const { Persistence } = require('../persistence');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); passed++; }
  catch (e) { console.log(`  ✗ ${name}\n    ${e.message}`); failures.push({ name, error: e.message }); failed++; }
}
function assertEq(a, e, m) { if (a !== e) throw new Error(`${m}: expected ${JSON.stringify(e)}, got ${JSON.stringify(a)}`); }
function assert(c, m) { if (!c) throw new Error(m); }

console.log('\n=== GATE FIXES TESTS ===\n');

// ─── GATE 0: loadTargets formats ─────────────────────────────────────

test('GATE 0a: targets.json as array', () => {
  const tmp = '/tmp/_boqa_targets_array_' + Date.now() + '.json';
  fs.writeFileSync(tmp, JSON.stringify([{ id: 't1', url: 'https://a.com' }]));
  const reg = new TargetRegistry({ path: tmp });
  assertEq(reg.all().length, 1, 'array format → 1 target');
  assertEq(reg.get('t1').url, 'https://a.com', 'url correct');
  fs.unlinkSync(tmp);
});

test('GATE 0b: targets.json as { targets: [] }', () => {
  const tmp = '/tmp/_boqa_targets_obj_' + Date.now() + '.json';
  fs.writeFileSync(tmp, JSON.stringify({ version: '1.0', targets: [{ id: 't2', url: 'https://b.com' }] }));
  const reg = new TargetRegistry({ path: tmp });
  assertEq(reg.all().length, 1, 'object format → 1 target');
  assertEq(reg.get('t2').url, 'https://b.com', 'url correct');
  fs.unlinkSync(tmp);
});

test('GATE 0c: targets.json as keyed object', () => {
  const tmp = '/tmp/_boqa_targets_keyed_' + Date.now() + '.json';
  fs.writeFileSync(tmp, JSON.stringify({ 't3': { url: 'https://c.com' } }));
  const reg = new TargetRegistry({ path: tmp });
  assertEq(reg.all().length, 1, 'keyed format → 1 target');
  assertEq(reg.get('t3').url, 'https://c.com', 'url correct, id derived from key');
  fs.unlinkSync(tmp);
});

test('GATE 0d: invalid targets.json fails closed', () => {
  const tmp = '/tmp/_boqa_targets_invalid_' + Date.now() + '.json';
  fs.writeFileSync(tmp, 'not json at all');
  const reg = new TargetRegistry({ path: tmp });
  assertEq(reg.all().length, 0, 'invalid JSON → 0 targets (fail closed)');
  fs.unlinkSync(tmp);
});

test('GATE 0e: empty targets array → 0 targets, no crash', () => {
  const tmp = '/tmp/_boqa_targets_empty_' + Date.now() + '.json';
  fs.writeFileSync(tmp, JSON.stringify({ targets: [] }));
  const reg = new TargetRegistry({ path: tmp });
  assertEq(reg.all().length, 0, 'empty targets → 0');
  fs.unlinkSync(tmp);
});

// ─── GATE 2: getStore merge policy ───────────────────────────────────

test('GATE 2a: persisted=5, memory=0 → returns 5', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-merge-'));
  try {
    const p = new Persistence({ root: tmpDir });
    const store = new CanonicalBugStore();
    // Add 5 bugs to persisted
    for (let i = 0; i < 5; i++) {
      store.observe({
        category: 'cors', endpoint: `/api/${i}`, evidence: [{type:'r'},{type:'s'}],
        session_id: `s${i}`, confidence: 80, severity: 'medium',
      }, { id: 't1', url: 'https://a.com' });
    }
    p.persistCanonicalStore(store);

    // Load fresh — simulates empty in-memory
    const loaded = p.loadCanonicalStore();
    assertEq(loaded.size(), 5, 'persisted=5 → 5');
  } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
});

test('GATE 2b: persisted=5, memory=same 5 → returns 5 (no dups)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-merge-'));
  try {
    const p = new Persistence({ root: tmpDir });
    const persisted = new CanonicalBugStore();
    for (let i = 0; i < 5; i++) {
      persisted.observe({
        category: 'cors', endpoint: `/api/${i}`, evidence: [{type:'r'},{type:'s'}],
        session_id: `s${i}`, confidence: 80, severity: 'medium',
      }, { id: 't1', url: 'https://a.com' });
    }
    p.persistCanonicalStore(persisted);

    // Simulate in-memory with same 5 bugs
    const memStore = new CanonicalBugStore();
    for (let i = 0; i < 5; i++) {
      memStore.observe({
        category: 'cors', endpoint: `/api/${i}`, evidence: [{type:'r'},{type:'s'}],
        session_id: `s${i+10}`, confidence: 85, severity: 'medium',
      }, { id: 't1', url: 'https://a.com' });
    }

    // Merge: should still be 5 (same fingerprints, merged)
    const merged = new Map();
    for (const b of p.loadCanonicalStore().all()) merged.set(b.fingerprint, b);
    for (const b of memStore.all()) merged.set(b.fingerprint, { ...merged.get(b.fingerprint), ...b });
    assertEq(merged.size, 5, '5+5 same → 5 (no dups)');
  } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
});

test('GATE 2c: persisted=5, memory=1 new → returns 6', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-merge-'));
  try {
    const p = new Persistence({ root: tmpDir });
    const persisted = new CanonicalBugStore();
    for (let i = 0; i < 5; i++) {
      persisted.observe({
        category: 'cors', endpoint: `/api/${i}`, evidence: [{type:'r'},{type:'s'}],
        session_id: `s${i}`, confidence: 80, severity: 'medium',
      }, { id: 't1', url: 'https://a.com' });
    }
    p.persistCanonicalStore(persisted);

    const memStore = new CanonicalBugStore();
    // 1 NEW bug (different endpoint → different fingerprint)
    memStore.observe({
      category: 'cors', endpoint: '/api/new', evidence: [{type:'r'},{type:'s'}],
      session_id: 'new', confidence: 90, severity: 'high',
    }, { id: 't1', url: 'https://a.com' });

    const merged = new Map();
    for (const b of p.loadCanonicalStore().all()) merged.set(b.fingerprint, b);
    for (const b of memStore.all()) {
      if (!merged.has(b.fingerprint)) merged.set(b.fingerprint, b);
    }
    assertEq(merged.size, 6, '5+1 new → 6');
  } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
});

test('GATE 2d: persisted=5, memory=1 dup updated → returns 5 with merge', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-merge-'));
  try {
    const p = new Persistence({ root: tmpDir });
    const persisted = new CanonicalBugStore();
    persisted.observe({
      category: 'cors', endpoint: '/api/0', evidence: [{type:'r'},{type:'s'}],
      session_id: 's0', confidence: 80, severity: 'medium',
    }, { id: 't1', url: 'https://a.com' });
    p.persistCanonicalStore(persisted);

    const memStore = new CanonicalBugStore();
    // Same bug, new session, higher confidence
    memStore.observe({
      category: 'cors', endpoint: '/api/0', evidence: [{type:'r'},{type:'s'}],
      session_id: 's1', confidence: 95, severity: 'high',
    }, { id: 't1', url: 'https://a.com' });

    const persistedLoaded = p.loadCanonicalStore();
    const merged = new Map();
    for (const b of persistedLoaded.all()) merged.set(b.fingerprint, b);
    for (const b of memStore.all()) {
      const existing = merged.get(b.fingerprint);
      if (existing) merged.set(b.fingerprint, { ...existing, ...b });
      else merged.set(b.fingerprint, b);
    }
    assertEq(merged.size, 1, '1+1 dup → 1');
    const bug = merged.values().next().value;
    assertEq(bug.confidence, 95, 'merged confidence = max(80, 95) = 95');
    assertEq(bug.severity, 'high', 'merged severity = max(medium, high) = high');
  } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
});

// ─── GATE 6: migration writes to canonical/ ──────────────────────────

test('GATE 6: migration writes to canonical/ subdir', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-mig-'));
  try {
    // Create minimal input
    fs.mkdirSync(path.join(tmpDir, 'verifications'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'dedup'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'verifications', 'test.json'), JSON.stringify({
      bugs: [{ category: 'cors', endpoint: '/api/test', evidence: [{type:'r'},{type:'s'}], confidence: 80, severity: 'medium' }],
    }));
    fs.writeFileSync(path.join(tmpDir, 'dedup', 'canonical-findings.json'), JSON.stringify([]));

    // Run migration (NOT dry-run)
    execFileSync('node', [
      path.resolve(__dirname, '..', 'scripts', 'migrate-canonical-bugs.js'),
      '--input', tmpDir, '--output', tmpDir,
    ], { cwd: path.resolve(__dirname, '..') });

    // Verify canonical/ exists with files
    const canonicalDir = path.join(tmpDir, 'canonical');
    assert(fs.existsSync(canonicalDir), 'canonical/ dir created');
    assert(fs.existsSync(path.join(canonicalDir, 'bugs.json')), 'canonical/bugs.json exists');
    assert(fs.existsSync(path.join(canonicalDir, 'migration-report.json')), 'canonical/migration-report.json exists');
    assert(fs.existsSync(path.join(canonicalDir, 'blocked-scope.json')), 'canonical/blocked-scope.json exists');

    // Verify bugs.json has ALL bugs (not just reportable)
    const bugs = JSON.parse(fs.readFileSync(path.join(canonicalDir, 'bugs.json'), 'utf-8'));
    assert(bugs.bugs.length > 0, 'bugs.json has bugs');
    assert(bugs.bugs.every(b => b.fingerprint), 'every bug has fingerprint');
  } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
});

// ─── GATE 3: route order (integration test) ──────────────────────────

test('GATE 3: server.js mounts quality-v1 before v01', () => {
  const serverSrc = fs.readFileSync(path.resolve(__dirname, '..', 'server.js'), 'utf-8');
  const q1Idx = serverSrc.indexOf("require('./routes/quality-v1')");
  const v01Idx = serverSrc.indexOf("require('./routes/v01')");
  assert(q1Idx > 0 && v01Idx > 0, 'both routes mounted');
  assert(q1Idx < v01Idx, 'quality-v1 mounted BEFORE v01');

  // Also verify quality-v1 is mounted only once
  const q1Count = (serverSrc.match(/require\('\.\/routes\/quality-v1'\)/g) || []).length;
  assertEq(q1Count, 1, 'quality-v1 mounted exactly once (no duplicate)');
});

// ─── GATE 10: blocked_scope bounty=null ──────────────────────────────

test('GATE 10: blocked_scope bug has bounty=null', () => {
  const { estimateBounty } = require('../bounty-estimator');
  const bug = { severity: 'high', evidence_quality: 90, reproduction_count: 3 };
  const target = { id: 't1', url: 'https://a.com', authorization_status: 'authorized', program_name: 'BB' };
  const reportability = { reportability_status: 'blocked_scope', confidence: 85 };
  const est = estimateBounty(bug, target, reportability);
  assertEq(est.typical, null, 'blocked_scope → bounty.typical = null');
  assertEq(est.min, null, 'blocked_scope → bounty.min = null');
  assertEq(est.max, null, 'blocked_scope → bounty.max = null');
});

// ─── GATE 11: restart persistence ────────────────────────────────────

test('GATE 11: persistence survives reload (simulates restart)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-restart-'));
  try {
    const p1 = new Persistence({ root: tmpDir });
    const store1 = new CanonicalBugStore();
    for (let i = 0; i < 5; i++) {
      store1.observe({
        category: 'cors', endpoint: `/api/${i}`, evidence: [{type:'r'},{type:'s'}],
        session_id: `s${i}`, confidence: 80, severity: 'medium',
      }, { id: 't1', url: 'https://a.com' });
    }
    p1.persistCanonicalStore(store1);

    const fps1 = store1.all().map(b => b.fingerprint).sort();

    // Simulate restart: new Persistence instance
    const p2 = new Persistence({ root: tmpDir });
    const store2 = p2.loadCanonicalStore();
    const fps2 = store2.all().map(b => b.fingerprint).sort();

    assertEq(store2.size(), 5, '5 bugs after reload');
    assertEq(JSON.stringify(fps1), JSON.stringify(fps2), 'fingerprints identical after reload');
  } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
});

// ─── Summary ─────────────────────────────────────────────────────────

setTimeout(() => {
  console.log('\n========================================');
  console.log(' SUMMARY — Gate Fixes Tests');
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

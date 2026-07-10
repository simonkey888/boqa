#!/usr/bin/env node
/**
 * BOQA v1.4.0 — Syntax check
 *
 * Runs `node --check` on every .js file in the project to detect
 * syntax errors (especially useful for finding truncated files).
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '_broken' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

const files = walk(ROOT).sort();
console.log(`\nChecking ${files.length} .js files...\n`);

let ok = 0;
let bad = 0;
const errors = [];

for (const f of files) {
  const rel = path.relative(ROOT, f);
  const res = spawnSync('node', ['--check', f], { encoding: 'utf8' });
  if (res.status === 0) {
    ok++;
    // console.log(`  ✓ ${rel}`);
  } else {
    bad++;
    const firstLine = (res.stderr || '').split('\n').find((l) => l.trim()) || '(no output)';
    errors.push({ file: rel, error: firstLine.slice(0, 200) });
    console.log(`  ✗ ${rel}`);
    console.log(`      ${firstLine.slice(0, 200)}`);
  }
}

console.log(`\n========================================`);
console.log(` Syntax check summary`);
console.log(`========================================`);
console.log(`  OK:   ${ok}`);
console.log(`  FAIL: ${bad}`);
console.log(`========================================\n`);

if (bad > 0) {
  console.log(`Failed files:`);
  for (const e of errors) {
    console.log(`  - ${e.file}`);
    console.log(`    ${e.error}`);
  }
}

process.exit(bad > 0 ? 1 : 0);

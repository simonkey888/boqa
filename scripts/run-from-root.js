#!/usr/bin/env node
/**
 * BOQA test runner — executes test files from the project root so that
 * `require('./memory-graph')` etc. resolve correctly.
 *
 * Usage:
 *   node scripts/run-from-root.js <test-file>
 *   node scripts/run-from-root.js test-v11
 *   node scripts/run-from-root.js test/test-v11.js
 */
const { spawnSync } = require('child_process');
const path = require('path');

const arg = process.argv[2];
if (!arg) {
  console.error('Usage: node scripts/run-from-root.js <test-file>');
  process.exit(2);
}

// Resolve the test file path
let testPath = arg;
if (!testPath.endsWith('.js')) testPath += '.js';
if (!testPath.startsWith('test/')) testPath = `test/${testPath}`;
const fullPath = path.resolve(__dirname, '..', testPath);

// Spawn node with cwd = project root so `require('./memory-graph')` resolves
// from the project root, not from test/.
const res = spawnSync('node', [fullPath], {
  cwd: path.resolve(__dirname, '..'),
  stdio: 'inherit',
  env: {
    ...process.env,
    NODE_ENV: 'test',
    BOQA_API_KEY: process.env.BOQA_API_KEY || 'test-key',
    BOQA_MODE: process.env.BOQA_MODE || 'observe',
    BOQA_AUTO_ANALYZE: 'false',
    HEADLESS: 'true',
  },
});

process.exit(res.status ?? 1);

#!/usr/bin/env node
/**
 * BOQA v1.4.0 — Single test runner
 *
 * Usage: node scripts/run-single-test.js <test-name>
 *   <test-name> can be "test-v11" or "test-v11.js" or "v11"
 */
const { spawnSync } = require('child_process');
const path = require('path');

const arg = process.argv[2];
if (!arg) {
  console.error('Usage: node scripts/run-single-test.js <test-name>');
  process.exit(2);
}

let name = arg;
if (!name.startsWith('test-')) name = `test-${name}`;
if (!name.endsWith('.js')) name = `${name}.js`;

const fullPath = path.resolve(__dirname, '..', 'test', name);

const res = spawnSync('node', [fullPath], {
  cwd: path.resolve(__dirname, '..'),
  stdio: 'inherit',
  env: {
    ...process.env,
    NODE_ENV: 'test',
    BOQA_API_KEY: process.env.BOQA_API_KEY || 'test-key',
  },
});

process.exit(res.status ?? 1);

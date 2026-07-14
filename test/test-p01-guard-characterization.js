'use strict';

/**
 * P0.1 characterization tests.
 *
 * The baseline gaps captured in docs/execution-guard-prechange-verdict.json
 * are now regression assertions. No browser, DNS, HTTP, or network primitive
 * is invoked.
 */

const fs = require('fs');
const path = require('path');
const guard = require('../lib/execution-authorization-guard');

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

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function source(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

console.log('\n=== P0.1 Execution Guard Characterization ===\n');

test('runtime execution modules import the execution guard', () => {
  const runtimeSources = [
    'agent.js',
    'verification-farm.js',
    'coverage-planner.js',
    'campaign-engine.js',
    'scheduler.js',
    'scheduler-multi-target.js',
    'target-runner.js',
    'server.js',
    'lib/init.js',
  ].map(source).join('\n');
  assert(runtimeSources.includes('execution-authorization-guard'), 'guard has no runtime caller');
});

test('VerificationFarm seals authorized payloads', () => {
  const farm = source('verification-farm.js');
  assert(farm.includes('sealTask(candidate)'), 'farm does not seal task payloads');
  assert(farm.includes('verifyTaskIntegrity(task)'), 'farm does not verify payload hashes');
});

test('VerificationFarm dispatch revalidates before execute', () => {
  const farm = source('verification-farm.js');
  assert(farm.includes('validateTaskAsync'), 'farm does not revalidate asynchronously');
});

test('browser policy has fail-closed request interception', () => {
  const policy = source('lib/browser-egress-guard.js');
  assert(/\.route\s*\(\s*['"]\*\*\/\*['"]/.test(policy), 'browser policy does not intercept all requests');
});

test('validateTaskAsync is exported for DNS validation', () => {
  assert(typeof guard.validateTask === 'function', 'validateTask missing');
  assert(typeof guard.validateTaskAsync === 'function', 'validateTaskAsync missing');
});

test('origin-bearing scope pattern does not authorize a different path', () => {
  const allowed = guard.matchesScope('example.com', '/admin/private', ['https://example.com/public/*']);
  assert(allowed === false, 'scope pattern overmatches by hostname');
});

test('IPv4-mapped private IPv6 is classified as blocked', () => {
  assert(guard.isBlockedIP('::ffff:127.0.0.1') === true, 'IPv4-mapped loopback was accepted');
});

test('WHATWG URL normalization blocks alternate IPv4 loopback representations', () => {
  for (const value of ['http://127.1/', 'http://2130706433/', 'http://0177.0.0.1/', 'http://0x7f000001/']) {
    assert(guard.validateUrlStructure(value).allowed === false, `${value} was unexpectedly accepted`);
  }
});

test('Agent startup navigation is conditioned on the admin execution gate', () => {
  const server = source('server.js');
  const agent = source('agent.js');
  assert(server.includes('await ctx.agent.start()'), 'agent startup call missing');
  assert(agent.includes('await this.page.goto(this.options.target'), 'startup navigation primitive missing');
  assert(/ctx\.agent && process\.env\.BOQA_ADMIN_EXECUTION_ENABLED === 'true'/.test(server), 'agent startup is not admin-gated');
});

console.log('\n========================================');
console.log(' SUMMARY — P0.1 Characterization');
console.log('========================================');
console.log(`  Total:  ${passed + failed}`);
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
console.log('========================================');
process.exit(failed === 0 ? 0 : 1);

'use strict';

/**
 * P1.C residual execution-surface tests. All browser, proxy, and DNS behavior
 * is represented by in-process fakes; this file performs no network I/O.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { Agent } = require('../agent');
const { PlaywrightRunner } = require('../agent/playwright-runner');

const ROOT = path.resolve(__dirname, '..');
let passed = 0;
let failed = 0;

function test(name, fn) {
  Promise.resolve().then(fn).then(() => {
    console.log(`  ✓ ${name}`);
    passed++;
  }, (error) => {
    console.log(`  ✗ ${name}\n    ${error.stack || error.message}`);
    failed++;
  });
}

function assert(value, message) {
  if (!value) throw new Error(message);
}

function loadPagesFunction() {
  const filename = path.join(ROOT, 'functions', 'api', '[[path]].js');
  const source = fs.readFileSync(filename, 'utf8').replace(/\bexport\s+(?=(async\s+function|const)\b)/g, '');
  return new Function(`${source}\nreturn { onRequest, onRequestGet, onRequestPost, onRequestPut, onRequestPatch, onDelete };`)();
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

function freshConfig(envOverrides = {}) {
  const env = { ...process.env, ...envOverrides };
  delete env.BOQA_TARGET;
  delete env.BOQA_TARGET_ID;
  const result = spawnSync(process.execPath, ['-e', "process.stdout.write(JSON.stringify(require('./lib/config').CONFIG))"], {
    cwd: ROOT,
    env,
    encoding: 'utf8',
  });
  if (result.status !== 0) throw new Error(result.stderr || `config exited ${result.status}`);
  return JSON.parse(result.stdout);
}

console.log('\n=== P1.C Residual Execution Surfaces ===\n');

test('legacy Pages proxy blocks POST before any forwarding', async () => {
  const pages = loadPagesFunction();
  const response = await pages.onRequest({
    request: new Request('https://fixture.invalid/api/bugs', { method: 'POST', body: '{}' }),
    env: { BOQA_BACKEND_URL: 'https://backend.invalid' },
  });
  const body = await responseJson(response);
  assert(response.status === 405, `expected 405, got ${response.status}`);
  assert(body.error === 'method_not_allowed', 'unexpected error code');
});

test('legacy Pages proxy blocks non-allowlisted GET', async () => {
  const pages = loadPagesFunction();
  const response = await pages.onRequest({ request: new Request('https://fixture.invalid/api/admin'), env: {} });
  assert(response.status === 404, `expected 404, got ${response.status}`);
});

test('legacy Pages allowlisted GET is quarantined and never forwards credentials', async () => {
  const pages = loadPagesFunction();
  const originalFetch = global.fetch;
  let forwarded = false;
  global.fetch = async () => { forwarded = true; throw new Error('network primitive invoked'); };
  try {
    const request = new Request('https://fixture.invalid/api/health', {
      headers: { Authorization: 'Bearer should-not-leave', Cookie: 'session=should-not-leave', 'X-API-Key': 'should-not-leave' },
    });
    const response = await pages.onRequest({ request, env: { BOQA_BACKEND_URL: 'https://backend.invalid' } });
    const body = await responseJson(response);
    assert(response.status === 503, `expected quarantine 503, got ${response.status}`);
    assert(body.error === 'legacy_proxy_disabled', 'legacy proxy did not identify quarantine');
    assert(!forwarded, 'legacy proxy invoked fetch');
  } finally {
    global.fetch = originalFetch;
  }
});

test('legacy Pages WebSocket surface is fail-closed', async () => {
  const pages = loadPagesFunction();
  const response = await pages.onRequest({ request: new Request('https://fixture.invalid/ws'), env: {} });
  assert(response.status === 426, `expected 426, got ${response.status}`);
});

test('legacy PlaywrightRunner cannot launch or navigate', async () => {
  const runner = new PlaywrightRunner({ emit() {} }, { target: 'https://fixture.invalid' });
  let message = '';
  try { await runner.start(); } catch (error) { message = error.message; }
  assert(message.startsWith('SECURITY_DISABLED:'), `unexpected result: ${message}`);
  assert(runner.browser === null, 'legacy runner opened a browser');
});

test('legacy and canonical CDP entrypoints are rejected', async () => {
  const runner = new PlaywrightRunner({ emit() {} }, { cdpEndpoint: 'ws://fixture.invalid' });
  let legacy = '';
  try { await runner._connectCDP(); } catch (error) { legacy = error.message; }
  assert(legacy.startsWith('SECURITY_DISABLED:'), 'legacy CDP was not quarantined');

  const agent = new Agent({ on() {}, emit() {} }, { cdpEndpoint: 'ws://fixture.invalid' });
  let canonical = '';
  try { await agent._connectCDP(); } catch (error) { canonical = error.message; }
  assert(canonical === 'CDP_ENDPOINT_DISABLED_BY_EGRESS_POLICY', 'canonical CDP was not rejected');
});

test('target and target ID defaults are absent', () => {
  const config = freshConfig();
  assert(config.target === null, `implicit target found: ${config.target}`);
  assert(config.targetId === null, `implicit target ID found: ${config.targetId}`);
});

test('admin true without canonical target cannot launch Chromium', async () => {
  const previous = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  let launched = false;
  const agent = new Agent({ on() {}, emit() {} }, { target: null, targetId: null });
  agent._launchBrowser = async () => { launched = true; };
  let message = '';
  try { await agent.start(); } catch (error) { message = error.message; }
  if (previous === undefined) delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  else process.env.BOQA_ADMIN_EXECUTION_ENABLED = previous;
  assert(message.startsWith('TARGET_REQUIRED:'), `unexpected authorization result: ${message}`);
  assert(!launched, 'browser launched without canonical target');
});

test('demo and CI configuration contain no executable external target', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const ci = JSON.parse(fs.readFileSync(path.join(ROOT, 'ci', 'config.json'), 'utf8'));
  assert(pkg.scripts.demo === 'node scripts/demo-disabled.js', 'demo is not explicitly disabled');
  assert(!/https?:\/\//i.test(pkg.scripts.demo), 'demo embeds an external target');
  assert(Array.isArray(ci.targets) && ci.targets.length === 0, 'CI config has an implicit target');
});

test('authenticated replay cookie handling has no fallback hostname', () => {
  const source = fs.readFileSync(path.join(ROOT, 'verification-farm.js'), 'utf8');
  assert(source.includes('COOKIE_TARGET_URL_REQUIRED'), 'cookie replay does not require an explicit URL');
  assert(!source.includes("task.params?.url || 'https://example.com'"), 'cookie replay retains an implicit fallback');
});

process.on('beforeExit', () => {
  console.log(`\nTotal: ${passed + failed}  Passed: ${passed}  Failed: ${failed}`);
  process.exitCode = failed ? 1 : 0;
});

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const guard = require('../lib/execution-authorization-guard');
const { BrowserEgressGuard } = require('../lib/browser-egress-guard');
const { VerificationFarm } = require('../verification-farm');
const { TargetRunner, ExecutionQueue } = require('../target-runner');
const { Agent } = require('../agent');
const { EventEmitter } = require('events');

let passed = 0;
let failed = 0;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const assert = (value, message) => { if (!value) throw new Error(message); };

function registry() {
  const target = {
    id: 'target-1', name: 'fixture', url: 'https://fixture.invalid/allowed/',
    authorization_status: 'authorized', enabled: true, execution_authorized: true,
    authorization_source_url: 'https://program.invalid/scope',
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://fixture.invalid/allowed/*'],
    scope_denylist: ['/allowed/denied/*'],
    allowed_methods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
    allowed_ports: ['443'],
  };
  return { get: id => id === target.id ? target : null };
}

function resolver(state = { v4: ['93.184.216.34'], v6: ['2606:2800:220:1:248:1893:25c8:1946'] }) {
  return {
    state,
    async resolve4() { return state.v4; },
    async resolve6() { return state.v6; },
  };
}

function fakeContext() {
  return {
    routeHandler: null,
    webSocketHandler: null,
    initScripts: [],
    async route(pattern, handler) { assert(pattern === '**/*', 'unexpected route pattern'); this.routeHandler = handler; },
    async routeWebSocket(pattern, handler) { assert(pattern === '**/*', 'unexpected websocket route pattern'); this.webSocketHandler = handler; },
    async addInitScript(script) { this.initScripts.push(script); },
    serviceWorkers() { return []; },
  };
}

function fakeRoute(url, resourceType = 'document', method = 'GET') {
  const state = { continued: 0, aborted: 0 };
  return {
    state,
    request() { return { url: () => url, method: () => method, resourceType: () => resourceType }; },
    async continue() { state.continued++; },
    async abort() { state.aborted++; },
  };
}

function fakeAgent() {
  const context = fakeContext();
  const calls = { goto: 0, evaluate: 0 };
  const page = {
    context: () => context,
    async goto() { calls.goto++; return { status: () => 200 }; },
    async evaluate() { calls.evaluate++; return { status: 200, headers: {} }; },
    url: () => 'https://fixture.invalid/allowed/final',
    async click() {}, async fill() {},
  };
  return { page, context, calls };
}

async function withAdminEnabled(fn) {
  const previous = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  try { return await fn(); } finally {
    if (previous === undefined) delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
    else process.env.BOQA_ADMIN_EXECUTION_ENABLED = previous;
  }
}

test('adversarial IPv4 and IPv6 private forms are blocked', async () => {
  const inputs = [
    'http://127.0.0.1/', 'http://127.1/', 'http://2130706433/',
    'http://0177.0.0.1/', 'http://0x7f000001/', 'http://[::1]/',
    'http://[::ffff:127.0.0.1]/', 'http://[::ffff:10.0.0.1]/',
    'http://[fc00::1]/', 'http://[fd00::1]/', 'http://[fe80::1]/',
  ];
  for (const url of inputs) assert(!guard.validateUrlStructure(url).allowed, `${url} accepted`);
});

test('mixed public A and private AAAA fails closed', async () => {
  const r = resolver({ v4: ['93.184.216.34'], v6: ['fd00::1'] });
  const result = await guard.validateUrlAsync('target-1', 'https://fixture.invalid/allowed/a', registry(), { resolver: r });
  assert(!result.allowed && result.code === 'DNS_RESOLVES_TO_BLOCKED', 'mixed DNS response accepted');
});

test('invalid task is rejected before enqueue', () => withAdminEnabled(async () => {
  const farm = new VerificationFarm({ registry: registry(), resolver: resolver(), maxWorkers: 1 });
  const result = await farm.submitTaskAsync({ action: 'navigation', target_id: 'target-1', params: { url: 'https://evil.invalid/' } });
  assert(result.error && farm.pendingQueue.length === 0, 'invalid task entered queue');
}));

test('allowed task is cloned, frozen, hashed, and queued', () => withAdminEnabled(async () => {
  const farm = new VerificationFarm({ registry: registry(), resolver: resolver(), maxWorkers: 1 });
  const input = { action: 'navigation', target_id: 'target-1', params: { url: 'https://fixture.invalid/allowed/a' } };
  const { task } = await farm.submitTaskAsync(input);
  input.params.url = 'https://evil.invalid/';
  assert(task.params.url.endsWith('/allowed/a'), 'queued params share caller reference');
  assert(Object.isFrozen(task.params), 'params are not frozen');
  assert(guard.verifyTaskIntegrity(task).allowed, 'sealed task hash invalid');
}));

test('mutated queued task is rejected and primitive is not invoked', () => withAdminEnabled(async () => {
  const agent = fakeAgent();
  const farm = new VerificationFarm({ registry: registry(), resolver: resolver(), agent, maxWorkers: 1 });
  const { task } = await farm.submitTaskAsync({ action: 'navigation', target_id: 'target-1', params: { url: 'https://fixture.invalid/allowed/a' } });
  const tampered = { ...task, action: 'request_replay' };
  farm.pendingQueue[0] = tampered;
  const results = await farm.processQueue();
  assert(results[0].verdict === 'rejected', 'mutated task was not rejected');
  assert(agent.calls.goto === 0 && agent.calls.evaluate === 0, 'network primitive was invoked');
}));

test('DNS change between enqueue and dispatch is rejected', () => withAdminEnabled(async () => {
  const state = { v4: ['93.184.216.34'], v6: [] };
  const agent = fakeAgent();
  const farm = new VerificationFarm({ registry: registry(), resolver: resolver(state), agent, maxWorkers: 1 });
  await farm.submitTaskAsync({ action: 'navigation', target_id: 'target-1', params: { url: 'https://fixture.invalid/allowed/a' } });
  state.v4 = ['127.0.0.1'];
  const results = await farm.processQueue();
  assert(results[0].verdict === 'rejected' && agent.calls.goto === 0, 'DNS revalidation did not block dispatch');
}));

test('allowed navigation reaches goto only after boundary validation', () => withAdminEnabled(async () => {
  const agent = fakeAgent();
  const farm = new VerificationFarm({ registry: registry(), resolver: resolver(), agent, maxWorkers: 1 });
  await farm.submitTaskAsync({ action: 'navigation', target_id: 'target-1', params: { url: 'https://fixture.invalid/allowed/a' } });
  const results = await farm.processQueue();
  assert(results[0].verdict === 'observed' && agent.calls.goto === 1, 'allowed navigation did not reach goto exactly once');
}));

test('replay primitives validate every individual URL', () => withAdminEnabled(async () => {
  const replayAgent = fakeAgent();
  const replayFarm = new VerificationFarm({ registry: registry(), resolver: resolver(), agent: replayAgent, maxWorkers: 1 });
  await replayFarm.submitTaskAsync({
    action: 'authenticated_replay', target_id: 'target-1',
    params: { url: 'https://fixture.invalid/allowed/a', request_sequence: [
      { url: 'https://fixture.invalid/allowed/one' },
      { url: 'https://fixture.invalid/allowed/two' },
    ] },
  });
  const results = await replayFarm.processQueue();
  assert(results[0].verdict === 'observed' && replayAgent.calls.goto === 2, 'authenticated replay did not validate/execute both steps');

  const requestAgent = fakeAgent();
  const requestFarm = new VerificationFarm({ registry: registry(), resolver: resolver(), agent: requestAgent, maxWorkers: 1 });
  await requestFarm.submitTaskAsync({ action: 'request_replay', target_id: 'target-1', params: {
    url: 'https://fixture.invalid/allowed/request', method: 'POST', body: { fixture: true },
  } });
  const requestResults = await requestFarm.processQueue();
  assert(requestResults[0].verdict === 'observed' && requestAgent.calls.evaluate === 1, 'request replay primitive not reached exactly once');
}));

test('workflow navigation is validated per step', () => withAdminEnabled(async () => {
  const agent = fakeAgent();
  const farm = new VerificationFarm({ registry: registry(), resolver: resolver(), agent, maxWorkers: 1 });
  await farm.submitTaskAsync({ action: 'workflow_validation', target_id: 'target-1', params: { steps: [
    { action: 'navigate', url: 'https://fixture.invalid/allowed/one' },
    { action: 'navigate', url: 'https://fixture.invalid/allowed/two' },
  ] } });
  const results = await farm.processQueue();
  assert(results[0].verdict === 'observed' && agent.calls.goto === 2, 'workflow navigation primitive count mismatch');
}));

test('agent startup fails before browser launch while admin execution is disabled', async () => {
  const previous = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  const bus = new EventEmitter();
  bus.emit = EventEmitter.prototype.emit.bind(bus);
  const agent = new Agent(bus, { target: 'https://fixture.invalid/allowed/', targetId: 'target-1', registry: registry(), resolver: resolver() });
  let launched = false;
  agent._launchBrowser = async () => { launched = true; };
  let rejected = false;
  try { await agent.start(); } catch (error) { rejected = error.message.includes('ADMIN_EXECUTION_DISABLED'); }
  if (previous !== undefined) process.env.BOQA_ADMIN_EXECUTION_ENABLED = previous;
  assert(rejected && !launched, 'agent initialized a browser before admin authorization');
});

test('out-of-scope redirect/document request aborts without continue', () => withAdminEnabled(async () => {
  const context = fakeContext();
  const policy = new BrowserEgressGuard({ registry: registry(), targetId: 'target-1', resolver: resolver() });
  await policy.install(context);
  const route = fakeRoute('https://evil.invalid/redirect', 'document');
  await context.routeHandler(route);
  assert(route.state.aborted === 1 && route.state.continued === 0, 'redirect request continued');
}));

test('out-of-scope subrequest aborts without continue', () => withAdminEnabled(async () => {
  const context = fakeContext();
  const policy = new BrowserEgressGuard({ registry: registry(), targetId: 'target-1', resolver: resolver() });
  await policy.install(context);
  for (const type of ['iframe', 'script', 'stylesheet', 'image', 'font', 'media', 'fetch', 'xhr', 'manifest', 'preflight']) {
    const route = fakeRoute('https://evil.invalid/resource', type);
    await context.routeHandler(route);
    assert(route.state.aborted === 1 && route.state.continued === 0, `${type} continued`);
  }
}));

test('in-scope request continues only after async DNS validation', () => withAdminEnabled(async () => {
  const context = fakeContext();
  const policy = new BrowserEgressGuard({ registry: registry(), targetId: 'target-1', resolver: resolver() });
  await policy.install(context);
  const route = fakeRoute('https://fixture.invalid/allowed/app.js', 'script');
  await context.routeHandler(route);
  assert(route.state.continued === 1 && route.state.aborted === 0, 'allowed fixture did not continue');
}));

test('WebSocket, EventSource, and service workers are explicitly disabled', async () => {
  const text = fs.readFileSync(path.join(__dirname, '..', 'lib/browser-egress-guard.js'), 'utf8');
  assert(text.includes("'WebSocket'"), 'WebSocket disable missing');
  assert(text.includes("'EventSource'"), 'EventSource disable missing');
  assert(text.includes("'serviceWorker'"), 'service worker disable missing');
  const context = fakeContext();
  const policy = new BrowserEgressGuard({ registry: registry(), targetId: 'target-1', resolver: resolver(), adminExecutionEnabled: true });
  await policy.install(context);
  let closed = 0;
  await context.webSocketHandler({ async close(options) { if (options.code === 1008) closed++; } });
  assert(closed === 1, 'WebSocket route was not closed fail-closed');
});

test('planner and campaign internal paths use guarded async enqueue', async () => {
  for (const file of ['coverage-planner.js', 'campaign-engine.js', 'routes/v01.js']) {
    const text = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    assert(text.includes('submitTaskAsync'), `${file} still uses unguarded enqueue`);
  }
});

test('persistence restore requires canonical registry and async authorization', () => withAdminEnabled(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-p01-'));
  fs.writeFileSync(path.join(dir, 'target-runner-checkpoint.json'), JSON.stringify({
    stats: {}, executions: [{ id: 'target-1', target_url: 'https://evil.invalid/', state: 'queued', retry_count: 0 }],
  }));
  const queue = new ExecutionQueue();
  const runner = new TargetRunner({ registry: registry(), resolver: resolver(), executionQueue: queue });
  const restored = await runner.resumeFromCheckpoint(dir);
  assert(restored === 1 && queue.peek().target_url === 'https://fixture.invalid/allowed/', 'restore trusted persisted URL');
}));

(async () => {
  console.log('\n=== P0.1 Execution Guard Integration Tests ===\n');
  for (const item of tests) {
    try { await item.fn(); console.log(`  ✓ ${item.name}`); passed++; }
    catch (error) { console.log(`  ✗ ${item.name}\n    ${error.message}`); failed++; }
  }
  console.log(`\nTotal: ${passed + failed}  Passed: ${passed}  Failed: ${failed}`);
  process.exit(failed ? 1 : 0);
})();

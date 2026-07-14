'use strict';

const { AuditTelemetry } = require('../lib/audit-telemetry');
const { RuntimeMonitor } = require('../lib/runtime-monitor');
const { createAdminGate } = require('../lib/admin-gate');
const guard = require('../lib/execution-authorization-guard');
const { BrowserEgressGuard } = require('../lib/browser-egress-guard');
const { VerificationFarm } = require('../verification-farm');
const pkg = require('../package.json');
const fs = require('fs');
const path = require('path');

const tests = [];
let passed = 0;
let failed = 0;
const test = (name, fn) => tests.push({ name, fn });
const assert = (value, message) => { if (!value) throw new Error(message); };

function registry() {
  const target = {
    id: 'target-1',
    url: 'https://fixture.invalid/allowed/',
    authorization_status: 'authorized',
    enabled: true,
    execution_authorized: true,
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://fixture.invalid/allowed/*'],
    allowed_methods: ['GET'],
    allowed_ports: ['443'],
  };
  return { get: id => id === target.id ? target : null };
}

function resolver() {
  return {
    async resolve4() { return ['93.184.216.34']; },
    async resolve6() { return ['2606:2800:220:1:248:1893:25c8:1946']; },
  };
}

function fakeOpenTelemetry() {
  const calls = { spans: [], events: [], statuses: [], ended: 0, counters: [] };
  return {
    calls,
    SpanStatusCode: { OK: 1, ERROR: 2 },
    trace: {
      getTracer() {
        return {
          startSpan(name, options) {
            calls.spans.push({ name, options });
            return {
              addEvent(event, attributes) { calls.events.push({ event, attributes }); },
              setStatus(status) { calls.statuses.push(status); },
              end() { calls.ended++; },
            };
          },
        };
      },
    },
    metrics: {
      getMeter() {
        return {
          createCounter() {
            return { add(value, attributes) { calls.counters.push({ value, attributes }); } };
          },
        };
      },
    },
  };
}

function fakeContext() {
  return {
    routeHandler: null,
    wsHandler: null,
    async route(_pattern, handler) { this.routeHandler = handler; },
    async routeWebSocket(_pattern, handler) { this.wsHandler = handler; },
    async addInitScript() {},
    serviceWorkers() { return []; },
  };
}

function fakeRoute(url) {
  const state = { continued: 0, aborted: 0 };
  return {
    state,
    request() {
      return {
        url: () => url,
        method: () => 'GET',
        resourceType: () => 'script',
      };
    },
    async continue() { state.continued++; },
    async abort() { state.aborted++; },
  };
}

async function withAdminEnabled(fn) {
  const previous = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  process.env.BOQA_ADMIN_EXECUTION_ENABLED = 'true';
  try { return await fn(); } finally {
    if (previous === undefined) delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
    else process.env.BOQA_ADMIN_EXECUTION_ENABLED = previous;
  }
}

test('OpenTelemetry is exact-true opt-in and no exporter SDK is installed', () => {
  const previous = process.env.BOQA_OTEL_ENABLED;
  try {
    delete process.env.BOQA_OTEL_ENABLED;
    const absent = new AuditTelemetry();
    process.env.BOQA_OTEL_ENABLED = 'false';
    const explicitFalse = new AuditTelemetry();
    process.env.BOQA_OTEL_ENABLED = 'true';
    const explicitTrue = new AuditTelemetry({ otelApi: fakeOpenTelemetry() });
    assert(absent.getSummary().opentelemetry.enabled === false, 'absent telemetry flag enabled tracing');
    assert(explicitFalse.getSummary().opentelemetry.enabled === false, 'false telemetry flag enabled tracing');
    assert(explicitTrue.getSummary().opentelemetry.enabled === true, 'true telemetry flag did not enable API bridge');
    assert(absent.getSummary().opentelemetry.api_loaded === false, 'API loaded while disabled');
    assert(absent.getSummary().opentelemetry.exporter_configured_by_boqa === false, 'BOQA configured an exporter');
  } finally {
    if (previous === undefined) delete process.env.BOQA_OTEL_ENABLED;
    else process.env.BOQA_OTEL_ENABLED = previous;
  }
  for (const dependency of Object.keys(pkg.dependencies || {})) {
    assert(!dependency.includes('exporter') && !dependency.includes('sdk-'), `exporter/SDK dependency found: ${dependency}`);
  }
  const dockerfile = fs.readFileSync(path.join(__dirname, '..', 'Dockerfile'), 'utf8');
  assert(dockerfile.includes('ENV BOQA_OTEL_ENABLED=false'), 'container telemetry default is not disabled');
});

test('enabled bridge emits sanitized span events and metrics through injected API', () => {
  const api = fakeOpenTelemetry();
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: api, clock: () => 1234 });
  telemetry.recordSecurityDecision('admin_gate', { allowed: false, code: 'ADMIN_EXECUTION_DISABLED' }, {
    method: 'POST',
    target_id: 'target-1',
  });
  assert(api.calls.spans.length === 1 && api.calls.ended === 1, 'span was not emitted and closed');
  assert(api.calls.events.length === 1 && api.calls.counters.length === 1, 'event/counter missing');
  assert(api.calls.statuses[0].code === api.SpanStatusCode.ERROR, 'denial status was not recorded');
});

test('audit buffer is bounded and removes secret-bearing attributes', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false, maxEvents: 2 });
  telemetry.audit('one', { authorization: 'secret', request_url: 'https://secret.invalid', method: 'GET' });
  telemetry.audit('two', { cookie: 'secret', target_id: 'target-1' });
  telemetry.audit('three', { body: { secret: true }, action: 'navigation' });
  const events = telemetry.getEventsForTesting();
  const serialized = JSON.stringify(events);
  assert(events.length === 2, 'bounded retention failed');
  assert(!serialized.includes('secret') && !serialized.includes('https://'), 'sensitive field retained');
  const summary = telemetry.getSummary();
  assert(summary.audit_events_dropped === 1 && summary.attributes_omitted === 4, 'drop/omission accounting mismatch');
});

test('OpenTelemetry provider failure is fail-safe and retains local audit event', () => {
  const api = fakeOpenTelemetry();
  api.trace.getTracer = () => ({ startSpan() { throw new Error('provider failed'); } });
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: api });
  const result = { allowed: true, code: 'OK' };
  assert(telemetry.recordSecurityDecision('execution_guard', result, { phase: 'test' }) === true, 'audit call failed');
  assert(telemetry.getSummary().emission_errors === 1, 'provider failure not contained');
  assert(result.allowed === true, 'telemetry changed security decision');
});

test('admin gate records allow/deny without changing fail-closed behavior', async () => {
  const previous = process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  delete process.env.BOQA_ADMIN_EXECUTION_ENABLED;
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  const middleware = createAdminGate({ telemetry });
  let status = null;
  let nextCalled = false;
  middleware({ method: 'POST', path: '/verification-queue' }, {
    status(code) { status = code; return this; },
    json() {},
  }, () => { nextCalled = true; });
  if (previous !== undefined) process.env.BOQA_ADMIN_EXECUTION_ENABLED = previous;
  assert(status === 403 && !nextCalled, 'admin gate behavior changed');
  assert(telemetry.getSummary().audit_events_by_type['security.admin_gate.denied'] === 1, 'admin denial audit missing');
});

test('execution guard records enqueue authorization without URLs or payloads', () => withAdminEnabled(async () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  const result = await guard.validateTaskAsync({
    id: 'task-1',
    action: 'navigation',
    target_id: 'target-1',
    params: { url: 'https://fixture.invalid/allowed/a' },
  }, registry(), { resolver: resolver(), telemetry, phase: 'enqueue' });
  assert(result.allowed, 'valid fixture was denied');
  const event = telemetry.getEventsForTesting()[0];
  assert(event.type === 'security.execution_guard.allowed', 'guard audit event missing');
  assert(event.attributes.phase === 'enqueue', 'boundary phase missing');
  assert(!JSON.stringify(event).includes('fixture.invalid'), 'URL leaked into audit event');
}));

test('farm audits enqueue, dispatch, retry and primitive boundaries without external network', () => withAdminEnabled(async () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  const farm = new VerificationFarm({
    registry: registry(),
    resolver: resolver(),
    telemetry,
    maxWorkers: 1,
    agent: null,
  });
  const submitted = await farm.submitTaskAsync({
    action: 'navigation',
    target_id: 'target-1',
    params: { url: 'https://fixture.invalid/allowed/a' },
  });
  assert(!submitted.error, 'fixture was not queued');
  await farm.processQueue();
  const phases = telemetry.getEventsForTesting()
    .filter(event => event.type === 'security.execution_guard.allowed')
    .map(event => event.attributes.phase);
  for (const phase of ['enqueue', 'dispatch', 'worker_retry']) {
    assert(phases.includes(phase), `missing ${phase} audit boundary`);
  }
}));

test('browser egress records allowed, denied and WebSocket decisions without leaking URLs', () => withAdminEnabled(async () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  const context = fakeContext();
  const policy = new BrowserEgressGuard({
    registry: registry(),
    targetId: 'target-1',
    resolver: resolver(),
    telemetry,
  });
  await policy.install(context);
  const allowed = fakeRoute('https://fixture.invalid/allowed/app.js');
  const denied = fakeRoute('https://evil.invalid/app.js');
  await context.routeHandler(allowed);
  await context.routeHandler(denied);
  await context.wsHandler({ async close() {} });
  assert(allowed.state.continued === 1 && denied.state.aborted === 1, 'egress behavior changed');
  const events = telemetry.getEventsForTesting();
  assert(events.some(event => event.type === 'security.browser_egress.allowed'), 'allowed egress audit missing');
  assert(events.some(event => event.type === 'security.browser_egress.denied'), 'denied egress audit missing');
  assert(events.some(event => event.type === 'security.browser_websocket.denied'), 'WebSocket audit missing');
  assert(!JSON.stringify(events).includes('fixture.invalid') && !JSON.stringify(events).includes('evil.invalid'), 'URL leaked');
}));

test('runtime metrics expose aggregate audit state but never raw events', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  telemetry.audit('security.test.denied', { target_id: 'target-1' });
  const monitor = new RuntimeMonitor({ auditTelemetry: telemetry });
  const metrics = monitor.getMetrics();
  assert(metrics.telemetry.audit_events_total === 1, 'audit aggregate missing from runtime metrics');
  assert(!Object.prototype.hasOwnProperty.call(metrics.telemetry, 'events'), 'raw events exposed by runtime metrics');
});

(async () => {
  for (const item of tests) {
    try {
      await item.fn();
      passed++;
      console.log(`PASS ${item.name}`);
    } catch (error) {
      failed++;
      console.error(`FAIL ${item.name}: ${error.message}`);
    }
  }
  console.log(`\n${passed}/${tests.length} tests passed`);
  process.exit(failed > 0 ? 1 : 0);
})();

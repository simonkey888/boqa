'use strict';

const { AuditTelemetry, sanitizeAttributes, safeRecordSecurityDecision, AUDIT_EVENT_TYPES } = require('../lib/audit-telemetry');
const { createAdminGate } = require('../lib/admin-gate');
const guard = require('../lib/execution-authorization-guard');
const { BrowserEgressGuard } = require('../lib/browser-egress-guard');

const tests = [];
let passed = 0;
let failed = 0;
const test = (name, fn) => tests.push({ name, fn });
const assert = (value, message) => { if (!value) throw new Error(message); };

function registry() {
  const target = {
    id: 'target-1', url: 'https://fixture.invalid/allowed/',
    authorization_status: 'authorized', enabled: true, execution_authorized: true,
    authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://fixture.invalid/allowed/*'],
    allowed_methods: ['GET'], allowed_ports: ['443'],
  };
  return { get: id => id === target.id ? target : null };
}

const resolver = {
  async resolve4() { return ['93.184.216.34']; },
  async resolve6() { return ['2606:2800:220:1:248:1893:25c8:1946']; },
};

function context() {
  return {
    routeHandler: null, wsHandler: null,
    async route(_pattern, handler) { this.routeHandler = handler; },
    async routeWebSocket(_pattern, handler) { this.wsHandler = handler; },
    async addInitScript() {}, serviceWorkers() { return []; },
  };
}

function route(url) {
  const state = { continued: 0, aborted: 0 };
  return {
    state,
    request() { return { url: () => url, method: () => 'GET', resourceType: () => 'script' }; },
    async continue() { state.continued++; }, async abort() { state.aborted++; },
  };
}

function serializedEvents(telemetry) { return JSON.stringify(telemetry.getEventsForTesting()); }

test('URL query tokens, userinfo, headers, cookies, bodies and evidence never serialize', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  telemetry.recordSecurityDecision('execution_guard', { allowed: false, code: 'INVALID_URL' }, {
    url: 'https://user:pass@fixture.invalid/a?token=QUERY_SENTINEL',
    authorization_url: 'https://AUTH_URL_SENTINEL.invalid',
    headers: { Authorization: 'Bearer HEADER_SENTINEL' }, cookie: 'COOKIE_SENTINEL',
    request_body: { password: 'PASSWORD_SENTINEL', api_key: 'APIKEY_SENTINEL' },
    response_body: 'RESPONSE_SENTINEL', evidence: 'EVIDENCE_SENTINEL', finding: 'FINDING_SENTINEL',
    action: 'navigation', phase: 'enqueue',
  });
  const text = serializedEvents(telemetry);
  for (const sentinel of ['QUERY_SENTINEL', 'AUTH_URL_SENTINEL', 'HEADER_SENTINEL', 'COOKIE_SENTINEL', 'PASSWORD_SENTINEL', 'APIKEY_SENTINEL', 'RESPONSE_SENTINEL', 'EVIDENCE_SENTINEL', 'FINDING_SENTINEL']) {
    assert(!text.includes(sentinel), `${sentinel} leaked`);
  }
});

test('user-controlled target IDs and raw error messages are discarded', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  telemetry.recordSecurityDecision('execution_guard', { allowed: false, code: 'TARGET_NOT_FOUND', reason: 'ERROR_SECRET' }, {
    target_id: 'USER_TARGET_SECRET', task_id: 'USER_TASK_SECRET', error: 'ERROR_SECRET', stack: 'STACK_SECRET',
  });
  const text = serializedEvents(telemetry);
  assert(!/USER_TARGET_SECRET|USER_TASK_SECRET|ERROR_SECRET|STACK_SECRET/.test(text), 'identifier/error leaked');
});

test('attribute and event cardinality are closed enums', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  for (let i = 0; i < 1000; i++) telemetry.audit(`user.${i}`, { action: `action-${i}`, resource_type: `type-${i}` });
  const summary = telemetry.getSummary();
  assert(Object.keys(summary.audit_events_by_type).length === AUDIT_EVENT_TYPES.size, 'metric label cardinality grew');
  assert(summary.audit_events_by_type['audit.unknown'] === 1000, 'unknown events not collapsed');
  assert(!serializedEvents(telemetry).includes('action-999'), 'unknown enum retained');
});

test('onDecision exceptions cannot alter allow or deny primitive behavior', async () => {
  const ctx = context();
  const policy = new BrowserEgressGuard({ registry: registry(), targetId: 'target-1', resolver, adminExecutionEnabled: true, onDecision() { throw new Error('CALLBACK_SECRET'); } });
  await policy.install(ctx);
  const allowed = route('https://fixture.invalid/allowed/app.js');
  const denied = route('https://evil.invalid/app.js');
  await ctx.routeHandler(allowed);
  await ctx.routeHandler(denied);
  assert(allowed.state.continued === 1 && denied.state.aborted === 1, 'callback changed egress decision');
});

test('missing OpenTelemetry API degrades to internal no-ops', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: null });
  assert(telemetry.audit('audit.unknown', { enabled: true }), 'missing API escaped');
  assert(!telemetry.getSummary().opentelemetry.api_loaded, 'missing API marked loaded');
});

test('partially implemented OpenTelemetry API degrades to internal no-ops', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: { trace: { getTracer() { return {}; } } } });
  assert(telemetry.recordSecurityDecision('admin_gate', { allowed: false, code: 'ADMIN_EXECUTION_DISABLED' }), 'partial API escaped');
  assert(!telemetry.getSummary().opentelemetry.api_loaded, 'partial API marked loaded');
});

test('tracer startSpan exception is contained', () => {
  const api = {
    trace: { getTracer: () => ({ startSpan() { throw new Error('SPAN_SECRET'); } }) },
    metrics: { getMeter: () => ({ createCounter: () => ({ add() {} }) }) },
  };
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: api });
  assert(telemetry.recordSecurityDecision('admin_gate', { allowed: false, code: 'ADMIN_EXECUTION_DISABLED' }), 'tracer exception escaped');
});

test('span attribute exception still ends span and is contained', () => {
  let ended = 0;
  const api = {
    trace: { getTracer: () => ({ startSpan: () => ({ addEvent() { throw new Error('ATTRIBUTE_SECRET'); }, end() { ended++; } }) }) },
    metrics: { getMeter: () => ({ createCounter: () => ({ add() {} }) }) },
  };
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: api });
  telemetry.recordSecurityDecision('admin_gate', { allowed: false, code: 'ADMIN_EXECUTION_DISABLED' });
  assert(ended === 1, 'span was not ended after addEvent failure');
});

test('span end exception is contained', () => {
  const api = {
    trace: { getTracer: () => ({ startSpan: () => ({ addEvent() {}, setStatus() {}, end() { throw new Error('END_SECRET'); } }) }) },
    metrics: { getMeter: () => ({ createCounter: () => ({ add() {} }) }) },
    SpanStatusCode: { OK: 1, ERROR: 2 },
  };
  const telemetry = new AuditTelemetry({ otelEnabled: true, otelApi: api });
  assert(telemetry.recordSecurityDecision('admin_gate', { allowed: true, code: 'ADMIN_EXECUTION_ENABLED' }), 'span end escaped');
  assert(telemetry.getSummary().emission_errors === 1, 'end failure not counted');
});

test('thousands of events cannot exceed configured or absolute memory limit', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false, maxEvents: 50 });
  for (let i = 0; i < 20000; i++) telemetry.audit('audit.unknown', { count: i });
  assert(telemetry.getEventsForTesting().length === 50, 'buffer exceeded configured limit');
  const capped = new AuditTelemetry({ otelEnabled: false, maxEvents: Number.MAX_SAFE_INTEGER });
  assert(capped.maxEvents === 5000, 'absolute buffer cap missing');
});

test('concurrent event calls retain unique deterministic sequence numbers', async () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false, maxEvents: 100 });
  await Promise.all(Array.from({ length: 1000 }, (_, i) => Promise.resolve().then(() => telemetry.audit('audit.unknown', { count: i }))));
  const events = telemetry.getEventsForTesting();
  assert(events.length === 100 && new Set(events.map(event => event.sequence)).size === 100, 'concurrent retention corrupt');
  assert(events[0].sequence === 901 && events[99].sequence === 1000, 'retention order is not deterministic');
});

test('deeply nested attributes are omitted without traversal', () => {
  const nested = { secret: 'DEEP_SECRET' };
  for (let i = 0; i < 1000; i++) nested.child = { nested: nested.child };
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  telemetry.audit('audit.unknown', { nested });
  assert(!serializedEvents(telemetry).includes('DEEP_SECRET'), 'deep value retained');
});

test('extremely long strings collapse to enum fallbacks', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false });
  const long = `LONG_SECRET_${'x'.repeat(1000000)}`;
  telemetry.audit(long, { action: long, method: long, resource_type: long });
  const text = serializedEvents(telemetry);
  assert(text.length < 1000 && !text.includes('LONG_SECRET'), 'long user string retained');
});

test('polluted prototypes cannot add audit attributes or global properties', () => {
  const input = JSON.parse('{"__proto__":{"polluted":"PROTO_SECRET"},"constructor":"CTOR_SECRET","decision.code":"OK"}');
  const clean = sanitizeAttributes(input).attributes;
  assert(clean['decision.code'] === 'OK', 'allowed enum missing');
  assert(!Object.prototype.polluted && !JSON.stringify(clean).includes('SECRET'), 'prototype pollution succeeded');
});

test('disabled OpenTelemetry never touches injected API', () => {
  let touched = 0;
  const api = {};
  Object.defineProperty(api, 'trace', { get() { touched++; throw new Error('must not load'); } });
  const telemetry = new AuditTelemetry({ otelEnabled: false, otelApi: api });
  telemetry.recordSecurityDecision('admin_gate', { allowed: false, code: 'ADMIN_EXECUTION_DISABLED' });
  assert(touched === 0 && telemetry.getSummary().opentelemetry.api_loaded === false, 'disabled API had side effects');
});

test('throwing telemetry cannot change admin gate HTTP response', () => {
  const middleware = createAdminGate({ telemetry: { recordSecurityDecision() { throw new Error('TELEMETRY_SECRET'); } } });
  let status = null;
  middleware({ method: 'POST' }, { status(code) { status = code; return this; }, json() {} }, () => { status = 200; });
  assert(status === 403, 'telemetry changed fail-closed response');
});

test('throwing telemetry cannot change authorization result', async () => {
  const telemetry = { recordSecurityDecision() { throw new Error('TELEMETRY_SECRET'); } };
  const result = await guard.validateTaskAsync({ action: 'navigation', target_id: 'missing', params: { url: 'https://fixture.invalid/' } }, registry(), {
    resolver, adminExecutionEnabled: true, telemetry, phase: 'enqueue',
  });
  assert(!result.allowed && result.code === 'TARGET_NOT_FOUND', 'telemetry changed authorization result');
  assert(!safeRecordSecurityDecision(telemetry, 'admin_gate', result), 'safe wrapper reported success');
});

test('throwing telemetry cannot enable or disable browser primitive', async () => {
  const ctx = context();
  const policy = new BrowserEgressGuard({
    registry: registry(), targetId: 'target-1', resolver, adminExecutionEnabled: true,
    telemetry: { recordSecurityDecision() { throw new Error('TELEMETRY_SECRET'); } },
  });
  await policy.install(ctx);
  const allowed = route('https://fixture.invalid/allowed/app.js');
  const denied = route('https://evil.invalid/app.js');
  await ctx.routeHandler(allowed);
  await ctx.routeHandler(denied);
  assert(allowed.state.continued === 1 && denied.state.aborted === 1, 'telemetry changed primitive behavior');
});

test('retention keeps exactly the newest N events in invocation order', () => {
  const telemetry = new AuditTelemetry({ otelEnabled: false, maxEvents: 3, clock: () => 42 });
  for (let i = 1; i <= 5; i++) telemetry.audit('audit.unknown', { count: i });
  const events = telemetry.getEventsForTesting();
  assert(events.map(event => event.attributes.count).join(',') === '3,4,5', 'ring retention mismatch');
  assert(events.map(event => event.sequence).join(',') === '3,4,5', 'sequence order mismatch');
});

(async () => {
  for (const item of tests) {
    try { await item.fn(); passed++; console.log(`PASS ${item.name}`); }
    catch (error) { failed++; console.error(`FAIL ${item.name}: ${error.message}`); }
  }
  console.log(`\n${passed}/${tests.length} tests passed`);
  process.exit(failed ? 1 : 0);
})();

'use strict';

/**
 * Passive, fail-safe security audit telemetry.
 *
 * Only closed enums and bounded numeric values are retained. URLs, identifiers,
 * free-form strings and request/response material are never accepted as audit
 * attributes. OpenTelemetry remains exact-true opt-in and this repository does
 * not install an SDK or exporter.
 */

const DEFAULT_MAX_EVENTS = 500;
const MAX_EVENTS_LIMIT = 5000;
const MAX_DURATION_MS = 300000;
const MAX_COUNT = 1000000;

const BOUNDARIES = new Set([
  'admin_gate', 'execution_guard', 'task_integrity',
  'browser_egress', 'browser_websocket',
]);
const OUTCOMES = new Set(['allowed', 'denied']);
const PHASES = new Set([
  'enqueue', 'dispatch', 'worker_retry', 'primitive',
  'agent_startup', 'browser_request', 'unspecified',
]);
const ACTIONS = new Set([
  'navigation', 'authenticated_replay', 'request_replay', 'state_comparison',
  'header_variation', 'cookie_variation', 'cache_validation',
  'permission_validation', 'workflow_validation', 'unknown',
]);
const RESOURCE_TYPES = new Set([
  'document', 'iframe', 'script', 'stylesheet', 'image', 'font', 'media',
  'fetch', 'xhr', 'manifest', 'preflight', 'websocket', 'other', 'unknown',
]);
const HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE', 'OTHER']);
const STATUS_CLASSES = new Set(['1xx', '2xx', '3xx', '4xx', '5xx', 'none']);
const DECISION_CODES = new Set([
  'OK', 'UNKNOWN', 'ADMIN_EXECUTION_ENABLED', 'ADMIN_EXECUTION_DISABLED',
  'AUTH_CHECK_INVALID', 'AUTH_EXPIRED', 'AUTH_NOT_CHECKED', 'BLOCKED_IP',
  'DNS_RESOLUTION_FAILED', 'DNS_RESOLVES_TO_BLOCKED', 'HOSTNAME_OUT_OF_SCOPE',
  'INVALID_PROTOCOL', 'INVALID_URL', 'LOCALHOST_BLOCKED', 'METHOD_NOT_ALLOWED',
  'PATH_DENIED', 'PATH_OUT_OF_SCOPE', 'PORT_NOT_ALLOWED', 'REDIRECT_OUT_OF_SCOPE',
  'SCOPE_EMPTY', 'SEQUENCE_STEP_INVALID', 'TARGET_DISABLED', 'TARGET_NOT_AUTHORIZED',
  'TARGET_NOT_EXECUTION_AUTHORIZED', 'TARGET_NOT_FOUND', 'TARGET_REQUIRED',
  'TARGET_URL_INVALID', 'TASK_MUTATED', 'TASK_NOT_SEALED', 'TASK_REQUIRED',
  'TASK_URL_INVALID', 'TASK_URL_REQUIRED', 'USERINFO_IN_URL',
  'WORKFLOW_STEP_INVALID', 'EGRESS_CHANNEL_DISABLED',
]);

const AUDIT_EVENT_TYPES = new Set(['audit.unknown']);
for (const boundary of BOUNDARIES) {
  for (const outcome of OUTCOMES) AUDIT_EVENT_TYPES.add(`security.${boundary}.${outcome}`);
}

const NOOP_SPAN = Object.freeze({ addEvent() {}, setStatus() {}, end() {} });
const NOOP_TRACER = Object.freeze({ startSpan() { return NOOP_SPAN; } });
const NOOP_COUNTER = Object.freeze({ add() {} });

function enumValue(value, allowed, fallback) {
  return typeof value === 'string' && allowed.has(value) ? value : fallback;
}

function boundedNumber(value, maximum) {
  if (!Number.isFinite(value)) return undefined;
  return Math.min(maximum, Math.max(0, Math.round(value)));
}

function sanitizeAttributes(attributes = {}) {
  const clean = Object.create(null);
  let omitted = 0;
  let entries;
  try { entries = Object.entries(attributes); } catch (_) { return { attributes: clean, omitted: 1 }; }

  for (const [key, value] of entries) {
    switch (key) {
      case 'decision.outcome':
        clean[key] = enumValue(value, OUTCOMES, 'denied');
        break;
      case 'decision.code':
        clean[key] = enumValue(value, DECISION_CODES, 'UNKNOWN');
        break;
      case 'phase':
        clean[key] = enumValue(value, PHASES, 'unspecified');
        break;
      case 'action':
        clean[key] = enumValue(value, ACTIONS, 'unknown');
        break;
      case 'resource_type':
        clean[key] = enumValue(value, RESOURCE_TYPES, 'unknown');
        break;
      case 'method':
      case 'http.method':
        clean['http.method'] = enumValue(String(value || '').toUpperCase(), HTTP_METHODS, 'OTHER');
        break;
      case 'status.class':
        clean[key] = enumValue(value, STATUS_CLASSES, 'none');
        break;
      case 'duration_ms': {
        const bounded = boundedNumber(value, MAX_DURATION_MS);
        if (bounded === undefined) omitted++; else clean[key] = bounded;
        break;
      }
      case 'count': {
        const bounded = boundedNumber(value, MAX_COUNT);
        if (bounded === undefined) omitted++; else clean[key] = bounded;
        break;
      }
      case 'enabled':
        if (typeof value === 'boolean') clean[key] = value; else omitted++;
        break;
      default:
        omitted++;
    }
  }
  return { attributes: clean, omitted };
}

function safeRecordSecurityDecision(telemetry, boundary, result, attributes = {}) {
  try {
    if (!telemetry || typeof telemetry.recordSecurityDecision !== 'function') return false;
    return telemetry.recordSecurityDecision(boundary, result, attributes) === true;
  } catch (_) {
    return false;
  }
}

class AuditTelemetry {
  constructor(options = {}) {
    this.otelEnabled = options.otelEnabled ?? process.env.BOQA_OTEL_ENABLED === 'true';
    const requestedSize = Number.isFinite(options.maxEvents) ? options.maxEvents : DEFAULT_MAX_EVENTS;
    this.maxEvents = Math.min(MAX_EVENTS_LIMIT, Math.max(1, Math.floor(requestedSize)));
    this.clock = typeof options.clock === 'function' ? options.clock : Date.now;
    this.buffer = new Array(this.maxEvents);
    this.bufferSize = 0;
    this.nextIndex = 0;
    this.sequence = 0;
    this.counts = Object.create(null);
    for (const type of AUDIT_EVENT_TYPES) this.counts[type] = 0;
    this.droppedEvents = 0;
    this.omittedAttributes = 0;
    this.emissionErrors = 0;
    this.lastEventAt = null;
    this.otelApiLoaded = false;
    this.tracer = NOOP_TRACER;
    this.eventCounter = NOOP_COUNTER;
    this.otelApi = null;

    if (this.otelEnabled) {
      const apiWasInjected = Object.prototype.hasOwnProperty.call(options, 'otelApi');
      this._initializeOpenTelemetry(options.otelApi, apiWasInjected);
    }
  }

  _initializeOpenTelemetry(injectedApi, apiWasInjected = false) {
    try {
      const api = apiWasInjected ? injectedApi : require('@opentelemetry/api');
      if (!api?.trace?.getTracer || !api?.metrics?.getMeter) throw new Error('OTEL_API_INCOMPLETE');
      const tracer = api.trace.getTracer('boqa-security-audit', '1.0.0');
      const meter = api.metrics.getMeter('boqa-security-audit', '1.0.0');
      const counter = meter?.createCounter?.('boqa.audit.events', {
        description: 'Sanitized BOQA security audit decisions',
      });
      if (!tracer?.startSpan || !counter?.add) throw new Error('OTEL_API_INCOMPLETE');
      this.otelApi = api;
      this.tracer = tracer;
      this.eventCounter = counter;
      this.otelApiLoaded = true;
    } catch (_) {
      this.emissionErrors++;
      this.otelApiLoaded = false;
      this.tracer = NOOP_TRACER;
      this.eventCounter = NOOP_COUNTER;
    }
  }

  audit(type, attributes = {}) {
    try {
      const eventType = AUDIT_EVENT_TYPES.has(type) ? type : 'audit.unknown';
      const sanitized = sanitizeAttributes(attributes);
      this.omittedAttributes += sanitized.omitted;
      const ts = boundedNumber(this.clock(), Number.MAX_SAFE_INTEGER) ?? 0;
      const event = Object.freeze({
        type: eventType,
        ts,
        sequence: ++this.sequence,
        attributes: Object.freeze({ ...sanitized.attributes }),
      });

      this.counts[eventType]++;
      this.lastEventAt = ts;
      if (this.bufferSize === this.maxEvents) this.droppedEvents++;
      else this.bufferSize++;
      this.buffer[this.nextIndex] = event;
      this.nextIndex = (this.nextIndex + 1) % this.maxEvents;

      this._emitOpenTelemetry(eventType, sanitized.attributes);
      return true;
    } catch (_) {
      this.emissionErrors++;
      return false;
    }
  }

  recordSecurityDecision(boundary, result, attributes = {}) {
    try {
      const safeBoundary = enumValue(boundary, BOUNDARIES, null);
      const outcome = result?.allowed === true ? 'allowed' : 'denied';
      const type = safeBoundary ? `security.${safeBoundary}.${outcome}` : 'audit.unknown';
      return this.audit(type, {
        ...attributes,
        'decision.outcome': outcome,
        'decision.code': result?.code,
      });
    } catch (_) {
      this.emissionErrors++;
      return false;
    }
  }

  _emitOpenTelemetry(eventType, attributes) {
    if (!this.otelEnabled || !this.otelApiLoaded) return;
    try {
      this.eventCounter.add(1, {
        'audit.event.type': eventType,
        'audit.decision.outcome': attributes['decision.outcome'] || 'denied',
      });
    } catch (_) { this.emissionErrors++; }

    let span = NOOP_SPAN;
    try {
      span = this.tracer.startSpan(`boqa.audit.${eventType}`, { attributes }) || NOOP_SPAN;
      if (typeof span.addEvent === 'function') span.addEvent(eventType, attributes);
      const denied = attributes['decision.outcome'] === 'denied';
      if (typeof span.setStatus === 'function' && this.otelApi?.SpanStatusCode) {
        span.setStatus({ code: denied ? this.otelApi.SpanStatusCode.ERROR : this.otelApi.SpanStatusCode.OK });
      }
    } catch (_) {
      this.emissionErrors++;
    } finally {
      try { if (typeof span.end === 'function') span.end(); } catch (_) { this.emissionErrors++; }
    }
  }

  getSummary() {
    return {
      audit_events_total: this.sequence,
      audit_events_retained: this.bufferSize,
      audit_events_dropped: this.droppedEvents,
      audit_events_by_type: Object.fromEntries(Object.entries(this.counts)),
      attributes_omitted: this.omittedAttributes,
      emission_errors: this.emissionErrors,
      last_event_at: this.lastEventAt,
      opentelemetry: {
        enabled: this.otelEnabled,
        api_loaded: this.otelApiLoaded,
        exporter_configured_by_boqa: false,
      },
    };
  }

  getEventsForTesting() {
    const events = [];
    const start = this.bufferSize === this.maxEvents ? this.nextIndex : 0;
    for (let offset = 0; offset < this.bufferSize; offset++) {
      const event = this.buffer[(start + offset) % this.maxEvents];
      events.push({ type: event.type, ts: event.ts, sequence: event.sequence, attributes: { ...event.attributes } });
    }
    return events;
  }
}

module.exports = {
  AuditTelemetry,
  sanitizeAttributes,
  safeRecordSecurityDecision,
  AUDIT_EVENT_TYPES,
};

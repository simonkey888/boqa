'use strict';

/**
 * Passive, fail-safe audit telemetry.
 *
 * Security audit events are retained only in a bounded in-memory buffer. The
 * OpenTelemetry API is opt-in and has no SDK or exporter in this repository,
 * so enabling it only emits to a provider explicitly registered by the host.
 * Telemetry failures are contained and never affect BOQA authorization.
 */

const DEFAULT_MAX_EVENTS = 500;
const MAX_STRING_LENGTH = 256;
const SENSITIVE_KEY = /(authorization|cookie|token|secret|password|api[_-]?key|hmac|headers?|body|payload|evidence|url)/i;

function normalizeValue(value) {
  if (typeof value === 'string') return value.slice(0, MAX_STRING_LENGTH);
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    return value.slice(0, 20).map(normalizeValue).filter(item => item !== undefined);
  }
  return undefined;
}

function sanitizeAttributes(attributes = {}) {
  const clean = {};
  let omitted = 0;
  for (const [key, value] of Object.entries(attributes)) {
    if (SENSITIVE_KEY.test(key)) {
      omitted++;
      continue;
    }
    const normalized = normalizeValue(value);
    if (normalized !== undefined) clean[key] = normalized;
    else omitted++;
  }
  return { attributes: clean, omitted };
}

class AuditTelemetry {
  constructor(options = {}) {
    this.otelEnabled = options.otelEnabled ?? process.env.BOQA_OTEL_ENABLED === 'true';
    this.maxEvents = Math.max(1, options.maxEvents || DEFAULT_MAX_EVENTS);
    this.clock = options.clock || Date.now;
    this.events = [];
    this.counts = {};
    this.droppedEvents = 0;
    this.omittedAttributes = 0;
    this.emissionErrors = 0;
    this.lastEventAt = null;
    this.otelApiLoaded = false;
    this.tracer = null;
    this.eventCounter = null;
    this.otelApi = null;

    if (this.otelEnabled) this._initializeOpenTelemetry(options.otelApi);
  }

  _initializeOpenTelemetry(injectedApi) {
    try {
      // The API package defaults to no-op unless the host explicitly registers
      // an SDK/provider. BOQA does not configure an exporter or endpoint.
      this.otelApi = injectedApi || require('@opentelemetry/api');
      this.tracer = this.otelApi.trace.getTracer('boqa-security-audit', '1.0.0');
      const meter = this.otelApi.metrics.getMeter('boqa-security-audit', '1.0.0');
      this.eventCounter = meter.createCounter('boqa.audit.events', {
        description: 'Sanitized BOQA security audit decisions',
      });
      this.otelApiLoaded = true;
    } catch (_) {
      this.emissionErrors++;
      this.otelApiLoaded = false;
      this.tracer = null;
      this.eventCounter = null;
    }
  }

  audit(type, attributes = {}) {
    try {
      const eventType = String(type || 'unknown').replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 120);
      const sanitized = sanitizeAttributes(attributes);
      this.omittedAttributes += sanitized.omitted;
      const ts = this.clock();
      const event = Object.freeze({
        type: eventType,
        ts,
        attributes: Object.freeze({ ...sanitized.attributes }),
      });

      this.counts[eventType] = (this.counts[eventType] || 0) + 1;
      this.lastEventAt = ts;
      this.events.push(event);
      if (this.events.length > this.maxEvents) {
        this.events.shift();
        this.droppedEvents++;
      }

      this._emitOpenTelemetry(eventType, sanitized.attributes);
      return true;
    } catch (_) {
      this.emissionErrors++;
      return false;
    }
  }

  recordSecurityDecision(boundary, result, attributes = {}) {
    const outcome = result?.allowed === true ? 'allowed' : 'denied';
    return this.audit(`security.${boundary}.${outcome}`, {
      ...attributes,
      'decision.outcome': outcome,
      'decision.code': result?.code || 'UNKNOWN',
    });
  }

  _emitOpenTelemetry(eventType, attributes) {
    if (!this.otelEnabled || !this.otelApiLoaded) return;
    try {
      this.eventCounter.add(1, {
        'audit.event.type': eventType,
        'audit.decision.outcome': attributes['decision.outcome'] || 'unknown',
      });
      const span = this.tracer.startSpan(`boqa.audit.${eventType}`, { attributes });
      try {
        span.addEvent(eventType, attributes);
        const denied = attributes['decision.outcome'] === 'denied';
        if (typeof span.setStatus === 'function' && this.otelApi.SpanStatusCode) {
          span.setStatus({
            code: denied ? this.otelApi.SpanStatusCode.ERROR : this.otelApi.SpanStatusCode.OK,
          });
        }
      } finally {
        span.end();
      }
    } catch (_) {
      this.emissionErrors++;
    }
  }

  getSummary() {
    return {
      audit_events_total: Object.values(this.counts).reduce((sum, count) => sum + count, 0),
      audit_events_retained: this.events.length,
      audit_events_dropped: this.droppedEvents,
      audit_events_by_type: { ...this.counts },
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
    return this.events.map(event => ({
      type: event.type,
      ts: event.ts,
      attributes: { ...event.attributes },
    }));
  }
}

module.exports = { AuditTelemetry, sanitizeAttributes };

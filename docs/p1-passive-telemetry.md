# P1 Passive OpenTelemetry and audit events

BOQA records security-boundary decisions in a bounded, in-memory audit buffer.
The runtime metrics endpoint exposes aggregate counts only; it never returns raw
audit events.

OpenTelemetry emission is disabled by default and requires the exact setting:

```text
BOQA_OTEL_ENABLED=true
```

The repository includes only `@opentelemetry/api`. It does not install or
configure an SDK, collector, exporter, endpoint, or automatic instrumentation.
Without a provider registered externally by the host, the API remains no-op and
does not create network traffic.

Audit coverage includes:

- administrative mutation gate decisions;
- execution authorization at enqueue, dispatch, retry, primitive, and startup;
- task-integrity rejection at dispatch;
- browser HTTP(S) request decisions by resource type;
- fail-closed WebSocket decisions.

Audit attributes intentionally omit URLs, authorization data, headers, cookies,
request and response bodies, payloads, evidence, tokens, secrets, HMAC values,
and API keys. Telemetry exceptions are counted and contained; they do not alter
the underlying authorization result or HTTP response.

This instrumentation does not enable automatic analysis or administrative
execution. It does not claim complete DNS-rebinding mitigation and does not
change the P0.1 egress policy.

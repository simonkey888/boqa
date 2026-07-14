# BOQA merge-readiness

## Scope

This review compares `main` at
`989b32d3213300c6941da73e7a764228e14f52ab` with the audited code head
`618672c642d90fd50e95064be517bdf505f19275` (tree
`7dadf542b8785582a6f9af6d0cab5b6f3553270f`). The documentation commit that
contains this report is intentionally not self-referenced; its final connector
commit and tree are recorded in PR #4 and the pipeline result.

## Security gates

| Gate | Estado | Evidencia | Bloqueante |
| --- | --- | --- | --- |
| P0 Worker | PASS | `worker.js`; `test/test-worker-readonly.js` | sí |
| Admin gate | PASS | `lib/admin-gate.js`; `test/test-execution-defaults.js` | sí |
| Execution guard | PASS | `lib/execution-authorization-guard.js`; P0.1 integration tests | sí |
| Browser egress | PASS | `lib/browser-egress-guard.js`; isolated browser fixtures | sí |
| DNS rebinding | KNOWN LIMITATION | Chromium DNS is not connection-pinned; A/AAAA validation alone is insufficient | no mientras admin=false |
| Defaults | PASS | Docker/config defaults and six regression tests | sí |
| Telemetry privacy | PASS | strict attribute allowlist and 19 adversarial fixtures | sí |
| CI | PASS | GitHub Actions run `29307367961` on the P1.C tree | sí para merge |
| Secrets | PASS | changed-file scan plus staged/final scans, zero findings | sí |
| Production deploy | NOT PERFORMED | explicit pipeline restriction | no |
| Tag | PENDING | annotated-tag connector limitation; no lightweight substitute | no |

PR #4 is technically prepared for human review but deliberately remains Draft.
The known DNS-rebinding limitation is acceptable only while administrative
execution remains false; enabling execution requires a separate reviewed change.

## Change audit

- **History:** 30 commits and 59 files differ from `main` at the audited code
  head. The chain contains the dashboard recovery, canonical quality model,
  P0/P0.1/P0.2 hardening, passive telemetry, reproducible CI, and residual
  execution-surface quarantine.
- **Generated/runtime output:** no output directory, log, temporary file,
  validation artifact, browser report, key, or environment file is tracked by
  this pipeline. `validation-evidence/` is ignored and CI uploads only its small
  non-sensitive `summary.json`.
- **Fixtures:** security tests use injected resolvers, fake browser objects,
  synthetic URLs, and in-process request objects. They perform no target
  navigation or real DNS lookup.
- **Dependencies:** P1 added only exact `@opentelemetry/api@1.9.1`; no SDK,
  exporter, collector, endpoint, or automatic instrumentation is configured.
- **Lockfile:** `package-lock.json` differs from `main` solely for the locked
  OpenTelemetry API dependency. P1.A through P1.D did not modify the lockfile.
- **Runtime compatibility:** Docker and CI both use Node 20. The clean GitHub
  Actions install and complete suite passed with the lockfile's Playwright build
  while browser download was disabled.
- **Docker:** external API-key/HMAC variables remain mandatory; auto-analysis,
  admin execution, and OpenTelemetry all default false; health requires HTTP 200.
- **Migrations and findings:** historical canonicalization files are unchanged
  by P1.A–P1.D. No historical input, finding, reportability state, or bounty
  semantic was modified.
- **Public routes:** the canonical Worker remains an explicit read-only allowlist;
  the legacy Pages surface is quarantined and cannot proxy.
- **Rollback concept:** no deployment occurred. Existing production rollback
  assets and procedures are outside this repository-only pipeline and were not
  accessed or changed.

## Other pull requests

| PR | Estado observado | Superposición con PR #4 | Acción |
| --- | --- | --- | --- |
| #1 | open, not Draft, unmerged | `package-lock.json` | Review ordering manually; not modified or closed |
| #2 | open, Draft, unmerged | `Dockerfile`, `compose.yaml`, dashboard files, `package.json`, dashboard test, `worker.js` | PR #4 is a superset for these paths; not modified or closed |
| #3 | open, not Draft, unmerged | GitHub reports no changed filenames | Not modified or closed |

The overlap table is advisory. No other pull request was rebased, closed,
retargeted, marked ready, or merged.

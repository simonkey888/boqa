# BOQA security invariants

These invariants are merge and release gates. A change that weakens one of them
must fail closed and receive an explicit security review. They describe source
behavior only; this pull request does not deploy or enable execution.

1. **The public Worker is read-only.** `worker.js` permits only enumerated
   `GET`/`HEAD` routes and rejects mutations before HMAC signing or backend
   forwarding. Evidence: `test/test-worker-readonly.js`.
2. **The legacy Pages proxy is disabled.** `functions/api/[[path]].js` performs
   no backend fetch, credential forwarding, signing, WebSocket upgrade, or
   mutation. Evidence: `test/test-p1c-residual-surfaces.js`.
3. **Administrative execution defaults to false.** Only the exact value `true`
   can pass the API gate, and it is not sufficient to authorize a task.
   Evidence: `lib/admin-gate.js`, `test/test-execution-defaults.js`.
4. **Automatic analysis defaults to false.** `BOQA_AUTO_ANALYZE` is an exact
   opt-in and Docker also sets it to false. Evidence: `lib/config.js`,
   `Dockerfile`, `test/test-execution-defaults.js`.
5. **OpenTelemetry defaults to false.** BOQA configures no exporter, collector,
   endpoint, SDK, or automatic instrumentation. Observational failures cannot
   change authorization or HTTP behavior. Evidence: `lib/audit-telemetry.js`,
   `test/test-p1a-telemetry-adversarial.js`.
6. **There is no implicit target.** Browser execution requires an explicit URL
   and canonical target ID. Demo and CI configurations contain no executable
   external target. Evidence: `lib/config.js`, `ci/config.json`,
   `test/test-p1c-residual-surfaces.js`.
7. **A canonical target is mandatory.** The registry entry must be enabled,
   authorized, execution-authorized, recently checked, and have non-empty
   scope. Callers cannot authorize an inline target.
8. **The execution guard runs before enqueue.** Rejected tasks never become
   pending. Accepted tasks are deep-cloned, frozen, and sealed with a canonical
   payload hash. Evidence: `verification-farm.js`,
   `test/test-p01-guard-integration.js`.
9. **Integrity is checked immediately before dispatch.** Any mutation after
   enqueue is rejected before an executor or network primitive can run.
10. **Retries and restored tasks are revalidated.** Current registry state,
    task integrity, every URL, scope, and injected A/AAAA resolver result are
    checked again before execution.
11. **Browser subrequests are guarded.** The browser context routes requests
    through `BrowserEgressGuard`; disallowed redirects, popups, frames, workers,
    downloads, forms and subresources fail closed. Service workers are blocked.
12. **WebSocket and EventSource are fail-closed.** Browser WebSocket requests
    are aborted, EventSource uses the guarded request route, and public `/ws`
    is unavailable.
13. **DNS rebinding is not claimed as fully mitigated.** BOQA validates injected
    A and AAAA answers, including mixed public/private results, but does not pin
    Chromium's connection resolution. Administrative execution must remain
    disabled unless a controlled egress proxy or equivalent connection-level
    pinning is added and independently tested.
14. **Production deployment is outside this change.** This pipeline performs no
    production access, deployment, configuration mutation, historical finding
    rewrite, or reportability/bounty semantic change.

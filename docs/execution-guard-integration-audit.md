# P0.1 Execution Guard Integration Audit

Baseline: `dd94f5b3a04b5e93e120ac9f6d98efa9b76fecae`.

Method: static inventory, caller tracing, source-level characterization, and isolated integration fixtures. No production, external navigation, real DNS, OCI, Cloudflare, SSH, or deployment was used. The pre-change verdict is preserved in `docs/execution-guard-prechange-verdict.json`.

## Pre-change verdict

| Question | Baseline | Evidence |
| --- | --- | --- |
| All enqueue paths guarded | false | `routes/v01.js`, `coverage-planner.js`, and `campaign-engine.js` called synchronous `VerificationFarm.submitTask()`; the guard had no runtime import. |
| All execution paths revalidated | false | `verification-farm.js` called `worker.execute(task)` directly and retried the same object. |
| All URL fields covered | false | `validateTask()` knew only three top-level fields plus two fixed arrays. |
| Async DNS before execution | false | `validateTask()` called only `validateUrl()`; `validateUrlAsync()` had no caller. |
| Redirects guarded | false | `validateRedirect()` had no caller and no browser route interception existed. |
| Browser subrequests guarded | false | `agent.js` observed requests but never aborted them. |
| WebSockets guarded | false | browser instrumentation wrapped and opened the original WebSocket. |
| DNS rebinding fully mitigated | false | DNS validation was not integrated and no pin/proxy existed. |
| Mutation after validation possible | true | `verification-farm.js` stored `task.params` by reference. |
| Persistence restore revalidated | false | `target-runner.js` trusted checkpoint `target_url` and resubmitted it. |

## Outbound primitive inventory

Line numbers below refer to the audited working tree after the P0.1 patch.

| ID | File/line | Primitive real | URL origin | Target ID | Guard before enqueue | Guard before execution | DNS async | Redirect | Subrequests | State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| O-01 | `agent.js:605` | `page.goto` | `CONFIG.target` | `BOQA_TARGET_ID` | startup task at `agent.js:518` | URL check at `agent.js:596`; context policy installed before page creation | yes, injected resolver | every browser request is routed | context-wide | PROVEN |
| O-02 | `agent.js:87` | page `fetch` wrapper | page JavaScript | active canonical target | startup authorization | `BrowserEgressGuard` | yes | request chain routed | fetch request routed | PROVEN |
| O-03 | `agent.js:118` | XHR `send` wrapper | page JavaScript | active canonical target | startup authorization | `BrowserEgressGuard` | yes | request chain routed | XHR request routed | PROVEN |
| O-04 | `agent.js:126` | aliased `new WebSocket` | page JavaScript | active canonical target | startup authorization | `routeWebSocket('**/*')` closes with policy code before connection; constructor is also disabled | n/a | n/a | disabled | PROVEN |
| O-05 | `agent.js:662` | `connectOverCDP` | `BOQA_CDP` | none | n/a | rejected at `agent.js:510` before browser launch | n/a | n/a | n/a | DEAD_CODE |
| O-06 | `verification-farm.js:318` | navigation `page.goto` | `task.params.url` | `task.target_id` | `submitTaskAsync` at `verification-farm.js:760` | queue, retry, per-URL, and browser route checks | yes | routed | context-wide | PROVEN |
| O-07 | `verification-farm.js:401` | replay `page.goto` | each `request_sequence[].url` | `task.target_id` | recursive URL extraction | per sequence item | yes | routed | context-wide | PROVEN |
| O-08 | `verification-farm.js:445` | browser `fetch` in `page.evaluate` | `task.params.url` | `task.target_id` | recursive URL extraction | immediately before evaluate plus browser route | yes | routed | fetch routed | PROVEN |
| O-09 | `verification-farm.js:559` | workflow `page.goto`; clicks/fills can navigate | each workflow step/page behavior | `task.target_id` | recursive URL extraction | each explicit navigation plus browser route for click/form side effects | yes | routed | context-wide | PROVEN |
| O-10 | `agent/playwright-runner.js:113,152` | `page.goto`, CDP | constructor options | none | none | none | no | no | no | DEAD_CODE (exported but no repository caller) |
| O-11 | `worker.js:405` | Worker backend `fetch` | secret/configured backend binding | n/a | public read-only allowlist before proxy | HMAC/API key proxy boundary | n/a | `redirect: manual` | n/a | PROVEN (infrastructure proxy, not target execution) |
| O-12 | `worker.js:567` | static asset binding fetch | incoming asset URL | n/a | non-API branch | Cloudflare ASSETS binding | n/a | binding-owned | n/a | PROVEN |
| O-13 | `functions/api/[[path]].js:43` | legacy Pages backend `fetch` | `BOQA_BACKEND_URL` plus request path | n/a | no execution guard | backend auth remains authoritative | n/a | `redirect: manual` | n/a | PARTIAL (legacy infrastructure proxy; not wired by Worker deployment) |
| O-14 | `agent.js:901`, `agent/playwright-runner.js:575` | `page.evaluate` performance reads | no URL | n/a | n/a | no network operation in callback | n/a | n/a | n/a | DEAD_CODE as outbound primitive |

`browser.newContext`, `context.newPage`, CDP session creation, `new URL`, dashboard polling, and the inbound WebSocket server were inventoried but are not themselves target-network egress. `page.reload`, `page.setContent`, `frame.goto`, `request.newContext`, Axios, Node `http.request`/`https.request`, request fulfillment, and CDP Network interception are absent from runtime code.

## Reachable call graph

1. Administrative verification API: `server.js` admin gate → `routes/v01.js:683` → `submitTaskAsync` → sealed priority queue → `processQueue` integrity/current-registry/DNS check → `VerificationWorker.execute` retry check → action dispatcher → per-URL check → Playwright primitive → context route check.
2. Coverage planner: admin-gated route or continuous planner → `_executeVerify` → `coverage-planner.js:574 submitTaskAsync` → the same farm path. The legacy synchronous submit method now fails closed.
3. Campaign engine: admin-gated iterate/start endpoints or an already scheduled internal timer → `executeIteration` → `campaign-engine.js:555 submitTaskAsync` → the same farm path. Internal generation therefore cannot bypass route middleware.
4. Server startup: `server.js:195` requires `BOQA_ADMIN_EXECUTION_ENABLED === 'true'` → `Agent.start` validates canonical target/URL asynchronously before launch → installs context egress policy → revalidates immediately before `page.goto`.
5. S6 API: admin gate → `routes/s6.js:30` rejects inline target URLs → `TargetRunner.submitTargetsAsync` reloads canonical registry target, validates, seals, and enqueues → `TargetScheduler` → `executeTarget` verifies hash and revalidates. Current S6 work analyzes the already guarded agent; it contains no independent network primitive.
6. Checkpoint restore: `TargetRunner.resumeFromCheckpoint` ignores persisted URL and calls `submitTargetAsync` with target ID → canonical registry URL → async validation and sealing.
7. `Scheduler`, `ScanScheduler`, and `WorkerPool` maintain job/resource state but have no caller to a browser/HTTP primitive. `MultiTargetScheduler.runSession` expects `agent.run`, which the repository `Agent` does not implement; it is classified dead/unwired.
8. `agent/playwright-runner.js` is exported but never imported. Its primitives are explicitly classified `DEAD_CODE`, not counted as protected execution.

## Mutation and retry properties

- Caller data is deep-cloned.
- Nested params are deep-frozen.
- Identity, action, target, and params properties are non-writable.
- Canonical serialization covers every execution URL field and produces `authorized_payload_hash`.
- Integrity is checked after dequeue and before every retry.
- Target registry authorization and A/AAAA resolution are repeated at dispatch and each explicit primitive.
- A context may not switch canonical target after its route policy is installed.
- Restored checkpoint URLs are not trusted.

## URL, scope, DNS, redirects, and browser channels

- URL protocols are limited to HTTP/HTTPS; userinfo and private/special IP literals are rejected.
- Scope URL patterns must match protocol, exact hostname, effective port, and path glob. Matching the hostname no longer authorizes every path.
- Every key named `url` or ending in `_url` is recursively extracted from the task object.
- Allowed HTTP methods and ports are enforced.
- Both A and AAAA are resolved through an injectable resolver. Any private member of a mixed answer rejects the request.
- Alternate IPv4 forms are normalized by WHATWG `URL`; IPv4-mapped IPv6, loopback, link-local, ULA, multicast, and private IPv4 are rejected.
- Context routing covers document, iframe, script, stylesheet, image, font, media, fetch, XHR, manifest, preload/prefetch, form submission, download requests, and HTTP redirect hops.
- WebSocket is closed through Playwright's dedicated context-wide `routeWebSocket('**/*')` handler and its page constructor is also disabled. EventSource is disabled. Service workers are blocked for new contexts and a context with a pre-existing service worker is rejected.
- Meta refresh, JavaScript location changes, popup/window.open, and iframe navigation produce browser requests governed by the context route.

## Explicit limitation: DNS rebinding

`dns_rebinding_fully_mitigated` remains **false**. The policy resolves A and AAAA immediately before `route.continue()`, but Chromium may perform a separate resolution. This patch does not implement a pinned resolver, validated egress proxy, or connect-by-IP with correct Host/SNI. Repeating DNS checks is useful defense but is not claimed as complete mitigation. Administrative execution therefore remains default-disabled.

## Post-change verdict

```json
{
  "all_enqueue_paths_guarded": true,
  "all_execution_paths_revalidated": true,
  "all_url_fields_covered": true,
  "async_dns_used_before_execution": true,
  "redirects_guarded": true,
  "browser_subrequests_guarded": true,
  "websockets_guarded": true,
  "dns_rebinding_fully_mitigated": false,
  "task_mutation_after_validation_possible": false,
  "persistence_restore_revalidated": true
}
```

## Test evidence

- Characterization: 9/9.
- P0.1 isolated integration: 16/16.
- Full suite: 26/26 test files, no failures, errors, or skips.
- Tests use fake resolvers, fake browser/context/page/route objects, source fixtures, and temporary checkpoint files only.

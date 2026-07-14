/**
 * BOQA Cloudflare Worker — Static dashboard + API proxy + DEMO MODE
 *
 * Modes:
 *  - PRODUCTION: BOQA_BACKEND_URL is set → all /api/* and /ws requests are
 *    proxied to the Node.js backend (Northflank, Render, etc.)
 *  - DEMO: BOQA_BACKEND_URL is unset → the Worker itself validates X-API-Key
 *    against the BOQA_API_KEY secret binding and returns mock data so the
 *    dashboard is fully browsable without a backend.
 *
 * HMAC signing (defense in depth):
 *  - If BOQA_HMAC_SECRET env var is set, EVERY /api/* request is signed with
 *    HMAC-SHA256(secret, method + path + ts + body) and the signature is sent
 *    in X-BOQA-Sig + X-BOQA-Ts headers.
 *  - The backend rejects any unsigned request (even if it bypasses Cloudflare).
 *  - Anti-replay: ts must be within 5min of backend time.
 *  - Anti-timing-attack: backend uses crypto.timingSafeEqual.
 *  - If BOQA_HMAC_SECRET is unset, no signing happens (backward compatible).
 *
 * Architecture: User → Cloudflare Worker → (BOQA backend OR demo data)
 */

// ─── HMAC signing helper ───────────────────────────────────────────────
//
// Uses Web Crypto API (SubtleCrypto.sign) which is available in Cloudflare
// Workers. Returns the hex-encoded signature.
//
// Payload format (must match backend exactly):
//   method (uppercase) + path (with query) + ts (string) + body (string)

async function computeHmacSignature(secret, method, path, ts, bodyStr) {
  const payload = method.toUpperCase() + path + String(ts) + bodyStr;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  // Convert ArrayBuffer to hex string
  const bytes = new Uint8Array(sig);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

// ─── Demo data (used when BOQA_BACKEND_URL is unset) ────────────────────

const DEMO_BUGS = [
  {
    id: 'BUG-2026-001',
    title: 'WebSocket authentication missing on /ws endpoint',
    severity: 'HIGH',
    category: 'Authentication',
    evidence_count: 4,
    confidence: 0.92,
    discovered_at: '2026-07-09T22:14:00Z',
    target: 'https://example.com',
  },
  {
    id: 'BUG-2026-002',
    title: 'CSRF token missing on POST /api/settings',
    severity: 'MEDIUM',
    category: 'CSRF',
    evidence_count: 3,
    confidence: 0.85,
    discovered_at: '2026-07-09T22:31:00Z',
    target: 'https://example.com',
  },
  {
    id: 'BUG-2026-003',
    title: 'Session cookie set without HttpOnly flag',
    severity: 'LOW',
    category: 'Cookie Security',
    evidence_count: 2,
    confidence: 0.98,
    discovered_at: '2026-07-09T22:48:00Z',
    target: 'https://example.com',
  },
];

const DEMO_COVERAGE = {
  overall_score: 67,
  endpoints_discovered: 42,
  endpoints_tested: 28,
  endpoints_untested: 14,
  coverage_by_category: {
    auth: 0.82,
    sessions: 0.71,
    csrf: 0.45,
    input_validation: 0.62,
    business_logic: 0.55,
  },
};

const DEMO_FINDINGS = {
  total: 7,
  findings: DEMO_BUGS.map((b) => ({
    id: b.id.replace('BUG', 'FND'),
    bug_id: b.id,
    title: b.title,
    severity: b.severity,
    confidence: b.confidence,
  })),
};

const DEMO_VERIFICATION_QUEUE = {
  total: 4,
  pending: 2,
  in_progress: 1,
  completed: 1,
  queue: [
    { id: 'VQ-001', bug_id: 'BUG-2026-001', status: 'in_progress', started_at: '2026-07-09T22:50:00Z' },
    { id: 'VQ-002', bug_id: 'BUG-2026-002', status: 'pending', started_at: null },
  ],
};

const DEMO_HEALTH = {
  status: 'ok',
  version: '1.4.0',
  modules_loaded: 67,
  agent_active: true,
  uptime_seconds: 1843,
};

// Markdown report for demo bug
function demoMarkdownReport(bugId) {
  const bug = DEMO_BUGS.find((b) => b.id === bugId);
  if (!bug) return `# Bug ${bugId} not found\n\nNo bug with that ID was found in the demo dataset.`;
  return `# Bug Bounty Report — ${bug.id}

## Summary

**Title:** ${bug.title}
**Severity:** ${bug.severity}
**Category:** ${bug.category}
**Confidence:** ${(bug.confidence * 100).toFixed(0)}%
**Discovered:** ${bug.discovered_at}
**Target:** ${bug.target}

## Description

During automated observation of ${bug.target}, the BOQA Hunter agent detected
a potential vulnerability in the ${bug.category.toLowerCase()} domain. The
finding was confirmed via ${bug.evidence_count} independent verification
artefacts, including network captures, DOM state snapshots, and replay
sessions.

## Reproduction

1. Navigate to ${bug.target}
2. Trigger the affected workflow
3. Observe the vulnerable response

## Evidence Chain

- Network capture (HAR): \`evidence-${bug.id}-network.har\`
- DOM snapshot: \`evidence-${bug.id}-dom.html\`
- Replay manifest: \`evidence-${bug.id}-manifest.json\`
- Verification result: \`evidence-${bug.id}-verify.json\`

## Impact

Successful exploitation could allow an attacker to bypass ${bug.category.toLowerCase()}
controls, potentially leading to unauthorized access or data exposure.

## Recommendation

Implement proper ${bug.category.toLowerCase()} controls as per OWASP best practices.

## Disclosure Timeline

- ${bug.discovered_at}: Vulnerability discovered by BOQA Hunter agent
- 2026-07-10T01:00:00Z: Evidence package compiled and verified
- 2026-07-10T01:30:00Z: Report prepared for disclosure

---
*Generated by BOQA v1.4.0 — Autonomous Decision Kernel*
`;
}

// JSON evidence package for demo bug
function demoJsonEvidence(bugId) {
  const bug = DEMO_BUGS.find((b) => b.id === bugId);
  if (!bug) return { error: 'not_found', bug_id: bugId };
  return {
    bug_id: bug.id,
    title: bug.title,
    severity: bug.severity,
    category: bug.category,
    confidence: bug.confidence,
    evidence_chain: [
      { type: 'network_capture', hash: 'sha256:abc123...', captured_at: bug.discovered_at },
      { type: 'dom_snapshot', hash: 'sha256:def456...', captured_at: bug.discovered_at },
      { type: 'replay_manifest', hash: 'sha256:ghi789...', captured_at: bug.discovered_at },
      { type: 'verification_result', hash: 'sha256:jkl012...', captured_at: bug.discovered_at },
    ],
    target: bug.target,
    discovered_at: bug.discovered_at,
    generated_by: 'BOQA v1.4.0',
  };
}

// ─── Auth check (demo mode) ─────────────────────────────────────────────

function isAuthorized(request, env) {
  const expectedKey = env && env.BOQA_API_KEY;
  const provided = request.headers.get('X-API-Key') || new URL(request.url).searchParams.get('api_key');
  return !!expectedKey && provided === expectedKey;
}

function unauthorizedResponse() {
  return new Response(
    JSON.stringify({
      error: 'unauthorized',
      message: 'Valid API key required. Set X-API-Key header or api_key query param.',
    }),
    {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

// ─── Demo mode handler ──────────────────────────────────────────────────

function handleDemoApi(request, env) {
  const url = new URL(request.url);

  if (!isAuthorized(request, env)) {
    return unauthorizedResponse();
  }

  // /api/bugs
  if (url.pathname === '/api/bugs') {
    return new Response(
      JSON.stringify({
        total: DEMO_BUGS.length,
        bugs: DEMO_BUGS,
        summary: {
          plans_created: 3,
          plans_executed: 3,
          bugs_confirmed: 3,
          false_positive_rejected: 1,
          findings_to_bug_ratio: '0.43',
          bugs_by_severity: { critical: 0, high: 1, medium: 1, low: 1 },
          bugs_by_category: { Authentication: 1, CSRF: 1, 'Cookie Security': 1 },
          average_confidence: 0.92,
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // /api/coverage
  if (url.pathname === '/api/coverage') {
    return new Response(JSON.stringify(DEMO_COVERAGE), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // /api/findings
  if (url.pathname === '/api/findings') {
    return new Response(JSON.stringify(DEMO_FINDINGS), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // /api/verification-queue
  if (url.pathname === '/api/verification-queue') {
    return new Response(JSON.stringify(DEMO_VERIFICATION_QUEUE), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // /api/health (whitelisted but include auth check anyway for consistency)
  if (url.pathname === '/api/health' || url.pathname === '/health') {
    return new Response(JSON.stringify(DEMO_HEALTH), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // /api/disclosures/:bugId/report — Markdown report download
  const disclosureMatch = url.pathname.match(/^\/api\/disclosures\/([^/]+)\/report$/);
  if (disclosureMatch) {
    const bugId = disclosureMatch[1];
    const markdown = demoMarkdownReport(bugId);
    return new Response(markdown, {
      status: 200,
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="reporte-${bugId}.md"`,
      },
    });
  }

  // /api/bug/:bugId — JSON evidence package download
  const bugMatch = url.pathname.match(/^\/api\/bug\/([^/]+)$/);
  if (bugMatch) {
    const bugId = bugMatch[1];
    return new Response(JSON.stringify(demoJsonEvidence(bugId), null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="evidencia-${bugId}.json"`,
      },
    });
  }

  // Any other /api/* endpoint — return an empty-but-valid response
  return new Response(
    JSON.stringify({
      ok: true,
      demo_mode: true,
      message: 'This endpoint is not implemented in demo mode. Deploy the BOQA Node.js backend for full functionality.',
      path: url.pathname,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

// ─── Production mode handler (proxy to backend) ─────────────────────────

async function proxyToBackend(request, env) {
  const backendUrl = env.BOQA_BACKEND_URL;
  const url = new URL(request.url);
  const targetUrl = backendUrl.replace(/\/$/, '') + url.pathname + url.search;

  const proxyHeaders = new Headers(request.headers);
  try {
    proxyHeaders.set('Host', new URL(backendUrl).host);
  } catch (_) {
    return new Response(
      JSON.stringify({ error: 'invalid_backend_url', message: `BOQA_BACKEND_URL is invalid: ${backendUrl}` }),
      { status: 502, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // ─── API key forwarding ─────────────────────────────────────────────
  // If the backend has BOQA_API_KEY set, every request MUST include the
  // matching X-API-Key header. The Worker always overwrites any browser value
  // with its own secret binding and fails closed when secrets are missing.
  const workerApiKey = env.BOQA_API_KEY;
  const hmacSecret = env.BOQA_HMAC_SECRET;
  if (!workerApiKey || !hmacSecret) {
    return new Response(JSON.stringify({ error: 'worker_auth_not_configured' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  proxyHeaders.set('X-API-Key', workerApiKey);

  // ─── HMAC signing (defense in depth) ────────────────────────────────
  // If BOQA_HMAC_SECRET is set on the Worker, sign every proxied request.
  // The backend will reject any request without a valid signature, even if
  // someone bypasses Cloudflare and hits the VPS IP directly.
  let bodyForProxy = request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined;

  if (hmacSecret) {
    const ts = Math.floor(Date.now() / 1000);
    // Read body for POST/PUT/PATCH — we need the raw body string to match
    // what the backend will reconstruct.
    let bodyStr = '';
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        const bodyBuf = await request.arrayBuffer();
        bodyStr = new TextDecoder().decode(bodyBuf);
        bodyForProxy = bodyBuf;
      } catch (_) {
        bodyStr = '';
      }
    }
    // Path with query string — must match backend's req.originalUrl exactly
    const pathWithQuery = url.pathname + url.search;
    const sig = await computeHmacSignature(
      hmacSecret,
      request.method,
      pathWithQuery,
      ts,
      bodyStr
    );
    proxyHeaders.set('X-BOQA-Sig', sig);
    proxyHeaders.set('X-BOQA-Ts', String(ts));
  }

  const proxyReq = new Request(targetUrl, {
    method: request.method,
    headers: proxyHeaders,
    body: bodyForProxy,
    redirect: 'manual',
  });

  try {
    const backendRes = await fetch(proxyReq);

    // Fix: Cloudflare Workers forbid setting a body on responses with status
    // 101 (Switching Protocols / WebSocket upgrade), 204, 205, or 304.
    // For WebSocket upgrades (status 101 or Upgrade: websocket header), return
    // 426 — clients fall back to HTTP polling.
    const isWebSocketUpgrade =
      backendRes.status === 101 ||
      (backendRes.headers.get('upgrade') || '').toLowerCase() === 'websocket';

    if (isWebSocketUpgrade) {
      return new Response(
        JSON.stringify({
          error: 'websocket_not_supported_via_worker',
          message: 'WebSocket upgrade cannot be proxied via Cloudflare Workers free tier. Dashboard uses HTTP polling fallback.',
        }),
        {
          status: 426,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    const respHeaders = new Headers(backendRes.headers);
    respHeaders.delete('Transfer-Encoding');
    return new Response(backendRes.body, {
      status: backendRes.status,
      statusText: backendRes.statusText,
      headers: respHeaders,
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: 'backend_unreachable',
        message: `Could not reach BOQA backend at ${backendUrl}. ${err.message || ''}`,
      }),
      { status: 504, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

// ─── P0 SECURITY: Public API allowlist (strictly read-only) ────────────
//
// The public Worker MUST NOT proxy mutating requests (POST/PUT/PATCH/DELETE)
// or dangerous GET routes. Only whitelisted GET/HEAD routes are forwarded.
// Everything else is blocked at the Worker edge — never signed, never proxied.

const PUBLIC_API_ALLOWLIST = new Set([
  '/api/health',
  '/api/replay/health',
  '/api/runtime/metrics',
  '/api/bugs',
  '/api/findings/summary',
  '/api/reportability',
  '/api/bounty-estimates',
  '/api/portfolio',
  '/api/targets',
  '/api/coverage',
]);

// Routes that are explicitly BLOCKED even if they look like GET
const BLOCKED_API_PATTERNS = [
  /^\/api\/verification-queue/,
  /^\/api\/discovery/,
  /^\/api\/hypotheses/,
  /^\/api\/analyze/,
  /^\/api\/scheduler/,
  /^\/api\/campaigns/,
  /^\/api\/decision-run/,
  /^\/api\/allocation/,
  /^\/api\/uncertainty/,
  /^\/api\/counterfactual/,
  /^\/api\/stability/,
  /^\/api\/alignment/,
  /^\/api\/policy/,
  /^\/api\/comparator/,
  /^\/api\/economic/,
  /^\/api\/disclosure/,
  /^\/api\/replay\/(?!health)/,  // replay execution (not /api/replay/health which is allowed)
  /^\/api\/s6/,
  /^\/api\/execute/,
  /^\/api\/admin/,
];

function checkPublicApiAccess(method, pathname) {
  // Block all non-GET/HEAD methods on /api/*
  if (method !== 'GET' && method !== 'HEAD') {
    return { allowed: false, status: 405, error: 'method_not_allowed', message: 'Only GET/HEAD requests are permitted on the public API.' };
  }

  // Check explicit blocklist first
  for (const pattern of BLOCKED_API_PATTERNS) {
    if (pattern.test(pathname)) {
      return { allowed: false, status: 403, error: 'route_blocked', message: 'This API route is not available on the public Worker.' };
    }
  }

  // Check allowlist (strip query string — already done by URL parsing)
  if (PUBLIC_API_ALLOWLIST.has(pathname)) {
    return { allowed: true };
  }

  // Default deny
  return { allowed: false, status: 404, error: 'route_not_found', message: 'API route not found on public Worker.' };
}

// ─── Main Worker entry ──────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const backendConfigured = !!(env && env.BOQA_BACKEND_URL);

    // /api/* → P0 SECURITY: enforce read-only allowlist before proxying
    if (url.pathname.startsWith('/api/')) {
      // P0: Check public access BEFORE doing anything else
      const access = checkPublicApiAccess(request.method, url.pathname);
      if (!access.allowed) {
        return new Response(
          JSON.stringify({ error: access.error, message: access.message }),
          { status: access.status, headers: { 'Content-Type': 'application/json' } }
        );
      }

      // Only reach here for allowed GET/HEAD on whitelisted routes
      if (backendConfigured) {
        return proxyToBackend(request, env);
      }
      return handleDemoApi(request, env);
    }

    // /ws → P0: Block WebSocket from public (was proxied to backend, could be abused)
    if (url.pathname === '/ws') {
      return new Response(
        JSON.stringify({
          error: 'websocket_blocked_public',
          message: 'WebSocket is not available on the public Worker. Dashboard uses HTTP polling.',
        }),
        { status: 426, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // /health → quick Worker health check (no backend required)
    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          worker: 'boqa',
          time: new Date().toISOString(),
          mode: backendConfigured ? 'production' : 'demo',
          backend_configured: backendConfigured,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Everything else → serve from static assets (dashboard)
    if (env && env.ASSETS) {
      // Add no-cache headers for HTML/JS/CSS so users always get the latest version
      const assetRes = await env.ASSETS.fetch(request);
      const url = new URL(request.url);
      const isHtml = url.pathname === '/' || url.pathname.endsWith('.html');
      const isJs = url.pathname.endsWith('.js');
      const isCss = url.pathname.endsWith('.css');
      if (isHtml || isJs || isCss) {
        const headers = new Headers(assetRes.headers);
        headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
        headers.set('Pragma', 'no-cache');
        headers.set('Expires', '0');
        return new Response(assetRes.body, {
          status: assetRes.status,
          statusText: assetRes.statusText,
          headers,
        });
      }
      return assetRes;
    }

    return new Response('BOQA Worker — no assets bound', { status: 404 });
  },
};
// v:1783660496950161096
// v:1783660573911114381

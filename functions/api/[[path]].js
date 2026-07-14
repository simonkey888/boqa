/**
 * Legacy Cloudflare Pages Function — deliberately quarantined.
 *
 * BOQA is served by the Worker in worker.js. This historical Pages catch-all
 * remains in the repository so an accidental Pages deployment fails closed:
 * it never contacts the backend, signs a request, or forwards caller headers.
 */

const PUBLIC_READ_ONLY_PATHS = new Set([
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

function json(status, error, message) {
  return new Response(JSON.stringify({ error, message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

export async function onRequest(context) {
  const request = context.request;
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { Allow: 'GET, HEAD, OPTIONS' } });
  }

  if (url.pathname === '/ws') {
    return json(426, 'websocket_blocked_public', 'WebSocket is disabled on the legacy Pages surface.');
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return json(405, 'method_not_allowed', 'Only GET/HEAD requests are permitted.');
  }

  if (!PUBLIC_READ_ONLY_PATHS.has(url.pathname)) {
    return json(404, 'route_not_found', 'Route is not available on the legacy Pages surface.');
  }

  return json(
    503,
    'legacy_proxy_disabled',
    'The legacy Pages proxy is disabled; use the canonical BOQA Worker.',
  );
}

// Method aliases retain Pages routing compatibility while preserving policy.
export const onRequestGet = onRequest;
export const onRequestPost = onRequest;
export const onRequestPut = onRequest;
export const onRequestPatch = onRequest;
export const onDelete = onRequest;

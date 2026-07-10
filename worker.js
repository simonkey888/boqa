/**
 * BOQA Cloudflare Worker — Static dashboard + API proxy
 *
 * Serves the dashboard HTML/CSS/JS from the bundled `dashboard/` assets,
 * and proxies /api/* requests to the BOQA Node.js backend configured
 * via the BOQA_BACKEND_URL environment variable.
 *
 * Architecture: User → Cloudflare Worker → (BOQA backend on Northflank)
 * The Worker acts as WAF/SSL terminator + static host + reverse proxy.
 */

// Inlined from functions/api/[[path]].js so we have a single Worker entry.
async function proxyToBackend(request, env) {
  const backendUrl = (env && env.BOQA_BACKEND_URL) || '';
  const url = new URL(request.url);

  if (!backendUrl) {
    return new Response(
      JSON.stringify({
        error: 'backend_not_configured',
        message:
          'BOQA backend URL not set. Set BOQA_BACKEND_URL in Cloudflare Worker → Settings → Variables to point to your Node.js host (e.g. your Northflank service URL).',
      }),
      {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  const targetUrl = backendUrl.replace(/\/$/, '') + url.pathname + url.search;

  // Build a proxied request, forwarding all headers (including X-API-Key).
  const proxyHeaders = new Headers(request.headers);
  try {
    proxyHeaders.set('Host', new URL(backendUrl).host);
  } catch (_) {
    // Invalid backend URL — fall through to 502 below
    return new Response(
      JSON.stringify({
        error: 'invalid_backend_url',
        message: `BOQA_BACKEND_URL is invalid: ${backendUrl}`,
      }),
      {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  const proxyReq = new Request(targetUrl, {
    method: request.method,
    headers: proxyHeaders,
    body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    redirect: 'manual',
  });

  try {
    const backendRes = await fetch(proxyReq);
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
      {
        status: 504,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // /api/* → proxy to BOQA backend
    if (url.pathname.startsWith('/api/')) {
      return proxyToBackend(request, env);
    }

    // /ws → proxy WebSocket upgrade (Workers support WS natively)
    if (url.pathname === '/ws') {
      return proxyToBackend(request, env);
    }

    // /health → quick Worker health check (no backend required)
    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          worker: 'boqa',
          time: new Date().toISOString(),
          backend_configured: !!(env && env.BOQA_BACKEND_URL),
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Everything else → serve from static assets (dashboard)
    if (env && env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('BOQA Worker — no assets bound', { status: 404 });
  },
};

/**
 * Cloudflare Pages Function — catch-all proxy for /api/*
 *
 * Forwards every /api/* request to the BOQA Node.js backend configured
 * via the BOQA_BACKEND_URL environment variable in Cloudflare dashboard.
 *
 * Until BOQA_BACKEND_URL is set, returns 502 with a clear message.
 */

export async function onRequest(context) {
  const { request, env } = context;
  const backendUrl = (env && env.BOQA_BACKEND_URL) || '';
  const url = new URL(request.url);

  if (!backendUrl) {
    return new Response(
      JSON.stringify({
        error: 'backend_not_configured',
        message:
          'BOQA backend URL not set. Configure BOQA_BACKEND_URL in Cloudflare Pages → Settings → Environment variables to point to your Node.js host (e.g. your Northflank service URL).',
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
  proxyHeaders.set('Host', new URL(backendUrl).host);

  const proxyReq = new Request(targetUrl, {
    method: request.method,
    headers: proxyHeaders,
    body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    redirect: 'manual',
  });

  try {
    const backendRes = await fetch(proxyReq);
    // Forward the response, preserving status and headers.
    const respHeaders = new Headers(backendRes.headers);
    respHeaders.delete('Transfer-Encoding'); // CF will set its own
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

// Alias the common HTTP methods.
export const onRequestGet = onRequest;
export const onRequestPost = onRequest;
export const onRequestPut = onRequest;
export const onRequestPatch = onRequest;
export const onDelete = onRequest;

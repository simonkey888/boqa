/**
 * BOQA Cloudflare Worker — static dashboard and fail-closed API proxy.
 * No demo data is generated at the edge.
 */

// BOQA_SAFE_LAB_PREVIEW_BUILD_START
const SAFE_LAB_PREVIEW_BUILD = Object.freeze({
  enabled: false,
  source_sha: null,
  contract_checksum: null,
  promotion_ready: false,
  promotion_blocker: null,
  contract: null,
});
// BOQA_SAFE_LAB_PREVIEW_BUILD_END

async function computeHmacSignature(secret, method, path, ts, bodyStr) {
  const payload = method.toUpperCase() + path + String(ts) + bodyStr;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      ...headers,
    },
  });
}

function failClosedApi(pathname) {
  return jsonResponse({
    error: 'backend_unavailable',
    source: pathname,
    timestamp: new Date().toISOString(),
  }, 503);
}

function normalizePathname(pathname) {
  let decoded = String(pathname || '/');
  for (let pass = 0; pass < 8; pass += 1) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch (_) {
      // Malformed encodings remain untrusted and are compared in their raw form.
      break;
    }
    if (next === decoded) break;
    decoded = next;
  }
  return decoded
    .replace(/\\/g, '/')
    .replace(/\/{2,}/g, '/')
    .toLowerCase();
}

function isPrivateSurface(pathname) {
  // This normalized classifier supersedes legacy literal checks such as
  // pathname === '/cobros.html' while preserving a fail-closed boundary.
  const normalized = normalizePathname(pathname);
  return normalized === '/cobros' ||
    normalized === '/cobros/' ||
    normalized.endsWith('/cobros.html') ||
    normalized.endsWith('/cobros.js') ||
    normalized.endsWith('/private.css') ||
    normalized === '/api/private/billing' ||
    normalized.startsWith('/api/private/billing/');
}

function hiddenPrivateResponse(pathname) {
  const normalized = normalizePathname(pathname);
  const headers = {
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0',
    'X-Content-Type-Options': 'nosniff',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  };
  if (normalized.startsWith('/api/')) {
    return jsonResponse({ error: 'not_found' }, 404, headers);
  }
  return new Response('Not Found', { status: 404, headers });
}

function canonicalizeForChecksum(value) {
  if (Array.isArray(value)) return value.map(canonicalizeForChecksum);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonicalizeForChecksum(value[key]);
      return result;
    }, {});
  }
  return value;
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function getSafeLabPreviewBuild() {
  const build = SAFE_LAB_PREVIEW_BUILD;
  if (!build || build.enabled !== true) return null;
  if (build.promotion_ready !== false || build.promotion_blocker !== 'CONTROLLED_LAB_PREVIEW') return null;
  if (!build.contract || build.contract.environment !== 'controlled_lab' || build.contract.reportable !== false) return null;
  if (build.contract.hunter_state !== 'LAB_COMPLETE' || build.contract.source_sha !== build.source_sha) return null;
  if (!/^sha256:[a-f0-9]{64}$/.test(String(build.contract_checksum || ''))) return null;
  const canonical = `${JSON.stringify(canonicalizeForChecksum(build.contract))}\n`;
  const actualChecksum = `sha256:${await sha256Hex(canonical)}`;
  if (actualChecksum !== build.contract_checksum) return null;
  return build;
}

function safeLabUnavailableResponse() {
  return jsonResponse({
    error: 'safe_lab_contract_unavailable',
    environment: 'controlled_lab',
    status: 'UNAVAILABLE',
    reportable: false,
  }, 503);
}

function isAllowedApiRequest(request, pathname) {
  // The public dashboard consumes only these two minimal, read-only contracts.
  // Every other backend API remains undiscoverable at the public edge.
  const publicReadPaths = new Set([
    '/api/health',
    '/api/hunter/status',
  ]);
  return request.method === 'GET' && publicReadPaths.has(pathname);
}

async function proxyToBackend(request, env) {
  const backendUrl = env.BOQA_BACKEND_URL;
  const workerApiKey = env.BOQA_API_KEY;
  const hmacSecret = env.BOQA_HMAC_SECRET;
  if (!backendUrl || !workerApiKey || !hmacSecret) {
    return jsonResponse({ error: 'worker_auth_not_configured' }, 503);
  }

  let parsedBackend;
  try {
    parsedBackend = new URL(backendUrl);
  } catch (_) {
    return jsonResponse({ error: 'invalid_backend_configuration' }, 502);
  }

  const incomingUrl = new URL(request.url);
  const targetUrl = new URL(incomingUrl.pathname + incomingUrl.search, parsedBackend);
  const proxyHeaders = new Headers(request.headers);
  proxyHeaders.set('Host', parsedBackend.host);
  proxyHeaders.set('X-API-Key', workerApiKey);
  proxyHeaders.delete('CF-Connecting-IP');
  proxyHeaders.delete('X-Forwarded-For');

  let bodyForProxy;
  let bodyString = '';
  if (!['GET', 'HEAD'].includes(request.method)) {
    const bodyBuffer = await request.arrayBuffer();
    bodyForProxy = bodyBuffer;
    bodyString = new TextDecoder().decode(bodyBuffer);
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const pathWithQuery = incomingUrl.pathname + incomingUrl.search;
  const signature = await computeHmacSignature(hmacSecret, request.method, pathWithQuery, timestamp, bodyString);
  proxyHeaders.set('X-BOQA-Sig', signature);
  proxyHeaders.set('X-BOQA-Ts', String(timestamp));

  try {
    const backendResponse = await fetch(new Request(targetUrl.toString(), {
      method: request.method,
      headers: proxyHeaders,
      body: bodyForProxy,
      redirect: 'manual',
    }));

    const websocketUpgrade = backendResponse.status === 101 ||
      (backendResponse.headers.get('upgrade') || '').toLowerCase() === 'websocket';
    if (websocketUpgrade) {
      return jsonResponse({ error: 'websocket_not_supported_via_worker', fallback: 'http_polling' }, 426);
    }

    const headers = new Headers(backendResponse.headers);
    headers.delete('Transfer-Encoding');
    headers.set('Cache-Control', 'no-store, max-age=0');
    headers.set('Pragma', 'no-cache');
    headers.set('X-Content-Type-Options', 'nosniff');
    return new Response(backendResponse.body, {
      status: backendResponse.status,
      statusText: backendResponse.statusText,
      headers,
    });
  } catch (_) {
    return jsonResponse({ error: 'backend_unreachable' }, 504);
  }
}

function secureAssetResponse(assetResponse, pathname) {
  const headers = new Headers(assetResponse.headers);
  const isMutableAsset = pathname === '/' || pathname.endsWith('.html') || pathname.endsWith('.js') || pathname.endsWith('.css');
  if (isMutableAsset) {
    headers.set('Cache-Control', 'no-store, max-age=0');
    headers.set('Pragma', 'no-cache');
    headers.set('Expires', '0');
  }
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  return new Response(assetResponse.body, {
    status: assetResponse.status,
    statusText: assetResponse.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const backendConfigured = Boolean(env && env.BOQA_BACKEND_URL);
    const safeLabBuild = await getSafeLabPreviewBuild();

    if (isPrivateSurface(url.pathname)) {
      return hiddenPrivateResponse(url.pathname);
    }

    if (url.pathname.startsWith('/api/')) {
      const allowed = isAllowedApiRequest(request, url.pathname);
      if (!allowed) return jsonResponse({ error: 'not_found' }, 404);
      if (url.pathname === '/api/hunter/status' && SAFE_LAB_PREVIEW_BUILD.enabled === true) {
        if (!safeLabBuild) return safeLabUnavailableResponse();
        return jsonResponse(safeLabBuild.contract);
      }
      if (!backendConfigured) return failClosedApi(url.pathname);
      return proxyToBackend(request, env);
    }

    if (url.pathname === '/ws') {
      if (!backendConfigured) return jsonResponse({ error: 'websocket_unavailable', fallback: 'http_polling' }, 426);
      return proxyToBackend(request, env);
    }

    if (url.pathname === '/health') {
      if (SAFE_LAB_PREVIEW_BUILD.enabled === true) {
        if (!safeLabBuild) return safeLabUnavailableResponse();
        return jsonResponse({
          status: 'ok',
          worker: 'boqa',
          mode: 'controlled_lab_preview',
          backend_configured: backendConfigured,
          source_sha: safeLabBuild.source_sha,
          contract_checksum: safeLabBuild.contract_checksum,
          promotion_ready: false,
          promotion_blocker: 'CONTROLLED_LAB_PREVIEW',
          timestamp: new Date().toISOString(),
        });
      }
      return jsonResponse({
        status: 'ok',
        worker: 'boqa',
        mode: backendConfigured ? 'production' : 'backend_unavailable',
        backend_configured: backendConfigured,
        timestamp: new Date().toISOString(),
      });
    }

    if (env && env.ASSETS) {
      return secureAssetResponse(await env.ASSETS.fetch(request), url.pathname);
    }

    return new Response('BOQA Worker — no assets bound', {
      status: 404,
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    });
  },
};

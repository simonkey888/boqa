/**
 * BOQA Instrumentation — document-start injection script
 *
 * This script is injected via page.addInitScript() and runs BEFORE any
 * page JavaScript. It patches fetch, XHR, and WebSocket at the prototype
 * level to capture auth-relevant signals that Playwright hooks alone
 * cannot see (e.g., request bodies, in-memory token access).
 *
 * Communication: window.postMessage → page.on('message') in Playwright
 *
 * Observability only. No bypass. No modification.
 */

(function BOQA_INSTRUMENTATION() {
  'use strict';

  const BOQA_PREFIX = '__BOQA__';
  const SESSION_ID = Math.random().toString(36).substring(2, 10);

  // ─── Helpers ─────────────────────────────────────────────────────────

  function emit(type, data) {
    try {
      window.postMessage({
        source: BOQA_PREFIX,
        sessionId: SESSION_ID,
        type,
        ts: Date.now(),
        data,
      }, '*');
    } catch (_) {}
  }

  function safeStringify(obj, maxLen) {
    try {
      const s = JSON.stringify(obj);
      return s.length > (maxLen || 5000) ? s.substring(0, maxLen || 5000) + '...[truncated]' : s;
    } catch (e) {
      return `[stringify error: ${e.message}]`;
    }
  }

  function isAuthURL(url) {
    return /\/auth\/|\/login|\/logout|\/token|\/session|\/2fa|\/verify|\/api\/users\/me/.test(url);
  }

  function extractAuthHeaders(headers) {
    const auth = {};
    const keys = ['authorization', 'x-csrftoken', 'x-auth-token', 'x-access-token'];
    for (const key of keys) {
      const val = headers[key] || headers[key.toLowerCase()];
      if (val) {
        auth[key] = val.length > 50 ? val.substring(0, 50) + '...' : val;
      }
    }
    return Object.keys(auth).length > 0 ? auth : null;
  }

  // ─── Fetch Hook ──────────────────────────────────────────────────────

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = function boqaFetch(input, init) {
      const url = typeof input === 'string' ? input : (input instanceof Request ? input.url : String(input));
      const method = (init?.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
      const headers = {};

      // Extract headers from init
      if (init?.headers) {
        if (init.headers instanceof Headers) {
          init.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        } else if (typeof init.headers === 'object') {
          for (const [k, v] of Object.entries(init.headers)) {
            headers[k.toLowerCase()] = v;
          }
        }
      }
      // Extract headers from Request input
      if (input instanceof Request && input.headers) {
        input.headers.forEach((v, k) => { if (!headers[k.toLowerCase()]) headers[k.toLowerCase()] = v; });
      }

      const authHeaders = extractAuthHeaders(headers);

      // Emit request signal
      emit('fetch_request', {
        url,
        method,
        hasAuthHeaders: !!authHeaders,
        authHeaders,
        hasBody: !!init?.body,
        isAuthURL: isAuthURL(url),
      });

      // Capture request body for auth endpoints
      if (isAuthURL(url) && init?.body) {
        try {
          const bodyText = typeof init.body === 'string' ? init.body : '[non-string body]';
          emit('fetch_request_body', {
            url,
            method,
            bodyPreview: bodyText.substring(0, 2000),
          });
        } catch (_) {}
      }

      return originalFetch.apply(this, arguments).then(response => {
        // Capture auth-relevant response details
        const respHeaders = {};
        response.headers.forEach((v, k) => { respHeaders[k.toLowerCase()] = v; });

        const hasSetCookie = 'set-cookie' in respHeaders;
        const authHeaders = extractAuthHeaders(respHeaders);

        if (isAuthURL(url) || hasSetCookie || authHeaders) {
          emit('fetch_response', {
            url,
            method,
            status: response.status,
            hasSetCookie,
            authHeaders,
            contentType: respHeaders['content-type'] || null,
          });
        }

        return response;
      }).catch(err => {
        emit('fetch_error', {
          url,
          method,
          error: err.message,
        });
        throw err;
      });
    };
    // Preserve toString for detection evasion
    window.fetch.toString = () => 'function fetch() { [native code] }';
  }

  // ─── XHR Hook ────────────────────────────────────────────────────────

  const OriginalXHR = window.XMLHttpRequest;
  const origOpen = OriginalXHR.prototype.open;
  const origSend = OriginalXHR.prototype.send;
  const origSetRequestHeader = OriginalXHR.prototype.setRequestHeader;

  // Track headers per XHR instance
  const xhrHeaders = new WeakMap();

  OriginalXHR.prototype.open = function boqaOpen(method, url) {
    xhrHeaders.set(this, { method: (method || 'GET').toUpperCase(), url: String(url), headers: {} });
    return origOpen.apply(this, arguments);
  };

  OriginalXHR.prototype.setRequestHeader = function boqaSetHeader(name, value) {
    const meta = xhrHeaders.get(this);
    if (meta) {
      meta.headers[name.toLowerCase()] = value;
    }
    return origSetRequestHeader.apply(this, arguments);
  };

  OriginalXHR.prototype.send = function boqaSend(body) {
    const meta = xhrHeaders.get(this);
    if (meta) {
      const authHeaders = extractAuthHeaders(meta.headers);

      emit('xhr_request', {
        url: meta.url,
        method: meta.method,
        hasAuthHeaders: !!authHeaders,
        authHeaders,
        hasBody: !!body,
        isAuthURL: isAuthURL(meta.url),
      });

      if (isAuthURL(meta.url) && body) {
        try {
          const bodyText = typeof body === 'string' ? body : '[non-string body]';
          emit('xhr_request_body', {
            url: meta.url,
            method: meta.method,
            bodyPreview: bodyText.substring(0, 2000),
          });
        } catch (_) {}
      }

      // Hook response
      this.addEventListener('load', function () {
        const hasAuthHeaders = !!authHeaders;
        const status = this.status;
        if (isAuthURL(meta.url) || hasAuthHeaders) {
          emit('xhr_response', {
            url: meta.url,
            method: meta.method,
            status,
            responseLength: this.responseText?.length || 0,
          });
        }
      });

      this.addEventListener('error', function () {
        emit('xhr_error', {
          url: meta.url,
          method: meta.method,
          error: 'Network error',
        });
      });
    }
    return origSend.apply(this, arguments);
  };

  // ─── WebSocket Hook ─────────────────────────────────────────────────

  const OriginalWebSocket = window.WebSocket;
  const wsInstances = new WeakMap();
  let wsCounter = 0;

  window.WebSocket = function boqaWebSocket(url, protocols) {
    const wsId = ++wsCounter;
    const ws = protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
    wsInstances.set(ws, { url, wsId });

    emit('ws_open', { url, wsId, protocols: protocols || null });

    ws.addEventListener('open', function () {
      emit('ws_connected', { url, wsId });
    });

    // Hook send (outgoing messages)
    const origWsSend = ws.send.bind(ws);
    ws.send = function boqaSend(data) {
      emit('ws_message_out', {
        url,
        wsId,
        dataType: typeof data,
        dataLength: typeof data === 'string' ? data.length : (data.byteLength || 0),
        dataPreview: typeof data === 'string'
          ? (data.length > 2000 ? data.substring(0, 2000) + '...[truncated]' : data)
          : `[binary ${data.byteLength || '?'} bytes]`,
      });
      return origWsSend(data);
    };

    // Hook incoming messages
    ws.addEventListener('message', function (event) {
      emit('ws_message_in', {
        url,
        wsId,
        dataType: typeof event.data,
        dataLength: typeof event.data === 'string' ? event.data.length : (event.data.byteLength || 0),
        dataPreview: typeof event.data === 'string'
          ? (event.data.length > 2000 ? event.data.substring(0, 2000) + '...[truncated]' : event.data)
          : `[binary]`,
      });
    });

    ws.addEventListener('close', function (event) {
      emit('ws_close', { url, wsId, code: event.code, reason: event.reason });
    });

    ws.addEventListener('error', function () {
      emit('ws_error', { url, wsId });
    });

    return ws;
  };

  // Preserve prototype chain and statics
  window.WebSocket.prototype = OriginalWebSocket.prototype;
  window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  window.WebSocket.OPEN = OriginalWebSocket.OPEN;
  window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
  window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
  window.WebSocket.toString = () => 'function WebSocket() { [native code] }';

  // ─── Cookie Write Monitor ────────────────────────────────────────────

  const origCookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (origCookieDesc && origCookieDesc.set) {
    const origSet = origCookieDesc.set;
    Object.defineProperty(Document.prototype, 'cookie', {
      get: origCookieDesc.get,
      set: function boqaCookieSet(value) {
        const cookieName = value.split('=')[0]?.trim();
        const authNames = ['ripio_access', 'sessionid', 'csrftoken', 'access_token', 'refresh_token'];

        if (authNames.includes(cookieName)) {
          emit('cookie_write', {
            name: cookieName,
            valuePreview: value.substring(0, 100),
            isAuthCookie: true,
          });
        }
        return origSet.call(this, value);
      },
      configurable: true,
    });
  }

  // ─── localStorage/sessionStorage Auth Token Monitor ──────────────────

  const origLocalStorageSet = Storage.prototype.setItem;
  Storage.prototype.setItem = function boqaSetItem(key, value) {
    const authKeys = ['token', 'jwt', 'auth', 'access', 'refresh', 'csrf', 'session'];
    const isAuth = authKeys.some(k => key.toLowerCase().includes(k));
    if (isAuth) {
      emit('storage_write', {
        storage: this === localStorage ? 'localStorage' : 'sessionStorage',
        key,
        valuePreview: String(value).substring(0, 100),
        isAuthRelated: true,
      });
    }
    return origLocalStorageSet.apply(this, arguments);
  };
  Storage.prototype.setItem.toString = () => 'function setItem() { [native code] }';

  // ─── CryptoJS AES Decrypt Detection ──────────────────────────────────
  // If CryptoJS is loaded, monitor decryption calls (passive observation)

  let cryptoJSMonitored = false;
  function monitorCryptoJS() {
    if (cryptoJSMonitored) return;
    if (window.CryptoJS && window.CryptoJS.AES) {
      cryptoJSMonitored = true;
      const origDecrypt = window.CryptoJS.AES.decrypt;
      window.CryptoJS.AES.decrypt = function boqaDecrypt(ciphertext, passphrase, cfg) {
        emit('cryptojs_decrypt', {
          ciphertextType: typeof ciphertext,
          ciphertextPreview: typeof ciphertext === 'string'
            ? ciphertext.substring(0, 50)
            : '[object]',
          passphraseType: typeof passphrase,
          hasConfig: !!cfg,
        });
        return origDecrypt.apply(this, arguments);
      };
    }
  }

  // Periodic check for CryptoJS (SPA may load it after initial render)
  setInterval(monitorCryptoJS, 3000);

  // ─── Global Error Handler ────────────────────────────────────────────

  window.addEventListener('error', function (event) {
    emit('global_error', {
      message: event.message,
      filename: event.filename,
      lineNumber: event.lineno,
      columnNumber: event.colno,
    });
  });

  window.addEventListener('unhandledrejection', function (event) {
    emit('unhandled_rejection', {
      reason: String(event.reason)?.substring(0, 500),
    });
  });

  // ─── Init Signal ─────────────────────────────────────────────────────

  emit('init', {
    url: location.href,
    userAgent: navigator.userAgent,
    timestamp: Date.now(),
    hooks: ['fetch', 'xhr', 'websocket', 'cookie', 'storage', 'cryptojs'],
  });

  console.log('%c[BOQA] Instrumentation active', 'color: #00ff88; font-weight: bold');

})();


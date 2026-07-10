/**
 * BOQA Playwright Runner — Browser instrumentation engine
 *
 * Hooks:
 *   - page.on('request')          → network_request
 *   - page.on('response')         → network_response  (includes Set-Cookie via all_headers())
 *   - page.on('requestfailed')    → network_failure
 *   - page.on('websocket')        → websocket_open/message_in/message_out/close
 *   - page.on('console')          → console_log / console_error
 *   - page.on('pageerror')        → console_error
 *   - page.on('framenavigated')   → page_navigation
 *   - Cookie polling              → cookie_snapshot
 *   - Performance entries         → performance_resource
 *   - Auth signal detection       → auth_signal
 *
 * Modes:
 *   - headed:  Launch Chromium with visible window
 *   - cdp:     Connect to existing browser via CDP endpoint
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

// Auth-related URL patterns for signal detection
const AUTH_PATTERNS = [
  /\/api\/users\/me\/?/,
  /\/auth\//,
  /\/login/,
  /\/logout/,
  /\/token/,
  /\/oauth/,
  /\/session/,
  /\/2fa/,
  /\/verify/,
  /\/refresh/,
];

// Auth-related cookie names
const AUTH_COOKIES = new Set([
  'ripio_access', 'sessionid', 'csrftoken',
  'access_token', 'refresh_token', 'auth_token',
  'id_token', '_jwt', '_session',
]);

// Auth-related header keys
const AUTH_HEADERS = new Set([
  'authorization', 'x-csrftoken', 'x-auth-token',
  'x-access-token', 'x-refresh-token',
]);

class PlaywrightRunner {
  constructor(eventBus, options = {}) {
    this.bus = eventBus;
    this.options = {
      target: options.target || 'https://ripio.com',
      headless: options.headless || false,
      devtools: options.devtools !== false,
      cdpEndpoint: options.cdpEndpoint || null,
      cookiePollInterval: options.cookiePollInterval || 3000,
      perfPollInterval: options.perfPollInterval || 5000,
      recordHar: options.recordHar || false,
      harPath: options.harPath || path.join(__dirname, '..', 'output', 'har.json'),
      slowMo: options.slowMo || 0,
      viewport: options.viewport || { width: 1440, height: 900 },
    };

    this.browser = null;
    this.context = null;
    this.page = null;
    this.cdpSession = null;
    this.cookiePollTimer = null;
    this.perfPollTimer = null;
    this.activeWebSockets = new Map(); // wsId → { url, meta }
    this.wsCounter = 0;
  }

  /**
   * Launch browser and attach all instrumentation hooks
   */
  async start() {
    console.log(`[Runner] Starting Playwright — target: ${this.options.target}`);

    if (this.options.cdpEndpoint) {
      await this._connectCDP();
    } else {
      await this._launchBrowser();
    }

    // Create CDP session for deeper network access
    if (!this.cdpSession) {
      try {
        this.cdpSession = await this.page.context().newCDPSession(this.page);
        console.log('[Runner] CDP session established');
      } catch (e) {
        console.warn('[Runner] CDP session failed:', e.message);
      }
    }

    // Attach all hooks
    this._hookNetwork();
    this._hookWebSocket();
    this._hookConsole();
    this._hookNavigation();
    this._startCookiePolling();
    this._startPerformancePolling();

    // Inject document-start instrumentation
    await this._injectInstrumentation();

    // Navigate to target
    console.log(`[Runner] Navigating to ${this.options.target}`);
    await this.page.goto(this.options.target, { waitUntil: 'domcontentloaded', timeout: 60000 });

    return this.page;
  }

  /**
   * Launch fresh Chromium instance
   */
  async _launchBrowser() {
    const contextOpts = {
      viewport: this.options.viewport,
      ignoreHTTPSErrors: true,
    };

    if (this.options.recordHar) {
      contextOpts.recordHar = { path: this.options.harPath };
    }

    this.browser = await chromium.launch({
      headless: this.options.headless,
      devtools: this.options.devtools,
      slowMo: this.options.slowMo,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--no-first-run',
        '--disable-features=TranslateUI',
      ],
    });

    this.context = await this.browser.newContext(contextOpts);
    this.page = await this.context.newPage();

    console.log('[Runner] Browser launched in headed mode');
  }

  /**
   * Connect to existing browser via CDP
   */
  async _connectCDP() {
    this.browser = await chromium.connectOverCDP(this.options.cdpEndpoint);
    this.context = this.browser.contexts()[0] || await this.browser.newContext();
    this.page = this.context.pages()[0] || await this.context.newPage();

    console.log(`[Runner] Connected via CDP to ${this.options.cdpEndpoint}`);
  }

  /**
   * Hook: Network request/response/failure
   */
  _hookNetwork() {
    // --- REQUEST ---
    this.page.on('request', (req) => {
      const url = req.url();
      const method = req.method();

      const event = {
        type: 'network_request',
        url,
        method,
        source: 'playwright',
        meta: {
          resourceType: req.resourceType(),
          frameUrl: req.frame()?.url() || null,
          isNavigationRequest: req.isNavigationRequest(),
          redirectChain: req.redirectChain().map(r => r.url()),
        },
      };

      // Capture request headers synchronously
      try {
        const headers = req.headers();
        event.headers = headers;

        // Auth signal detection on request
        const lowerHeaders = {};
        for (const [k, v] of Object.entries(headers)) {
          lowerHeaders[k.toLowerCase()] = v;
        }
        if (lowerHeaders['authorization'] || lowerHeaders['x-csrftoken']) {
          this.bus.emit({
            type: 'auth_signal',
            url,
            method,
            headers: headers,
            source: 'request_header',
            meta: {
              signalType: lowerHeaders['authorization'] ? 'bearer_token' : 'csrf_header',
              headerKey: lowerHeaders['authorization'] ? 'Authorization' : 'X-CSRFToken',
              headerPreview: lowerHeaders['authorization']
                ? lowerHeaders['authorization'].substring(0, 30) + '...'
                : lowerHeaders['x-csrftoken']?.substring(0, 8) + '...',
            },
          });
        }
      } catch (e) {
        event.meta.headerCaptureError = e.message;
      }

      // Capture POST body for auth endpoints
      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        try {
          const postData = req.postData();
          if (postData) {
            event.payload = postData.length > 5000 ? postData.substring(0, 5000) + '...[truncated]' : postData;
          }
        } catch (_) {}

        // Check if it's an auth-related request
        if (AUTH_PATTERNS.some(p => p.test(url))) {
          this.bus.emit({
            type: 'auth_signal',
            url,
            method,
            source: 'request_url',
            meta: {
              signalType: 'auth_endpoint_request',
              matchedPattern: AUTH_PATTERNS.find(p => p.test(url))?.source,
            },
          });
        }
      }

      this.bus.emit(event);
    });

    // --- RESPONSE ---
    this.page.on('response', async (res) => {
      const url = res.url();
      const status = res.status();

      const event = {
        type: 'network_response',
        url,
        method: res.request()?.method() || 'GET',
        status,
        source: 'playwright',
        meta: {
          resourceType: res.request()?.resourceType() || 'unknown',
          fromCache: (() => { try { return typeof res.fromCache === 'function' ? res.fromCache() : false; } catch(_) { return false; } })(),
          fromServiceWorker: (() => { try { return typeof res.fromServiceWorker === 'function' ? res.fromServiceWorker() : false; } catch(_) { return false; } })(),
        },
      };

      // Capture ALL headers including Set-Cookie (forbidden in JS, accessible via Playwright)
      try {
        const allHeaders = await res.allHeaders();
        event.headers = allHeaders;

        // Auth signal: detect Set-Cookie with auth-related names
        const setCookieHeaders = Object.entries(allHeaders).filter(
          ([k]) => k.toLowerCase() === 'set-cookie'
        );

        if (setCookieHeaders.length > 0) {
          const authCookies = setCookieHeaders.filter(([_, v]) =>
            [...AUTH_COOKIES].some(name => v.toLowerCase().startsWith(name.toLowerCase() + '='))
          );

          if (authCookies.length > 0) {
            this.bus.emit({
              type: 'auth_signal',
              url,
              status,
              headers: Object.fromEntries(authCookies),
              source: 'response_set_cookie',
              meta: {
                signalType: 'auth_cookie_set',
                cookies: authCookies.map(([_, v]) => {
                  const parts = v.split(';');
                  const nameVal = parts[0].split('=');
                  const attrs = {};
                  for (const part of parts.slice(1)) {
                    const [k, ...rest] = part.trim().split('=');
                    attrs[k.toLowerCase()] = rest.join('=') || true;
                  }
                  return {
                    name: nameVal[0],
                    valuePreview: nameVal[1]?.substring(0, 20) + '...',
                    httpOnly: 'httponly' in attrs,
                    secure: 'secure' in attrs,
                    sameSite: attrs.samesite || null,
                    domain: attrs.domain || null,
                    path: attrs.path || null,
                    maxAge: attrs['max-age'] || null,
                    expires: attrs.expires || null,
                  };
                }),
              },
            });
          }
        }
      } catch (e) {
        event.meta.headerCaptureError = e.message;
      }

      // Capture response body for auth endpoints (small payloads only)
      if (AUTH_PATTERNS.some(p => p.test(url)) && status < 400) {
        try {
          const contentType = event.headers?.['content-type'] || '';
          if (contentType.includes('json')) {
            const body = await res.text();
            if (body && body.length < 10000) {
              event.payload = body;
            }
          }
        } catch (_) {}
      }

      // Detect auth-related status codes
      if (status === 401 || status === 403) {
        this.bus.emit({
          type: 'auth_signal',
          url,
          status,
          source: 'response_status',
          meta: {
            signalType: status === 401 ? 'unauthorized' : 'forbidden',
          },
        });
      }

      this.bus.emit(event);
    });

    // --- REQUEST FAILED ---
    this.page.on('requestfailed', (req) => {
      this.bus.emit({
        type: 'network_failure',
        url: req.url(),
        method: req.method(),
        source: 'playwright',
        meta: {
          failure: req.failure()?.errorText || 'unknown',
          resourceType: req.resourceType(),
        },
      });
    });
  }

  /**
   * Hook: WebSocket open/message/close
   */
  _hookWebSocket() {
    this.page.on('websocket', (ws) => {
      const wsId = ++this.wsCounter;
      const wsUrl = ws.url();

      this.activeWebSockets.set(wsId, { url: wsUrl, openedAt: Date.now() });

      // WebSocket Open
      this.bus.emit({
        type: 'websocket_open',
        url: wsUrl,
        source: 'playwright',
        meta: {
          wsId,
          eventCount: this.activeWebSockets.size,
        },
      });

      // Auth signal: detect WebSocket URLs that may carry auth
      if (wsUrl.includes('nexus') || wsUrl.includes('socket') || wsUrl.includes('ws') || wsUrl.includes('push')) {
        this.bus.emit({
          type: 'auth_signal',
          url: wsUrl,
          source: 'websocket_connect',
          meta: {
            signalType: 'auth_related_ws',
            wsId,
            protocol: new URL(wsUrl).protocol,
          },
        });
      }

      // Frame Received
      ws.on('framereceived', (frame) => {
        const payload = frame.payload;
        this.bus.emit({
          type: 'websocket_message_in',
          url: wsUrl,
          payload: typeof payload === 'string'
            ? (payload.length > 5000 ? payload.substring(0, 5000) + '...[truncated]' : payload)
            : `[binary ${payload.byteLength} bytes]`,
          source: 'playwright',
          meta: { wsId, opcode: frame.opcode },
        });
      });

      // Frame Sent
      ws.on('framesent', (frame) => {
        const payload = frame.payload;
        this.bus.emit({
          type: 'websocket_message_out',
          url: wsUrl,
          payload: typeof payload === 'string'
            ? (payload.length > 5000 ? payload.substring(0, 5000) + '...[truncated]' : payload)
            : `[binary ${payload.byteLength} bytes]`,
          source: 'playwright',
          meta: { wsId, opcode: frame.opcode },
        });
      });

      // Close
      ws.on('close', () => {
        const info = this.activeWebSockets.get(wsId);
        this.activeWebSockets.delete(wsId);
        this.bus.emit({
          type: 'websocket_close',
          url: wsUrl,
          source: 'playwright',
          meta: {
            wsId,
            lifetime: info ? Date.now() - info.openedAt : 0,
          },
        });
      });
    });
  }

  /**
   * Hook: Console and errors
   */
  _hookConsole() {
    this.page.on('console', (msg) => {
      const type = msg.type();
      const text = msg.text();

      // Only capture warnings, errors, and auth-related logs
      if (type === 'warning' || type === 'error' || type === 'assert') {
        this.bus.emit({
          type: 'console_error',
          payload: text.length > 3000 ? text.substring(0, 3000) + '...[truncated]' : text,
          source: 'playwright',
          meta: {
            consoleType: type,
            location: msg.location()?.url || null,
            lineNumber: msg.location()?.lineNumber || null,
          },
        });
      } else if (text && (
        text.toLowerCase().includes('auth') ||
        text.toLowerCase().includes('token') ||
        text.toLowerCase().includes('jwt') ||
        text.toLowerCase().includes('session') ||
        text.toLowerCase().includes('cookie') ||
        text.toLowerCase().includes('csrf')
      )) {
        this.bus.emit({
          type: 'console_log',
          payload: text.length > 3000 ? text.substring(0, 3000) + '...[truncated]' : text,
          source: 'playwright',
          meta: {
            consoleType: type,
            authRelated: true,
          },
        });
      }
    });

    this.page.on('pageerror', (err) => {
      this.bus.emit({
        type: 'console_error',
        payload: err.message,
        source: 'playwright',
        meta: {
          consoleType: 'pageerror',
          stack: err.stack?.substring(0, 2000) || null,
        },
      });
    });
  }

  /**
   * Hook: Page navigation
   */
  _hookNavigation() {
    this.page.on('framenavigated', (frame) => {
      const url = frame.url();
      if (!url || url === 'about:blank') return;

      this.bus.emit({
        type: 'page_navigation',
        url,
        source: 'playwright',
        meta: {
          frameName: frame.name() || null,
          isMainFrame: frame === this.page.mainFrame(),
        },
      });

      // Auth signal on navigation to auth pages
      if (AUTH_PATTERNS.some(p => p.test(url))) {
        this.bus.emit({
          type: 'auth_signal',
          url,
          source: 'navigation',
          meta: {
            signalType: 'auth_page_navigation',
          },
        });
      }
    });
  }

  /**
   * Cookie polling — periodic snapshot of all cookies
   */
  _startCookiePolling() {
    this.cookiePollTimer = setInterval(async () => {
      try {
        const cookies = await this.context.cookies();
        const authCookies = cookies.filter(c => AUTH_COOKIES.has(c.name));

        this.bus.emit({
          type: 'cookie_snapshot',
          source: 'playwright',
          meta: {
            totalCookies: cookies.length,
            authCookies: authCookies.map(c => ({
              name: c.name,
              domain: c.domain,
              path: c.path,
              httpOnly: c.httpOnly,
              secure: c.secure,
              sameSite: c.sameSite,
              expires: c.expires,
              valuePreview: c.value?.substring(0, 30) + '...',
            })),
            allCookieNames: cookies.map(c => c.name),
          },
        });

        // Auth signal for auth cookie presence
        if (authCookies.length > 0) {
          this.bus.emit({
            type: 'auth_signal',
            source: 'cookie_poll',
            meta: {
              signalType: 'auth_cookies_present',
              cookies: authCookies.map(c => ({
                name: c.name,
                domain: c.domain,
                httpOnly: c.httpOnly,
                secure: c.secure,
                sameSite: c.sameSite,
                valuePrefix: c.value?.substring(0, 15),
              })),
            },
          });
        }
      } catch (e) {
        // Context may be closed during shutdown
      }
    }, this.options.cookiePollInterval);
  }

  /**
   * Performance entries polling
   */
  _startPerformancePolling() {
    this.perfPollTimer = setInterval(async () => {
      try {
        const entries = await this.page.evaluate(() => {
          const resources = performance.getEntriesByType('resource');
          return resources.map(r => ({
            name: r.name,
            type: r.initiatorType,
            duration: Math.round(r.duration),
            size: r.transferSize,
            startTime: Math.round(r.startTime),
          }));
        });

        if (entries.length > 0) {
          this.bus.emit({
            type: 'performance_resource',
            source: 'playwright',
            meta: {
              entryCount: entries.length,
              entries: entries.slice(-50), // last 50
              summary: {
                totalSize: entries.reduce((s, e) => s + (e.size || 0), 0),
                avgDuration: Math.round(entries.reduce((s, e) => s + e.duration, 0) / entries.length),
                byType: entries.reduce((acc, e) => {
                  acc[e.type] = (acc[e.type] || 0) + 1;
                  return acc;
                }, {}),
              },
            },
          });
        }
      } catch (_) {}
    }, this.options.perfPollInterval);
  }

  /**
   * Inject document-start instrumentation script
   */
  async _injectInstrumentation() {
    const scriptPath = path.join(__dirname, 'instrumentation.js');
    if (fs.existsSync(scriptPath)) {
      const script = fs.readFileSync(scriptPath, 'utf8');
      await this.page.addInitScript(script);
      console.log('[Runner] Instrumentation script injected (addInitScript)');
    } else {
      console.warn('[Runner] instrumentation.js not found — skipping document-start hooks');
    }
  }

  /**
   * Graceful shutdown
   */
  async stop() {
    console.log('[Runner] Shutting down...');

    if (this.cookiePollTimer) clearInterval(this.cookiePollTimer);
    if (this.perfPollTimer) clearInterval(this.perfPollTimer);

    try {
      if (this.context && this.options.recordHar) {
        await this.context.close(); // flush HAR
      }
      if (this.browser) {
        await this.browser.close();
      }
    } catch (e) {
      console.error('[Runner] Shutdown error:', e.message);
    }

    console.log('[Runner] Stopped');
  }
}

module.exports = { PlaywrightRunner, AUTH_PATTERNS, AUTH_COOKIES, AUTH_HEADERS };


'use strict';

const { validateTaskAsync } = require('./execution-authorization-guard');
const installedContextTargets = new WeakMap();

/**
 * Fail-closed browser policy. Every Playwright HTTP(S) request is intercepted
 * at context level. WebSocket and EventSource are disabled because Playwright
 * 1.41 cannot reliably pin/validate their socket resolution.
 *
 * DNS is checked immediately before route.continue(), but Chromium performs
 * its own resolution afterwards. This reduces exposure; it is deliberately
 * not represented as complete DNS-rebinding mitigation.
 */
class BrowserEgressGuard {
  constructor(options = {}) {
    this.registry = options.registry;
    this.targetId = options.targetId;
    this.resolver = options.resolver;
    this.adminExecutionEnabled = options.adminExecutionEnabled;
    this.onDecision = options.onDecision || (() => {});
    this.telemetry = options.telemetry || null;
    this.installedContexts = new WeakSet();
  }

  async validate(url, method = 'GET') {
    return validateTaskAsync({
      action: 'navigation',
      target_id: this.targetId,
      params: { url, method },
    }, this.registry, {
      resolver: this.resolver,
      adminExecutionEnabled: this.adminExecutionEnabled,
      telemetry: this.telemetry,
      phase: 'browser_request',
    });
  }

  async install(context) {
    if (!context || this.installedContexts.has(context)) return;
    const installedTarget = installedContextTargets.get(context);
    if (installedTarget && installedTarget !== this.targetId) {
      throw new Error('BROWSER_CONTEXT_TARGET_SWITCH_FORBIDDEN');
    }
    if (installedTarget === this.targetId) {
      this.installedContexts.add(context);
      return;
    }
    if (typeof context.route !== 'function') throw new Error('BROWSER_EGRESS_ROUTE_UNAVAILABLE');
    if (typeof context.routeWebSocket !== 'function') throw new Error('BROWSER_EGRESS_WEBSOCKET_ROUTE_UNAVAILABLE');

    if (typeof context.serviceWorkers === 'function' && context.serviceWorkers().length > 0) {
      throw new Error('BROWSER_EGRESS_PREEXISTING_SERVICE_WORKER');
    }

    if (typeof context.addInitScript === 'function') {
      await context.addInitScript(() => {
        const blocked = () => { throw new Error('BOQA_EGRESS_CHANNEL_DISABLED'); };
        Object.defineProperty(globalThis, 'WebSocket', { value: blocked, configurable: false, writable: false });
        Object.defineProperty(globalThis, 'EventSource', { value: blocked, configurable: false, writable: false });
        if (navigator.serviceWorker) {
          Object.defineProperty(navigator, 'serviceWorker', { value: undefined, configurable: false });
        }
      });
    }

    await context.route('**/*', async route => {
      const request = route.request();
      const url = request.url();
      const resourceType = typeof request.resourceType === 'function' ? request.resourceType() : 'unknown';
      const result = await this.validate(url, request.method());
      this.onDecision({ url, resource_type: resourceType, ...result });
      this.telemetry?.recordSecurityDecision('browser_egress', result, {
        target_id: this.targetId,
        method: request.method(),
        resource_type: resourceType,
      });
      if (!result.allowed) return route.abort('blockedbyclient');
      return route.continue();
    });

    // WebSocket handshakes do not use the normal HTTP route API. Keep them
    // disabled fail-closed until a separately authorized WS policy exists.
    await context.routeWebSocket('**/*', async webSocketRoute => {
      this.telemetry?.recordSecurityDecision('browser_websocket', {
        allowed: false,
        code: 'EGRESS_CHANNEL_DISABLED',
      }, { target_id: this.targetId, resource_type: 'websocket' });
      await webSocketRoute.close({ code: 1008, reason: 'BOQA_EGRESS_CHANNEL_DISABLED' });
    });

    this.installedContexts.add(context);
    installedContextTargets.set(context, this.targetId);
  }
}

module.exports = { BrowserEgressGuard };

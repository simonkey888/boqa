'use strict';

function createIsolatedRuntime(options = {}) {
  const state = new Map();
  let cleaned = false;
  let requests = 0;
  let scopeViolations = 0;
  let destructiveActions = 0;
  let externalNetworkAttempts = 0;
  const allowedPaths = new Set(options.allowedPaths || ['/']);
  const allowedMethods = new Set(options.allowedMethods || ['GET']);

  function assertActive() {
    if (cleaned) throw new Error('RUNTIME_CLEANED');
  }

  const runtime = {
    authorizedUrl: 'http://lab.internal',
    scope: [...allowedPaths],
    credentials: options.credentials || null,
    async request(method, pathname, requestOptions = {}) {
      assertActive();
      requests++;
      method = String(method || 'GET').toUpperCase();
      if (!allowedMethods.has(method) || !allowedPaths.has(pathname)) {
        scopeViolations++;
        return { status: 403, headers: {}, body: 'scope_denied' };
      }
      if (requestOptions.destructive === true) {
        destructiveActions++;
        return { status: 403, headers: {}, body: 'destructive_action_denied' };
      }
      return options.handler ? options.handler({ method, pathname, options: requestOptions, state }) : { status: 200, headers: {}, body: 'fixture' };
    },
    async resolve() { externalNetworkAttempts++; throw new Error('EXTERNAL_DNS_DISABLED'); },
    async connect() { externalNetworkAttempts++; throw new Error('EXTERNAL_NETWORK_DISABLED'); },
    async metadata() { externalNetworkAttempts++; throw new Error('METADATA_SERVICE_DISABLED'); },
    async host() { externalNetworkAttempts++; throw new Error('HOST_ACCESS_DISABLED'); },
    async peerScenario() { externalNetworkAttempts++; throw new Error('CROSS_SCENARIO_ACCESS_DISABLED'); },
    persist(key, value) { assertActive(); state.set(key, value); },
    read(key) { assertActive(); return state.get(key); },
    cleanup() { state.clear(); cleaned = true; },
    stats() { return { requests, scopeViolations, destructiveActions, externalNetworkAttempts, cleaned, persistedKeys: state.size }; },
  };
  return runtime;
}

module.exports = { createIsolatedRuntime };

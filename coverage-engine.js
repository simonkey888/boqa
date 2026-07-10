/**
 * BOQA coverage-engine.js — Coverage Engine v0.6
 *
 * Builds a complete application surface map from observed events.
 * Generates a coverage graph that tracks which routes, endpoints,
 * auth flows, WebSocket channels, forms, and state transitions
 * have been discovered vs. which remain unexplored.
 *
 * Outputs:
 *   - routes:             discovered URL routes (grouped by path prefix)
 *   - api_endpoints:      REST/API endpoints with method + auth requirements
 *   - auth_flows:         login/logout/token/refresh flow chains
 *   - websocket_channels: WS connection URLs + message types
 *   - forms:              discovered form submissions + field inventories
 *   - state_transitions:  page navigation state graph edges
 *
 * Coverage score = weighted sum of coverage across all domains:
 *   routes(0.25) + api_endpoints(0.25) + auth_flows(0.20) +
 *   websockets(0.15) + forms(0.10) + state_transitions(0.05)
 *
 * Safe mode: only observes, never initiates requests or modifies state.
 */

const crypto = require('crypto');

// ─── Domain Weights ─────────────────────────────────────────────────

const DOMAIN_WEIGHTS = {
  routes:             0.25,
  api_endpoints:      0.25,
  auth_flows:         0.20,
  websocket_channels: 0.15,
  forms:              0.10,
  state_transitions:  0.05,
};

// ─── Auth URL Pattern Detection ─────────────────────────────────────

const AUTH_PATTERNS = [
  /\/api\/users\/me\/?/, /\/auth\//, /\/login/, /\/logout/, /\/token/,
  /\/oauth/, /\/session/, /\/2fa/, /\/verify/, /\/refresh/,
  /\/signup/, /\/register/, /\/forgot-password/, /\/reset-password/,
];

// ─── API Detection Heuristics ───────────────────────────────────────

const API_PREFIXES = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/rpc/'];

// =====================================================================
//  CoverageEngine
// =====================================================================

class CoverageEngine {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance for persistence
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;

    /** @type {Map<string, object>} target_id → coverage map */
    this.coverageMaps = new Map();

    /** @type {Map<string, Set>} target_id → discovered route set */
    this._routes = new Map();

    /** @type {Map<string, Map>} target_id → endpoint key → endpoint info */
    this._endpoints = new Map();

    /** @type {Map<string, object[]>} target_id → auth flow list */
    this._authFlows = new Map();

    /** @type {Map<string, Map>} target_id → ws url → channel info */
    this._wsChannels = new Map();

    /** @type {Map<string, Map>} target_id → form key → form info */
    this._forms = new Map();

    /** @type {Map<string, Set>} target_id → state transition edges */
    this._stateTransitions = new Map();

    /** @type {Map<string, string>} target_id → last known URL for state tracking */
    this._lastUrl = new Map();

    /** @type {Map<string, object>} target_id → estimated total surface */
    this._estimatedSurface = new Map();
  }

  // ─── Event Ingestion ─────────────────────────────────────────────

  /**
   * Process an event from the observability stream and update
   * the coverage map for the appropriate target.
   *
   * @param {string} targetId
   * @param {object} event - normalized event from EventBus
   * @returns {object|null} coverage delta if coverage changed
   */
  ingestEvent(targetId, event) {
    if (!targetId || !event) return null;

    let changed = false;
    const delta = { target_id: targetId, domain: null, added: null };

    switch (event.type) {
      case 'network_request':
      case 'network_response':
        changed = this._processNetworkEvent(targetId, event);
        if (changed) {
          delta.domain = 'api_endpoints';
          delta.added = event.url;
        }
        break;

      case 'page_navigation':
        changed = this._processNavigationEvent(targetId, event);
        if (changed) {
          delta.domain = 'routes';
          delta.added = event.url;
        }
        break;

      case 'websocket_open':
      case 'websocket_message_in':
      case 'websocket_message_out':
      case 'websocket_close':
        changed = this._processWsEvent(targetId, event);
        if (changed) {
          delta.domain = 'websocket_channels';
          delta.added = event.url || event.payload?.url;
        }
        break;

      case 'auth_signal':
        changed = this._processAuthEvent(targetId, event);
        if (changed) {
          delta.domain = 'auth_flows';
          delta.added = event.url;
        }
        break;

      case 'cookie_snapshot':
        // Cookies don't directly add coverage but inform auth flow detection
        break;

      default:
        break;
    }

    if (changed) {
      // Persist to knowledge base
      if (this.kb) {
        this.kb.addObservation(targetId, event);
      }
      return delta;
    }

    return null;
  }

  // ─── Network Event Processing ────────────────────────────────────

  /**
   * Process a network request/response event.
   * Discovers API endpoints and routes.
   *
   * @param {string} targetId
   * @param {object} event
   * @returns {boolean} true if new coverage discovered
   * @private
   */
  _processNetworkEvent(targetId, event) {
    const url = event.url;
    if (!url || typeof url !== 'string') return false;

    // Skip data URLs, chrome-extension, etc.
    if (url.startsWith('data:') || url.startsWith('chrome-extension://') ||
        url.startsWith('blob:')) return false;

    let pathname;
    let host;
    try {
      const parsed = new URL(url);
      pathname = parsed.pathname;
      host = parsed.host;
    } catch {
      return false;
    }

    let changed = false;

    // ── Route discovery ────────────────────────────────────────────
    if (!this._routes.has(targetId)) {
      this._routes.set(targetId, new Set());
    }

    // Normalize route: strip trailing slashes, group by path prefix
    const normalizedRoute = this._normalizeRoute(pathname);
    if (!this._routes.get(targetId).has(normalizedRoute)) {
      this._routes.get(targetId).add(normalizedRoute);
      changed = true;
    }

    // ── API endpoint discovery ─────────────────────────────────────
    const isApi = API_PREFIXES.some(p => pathname.startsWith(p));
    if (isApi || (event.method && event.method !== 'GET' && event.type === 'network_request')) {
      if (!this._endpoints.has(targetId)) {
        this._endpoints.set(targetId, new Map());
      }

      const endpointKey = `${event.method || 'GET'} ${normalizedRoute}`;
      if (!this._endpoints.get(targetId).has(endpointKey)) {
        this._endpoints.get(targetId).set(endpointKey, {
          method: event.method || 'GET',
          path: normalizedRoute,
          full_url: url,
          is_auth: AUTH_PATTERNS.some(p => p.test(pathname)),
          first_seen: event.ts || Date.now(),
          status_codes: new Set(),
          request_count: 1,
        });
        changed = true;
      } else {
        const ep = this._endpoints.get(targetId).get(endpointKey);
        ep.request_count = (ep.request_count || 0) + 1;
        if (event.status) ep.status_codes.add(event.status);
      }
    }

    return changed;
  }

  // ─── Navigation Event Processing ─────────────────────────────────

  /**
   * Process a page navigation event.
   * Discovers routes and state transitions.
   *
   * @param {string} targetId
   * @param {object} event
   * @returns {boolean}
   * @private
   */
  _processNavigationEvent(targetId, event) {
    const url = event.url;
    if (!url || typeof url !== 'string') return false;

    let pathname;
    try {
      pathname = new URL(url).pathname;
    } catch {
      return false;
    }

    let changed = false;

    // Add to routes
    if (!this._routes.has(targetId)) {
      this._routes.set(targetId, new Set());
    }
    const normalizedRoute = this._normalizeRoute(pathname);
    if (!this._routes.get(targetId).has(normalizedRoute)) {
      this._routes.get(targetId).add(normalizedRoute);
      changed = true;
    }

    // State transition tracking
    const lastUrl = this._lastUrl.get(targetId);
    if (lastUrl && lastUrl !== normalizedRoute) {
      if (!this._stateTransitions.has(targetId)) {
        this._stateTransitions.set(targetId, new Set());
      }
      const edge = `${lastUrl} → ${normalizedRoute}`;
      if (!this._stateTransitions.get(targetId).has(edge)) {
        this._stateTransitions.get(targetId).add(edge);
        changed = true;
      }
    }

    this._lastUrl.set(targetId, normalizedRoute);
    return changed;
  }

  // ─── WebSocket Event Processing ──────────────────────────────────

  /**
   * Process a WebSocket event.
   * Discovers WS channels and message types.
   *
   * @param {string} targetId
   * @param {object} event
   * @returns {boolean}
   * @private
   */
  _processWsEvent(targetId, event) {
    const wsUrl = event.url || event.payload?.url;
    if (!wsUrl) return false;

    if (!this._wsChannels.has(targetId)) {
      this._wsChannels.set(targetId, new Map());
    }

    let changed = false;
    if (!this._wsChannels.get(targetId).has(wsUrl)) {
      this._wsChannels.get(targetId).set(wsUrl, {
        url: wsUrl,
        message_types: new Set(),
        first_seen: event.ts || Date.now(),
        message_count: 0,
      });
      changed = true;
    }

    const channel = this._wsChannels.get(targetId).get(wsUrl);
    channel.message_count = (channel.message_count || 0) + 1;

    // Track message types
    if (event.payload?.type) {
      if (!channel.message_types.has(event.payload.type)) {
        channel.message_types.add(event.payload.type);
      }
    }

    return changed;
  }

  // ─── Auth Event Processing ───────────────────────────────────────

  /**
   * Process an auth signal event.
   * Discovers authentication flow steps.
   *
   * @param {string} targetId
   * @param {object} event
   * @returns {boolean}
   * @private
   */
  _processAuthEvent(targetId, event) {
    if (!this._authFlows.has(targetId)) {
      this._authFlows.set(targetId, []);
    }

    const flows = this._authFlows.get(targetId);

    // Check if this auth step is already recorded
    const url = event.url || '';
    const step = {
      url,
      type: event.payload?.signal_type || event.payload?.type || 'auth_signal',
      ts: event.ts || Date.now(),
      cookies: event.payload?.cookies || [],
      headers: event.payload?.headers || {},
    };

    // Deduplicate by URL + type
    const existing = flows.find(f => f.url === url && f.type === step.type);
    if (!existing) {
      flows.push(step);
      return true;
    }

    return false;
  }

  // ─── Coverage Map Generation ─────────────────────────────────────

  /**
   * Build and return the complete coverage map for a target.
   *
   * @param {string} targetId
   * @returns {object} coverage map with score
   */
  getCoverageMap(targetId) {
    const routes = [...(this._routes.get(targetId) || [])];
    const endpoints = [...(this._endpoints.get(targetId) || new Map()).values()]
      .map(ep => ({
        ...ep,
        status_codes: [...(ep.status_codes || [])],
      }));
    const authFlows = this._authFlows.get(targetId) || [];
    const wsChannels = [...(this._wsChannels.get(targetId) || new Map()).values()]
      .map(ch => ({
        ...ch,
        message_types: [...(ch.message_types || [])],
      }));
    const forms = [...(this._forms.get(targetId) || new Map()).values()];
    const stateTransitions = [...(this._stateTransitions.get(targetId) || [])];

    // Compute coverage score (0-100)
    const score = this.computeCoverageScore(targetId);

    const coverageMap = {
      target_id: targetId,
      routes,
      api_endpoints: endpoints,
      auth_flows: authFlows,
      websocket_channels: wsChannels,
      forms,
      state_transitions: stateTransitions,
      score,
      generated_at: Date.now(),
    };

    // Cache and persist
    this.coverageMaps.set(targetId, coverageMap);
    if (this.kb) {
      this.kb.upsertCoverage(targetId, coverageMap);
    }

    return coverageMap;
  }

  /**
   * Compute the coverage score for a target (0-100).
   *
   * The score is a weighted composite across all discovered domains.
   * Each domain score is based on the ratio of discovered items
   * to an estimated total surface. If no estimate is available,
   * a heuristic growth model is used.
   *
   * @param {string} targetId
   * @returns {number} 0-100
   */
  computeCoverageScore(targetId) {
    const routeCount = (this._routes.get(targetId) || new Set()).size;
    const endpointCount = (this._endpoints.get(targetId) || new Map()).size;
    const authFlowCount = (this._authFlows.get(targetId) || []).length;
    const wsChannelCount = (this._wsChannels.get(targetId) || new Map()).size;
    const formCount = (this._forms.get(targetId) || new Map()).size;
    const stateTransitionCount = (this._stateTransitions.get(targetId) || new Set()).size;

    // Heuristic: estimate total surface from what we've discovered
    // Using a logarithmic growth model: estimated_total = discovered * (1 + 1/ln(discovered+2))
    const estimate = (count) => {
      if (count === 0) return { discovered: 0, estimated_total: 10 };
      const estimated = Math.round(count * (1 + 1 / Math.log(count + 2)));
      return { discovered: count, estimated_total: Math.max(estimated, count) };
    };

    const r = estimate(routeCount);
    const e = estimate(endpointCount);
    const a = estimate(authFlowCount);
    const w = estimate(wsChannelCount);
    const f = estimate(formCount);
    const s = estimate(stateTransitionCount);

    // Domain scores (0-100): min(discovered/estimated * 100, 100)
    const domainScores = {
      routes:             Math.min((r.discovered / r.estimated_total) * 100, 100),
      api_endpoints:      Math.min((e.discovered / e.estimated_total) * 100, 100),
      auth_flows:         Math.min((a.discovered / a.estimated_total) * 100, 100),
      websocket_channels: Math.min((w.discovered / w.estimated_total) * 100, 100),
      forms:              Math.min((f.discovered / f.estimated_total) * 100, 100),
      state_transitions:  Math.min((s.discovered / s.estimated_total) * 100, 100),
    };

    // Weighted composite
    let score = 0;
    for (const [domain, weight] of Object.entries(DOMAIN_WEIGHTS)) {
      score += (domainScores[domain] || 0) * weight;
    }

    return Math.round(Math.min(score, 100));
  }

  // ─── Coverage Gaps ───────────────────────────────────────────────

  /**
   * Identify coverage gaps — domains where discovery is below threshold.
   *
   * @param {string} targetId
   * @param {number} [threshold=50] - below this % is considered a gap
   * @returns {object[]} array of { domain, current_score, weight, gap }
   */
  getCoverageGaps(targetId, threshold = 50) {
    const routeCount = (this._routes.get(targetId) || new Set()).size;
    const endpointCount = (this._endpoints.get(targetId) || new Map()).size;
    const authFlowCount = (this._authFlows.get(targetId) || []).length;
    const wsChannelCount = (this._wsChannels.get(targetId) || new Map()).size;
    const formCount = (this._forms.get(targetId) || new Map()).size;
    const stateTransitionCount = (this._stateTransitions.get(targetId) || new Set()).size;

    const counts = {
      routes: routeCount,
      api_endpoints: endpointCount,
      auth_flows: authFlowCount,
      websocket_channels: wsChannelCount,
      forms: formCount,
      state_transitions: stateTransitionCount,
    };

    const gaps = [];
    for (const [domain, count] of Object.entries(counts)) {
      const estimate = Math.max(count * (1 + 1 / Math.log(count + 2)), count);
      const score = count > 0 ? Math.min((count / estimate) * 100, 100) : 0;

      if (score < threshold) {
        gaps.push({
          domain,
          current_score: Math.round(score),
          weight: DOMAIN_WEIGHTS[domain],
          gap: Math.round(threshold - score),
        });
      }
    }

    // Sort by gap * weight (highest impact first)
    gaps.sort((a, b) => (b.gap * b.weight) - (a.gap * a.weight));
    return gaps;
  }

  // ─── Unexplored Endpoints ────────────────────────────────────────

  /**
   * Find API endpoints that have been discovered but not yet
   * tested with all relevant HTTP methods.
   *
   * @param {string} targetId
   * @returns {object[]} endpoints with missing methods
   */
  getUnexploredEndpoints(targetId) {
    const endpoints = this._endpoints.get(targetId) || new Map();
    const unexplored = [];

    // Group endpoints by path
    const pathGroups = new Map();
    for (const [, ep] of endpoints) {
      if (!pathGroups.has(ep.path)) {
        pathGroups.set(ep.path, new Set());
      }
      pathGroups.get(ep.path).add(ep.method);
    }

    const commonMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

    for (const [path, methods] of pathGroups) {
      const missing = commonMethods.filter(m => !methods.has(m));
      if (missing.length > 0) {
        unexplored.push({
          path,
          discovered_methods: [...methods],
          missing_methods: missing,
          is_auth: AUTH_PATTERNS.some(p => p.test(path)),
        });
      }
    }

    return unexplored;
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  /**
   * Normalize a route path for deduplication.
   * Replaces UUIDs, numeric IDs, and hash segments with placeholders.
   *
   * @param {string} pathname
   * @returns {string}
   * @private
   */
  _normalizeRoute(pathname) {
    if (!pathname) return '/';

    let normalized = pathname;

    // Remove trailing slash (except for root)
    if (normalized.length > 1 && normalized.endsWith('/')) {
      normalized = normalized.slice(0, -1);
    }

    // Replace UUID segments
    normalized = normalized.replace(
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
      ':uuid'
    );

    // Replace numeric IDs
    normalized = normalized.replace(/\/\d{2,}(?=[/?#]|$)/g, '/:id');

    // Replace hash-like segments (32+ hex chars)
    normalized = normalized.replace(/\/[0-9a-f]{32,}/gi, '/:hash');

    return normalized;
  }

  /**
   * Get a summary of coverage for all tracked targets.
   * @returns {object[]}
   */
  getAllCoverageSummaries() {
    const summaries = [];
    for (const [targetId] of this.coverageMaps) {
      summaries.push({
        target_id: targetId,
        score: this.computeCoverageScore(targetId),
      });
    }
    return summaries;
  }
}

module.exports = { CoverageEngine };


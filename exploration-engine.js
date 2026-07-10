/**
 * BOQA exploration-engine.js — Exploration Engine v0.6
 *
 * Adaptive navigation of authorized applications. Discovers routes,
 * traverses workflows, identifies authenticated paths, and builds
 * a state graph of the application under observation.
 *
 * Features:
 *   - Route discovery: identifies new routes from observations
 *   - Workflow traversal: follows multi-step flows (login→dashboard→action)
 *   - Authenticated path discovery: finds paths requiring auth
 *   - State graph generation: builds a directed graph of page states
 *
 * Exploration strategies:
 *   - breadth_first:  explore all direct children first
 *   - depth_first:    follow deep paths before backtracking
 *   - coverage_greedy: prioritize unexplored domains
 *   - risk_directed:   prioritize high-risk areas (auth, payments)
 *
 * The engine operates in OBSERVE mode — it plans explorations but
 * does not execute them directly. Execution is delegated to the
 * WorkerPool or the Playwright Agent.
 *
 * Safe mode: never initiates destructive actions, credential attacks,
 * or mass scanning. Only plans authorized, observation-based exploration.
 */

const crypto = require('crypto');

// ─── Exploration Strategies ─────────────────────────────────────────

const STRATEGIES = {
  breadth_first:   'breadth_first',
  depth_first:     'depth_first',
  coverage_greedy: 'coverage_greedy',
  risk_directed:   'risk_directed',
};

// ─── Risk Weights for Route Prioritization ──────────────────────────

const ROUTE_RISK_WEIGHTS = {
  auth:     1.0,  // /login, /logout, /token, /2fa
  payment:  0.9,  // /payment, /checkout, /billing
  user:     0.7,  // /profile, /settings, /account
  admin:    0.8,  // /admin, /manage, /dashboard
  api:      0.6,  // /api/*, /v1/*
  upload:   0.7,  // /upload, /file
  ws:       0.5,  // websocket endpoints
  general:  0.3,  // everything else
};

// ─── Auth Route Patterns ────────────────────────────────────────────

const AUTH_ROUTE_PATTERNS = [
  /\/login/, /\/logout/, /\/signup/, /\/register/,
  /\/auth\//, /\/token/, /\/oauth/, /\/2fa/,
  /\/verify/, /\/refresh/, /\/session/,
];

const PAYMENT_ROUTE_PATTERNS = [
  /\/payment/, /\/checkout/, /\/billing/, /\/charge/,
  /\/subscribe/, /\/invoice/, /\/wallet/, /\/deposit/,
];

const ADMIN_ROUTE_PATTERNS = [
  /\/admin/, /\/manage/, /\/dashboard/, /\/console/,
  /\/backoffice/, /\/control/, /\/cms/,
];

const USER_ROUTE_PATTERNS = [
  /\/profile/, /\/settings/, /\/account/, /\/user/,
  /\/me/, /\/my-/, /\/personal/,
];

const UPLOAD_ROUTE_PATTERNS = [
  /\/upload/, /\/file/, /\/attachment/, /\/media/,
];

// =====================================================================
//  ExplorationEngine
// =====================================================================

class ExplorationEngine {
  /**
   * @param {object} options
   * @param {object} [options.coverageEngine]  - CoverageEngine for gap analysis
   * @param {object} [options.knowledgeBase]   - KnowledgeBase for historical data
   * @param {string} [options.strategy]        - Default exploration strategy
   * @param {number} [options.maxDepth]        - Maximum exploration depth (default 10)
   * @param {number} [options.maxFrontierSize] - Maximum frontier queue size (default 1000)
   */
  constructor(options = {}) {
    this.coverageEngine = options.coverageEngine || null;
    this.kb = options.knowledgeBase || null;
    this.strategy = options.strategy || STRATEGIES.coverage_greedy;
    this.maxDepth = options.maxDepth || 10;
    this.maxFrontierSize = options.maxFrontierSize || 1000;

    /** @type {Map<string, object>} target_id → state graph */
    this.stateGraphs = new Map();

    /** @type {Map<string, object[]>} target_id → exploration frontier */
    this.frontiers = new Map();

    /** @type {Map<string, Set>} target_id → visited route set */
    this.visited = new Map();

    /** @type {Map<string, object[]>} target_id → exploration plan history */
    this.planHistory = new Map();

    /** @type {Map<string, object>} target_id → discovered workflows */
    this.workflows = new Map();

    /** @type {Map<string, object>} target_id → authenticated paths */
    this.authenticatedPaths = new Map();
  }

  // ─── State Graph Building ────────────────────────────────────────

  /**
   * Record a state transition in the exploration graph.
   *
   * @param {string} targetId
   * @param {string} fromUrl - source URL/path
   * @param {string} toUrl   - destination URL/path
   * @param {object} [meta]  - transition metadata
   * @returns {object} the edge added/updated
   */
  recordTransition(targetId, fromUrl, toUrl, meta = {}) {
    if (!this.stateGraphs.has(targetId)) {
      this.stateGraphs.set(targetId, { nodes: new Map(), edges: [] });
    }

    const graph = this.stateGraphs.get(targetId);

    // Add nodes
    if (!graph.nodes.has(fromUrl)) {
      graph.nodes.set(fromUrl, {
        url: fromUrl,
        first_seen: Date.now(),
        visit_count: 1,
        risk_class: this._classifyRoute(fromUrl),
        requires_auth: this._isAuthRoute(fromUrl),
      });
    } else {
      graph.nodes.get(fromUrl).visit_count++;
    }

    if (!graph.nodes.has(toUrl)) {
      graph.nodes.set(toUrl, {
        url: toUrl,
        first_seen: Date.now(),
        visit_count: 1,
        risk_class: this._classifyRoute(toUrl),
        requires_auth: this._isAuthRoute(toUrl),
      });
    } else {
      graph.nodes.get(toUrl).visit_count++;
    }

    // Add or update edge
    const existingEdge = graph.edges.find(
      e => e.from === fromUrl && e.to === toUrl
    );

    if (existingEdge) {
      existingEdge.traversal_count++;
      existingEdge.last_seen = Date.now();
      if (meta.trigger) existingEdge.triggers.add(meta.trigger);
      return existingEdge;
    }

    const edge = {
      id: `EDGE-${crypto.randomUUID().substring(0, 8)}`,
      from: fromUrl,
      to: toUrl,
      triggers: new Set(meta.trigger ? [meta.trigger] : []),
      traversal_count: 1,
      first_seen: Date.now(),
      last_seen: Date.now(),
      meta,
    };

    graph.edges.push(edge);
    return edge;
  }

  // ─── Frontier Management ─────────────────────────────────────────

  /**
   * Add a route to the exploration frontier.
   *
   * @param {string} targetId
   * @param {string} url
   * @param {object} [context] - { referrer, depth, risk_class, requires_auth }
   * @returns {boolean} true if added (was not already visited)
   */
  addToFrontier(targetId, url, context = {}) {
    if (!this.visited.has(targetId)) {
      this.visited.set(targetId, new Set());
    }

    // Skip if already visited
    if (this.visited.get(targetId).has(url)) {
      return false;
    }

    if (!this.frontiers.has(targetId)) {
      this.frontiers.set(targetId, []);
    }

    const frontier = this.frontiers.get(targetId);

    // Check if already in frontier
    if (frontier.some(f => f.url === url)) {
      return false;
    }

    // Cap frontier size
    if (frontier.length >= this.maxFrontierSize) {
      // Remove lowest-priority item
      frontier.sort((a, b) => (b.priority || 0) - (a.priority || 0));
      frontier.pop();
    }

    const priority = this._computePriority(url, context);

    frontier.push({
      url,
      referrer: context.referrer || null,
      depth: context.depth || 0,
      risk_class: context.risk_class || this._classifyRoute(url),
      requires_auth: context.requires_auth || this._isAuthRoute(url),
      priority,
      added_at: Date.now(),
    });

    // Re-sort by priority
    frontier.sort((a, b) => (b.priority || 0) - (a.priority || 0));
    return true;
  }

  /**
   * Mark a URL as visited and remove from frontier.
   *
   * @param {string} targetId
   * @param {string} url
   */
  markVisited(targetId, url) {
    if (!this.visited.has(targetId)) {
      this.visited.set(targetId, new Set());
    }
    this.visited.get(targetId).add(url);

    // Remove from frontier
    if (this.frontiers.has(targetId)) {
      const frontier = this.frontiers.get(targetId);
      const idx = frontier.findIndex(f => f.url === url);
      if (idx !== -1) frontier.splice(idx, 1);
    }
  }

  /**
   * Get the next exploration target from the frontier.
   *
   * @param {string} targetId
   * @param {string} [strategy] - override default strategy
   * @returns {object|null} next target { url, priority, depth, ... }
   */
  getNext(targetId, strategy) {
    const frontier = this.frontiers.get(targetId);
    if (!frontier || frontier.length === 0) return null;

    const strat = strategy || this.strategy;

    switch (strat) {
      case STRATEGIES.breadth_first:
        // Lowest depth first
        frontier.sort((a, b) => (a.depth || 0) - (b.depth || 0));
        return frontier.shift();

      case STRATEGIES.depth_first:
        // Highest depth first
        frontier.sort((a, b) => (b.depth || 0) - (a.depth || 0));
        return frontier.shift();

      case STRATEGIES.risk_directed:
        // Highest risk first
        frontier.sort((a, b) => (b.priority || 0) - (a.priority || 0));
        return frontier.shift();

      case STRATEGIES.coverage_greedy:
      default:
        // Use pre-computed priority (already sorted)
        return frontier.shift();
    }
  }

  // ─── Workflow Detection ──────────────────────────────────────────

  /**
   * Detect multi-step workflows from the state graph.
   * A workflow is a sequence of state transitions that forms
   * a coherent user journey (e.g., login → 2fa → dashboard).
   *
   * @param {string} targetId
   * @returns {object[]} detected workflows
   */
  detectWorkflows(targetId) {
    const graph = this.stateGraphs.get(targetId);
    if (!graph) return [];

    const workflows = [];

    // Find auth-initiated workflows (start from login/signup)
    for (const [, node] of graph.nodes) {
      if (this._isAuthRoute(node.url)) {
        const paths = this._findPaths(graph, node.url, 5);
        for (const path of paths) {
          if (path.length >= 2) {
            workflows.push({
              id: `WF-${crypto.randomUUID().substring(0, 8)}`,
              type: 'auth_flow',
              steps: path,
              risk_class: 'auth',
              discovered_at: Date.now(),
            });
          }
        }
      }
    }

    // Find payment workflows
    for (const [, node] of graph.nodes) {
      if (this._isPaymentRoute(node.url)) {
        const paths = this._findPaths(graph, node.url, 4);
        for (const path of paths) {
          if (path.length >= 2) {
            workflows.push({
              id: `WF-${crypto.randomUUID().substring(0, 8)}`,
              type: 'payment_flow',
              steps: path,
              risk_class: 'payment',
              discovered_at: Date.now(),
            });
          }
        }
      }
    }

    // Deduplicate by step sequence
    const seen = new Set();
    const unique = [];
    for (const wf of workflows) {
      const key = wf.steps.join('→');
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(wf);
      }
    }

    this.workflows.set(targetId, unique);
    return unique;
  }

  /**
   * Identify authenticated paths — routes that are only reachable
   * after authentication.
   *
   * @param {string} targetId
   * @returns {object[]} authenticated paths
   */
  findAuthenticatedPaths(targetId) {
    const graph = this.stateGraphs.get(targetId);
    if (!graph) return [];

    const authPaths = [];

    // Find all nodes reachable from auth routes
    const authNodes = new Set();
    for (const [url, node] of graph.nodes) {
      if (this._isAuthRoute(url)) {
        authNodes.add(url);
      }
    }

    // BFS from auth nodes to find post-auth reachable paths
    const visited = new Set();
    const queue = [...authNodes];

    while (queue.length > 0) {
      const current = queue.shift();
      if (visited.has(current)) continue;
      visited.add(current);

      for (const edge of graph.edges) {
        if (edge.from === current && !visited.has(edge.to)) {
          queue.push(edge.to);

          // Only include non-auth nodes as authenticated paths
          if (!this._isAuthRoute(edge.to)) {
            authPaths.push({
              url: edge.to,
              reachable_from: current,
              risk_class: this._classifyRoute(edge.to),
              depth: this._pathDepth(graph, current),
            });
          }
        }
      }
    }

    // Deduplicate
    const seen = new Set();
    const unique = authPaths.filter(p => {
      if (seen.has(p.url)) return false;
      seen.add(p.url);
      return true;
    });

    this.authenticatedPaths.set(targetId, unique);
    return unique;
  }

  // ─── Exploration Planning ────────────────────────────────────────

  /**
   * Generate an exploration plan for a target based on current
   * coverage gaps and frontier state.
   *
   * @param {string} targetId
   * @param {object} [options] - { strategy, max_steps, focus_domains }
   * @returns {object} exploration plan
   */
  generatePlan(targetId, options = {}) {
    const strategy = options.strategy || this.strategy;
    const maxSteps = options.max_steps || 20;
    const focusDomains = options.focus_domains || null;

    // Get coverage gaps if coverage engine is available
    let coverageGaps = [];
    if (this.coverageEngine) {
      coverageGaps = this.coverageEngine.getCoverageGaps(targetId);
    }

    // Get frontier
    const frontier = this.frontiers.get(targetId) || [];
    const visitedSet = this.visited.get(targetId) || new Set();

    // Generate steps
    const steps = [];
    const usedUrls = new Set();

    for (const item of frontier) {
      if (steps.length >= maxSteps) break;
      if (usedUrls.has(item.url)) continue;

      // Filter by focus domains
      if (focusDomains) {
        const itemDomain = this._domainForRoute(item.url);
        if (!focusDomains.includes(itemDomain)) continue;
      }

      steps.push({
        action: 'navigate',
        url: item.url,
        priority: item.priority,
        depth: item.depth,
        risk_class: item.risk_class,
        requires_auth: item.requires_auth,
        referrer: item.referrer,
        reason: this._reasonForStep(item, coverageGaps),
      });

      usedUrls.add(item.url);
    }

    const plan = {
      id: `PLAN-${crypto.randomUUID().substring(0, 8)}`,
      target_id: targetId,
      strategy,
      steps,
      total_frontier_size: frontier.length,
      visited_count: visitedSet.size,
      coverage_gaps: coverageGaps,
      generated_at: Date.now(),
    };

    // Record plan
    if (!this.planHistory.has(targetId)) {
      this.planHistory.set(targetId, []);
    }
    this.planHistory.get(targetId).push(plan);

    return plan;
  }

  // ─── State Graph Export ──────────────────────────────────────────

  /**
   * Get the state graph for a target as a serializable object.
   *
   * @param {string} targetId
   * @returns {object|null}
   */
  getStateGraph(targetId) {
    const graph = this.stateGraphs.get(targetId);
    if (!graph) return null;

    return {
      target_id: targetId,
      nodes: [...graph.nodes.values()].map(n => ({
        ...n,
        risk_class: n.risk_class || 'general',
      })),
      edges: graph.edges.map(e => ({
        ...e,
        triggers: [...(e.triggers || [])],
      })),
      stats: {
        total_nodes: graph.nodes.size,
        total_edges: graph.edges.length,
        auth_nodes: [...graph.nodes.values()].filter(n => n.requires_auth).length,
        high_risk_nodes: [...graph.nodes.values()].filter(n => n.risk_class === 'auth' || n.risk_class === 'payment').length,
      },
    };
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  /**
   * Classify a route by its risk category.
   * @param {string} url
   * @returns {string}
   * @private
   */
  _classifyRoute(url) {
    for (const p of AUTH_ROUTE_PATTERNS) {
      if (p.test(url)) return 'auth';
    }
    for (const p of PAYMENT_ROUTE_PATTERNS) {
      if (p.test(url)) return 'payment';
    }
    for (const p of ADMIN_ROUTE_PATTERNS) {
      if (p.test(url)) return 'admin';
    }
    for (const p of USER_ROUTE_PATTERNS) {
      if (p.test(url)) return 'user';
    }
    for (const p of UPLOAD_ROUTE_PATTERNS) {
      if (p.test(url)) return 'upload';
    }
    if (/\/api\/|\/v\d+\//.test(url)) return 'api';
    if (/wss?:\/\//.test(url)) return 'ws';
    return 'general';
  }

  /**
   * Check if a route is an auth-related route.
   * @param {string} url
   * @returns {boolean}
   * @private
   */
  _isAuthRoute(url) {
    return AUTH_ROUTE_PATTERNS.some(p => p.test(url));
  }

  /**
   * Check if a route is a payment-related route.
   * @param {string} url
   * @returns {boolean}
   * @private
   */
  _isPaymentRoute(url) {
    return PAYMENT_ROUTE_PATTERNS.some(p => p.test(url));
  }

  /**
   * Compute the priority score for a frontier item.
   * Higher = more important to explore.
   *
   * @param {string} url
   * @param {object} context
   * @returns {number} 0-100
   * @private
   */
  _computePriority(url, context = {}) {
    const riskClass = context.risk_class || this._classifyRoute(url);
    const riskWeight = ROUTE_RISK_WEIGHTS[riskClass] || 0.3;

    let priority = riskWeight * 60; // 0-60 points from risk

    // Depth bonus: shallower paths get slight bonus (accessibility)
    const depth = context.depth || 0;
    if (depth <= 2) priority += 15;
    else if (depth <= 4) priority += 10;
    else if (depth <= 6) priority += 5;

    // Auth requirement bonus
    if (context.requires_auth || this._isAuthRoute(url)) {
      priority += 15;
    }

    // Historical success bonus
    if (this.kb) {
      const histRate = this.kb.getHistoricalValidationRate(riskClass);
      priority += histRate * 10;
    }

    return Math.round(Math.min(priority, 100));
  }

  /**
   * Find paths from a starting node in the state graph.
   * BFS with depth limit.
   *
   * @param {object} graph
   * @param {string} startUrl
   * @param {number} maxDepth
   * @returns {string[][]}
   * @private
   */
  _findPaths(graph, startUrl, maxDepth) {
    const paths = [];
    const queue = [[startUrl]];
    const visited = new Set();

    while (queue.length > 0 && paths.length < 10) {
      const path = queue.shift();
      const current = path[path.length - 1];

      if (path.length > maxDepth) continue;

      // Only save paths of length > 1
      if (path.length > 1) {
        paths.push([...path]);
      }

      if (visited.has(current)) continue;
      visited.add(current);

      for (const edge of graph.edges) {
        if (edge.from === current) {
          queue.push([...path, edge.to]);
        }
      }
    }

    return paths;
  }

  /**
   * Compute the depth of a path from auth nodes to a given node.
   *
   * @param {object} graph
   * @param {string} url
   * @returns {number}
   * @private
   */
  _pathDepth(graph, url) {
    // BFS backwards from url to find distance from nearest auth node
    const queue = [{ url, depth: 0 }];
    const visited = new Set();

    while (queue.length > 0) {
      const { url: current, depth } = queue.shift();
      if (visited.has(current)) continue;
      visited.add(current);

      if (this._isAuthRoute(current)) {
        return depth;
      }

      for (const edge of graph.edges) {
        if (edge.to === current && !visited.has(edge.from)) {
          queue.push({ url: edge.from, depth: depth + 1 });
        }
      }
    }

    return -1; // no auth path found
  }

  /**
   * Determine the reason for including a step in the plan.
   *
   * @param {object} item - frontier item
   * @param {object[]} coverageGaps
   * @returns {string}
   * @private
   */
  _reasonForStep(item, coverageGaps) {
    if (item.risk_class === 'auth') return 'auth_flow_discovery';
    if (item.risk_class === 'payment') return 'high_value_target';
    if (item.requires_auth) return 'authenticated_path';

    const relevantGap = coverageGaps.find(g =>
      (g.domain === 'api_endpoints' && item.risk_class === 'api') ||
      (g.domain === 'auth_flows' && item.risk_class === 'auth') ||
      (g.domain === 'routes')
    );

    if (relevantGap) return `coverage_gap:${relevantGap.domain}`;
    return 'frontier_exploration';
  }

  /**
   * Map a URL to a coverage domain.
   * @param {string} url
   * @returns {string}
   * @private
   */
  _domainForRoute(url) {
    const riskClass = this._classifyRoute(url);
    switch (riskClass) {
      case 'auth': return 'auth_flows';
      case 'api': return 'api_endpoints';
      case 'ws': return 'websocket_channels';
      default: return 'routes';
    }
  }
}

module.exports = { ExplorationEngine, STRATEGIES };


/**
 * BOQA attack-surface-modeler.js — AttackSurfaceModeler v1.1
 *
 * Converts opportunities and observations into structured system
 * surface graphs. The AttackSurfaceModeler creates a graph representation
 * of target surfaces including endpoints, auth flows, data flows,
 * and their interconnections.
 *
 * Surface graph structure:
 *   - SurfaceNode: individual surface element (endpoint, auth flow,
 *     data flow, cookie, websocket, form, state transition)
 *   - SurfaceEdge: connection between surface elements (data_flow,
 *     auth_dependency, temporal_order, error_path)
 *   - SurfaceGraph: complete graph for a target
 *
 * Capabilities:
 *   - Extract surfaces from KnowledgeBase asset inventories
 *   - Normalize entities across different observation formats
 *   - Compute coverage gaps (untested surface areas)
 *   - Rank surfaces by exploitability and impact potential
 *   - Detect surface changes between sessions
 *   - Feed surface data to HypothesisGenerator for gap analysis
 *
 * Safe mode: surface modeling is purely observational. No attack
 * logic is generated; surfaces are abstract representations.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Constants ──────────────────────────────────────────────────────

const ASM_DIR = path.join(__dirname, 'output', 'knowledge', 'surfaces');

const SURFACE_NODE_TYPES = {
  ENDPOINT:       'endpoint',
  AUTH_FLOW:      'auth_flow',
  DATA_FLOW:      'data_flow',
  COOKIE:         'cookie',
  WEBSOCKET:      'websocket',
  FORM:           'form',
  STATE_TRANSITION: 'state_transition',
  API_ENDPOINT:   'api_endpoint',
  STATIC_RESOURCE: 'static_resource',
};

const SURFACE_EDGE_TYPES = {
  DATA_FLOW:       'data_flow',
  AUTH_DEPENDENCY: 'auth_dependency',
  TEMPORAL_ORDER:  'temporal_order',
  ERROR_PATH:      'error_path',
  REDIRECT:        'redirect',
  EMBEDDED:        'embedded',
};

const DEFAULT_OPTIONS = {
  maxSurfaces:  100,   // max targets tracked
  maxNodesPerSurface: 5000,
  coverageThreshold: 0.7,
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  SurfaceNode
// =====================================================================

class SurfaceNode {
  constructor(data = {}) {
    this.id           = data.id || `SN-${crypto.randomUUID().substring(0, 10)}`;
    this.type         = data.type || SURFACE_NODE_TYPES.ENDPOINT;
    this.target_id    = data.target_id || null;
    this.surface_id   = data.surface_id || null;

    // Endpoint attributes
    this.url          = data.url || null;
    this.method       = data.method || null;
    this.status_code  = data.status_code || null;

    // Auth attributes
    this.auth_required  = data.auth_required ?? null;
    this.auth_type      = data.auth_type || null;
    this.auth_tokens    = data.auth_tokens || [];

    // Data attributes
    this.content_type    = data.content_type || null;
    this.request_params  = data.request_params || [];
    this.response_fields = data.response_fields || [];

    // Risk indicators
    this.exploitability  = data.exploitability ?? null; // 0-1
    this.impact          = data.impact ?? null;          // 0-1
    this.attack_surface_score = data.attack_surface_score ?? null; // 0-100

    // Coverage
    this.tested        = data.tested ?? false;
    this.test_count    = data.test_count || 0;
    this.last_tested   = data.last_tested || null;
    this.finding_count = data.finding_count || 0;

    // Metadata
    this.label         = data.label || '';
    this.tags          = data.tags || [];
    this.created_at    = data.created_at || Date.now();
    this.updated_at    = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  SurfaceEdge
// =====================================================================

class SurfaceEdge {
  constructor(data = {}) {
    this.id         = data.id || `SE-${crypto.randomUUID().substring(0, 10)}`;
    this.source     = data.source;
    this.target     = data.target;
    this.type       = data.type || SURFACE_EDGE_TYPES.DATA_FLOW;
    this.label      = data.label || '';
    this.metadata   = data.metadata || {};
    this.created_at = data.created_at || Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  SurfaceGraph
// =====================================================================

class SurfaceGraph {
  constructor(targetId) {
    this.target_id = targetId;
    this.nodes = new Map();
    this.edges = new Map();
    this.adjacency = new Map();
    this.created_at = Date.now();
    this.updated_at = Date.now();
  }

  addNode(node) {
    this.nodes.set(node.id, node);
    if (!this.adjacency.has(node.id)) this.adjacency.set(node.id, new Set());
    this.updated_at = Date.now();
    return node;
  }

  addEdge(edge) {
    this.edges.set(edge.id, edge);
    if (this.adjacency.has(edge.source)) this.adjacency.get(edge.source).add(edge.id);
    this.updated_at = Date.now();
    return edge;
  }

  getNode(id) { return this.nodes.get(id) || null; }

  getNeighbors(nodeId) {
    const neighborIds = new Set();
    for (const edgeId of (this.adjacency.get(nodeId) || [])) {
      const edge = this.edges.get(edgeId);
      if (edge) {
        neighborIds.add(edge.target);
        neighborIds.add(edge.source);
      }
    }
    neighborIds.delete(nodeId);
    return [...neighborIds].map(id => this.nodes.get(id)).filter(Boolean);
  }

  getUntestedNodes() {
    return [...this.nodes.values()].filter(n => !n.tested);
  }

  getTestedNodes() {
    return [...this.nodes.values()].filter(n => n.tested);
  }

  computeCoverage() {
    const total = this.nodes.size;
    if (total === 0) return 0;
    const tested = this.getTestedNodes().length;
    return Math.round(tested / total * 1000) / 1000;
  }

  toJSON() {
    return {
      target_id: this.target_id,
      node_count: this.nodes.size,
      edge_count: this.edges.size,
      coverage: this.computeCoverage(),
      created_at: this.created_at,
      updated_at: this.updated_at,
    };
  }
}

// =====================================================================
//  AttackSurfaceModeler
// =====================================================================

class AttackSurfaceModeler {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   */
  constructor(options = {}) {
    this.knowledgeBase = options.knowledgeBase || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, SurfaceGraph>} target_id → SurfaceGraph */
    this.surfaces = new Map();

    /** @type {Map<string, object>} target_id → coverage gaps */
    this.coverageGaps = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_surfaces: 0,
      total_nodes: 0,
      total_edges: 0,
      avg_coverage: 0,
      total_gaps: 0,
      surfaces_built: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(ASM_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Surface Construction ──────────────────────────────────────────

  /**
   * Build a surface graph for a target from KnowledgeBase assets.
   *
   * @param {string} targetId
   * @param {object} [assetData] - Optional override asset data
   * @returns {SurfaceGraph}
   */
  buildSurface(targetId, assetData = null) {
    let graph = this.surfaces.get(targetId);
    if (!graph) {
      graph = new SurfaceGraph(targetId);
      this.surfaces.set(targetId, graph);
    }

    // Get assets from KnowledgeBase or provided data
    const assets = assetData || (this.knowledgeBase ? this.knowledgeBase.getAssets(targetId) : null);
    if (!assets) return graph;

    // Extract and normalize endpoint nodes
    if (assets.endpoints) {
      for (const ep of assets.endpoints) {
        this._addEndpointNode(graph, ep, targetId);
      }
    }

    // Extract API endpoints
    if (assets.api_endpoints) {
      for (const api of assets.api_endpoints) {
        this._addEndpointNode(graph, api, targetId);
      }
    }

    // Extract auth flow nodes
    if (assets.auth_flows) {
      for (const flow of assets.auth_flows) {
        this._addAuthFlowNode(graph, flow, targetId);
      }
    }

    // Extract cookie nodes
    if (assets.cookies) {
      for (const cookie of assets.cookies) {
        this._addCookieNode(graph, cookie, targetId);
      }
    }

    // Extract websocket nodes
    if (assets.websockets) {
      for (const ws of assets.websockets) {
        this._addWebsocketNode(graph, ws, targetId);
      }
    }

    // Extract form nodes
    if (assets.forms) {
      for (const form of assets.forms) {
        this._addFormNode(graph, form, targetId);
      }
    }

    // Extract state transitions
    if (assets.state_transitions) {
      for (const st of assets.state_transitions) {
        this._addStateTransitionNode(graph, st, targetId);
      }
    }

    // Auto-connect nodes based on observed relationships
    this._autoConnectNodes(graph, targetId);

    // Compute coverage gaps
    this._computeCoverageGaps(targetId);

    // Update metrics
    this.metrics.surfaces_built++;
    this._updateMetrics();

    return graph;
  }

  /**
   * Build surfaces for all targets in the KnowledgeBase.
   * @returns {SurfaceGraph[]}
   */
  buildAllSurfaces() {
    if (!this.knowledgeBase) return [];

    const graphs = [];
    for (const [targetId] of this.knowledgeBase.assets) {
      graphs.push(this.buildSurface(targetId));
    }
    return graphs;
  }

  // ─── Node Builders ─────────────────────────────────────────────────

  _addEndpointNode(graph, ep, targetId) {
    const normalized = this._normalizeEndpoint(ep);
    const node = new SurfaceNode({
      type: SURFACE_NODE_TYPES.ENDPOINT,
      target_id: targetId,
      url: normalized.url,
      method: normalized.method || 'GET',
      status_code: normalized.status_code || null,
      auth_required: normalized.auth_required ?? null,
      auth_type: normalized.auth_type || null,
      content_type: normalized.content_type || null,
      request_params: normalized.params || [],
      response_fields: normalized.response_fields || [],
      label: `${normalized.method || 'GET'} ${normalized.path || normalized.url}`,
      tags: normalized.tags || [],
      exploitability: this._computeExploitability(normalized),
      impact: this._computeImpact(normalized),
    });

    node.attack_surface_score = this._computeSurfaceScore(node);
    graph.addNode(node);
    return node;
  }

  _addAuthFlowNode(graph, flow, targetId) {
    const node = new SurfaceNode({
      type: SURFACE_NODE_TYPES.AUTH_FLOW,
      target_id: targetId,
      label: flow.name || flow.type || `auth_flow_${flow.id || Date.now()}`,
      auth_required: true,
      auth_type: flow.type || flow.auth_type || 'unknown',
      auth_tokens: flow.tokens || flow.cookies || [],
      tags: ['auth', flow.type || 'unknown'],
      exploitability: flow.type === 'jwt' ? 0.7 : flow.type === 'oauth' ? 0.5 : 0.3,
      impact: 0.8,
    });

    node.attack_surface_score = this._computeSurfaceScore(node);
    graph.addNode(node);
    return node;
  }

  _addCookieNode(graph, cookie, targetId) {
    const node = new SurfaceNode({
      type: SURFACE_NODE_TYPES.COOKIE,
      target_id: targetId,
      label: cookie.name || `cookie_${Date.now()}`,
      auth_type: cookie.httpOnly ? 'http_only' : cookie.secure ? 'secure' : 'plain',
      auth_tokens: [cookie.name],
      tags: ['cookie', cookie.httpOnly ? 'httponly' : '', cookie.secure ? 'secure' : '', cookie.sameSite || ''].filter(Boolean),
      exploitability: (!cookie.httpOnly && !cookie.secure) ? 0.8 : 0.3,
      impact: cookie.httpOnly ? 0.3 : 0.7,
    });

    node.attack_surface_score = this._computeSurfaceScore(node);
    graph.addNode(node);
    return node;
  }

  _addWebsocketNode(graph, ws, targetId) {
    const node = new SurfaceNode({
      type: SURFACE_NODE_TYPES.WEBSOCKET,
      target_id: targetId,
      url: ws.url || ws.endpoint || null,
      label: ws.url || `ws_${Date.now()}`,
      auth_required: ws.auth_required ?? null,
      tags: ['websocket'],
      exploitability: 0.6,
      impact: 0.5,
    });

    node.attack_surface_score = this._computeSurfaceScore(node);
    graph.addNode(node);
    return node;
  }

  _addFormNode(graph, form, targetId) {
    const node = new SurfaceNode({
      type: SURFACE_NODE_TYPES.FORM,
      target_id: targetId,
      url: form.action || form.url || null,
      method: form.method || 'POST',
      label: form.name || form.id || `form_${Date.now()}`,
      request_params: form.fields || form.inputs || [],
      tags: ['form', form.method || 'POST'],
      exploitability: (form.method || '').toUpperCase() === 'POST' ? 0.6 : 0.3,
      impact: 0.5,
    });

    node.attack_surface_score = this._computeSurfaceScore(node);
    graph.addNode(node);
    return node;
  }

  _addStateTransitionNode(graph, st, targetId) {
    const node = new SurfaceNode({
      type: SURFACE_NODE_TYPES.STATE_TRANSITION,
      target_id: targetId,
      label: st.name || `transition_${st.from || ''}_${st.to || ''}`,
      tags: ['state_transition'],
      exploitability: 0.4,
      impact: 0.6,
    });

    node.attack_surface_score = this._computeSurfaceScore(node);
    graph.addNode(node);
    return node;
  }

  // ─── Auto-Connection ──────────────────────────────────────────────

  _autoConnectNodes(graph, targetId) {
    const nodes = [...graph.nodes.values()];

    // Connect auth flows to their dependent endpoints
    const authNodes = nodes.filter(n => n.type === SURFACE_NODE_TYPES.AUTH_FLOW);
    const endpointNodes = nodes.filter(n => n.type === SURFACE_NODE_TYPES.ENDPOINT);

    for (const authNode of authNodes) {
      for (const ep of endpointNodes) {
        if (ep.auth_required) {
          graph.addEdge(new SurfaceEdge({
            source: authNode.id,
            target: ep.id,
            type: SURFACE_EDGE_TYPES.AUTH_DEPENDENCY,
            label: `${authNode.label} → ${ep.label}`,
          }));
        }
      }
    }

    // Connect cookies to endpoints on same domain
    const cookieNodes = nodes.filter(n => n.type === SURFACE_NODE_TYPES.COOKIE);
    for (const cookieNode of cookieNodes) {
      for (const ep of endpointNodes) {
        if (ep.auth_required || ep.method === 'POST') {
          graph.addEdge(new SurfaceEdge({
            source: cookieNode.id,
            target: ep.id,
            type: SURFACE_EDGE_TYPES.AUTH_DEPENDENCY,
            label: `cookie:${cookieNode.label} → ${ep.label}`,
          }));
        }
      }
    }

    // Connect forms to their target endpoints
    const formNodes = nodes.filter(n => n.type === SURFACE_NODE_TYPES.FORM);
    for (const formNode of formNodes) {
      if (formNode.url) {
        const matching = endpointNodes.find(ep => ep.url === formNode.url);
        if (matching) {
          graph.addEdge(new SurfaceEdge({
            source: formNode.id,
            target: matching.id,
            type: SURFACE_EDGE_TYPES.DATA_FLOW,
            label: `form:${formNode.label} → ${matching.label}`,
          }));
        }
      }
    }
  }

  // ─── Coverage Gaps ─────────────────────────────────────────────────

  /**
   * Get coverage gaps for a target.
   * Gaps are untested surface areas ranked by exploitability and impact.
   *
   * @param {string} targetId
   * @returns {object[]}
   */
  getCoverageGaps(targetId) {
    return this.coverageGaps.get(targetId) || [];
  }

  _computeCoverageGaps(targetId) {
    const graph = this.surfaces.get(targetId);
    if (!graph) return;

    const untested = graph.getUntestedNodes();
    const gaps = [];

    for (const node of untested) {
      const gap = {
        node_id: node.id,
        area: node.label || node.url || node.type,
        surface_id: node.surface_id,
        type: node.type,
        endpoint: node.url || null,
        reason: this._gapReason(node),
        endpoint_count: 1,
        exploitability: node.exploitability || 0,
        impact: node.impact || 0,
        priority_score: (node.attack_surface_score || 50) * (1 - graph.computeCoverage()),
      };

      gaps.push(gap);
    }

    gaps.sort((a, b) => b.priority_score - a.priority_score);
    this.coverageGaps.set(targetId, gaps);
    this.metrics.total_gaps = gaps.length;
  }

  _gapReason(node) {
    if (node.type === SURFACE_NODE_TYPES.AUTH_FLOW) return 'auth flow untested';
    if (node.type === SURFACE_NODE_TYPES.COOKIE && !node.auth_required) return 'non-httponly cookie untested';
    if (node.type === SURFACE_NODE_TYPES.WEBSOCKET) return 'websocket untested';
    if (node.type === SURFACE_NODE_TYPES.FORM && node.method === 'POST') return 'POST form untested';
    if (node.auth_required) return 'authenticated endpoint untested';
    return 'untested surface area';
  }

  // ─── Surface Scoring ──────────────────────────────────────────────

  _computeSurfaceScore(node) {
    let score = 50; // base

    // Exploitability boost
    if (node.exploitability) score += node.exploitability * 20;

    // Impact boost
    if (node.impact) score += node.impact * 15;

    // Auth-required surfaces are more interesting
    if (node.auth_required) score += 10;

    // POST/PUT methods more interesting than GET
    if (node.method === 'POST' || node.method === 'PUT') score += 5;

    // Untested = more potential
    if (!node.tested) score += 5;

    return Math.round(Math.min(100, Math.max(0, score)));
  }

  _computeExploitability(ep) {
    let score = 0.3;
    if (ep.method === 'POST' || ep.method === 'PUT') score += 0.2;
    if (ep.auth_required) score += 0.1;
    if (ep.params && ep.params.length > 0) score += 0.1;
    if (ep.auth_type === 'jwt') score += 0.2;
    return Math.min(1, score);
  }

  _computeImpact(ep) {
    let score = 0.3;
    if (ep.auth_required) score += 0.2;
    if (ep.response_fields && ep.response_fields.length > 3) score += 0.2;
    if (ep.auth_type === 'session') score += 0.1;
    return Math.min(1, score);
  }

  // ─── Entity Normalization ──────────────────────────────────────────

  _normalizeEndpoint(ep) {
    let url = ep.url || ep.endpoint || ep.path || '';
    let urlPath = '';

    try {
      const parsed = new URL(url, 'https://placeholder.com');
      urlPath = parsed.pathname;
    } catch (_) {
      urlPath = url;
    }

    return {
      url,
      path: urlPath,
      method: (ep.method || 'GET').toUpperCase(),
      status_code: ep.status || ep.status_code || null,
      auth_required: ep.auth_required ?? ep.auth ?? null,
      auth_type: ep.auth_type || ep.authentication_type || null,
      content_type: ep.content_type || ep.contentType || null,
      params: ep.params || ep.parameters || ep.query || [],
      response_fields: ep.response_fields || ep.responseFields || [],
      tags: ep.tags || [],
    };
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getSurface(targetId) {
    return this.surfaces.get(targetId) || null;
  }

  getSurfaceDetails(targetId) {
    const graph = this.surfaces.get(targetId);
    if (!graph) return null;
    return {
      target_id: targetId,
      node_count: graph.nodes.size,
      edge_count: graph.edges.size,
      coverage: graph.computeCoverage(),
      tested_count: graph.getTestedNodes().length,
      untested_count: graph.getUntestedNodes().length,
      nodes_by_type: this._countByType(graph),
      coverage_gaps: this.getCoverageGaps(targetId),
      created_at: graph.created_at,
      updated_at: graph.updated_at,
    };
  }

  _countByType(graph) {
    const counts = {};
    for (const [, node] of graph.nodes) {
      counts[node.type] = (counts[node.type] || 0) + 1;
    }
    return counts;
  }

  /**
   * Update a surface node's test status.
   * @param {string} targetId
   * @param {string} nodeId
   * @param {object} [data] - { tested, finding_count }
   */
  updateNodeStatus(targetId, nodeId, data = {}) {
    const graph = this.surfaces.get(targetId);
    if (!graph) return null;

    const node = graph.getNode(nodeId);
    if (!node) return null;

    if (data.tested !== undefined) node.tested = data.tested;
    if (data.finding_count !== undefined) node.finding_count = data.finding_count;
    node.last_tested = Date.now();
    node.updated_at = Date.now();

    this._computeCoverageGaps(targetId);
    this._updateMetrics();

    return node;
  }

  getMetrics() {
    return { ...this.metrics };
  }

  _updateMetrics() {
    this.metrics.total_surfaces = this.surfaces.size;
    let totalNodes = 0, totalEdges = 0, totalCoverage = 0;
    for (const [, graph] of this.surfaces) {
      totalNodes += graph.nodes.size;
      totalEdges += graph.edges.size;
      totalCoverage += graph.computeCoverage();
    }
    this.metrics.total_nodes = totalNodes;
    this.metrics.total_edges = totalEdges;
    this.metrics.avg_coverage = this.surfaces.size > 0
      ? Math.round(totalCoverage / this.surfaces.size * 1000) / 1000
      : 0;
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(ASM_DIR, 'surfaces-state.json');
    const surfacesData = [];
    for (const [targetId, graph] of this.surfaces) {
      surfacesData.push({
        target_id: targetId,
        nodes: [...graph.nodes.entries()],
        edges: [...graph.edges.entries()],
        created_at: graph.created_at,
        updated_at: graph.updated_at,
      });
    }

    const data = {
      version: '1.1',
      saved_at: Date.now(),
      surfaces: surfacesData.slice(-this.options.maxSurfaces),
      coverage_gaps: [...this.coverageGaps.entries()],
      metrics: this.metrics,
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(ASM_DIR, 'surfaces-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      if (data.surfaces) {
        for (const surfaceData of data.surfaces) {
          const graph = new SurfaceGraph(surfaceData.target_id);
          if (surfaceData.nodes) {
            graph.nodes = new Map(surfaceData.nodes.map(([k, v]) => [k, new SurfaceNode(v)]));
          }
          if (surfaceData.edges) {
            graph.edges = new Map(surfaceData.edges.map(([k, v]) => [k, new SurfaceEdge(v)]));
          }
          graph.created_at = surfaceData.created_at || Date.now();
          graph.updated_at = surfaceData.updated_at || Date.now();

          // Rebuild adjacency
          for (const [id] of graph.nodes) {
            graph.adjacency.set(id, new Set());
          }
          for (const [, edge] of graph.edges) {
            if (graph.adjacency.has(edge.source)) graph.adjacency.get(edge.source).add(edge.id);
          }

          this.surfaces.set(surfaceData.target_id, graph);
        }
      }

      if (data.coverage_gaps) {
        this.coverageGaps = new Map(data.coverage_gaps);
      }

      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.surfaces.clear();
    this.coverageGaps.clear();
    this.metrics = {
      total_surfaces: 0, total_nodes: 0, total_edges: 0,
      avg_coverage: 0, total_gaps: 0, surfaces_built: 0,
    };
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  AttackSurfaceModeler,
  SurfaceGraph,
  SurfaceNode,
  SurfaceEdge,
  SURFACE_NODE_TYPES,
  SURFACE_EDGE_TYPES,
};


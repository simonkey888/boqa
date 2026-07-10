/**
 * BOQA knowledge-graph-integration.js — Knowledge Graph Integration (S6-7)
 *
 * Persists discovered bugs as relationships in the existing MemoryGraph
 * and KnowledgeBase instead of isolated findings. Creates a connected
 * graph where bugs are linked to:
 *
 *   - Page (where the bug was found)
 *   - Endpoint (which API was involved)
 *   - Cookie (auth cookies related to the bug)
 *   - Storage (localStorage/sessionStorage involved)
 *   - Authentication (auth state at bug time)
 *   - DOM (DOM state associated with the bug)
 *   - Network (network requests/responses)
 *   - Replay (replay recording and manifest)
 *   - Verification (verification result)
 *
 * This transforms flat bug lists into a queryable knowledge graph
 * that supports:
 *   - Cross-target pattern recognition
 *   - Temporal correlation (same bug across versions)
 *   - Root cause analysis (shared auth, shared endpoint)
 *   - Impact analysis (bugs affecting auth flow)
 */

const crypto = require('crypto');

// ─── Relationship Types ──────────────────────────────────────────────

const RELATIONSHIP_TYPES = {
  FOUND_ON_PAGE: 'found_on_page',
  INVOLVES_ENDPOINT: 'involves_endpoint',
  INVOLVES_COOKIE: 'involves_cookie',
  INVOLVES_STORAGE: 'involves_storage',
  INVOLVES_AUTH: 'involves_auth',
  AFFECTS_DOM: 'affects_dom',
  TRIGGERED_NETWORK: 'triggered_network',
  CONFIRMED_BY_REPLAY: 'confirmed_by_replay',
  VERIFIED_BY: 'verified_by',
  RELATED_TO_BUG: 'related_to_bug',
  SAME_ROOT_CAUSE: 'same_root_cause',
  REGRESSION_OF: 'regression_of',
  FIXED_BY: 'fixed_by',
};

// ─── Node Types ──────────────────────────────────────────────────────

const NODE_TYPES = {
  BUG: 'bug',
  PAGE: 'page',
  ENDPOINT: 'endpoint',
  COOKIE: 'cookie',
  STORAGE: 'storage',
  AUTH: 'auth',
  DOM: 'dom',
  NETWORK: 'network',
  REPLAY: 'replay',
  VERIFICATION: 'verification',
  TARGET: 'target',
  SESSION: 'session',
};

class KnowledgeGraphIntegration {
  /**
   * @param {object} opts
   * @param {object} opts.knowledgeBase - KnowledgeBase instance
   * @param {object} opts.memoryGraph   - MemoryGraph instance
   */
  constructor(opts = {}) {
    this.knowledgeBase = opts.knowledgeBase || null;
    this.memoryGraph = opts.memoryGraph || null;

    this._nodes = new Map();
    this._edges = [];
    this._stats = {
      total_persisted: 0,
      total_nodes: 0,
      total_edges: 0,
      by_node_type: {},
      by_relationship_type: {},
      cross_target_patterns: 0,
    };
  }

  /**
   * Persist all findings from a completed target execution as a
   * connected subgraph in the knowledge graph.
   *
   * @param {object} execution - Completed TargetRunner execution
   * @returns {object} Summary of persisted relationships
   */
  persistFindings(execution) {
    const result = {
      execution_id: execution.id,
      target: execution.target_url,
      bugs_persisted: 0,
      nodes_created: 0,
      edges_created: 0,
    };

    // Create target node
    const targetNode = this._createNode(NODE_TYPES.TARGET, execution.target_url, {
      url: execution.target_url,
      name: execution.target_name,
      execution_time_ms: execution.execution_time_ms,
    });
    result.nodes_created++;

    // Create session node
    const sessionNode = this._createNode(NODE_TYPES.SESSION, execution.id, {
      execution_id: execution.id,
      submitted_at: execution.submitted_at,
      completed_at: execution.completed_at,
      state: execution.state,
    });
    result.nodes_created++;

    // Link session to target
    this._createEdge(sessionNode.id, targetNode.id, RELATIONSHIP_TYPES.FOUND_ON_PAGE);
    result.edges_created++;

    // Persist each confirmed bug
    for (const bug of execution.confirmed_bugs) {
      const bugResult = this._persistBug(bug, targetNode, sessionNode);
      result.bugs_persisted++;
      result.nodes_created += bugResult.nodes_created;
      result.edges_created += bugResult.edges_created;
    }

    // Persist false positives (lower detail, for pattern learning)
    for (const fp of execution.false_positives) {
      this._persistFalsePositive(fp, targetNode);
    }

    // Sync with existing knowledge infrastructure
    this._syncToKnowledgeBase(execution);
    this._syncToMemoryGraph(execution);

    // Detect cross-target patterns
    this._detectCrossTargetPatterns();

    this._stats.total_persisted += result.bugs_persisted;

    return result;
  }

  /**
   * Persist a single confirmed bug as a connected subgraph.
   */
  _persistBug(bug, targetNode, sessionNode) {
    const result = { nodes_created: 0, edges_created: 0 };

    // Bug node
    const bugNode = this._createNode(NODE_TYPES.BUG, bug.id, {
      category: bug.category,
      confidence_score: bug.confidence_score,
      confidence_level: bug.confidence_level,
      reasoning: bug.reasoning,
      detected_at: bug.detected_at,
      url: bug.url,
    });
    result.nodes_created++;

    // Link bug to session and target
    this._createEdge(bugNode.id, sessionNode.id, RELATIONSHIP_TYPES.FOUND_ON_PAGE);
    result.edges_created++;
    this._createEdge(bugNode.id, targetNode.id, RELATIONSHIP_TYPES.FOUND_ON_PAGE);
    result.edges_created++;

    // Extract and link related entities from bug evidence
    if (bug.evidence) {
      // Endpoint involvement
      if (bug.evidence.urls || bug.url) {
        const urls = bug.evidence.urls || [bug.url];
        for (const url of urls.slice(0, 5)) {
          if (url && url.startsWith('http')) {
            const endpointNode = this._createNode(NODE_TYPES.ENDPOINT, url, {
              url,
              method: 'unknown',
              status: bug.evidence.status_codes?.[0] || null,
            });
            this._createEdge(bugNode.id, endpointNode.id, RELATIONSHIP_TYPES.INVOLVES_ENDPOINT);
            result.nodes_created++;
            result.edges_created++;
          }
        }
      }

      // Cookie involvement
      if (bug.evidence.cookie_name || bug.category === 'cookie_anomaly') {
        const cookieName = bug.evidence.cookie_name || 'unknown';
        const cookieNode = this._createNode(NODE_TYPES.COOKIE, `cookie:${cookieName}`, {
          name: cookieName,
          missing_attribute: bug.evidence.missing_attribute || null,
        });
        this._createEdge(bugNode.id, cookieNode.id, RELATIONSHIP_TYPES.INVOLVES_COOKIE);
        result.nodes_created++;
        result.edges_created++;
      }

      // Auth involvement
      if (bug.category === 'auth_inconsistency' || bug.evidence.auth_signal_type) {
        const authNode = this._createNode(NODE_TYPES.AUTH, `auth:${bug.context_hash}`, {
          signal_type: bug.evidence.auth_signal_type || 'unknown',
          status: bug.evidence.status || null,
        });
        this._createEdge(bugNode.id, authNode.id, RELATIONSHIP_TYPES.INVOLVES_AUTH);
        result.nodes_created++;
        result.edges_created++;
      }

      // Network involvement
      if (bug.category === 'http_failure' || bug.category === 'unexpected_redirect') {
        const networkNode = this._createNode(NODE_TYPES.NETWORK, `network:${bug.context_hash}`, {
          status_codes: bug.evidence.status_codes || [],
          count: bug.evidence.count || 1,
        });
        this._createEdge(bugNode.id, networkNode.id, RELATIONSHIP_TYPES.TRIGGERED_NETWORK);
        result.nodes_created++;
        result.edges_created++;
      }
    }

    // Replay confirmation link
    if (bug._confirmation) {
      const replayNode = this._createNode(NODE_TYPES.REPLAY, `replay:${bug._confirmation.id}`, {
        confirmation_id: bug._confirmation.id,
        score: bug._confirmation.final_score,
        verdict: bug._confirmation.final_verdict,
        attempts: bug._confirmation.attempts,
      });
      this._createEdge(bugNode.id, replayNode.id, RELATIONSHIP_TYPES.CONFIRMED_BY_REPLAY);
      result.nodes_created++;
      result.edges_created++;
    }

    // Verification link
    if (bug._validationScore !== undefined) {
      const verificationNode = this._createNode(NODE_TYPES.VERIFICATION, `verify:${bug.id}`, {
        score: bug._validationScore,
      });
      this._createEdge(bugNode.id, verificationNode.id, RELATIONSHIP_TYPES.VERIFIED_BY);
      result.nodes_created++;
      result.edges_created++;
    }

    // Find related bugs (same category, same target)
    this._linkRelatedBugs(bugNode, bug);

    return result;
  }

  /**
   * Persist a false positive as a lightweight node for pattern learning.
   */
  _persistFalsePositive(fp, targetNode) {
    const fpNode = this._createNode(NODE_TYPES.BUG, `fp:${fp.id}`, {
      category: fp.category,
      false_positive: true,
      fp_reason: fp.fp_reason || 'unknown',
    });
    this._createEdge(fpNode.id, targetNode.id, RELATIONSHIP_TYPES.FOUND_ON_PAGE);
  }

  /**
   * Link related bugs by category and root cause.
   */
  _linkRelatedBugs(bugNode, bug) {
    const existingBugs = [...this._nodes.values()].filter(
      n => n.type === NODE_TYPES.BUG && n.id !== bugNode.id && !n.id.startsWith('fp:')
    );

    for (const existing of existingBugs) {
      // Same category on different targets → related
      if (existing.data.category === bug.category && existing.data.url !== bug.url) {
        this._createEdge(bugNode.id, existing.id, RELATIONSHIP_TYPES.RELATED_TO_BUG);
        this._stats.cross_target_patterns++;
      }

      // Same context hash → same root cause
      if (bug.context_hash && existing.data.context_hash === bug.context_hash) {
        this._createEdge(bugNode.id, existing.id, RELATIONSHIP_TYPES.SAME_ROOT_CAUSE);
      }
    }
  }

  /**
   * Sync findings to the existing KnowledgeBase.
   */
  _syncToKnowledgeBase(execution) {
    if (!this.knowledgeBase) return;

    for (const bug of execution.confirmed_bugs) {
      try {
        // Add as a finding node in KnowledgeBase
        if (typeof this.knowledgeBase.addReplayNode === 'function') {
          this.knowledgeBase.addReplayNode({
            replay_id: `bug-${bug.id}`,
            bug_id: bug.id,
            category: bug.category,
            confidence: bug.confidence_score,
            target: execution.target_url,
          });
        }
      } catch (_) {}
    }
  }

  /**
   * Sync findings to the existing MemoryGraph.
   */
  _syncToMemoryGraph(execution) {
    if (!this.memoryGraph) return;

    for (const bug of execution.confirmed_bugs) {
      try {
        // Add bug as a node in MemoryGraph
        this.memoryGraph.addNode(`bug:${bug.id}`, {
          type: 'bug_finding',
          category: bug.category,
          confidence: bug.confidence_score,
          target: execution.target_url,
          detected_at: bug.detected_at,
        });

        // Add edges to target
        this.memoryGraph.addEdge(`bug:${bug.id}`, `target:${execution.target_url}`, {
          type: 'found_on',
          weight: bug.confidence_score || 50,
        });
      } catch (_) {}
    }
  }

  /**
   * Detect cross-target patterns (same bug category appearing across targets).
   */
  _detectCrossTargetPatterns() {
    const bugsByCategory = {};
    for (const node of this._nodes.values()) {
      if (node.type === NODE_TYPES.BUG && !node.id.startsWith('fp:')) {
        const cat = node.data.category;
        bugsByCategory[cat] = bugsByCategory[cat] || [];
        bugsByCategory[cat].push(node);
      }
    }

    for (const [category, nodes] of Object.entries(bugsByCategory)) {
      if (nodes.length > 1) {
        const targets = new Set(nodes.map(n => n.data.url || n.data.target));
        if (targets.size > 1) {
          // Cross-target pattern detected
          this._stats.cross_target_patterns++;
        }
      }
    }
  }

  /**
   * Query the knowledge graph for bugs matching criteria.
   */
  query(filters) {
    let nodes = [...this._nodes.values()];

    if (filters.type) nodes = nodes.filter(n => n.type === filters.type);
    if (filters.category) nodes = nodes.filter(n => n.data.category === filters.category);
    if (filters.minConfidence) nodes = nodes.filter(n => (n.data.confidence_score || 0) >= filters.minConfidence);
    if (filters.target) nodes = nodes.filter(n =>
      n.data.url === filters.target || n.data.target === filters.target
    );

    // Get edges for matching nodes
    const nodeIds = new Set(nodes.map(n => n.id));
    const edges = this._edges.filter(e => nodeIds.has(e.source) || nodeIds.has(e.target));

    return { nodes, edges, total_nodes: nodes.length, total_edges: edges.length };
  }

  /**
   * Get the full graph.
   */
  getGraph() {
    return {
      nodes: [...this._nodes.values()],
      edges: [...this._edges],
      stats: this.getStats(),
    };
  }

  // ─── Node/Edge Creation ───────────────────────────────────────────

  _createNode(type, id, data) {
    const nodeId = id || crypto.randomUUID();
    const node = {
      id: nodeId,
      type,
      data: data || {},
      created_at: Date.now(),
    };

    // Avoid duplicates
    if (this._nodes.has(nodeId)) {
      return this._nodes.get(nodeId);
    }

    this._nodes.set(nodeId, node);
    this._stats.total_nodes++;
    this._stats.by_node_type[type] = (this._stats.by_node_type[type] || 0) + 1;

    // Also add to MemoryGraph if available
    if (this.memoryGraph && typeof this.memoryGraph.addNode === 'function') {
      try {
        this.memoryGraph.addNode(nodeId, { type, ...data });
      } catch (_) {}
    }

    return node;
  }

  _createEdge(source, target, type, meta) {
    const edge = {
      id: crypto.randomUUID(),
      source,
      target,
      type,
      meta: meta || {},
      created_at: Date.now(),
    };

    this._edges.push(edge);
    this._stats.total_edges++;
    this._stats.by_relationship_type[type] = (this._stats.by_relationship_type[type] || 0) + 1;

    return edge;
  }

  /**
   * Get integration statistics.
   */
  getStats() {
    return { ...this._stats };
  }

  /**
   * Reset all state.
   */
  reset() {
    this._nodes.clear();
    this._edges = [];
    this._stats = {
      total_persisted: 0, total_nodes: 0, total_edges: 0,
      by_node_type: {}, by_relationship_type: {}, cross_target_patterns: 0,
    };
  }
}

module.exports = { KnowledgeGraphIntegration, RELATIONSHIP_TYPES, NODE_TYPES };


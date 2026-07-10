/**
 * BOQA memory-graph.js — MemoryGraph v1.1
 *
 * Cross-session persistent learning layer implemented as a weighted
 * directed graph. Nodes represent findings, hypotheses, and patterns;
 * edges represent similarity, regression, causality, and temporal
 * relationships.
 *
 * Core capabilities:
 *   - Store findings as graph nodes with rich metadata
 *   - Link nodes via weighted directed edges (similarity, regression,
 *     causality, temporal)
 *   - Detect repeated failure patterns across opportunities and targets
 *   - Retrieve similar historical findings for hypothesis generation
 *   - Cluster findings by category, surface, or pattern
 *   - Decay edge weights over time (recency bias)
 *   - Persist entire graph to disk for cross-session continuity
 *
 * Safe mode: all data is observational; no execution logic stored.
 * The graph is a read-only knowledge structure used by the
 * DiscoveryLoopEngine for hypothesis generation and calibration.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── STRUCT-4: Collision-free ID generation ──────────────────────────
// Replaces timestamp-based IDs with content-signature + SHA-256 hashes
// to prevent collisions in high-concurrency scenarios.

function generateCollisionFreeId(nodeData) {
  const signature = `${nodeData.type}:${nodeData.target_id || 'global'}:${nodeData.label}:${Date.now()}`;
  return 'node-' + crypto.createHash('sha256').update(signature).digest('hex').substring(0, 16);
}

// ─── Persistence ────────────────────────────────────────────────────

const MG_DIR = path.join(__dirname, 'output', 'knowledge', 'memory-graph');

// ─── Constants ──────────────────────────────────────────────────────

const EDGE_TYPES = {
  SIMILARITY:  'similarity',   // two findings share characteristics
  REGRESSION:  'regression',   // finding B regresses from finding A
  CAUSALITY:   'causality',    // finding A likely causes finding B
  TEMPORAL:    'temporal',     // finding B occurred after finding A
  PATTERN:     'pattern',      // both findings match same pattern cluster
  COVERAGE:    'coverage',     // both findings relate to same surface area
};

const NODE_TYPES = {
  FINDING:      'finding',
  HYPOTHESIS:   'hypothesis',
  PATTERN:      'pattern',
  ANOMALY:      'anomaly',
  FAILURE:      'failure',
  SURFACE:      'surface',
};

const DEFAULT_OPTIONS = {
  maxNodes:           50000,
  maxEdges:           200000,
  decayFactor:        0.95,     // per-cycle weight decay
  decayIntervalMs:    3600000,  // 1 hour
  similarityThreshold: 0.3,
  persistenceIntervalMs: 300000, // 5 minutes
};

// =====================================================================
//  GraphNode
// =====================================================================

class GraphNode {
  constructor(data = {}) {
    this.id           = data.id || `GN-${crypto.randomUUID().substring(0, 10)}`;
    this.type         = data.type || NODE_TYPES.FINDING;
    this.label        = data.label || '';
    this.category     = data.category || null;
    this.target_id    = data.target_id || null;
    this.surface_id   = data.surface_id || null;

    // Core attributes
    this.severity     = data.severity || null;
    this.confidence   = data.confidence ?? null;
    this.evi_score    = data.evi_score ?? null;
    this.cevi_score   = data.cevi_score ?? null;
    this.verdict      = data.verdict || null; // confirmed, rejected, inconclusive

    // Pattern attributes
    this.pattern_hash = data.pattern_hash || null;
    this.features     = data.features || {};   // normalized feature vector
    this.tags         = data.tags || [];

    // Temporal
    this.created_at   = data.created_at || Date.now();
    this.updated_at   = Date.now();
    this.last_seen_at = data.last_seen_at || Date.now();
    this.occurrence_count = data.occurrence_count || 1;

    // Source reference
    this.source_id    = data.source_id || null;
    this.source_type  = data.source_type || null;
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  GraphEdge
// =====================================================================

class GraphEdge {
  constructor(data = {}) {
    this.id           = data.id || `GE-${crypto.randomUUID().substring(0, 10)}`;
    this.source       = data.source;  // node id (from)
    this.target       = data.target;  // node id (to)
    this.type         = data.type || EDGE_TYPES.SIMILARITY;
    this.weight       = data.weight ?? 1.0;
    this.label        = data.label || '';
    this.metadata     = data.metadata || {};
    this.created_at   = data.created_at || Date.now();
    this.updated_at   = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  MemoryGraph
// =====================================================================

class MemoryGraph {
  /**
   * @param {object} [options]
   * @param {number} [options.maxNodes] - Maximum nodes stored
   * @param {number} [options.maxEdges] - Maximum edges stored
   * @param {number} [options.decayFactor] - Edge weight decay per cycle
   * @param {number} [options.decayIntervalMs] - Decay cycle interval
   * @param {number} [options.similarityThreshold] - Min similarity to create edge
   * @param {number} [options.persistenceIntervalMs] - Auto-save interval
   */
  constructor(options = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, GraphNode>} */
    this.nodes = new Map();

    /** @type {Map<string, GraphEdge>} */
    this.edges = new Map();

    /** @type {Map<string, Set<string>>} adjacency: nodeId → Set<edgeId> */
    this.adjacency = new Map();

    /** @type {Map<string, Set<string>>} reverse adjacency: nodeId → Set<edgeId> */
    this.reverseAdjacency = new Map();

    /** @type {Map<string, number>} pattern_hash → occurrence count */
    this.patternIndex = new Map();

    /** @type {Map<string, Set<string>>} category → Set<nodeId> */
    this.categoryIndex = new Map();

    /** @type {Map<string, Set<string>>} target_id → Set<nodeId> */
    this.targetIndex = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_nodes: 0,
      total_edges: 0,
      total_patterns: 0,
      avg_degree: 0,
      cluster_count: 0,
      cross_target_edges: 0,
      decay_cycles: 0,
      persistence_saves: 0,
    };

    // ── Decay timer ──────────────────────────────────────────
    this._decayTimer = null;
    this._persistTimer = null;

    fs.mkdirSync(MG_DIR, { recursive: true });
    this.load();

    if (this.options.decayIntervalMs > 0) {
      this._decayTimer = setInterval(() => this._decayEdges(), this.options.decayIntervalMs);
    }
    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Node Operations ──────────────────────────────────────────────

  /**
   * Add or update a node in the graph.
   * If a node with the same source_id exists, it is updated (occurrence_count incremented).
   *
   * @param {object} data - Node data
   * @returns {GraphNode}
   */
  addNode(data) {
    // Check for existing node with same source_id
    if (data.source_id) {
      for (const [, existing] of this.nodes) {
        if (existing.source_id === data.source_id && existing.source_type === data.source_type) {
          // Update existing node
          existing.occurrence_count++;
          existing.last_seen_at = Date.now();
          existing.updated_at = Date.now();
          if (data.severity) existing.severity = data.severity;
          if (data.confidence !== undefined) existing.confidence = data.confidence;
          if (data.verdict) existing.verdict = data.verdict;
          if (data.features) existing.features = { ...existing.features, ...data.features };
          if (data.tags) existing.tags = [...new Set([...existing.tags, ...data.tags])];
          return existing;
        }
      }
    }

    const node = new GraphNode(data);
    this.nodes.set(node.id, node);

    // Update indexes
    if (node.pattern_hash) {
      this.patternIndex.set(node.pattern_hash, (this.patternIndex.get(node.pattern_hash) || 0) + 1);
    }
    if (node.category) {
      if (!this.categoryIndex.has(node.category)) this.categoryIndex.set(node.category, new Set());
      this.categoryIndex.get(node.category).add(node.id);
    }
    if (node.target_id) {
      if (!this.targetIndex.has(node.target_id)) this.targetIndex.set(node.target_id, new Set());
      this.targetIndex.get(node.target_id).add(node.id);
    }

    // Initialize adjacency entries
    if (!this.adjacency.has(node.id)) this.adjacency.set(node.id, new Set());
    if (!this.reverseAdjacency.has(node.id)) this.reverseAdjacency.set(node.id, new Set());

    this.metrics.total_nodes = this.nodes.size;

    // Cap nodes
    if (this.nodes.size > this.options.maxNodes) {
      this._evictOldestNodes(this.nodes.size - this.options.maxNodes);
    }

    return node;
  }

  /**
   * Get a node by ID.
   * @param {string} nodeId
   * @returns {GraphNode|null}
   */
  getNode(nodeId) {
    return this.nodes.get(nodeId) || null;
  }

  /**
   * Query nodes by filter.
   * @param {object} [filter] - { type, category, target_id, min_confidence, min_severity, tags, limit }
   * @returns {GraphNode[]}
   */
  queryNodes(filter = {}) {
    let results = [...this.nodes.values()];

    if (filter.type) results = results.filter(n => n.type === filter.type);
    if (filter.category) results = results.filter(n => n.category === filter.category);
    if (filter.target_id) results = results.filter(n => n.target_id === filter.target_id);
    if (filter.min_confidence !== undefined) results = results.filter(n => n.confidence >= filter.min_confidence);
    if (filter.min_severity !== undefined) results = results.filter(n => (n.severity || 0) >= filter.min_severity);
    if (filter.tags && filter.tags.length > 0) {
      results = results.filter(n => filter.tags.some(t => n.tags.includes(t)));
    }
    if (filter.verdict) results = results.filter(n => n.verdict === filter.verdict);

    // Sort by recency and confidence
    results.sort((a, b) => {
      const scoreA = (a.confidence || 0) * 0.6 + (a.occurrence_count || 1) * 0.4;
      const scoreB = (b.confidence || 0) * 0.6 + (b.occurrence_count || 1) * 0.4;
      return scoreB - scoreA;
    });

    return results.slice(0, filter.limit || results.length);
  }

  // ─── Edge Operations ──────────────────────────────────────────────

  /**
   * Add or update an edge between two nodes.
   *
   * @param {string} sourceId - Source node ID
   * @param {string} targetId - Target node ID
   * @param {object} [edgeData] - { type, weight, label, metadata }
   * @returns {GraphEdge|null}
   */
  addEdge(sourceId, targetId, edgeData = {}) {
    if (!this.nodes.has(sourceId) || !this.nodes.has(targetId)) return null;
    if (sourceId === targetId) return null; // no self-loops

    // Check for existing edge between these nodes with same type
    const existingEdge = this._findEdge(sourceId, targetId, edgeData.type);
    if (existingEdge) {
      // Update existing edge
      existingEdge.weight = Math.max(existingEdge.weight, edgeData.weight ?? existingEdge.weight);
      existingEdge.updated_at = Date.now();
      if (edgeData.metadata) existingEdge.metadata = { ...existingEdge.metadata, ...edgeData.metadata };
      return existingEdge;
    }

    const edge = new GraphEdge({
      source: sourceId,
      target: targetId,
      ...edgeData,
    });

    this.edges.set(edge.id, edge);
    this.adjacency.get(sourceId).add(edge.id);
    this.reverseAdjacency.get(targetId).add(edge.id);

    // Track cross-target edges
    const sourceNode = this.nodes.get(sourceId);
    const targetNode = this.nodes.get(targetId);
    if (sourceNode && targetNode && sourceNode.target_id && targetNode.target_id &&
        sourceNode.target_id !== targetNode.target_id) {
      this.metrics.cross_target_edges++;
    }

    this.metrics.total_edges = this.edges.size;

    // Cap edges
    if (this.edges.size > this.options.maxEdges) {
      this._evictWeakestEdges(this.edges.size - this.options.maxEdges);
    }

    return edge;
  }

  /**
   * Get all edges connected to a node (both directions).
   * @param {string} nodeId
   * @returns {GraphEdge[]}
   */
  getEdgesForNode(nodeId) {
    const edgeIds = new Set([
      ...(this.adjacency.get(nodeId) || []),
      ...(this.reverseAdjacency.get(nodeId) || []),
    ]);
    return [...edgeIds].map(id => this.edges.get(id)).filter(Boolean);
  }

  /**
   * Get neighbors of a node.
   * @param {string} nodeId
   * @param {object} [options] - { direction: 'out'|'in'|'both', edgeType, minWeight }
   * @returns {GraphNode[]}
   */
  getNeighbors(nodeId, options = {}) {
    const direction = options.direction || 'both';
    const edgeType = options.edgeType;
    const minWeight = options.minWeight || 0;

    const neighborIds = new Set();

    if (direction === 'out' || direction === 'both') {
      for (const edgeId of (this.adjacency.get(nodeId) || [])) {
        const edge = this.edges.get(edgeId);
        if (edge && edge.weight >= minWeight && (!edgeType || edge.type === edgeType)) {
          neighborIds.add(edge.target);
        }
      }
    }

    if (direction === 'in' || direction === 'both') {
      for (const edgeId of (this.reverseAdjacency.get(nodeId) || [])) {
        const edge = this.edges.get(edgeId);
        if (edge && edge.weight >= minWeight && (!edgeType || edge.type === edgeType)) {
          neighborIds.add(edge.source);
        }
      }
    }

    return [...neighborIds].map(id => this.nodes.get(id)).filter(Boolean);
  }

  // ─── Pattern Detection ──────────────────────────────────────────────

  /**
   * Find repeated failure patterns across targets.
   * A failure pattern is a cluster of FAILURE nodes connected by
   * SIMILARITY or PATTERN edges across different targets.
   *
   * @param {number} [minOccurrences=3] - Minimum occurrences to flag as pattern
   * @returns {object[]} pattern clusters with cross-target flag
   */
  detectRepeatedFailures(minOccurrences = 3) {
    const failureNodes = [...this.nodes.values()].filter(n =>
      n.type === NODE_TYPES.FAILURE || n.verdict === 'rejected'
    );

    // Group by pattern_hash
    const patternGroups = new Map();
    for (const node of failureNodes) {
      const key = node.pattern_hash || node.category || `${node.type}:${node.severity}`;
      if (!patternGroups.has(key)) patternGroups.set(key, []);
      patternGroups.get(key).push(node);
    }

    const patterns = [];
    for (const [patternKey, nodes] of patternGroups) {
      if (nodes.length < minOccurrences) continue;

      const targets = new Set(nodes.map(n => n.target_id).filter(Boolean));
      const categories = new Set(nodes.map(n => n.category).filter(Boolean));
      const avgConfidence = nodes.reduce((s, n) => s + (n.confidence || 0), 0) / nodes.length;

      patterns.push({
        pattern_key: patternKey,
        occurrence_count: nodes.length,
        target_count: targets.size,
        targets: [...targets],
        categories: [...categories],
        cross_target: targets.size > 1,
        avg_confidence: Math.round(avgConfidence * 1000) / 1000,
        node_ids: nodes.map(n => n.id),
        first_seen: Math.min(...nodes.map(n => n.created_at)),
        last_seen: Math.max(...nodes.map(n => n.last_seen_at)),
      });
    }

    patterns.sort((a, b) => b.occurrence_count - a.occurrence_count);
    return patterns;
  }

  /**
   * Find nodes similar to a given feature vector.
   * Uses cosine similarity on feature vectors.
   *
   * @param {object} features - Feature vector { key: number }
   * @param {object} [options] - { limit, minSimilarity, type, category }
   * @returns {object[]} { node, similarity } pairs
   */
  findSimilar(features, options = {}) {
    const limit = options.limit || 20;
    const minSimilarity = options.minSimilarity || this.options.similarityThreshold;

    let candidates = [...this.nodes.values()];
    if (options.type) candidates = candidates.filter(n => n.type === options.type);
    if (options.category) candidates = candidates.filter(n => n.category === options.category);

    const featureKeys = Object.keys(features);
    const featureVec = featureKeys.map(k => features[k] || 0);
    const featureMag = Math.sqrt(featureVec.reduce((s, v) => s + v * v, 0));

    if (featureMag === 0) return [];

    const scored = [];
    for (const node of candidates) {
      const nodeVec = featureKeys.map(k => node.features[k] || 0);
      const nodeMag = Math.sqrt(nodeVec.reduce((s, v) => s + v * v, 0));

      if (nodeMag === 0) continue;

      const dotProduct = featureVec.reduce((s, v, i) => s + v * nodeVec[i], 0);
      const similarity = dotProduct / (featureMag * nodeMag);

      if (similarity >= minSimilarity) {
        scored.push({ node, similarity: Math.round(similarity * 1000) / 1000 });
      }
    }

    scored.sort((a, b) => b.similarity - a.similarity);
    return scored.slice(0, limit);
  }

  /**
   * Cluster nodes by feature similarity.
   * Simple single-linkage clustering with configurable threshold.
   *
   * @param {object} [options] - { type, category, threshold, minClusterSize }
   * @returns {object[]} clusters
   */
  clusterNodes(options = {}) {
    const threshold = options.threshold || 0.6;
    const minClusterSize = options.minClusterSize || 3;

    let candidates = [...this.nodes.values()];
    if (options.type) candidates = candidates.filter(n => n.type === options.type);
    if (options.category) candidates = candidates.filter(n => n.category === options.category);

    // Build similarity-connected components
    const visited = new Set();
    const clusters = [];

    for (const node of candidates) {
      if (visited.has(node.id)) continue;
      visited.add(node.id);

      const cluster = [node];
      const queue = [node];

      while (queue.length > 0) {
        const current = queue.shift();
        const neighbors = this.getNeighbors(current.id, {
          edgeType: EDGE_TYPES.SIMILARITY,
          minWeight: threshold,
        });

        for (const neighbor of neighbors) {
          if (!visited.has(neighbor.id)) {
            visited.add(neighbor.id);
            cluster.push(neighbor);
            queue.push(neighbor);
          }
        }
      }

      if (cluster.length >= minClusterSize) {
        const targets = new Set(cluster.map(n => n.target_id).filter(Boolean));
        const categories = new Set(cluster.map(n => n.category).filter(Boolean));
        clusters.push({
          size: cluster.length,
          node_ids: cluster.map(n => n.id),
          targets: [...targets],
          categories: [...categories],
          cross_target: targets.size > 1,
          avg_confidence: cluster.reduce((s, n) => s + (n.confidence || 0), 0) / cluster.length,
        });
      }
    }

    clusters.sort((a, b) => b.size - a.size);
    this.metrics.cluster_count = clusters.length;
    return clusters;
  }

  // ─── Auto-Linking ──────────────────────────────────────────────────

  /**
   * Automatically create SIMILARITY edges between nodes with similar features.
   * Scans recent nodes and links them to existing nodes above threshold.
   *
   * @param {GraphNode} node - The new node to auto-link
   * @param {number} [threshold] - Min similarity to create edge
   * @returns {GraphEdge[]} created edges
   */
  autoLink(node, threshold) {
    const minSim = threshold || this.options.similarityThreshold;
    const similar = this.findSimilar(node.features, {
      minSimilarity: minSim,
      limit: 10,
      type: node.type,
    });

    const created = [];
    for (const { node: otherNode, similarity } of similar) {
      if (otherNode.id === node.id) continue;

      const edge = this.addEdge(node.id, otherNode.id, {
        type: EDGE_TYPES.SIMILARITY,
        weight: similarity,
        label: `auto_similarity_${similarity.toFixed(2)}`,
        metadata: { auto_linked: true },
      });

      if (edge) created.push(edge);

      // Also create reverse edge (undirected similarity)
      const reverseEdge = this.addEdge(otherNode.id, node.id, {
        type: EDGE_TYPES.SIMILARITY,
        weight: similarity,
        label: `auto_similarity_${similarity.toFixed(2)}`,
        metadata: { auto_linked: true },
      });

      if (reverseEdge) created.push(reverseEdge);
    }

    return created;
  }

  // ─── Graph Traversal ──────────────────────────────────────────────

  /**
   * Get the shortest path between two nodes (BFS).
   * @param {string} fromId
   * @param {string} toId
   * @param {number} [maxDepth=6]
   * @returns {string[]|null} node IDs along the path, or null
   */
  shortestPath(fromId, toId, maxDepth = 6) {
    if (!this.nodes.has(fromId) || !this.nodes.has(toId)) return null;
    if (fromId === toId) return [fromId];

    const visited = new Set([fromId]);
    const queue = [[fromId, [fromId]]];

    while (queue.length > 0) {
      const [currentId, path] = queue.shift();
      if (path.length >= maxDepth) continue;

      const neighbors = this.getNeighbors(currentId);
      for (const neighbor of neighbors) {
        if (neighbor.id === toId) return [...path, neighbor.id];
        if (visited.has(neighbor.id)) continue;
        visited.add(neighbor.id);
        queue.push([neighbor.id, [...path, neighbor.id]]);
      }
    }

    return null;
  }

  /**
   * Get the subgraph around a node (N hops).
   * @param {string} nodeId
   * @param {number} [depth=2]
   * @returns {object} { nodes, edges }
   */
  getSubgraph(nodeId, depth = 2) {
    const nodeSet = new Set([nodeId]);
    const edgeSet = new Set();
    let frontier = [nodeId];

    for (let d = 0; d < depth; d++) {
      const nextFrontier = [];
      for (const nid of frontier) {
        for (const edge of this.getEdgesForNode(nid)) {
          edgeSet.add(edge.id);
          if (!nodeSet.has(edge.source)) { nodeSet.add(edge.source); nextFrontier.push(edge.source); }
          if (!nodeSet.has(edge.target)) { nodeSet.add(edge.target); nextFrontier.push(edge.target); }
        }
      }
      frontier = nextFrontier;
    }

    return {
      nodes: [...nodeSet].map(id => this.nodes.get(id)).filter(Boolean),
      edges: [...edgeSet].map(id => this.edges.get(id)).filter(Boolean),
    };
  }

  // ─── Statistics ────────────────────────────────────────────────────

  /**
   * Compute graph statistics.
   * @returns {object}
   */
  getStats() {
    const nodeCount = this.nodes.size;
    const edgeCount = this.edges.size;

    let totalDegree = 0;
    for (const [, edgeIds] of this.adjacency) {
      totalDegree += edgeIds.size;
    }
    const avgDegree = nodeCount > 0 ? Math.round(totalDegree / nodeCount * 100) / 100 : 0;

    return {
      ...this.metrics,
      total_nodes: nodeCount,
      total_edges: edgeCount,
      avg_degree: avgDegree,
      pattern_count: this.patternIndex.size,
      category_count: this.categoryIndex.size,
      target_count: this.targetIndex.size,
    };
  }

  getMetrics() { return this.getStats(); }

  // ─── Edge Decay ────────────────────────────────────────────────────

  _decayEdges() {
    const factor = this.options.decayFactor;
    for (const [, edge] of this.edges) {
      edge.weight *= factor;
      edge.updated_at = Date.now();
    }
    this.metrics.decay_cycles++;
  }

  // ─── Eviction ──────────────────────────────────────────────────────

  _evictOldestNodes(count) {
    const sorted = [...this.nodes.entries()]
      .sort((a, b) => a[1].updated_at - b[1].updated_at);

    for (let i = 0; i < Math.min(count, sorted.length); i++) {
      this._removeNode(sorted[i][0]);
    }
  }

  _evictWeakestEdges(count) {
    const sorted = [...this.edges.entries()]
      .sort((a, b) => a[1].weight - b[1].weight);

    for (let i = 0; i < Math.min(count, sorted.length); i++) {
      this._removeEdge(sorted[i][0]);
    }
  }

  _removeNode(nodeId) {
    // Remove all connected edges first
    const edgeIds = this.getEdgesForNode(nodeId).map(e => e.id);
    for (const eid of edgeIds) this._removeEdge(eid);

    // Remove from indexes
    const node = this.nodes.get(nodeId);
    if (node) {
      if (node.pattern_hash) this.patternIndex.delete(node.pattern_hash);
      if (node.category && this.categoryIndex.has(node.category)) {
        this.categoryIndex.get(node.category).delete(nodeId);
      }
      if (node.target_id && this.targetIndex.has(node.target_id)) {
        this.targetIndex.get(node.target_id).delete(nodeId);
      }
    }

    this.adjacency.delete(nodeId);
    this.reverseAdjacency.delete(nodeId);
    this.nodes.delete(nodeId);
  }

  _removeEdge(edgeId) {
    const edge = this.edges.get(edgeId);
    if (!edge) return;

    if (this.adjacency.has(edge.source)) this.adjacency.get(edge.source).delete(edgeId);
    if (this.reverseAdjacency.has(edge.target)) this.reverseAdjacency.get(edge.target).delete(edgeId);
    this.edges.delete(edgeId);
  }

  _findEdge(sourceId, targetId, type) {
    const edgeIds = this.adjacency.get(sourceId);
    if (!edgeIds) return null;

    for (const eid of edgeIds) {
      const edge = this.edges.get(eid);
      if (edge && edge.target === targetId && edge.type === type) return edge;
    }
    return null;
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const nodesData = [...this.nodes.entries()].slice(-10000);
    const edgesData = [...this.edges.entries()].slice(-50000);

    const payload = {
      version: '1.1',
      saved_at: Date.now(),
      nodes: nodesData,
      edges: edgesData,
      metrics: this.metrics,
      pattern_index: [...this.patternIndex.entries()],
    };

    const filePath = path.join(MG_DIR, 'memory-graph-state.json');
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2));
    this.metrics.persistence_saves++;
    return filePath;
  }

  load() {
    const filePath = path.join(MG_DIR, 'memory-graph-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      if (data.nodes) {
        this.nodes = new Map(data.nodes.map(([k, v]) => [k, new GraphNode(v)]));
      }
      if (data.edges) {
        this.edges = new Map(data.edges.map(([k, v]) => [k, new GraphEdge(v)]));
      }

      // Rebuild indexes
      this._rebuildIndexes();

      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      if (data.pattern_index) {
        this.patternIndex = new Map(data.pattern_index);
      }

      return true;
    } catch (_) {
      return false;
    }
  }

  _rebuildIndexes() {
    this.adjacency.clear();
    this.reverseAdjacency.clear();
    this.categoryIndex.clear();
    this.targetIndex.clear();

    for (const [id] of this.nodes) {
      this.adjacency.set(id, new Set());
      this.reverseAdjacency.set(id, new Set());
    }

    for (const [edgeId, edge] of this.edges) {
      if (this.adjacency.has(edge.source)) this.adjacency.get(edge.source).add(edgeId);
      if (this.reverseAdjacency.has(edge.target)) this.reverseAdjacency.get(edge.target).add(edgeId);
    }

    for (const [, node] of this.nodes) {
      if (node.category) {
        if (!this.categoryIndex.has(node.category)) this.categoryIndex.set(node.category, new Set());
        this.categoryIndex.get(node.category).add(node.id);
      }
      if (node.target_id) {
        if (!this.targetIndex.has(node.target_id)) this.targetIndex.set(node.target_id, new Set());
        this.targetIndex.get(node.target_id).add(node.id);
      }
    }

    this.metrics.total_nodes = this.nodes.size;
    this.metrics.total_edges = this.edges.size;
  }

  /**
   * Reset the graph entirely.
   */
  reset() {
    this.nodes.clear();
    this.edges.clear();
    this.adjacency.clear();
    this.reverseAdjacency.clear();
    this.patternIndex.clear();
    this.categoryIndex.clear();
    this.targetIndex.clear();
    this.metrics = {
      total_nodes: 0, total_edges: 0, total_patterns: 0,
      avg_degree: 0, cluster_count: 0, cross_target_edges: 0,
      decay_cycles: 0, persistence_saves: 0,
    };
  }

  /**
   * Shutdown: stop timers and save.
   */
  shutdown() {
    if (this._decayTimer) clearInterval(this._decayTimer);
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  MemoryGraph,
  GraphNode,
  GraphEdge,
  NODE_TYPES,
  EDGE_TYPES,
};


/**
 * BOQA finding-memory.js — Finding Memory v0.7
 *
 * Cross-target pattern memory and fingerprint knowledge.
 * Stores finding patterns that recur across different targets,
 * enabling:
 *
 *   - Pattern recognition: identify common vulnerability patterns
 *   - Fingerprint matching: match new observations to known patterns
 *   - Cross-target transfer: apply knowledge from one target to another
 *   - Regression tracking: detect patterns that reappear after fixes
 *   - Similarity graph: build a graph of related findings across targets
 *
 * Knowledge evolution:
 *   - target_profiles:           per-target intelligence
 *   - cross_target_patterns:     patterns observed on multiple targets
 *   - historical_regressions:    bugs that came back after being fixed
 *   - finding_similarity_graph:  graph connecting similar findings
 *   - verification_outcomes:     outcomes feed back into pattern confidence
 *
 * Fingerprint structure:
 *   - category:     finding category (auth_bypass, csrf, etc.)
 *   - cookie_set:   affected cookies (normalized)
 *   - endpoint_pattern: affected URL patterns (normalized)
 *   - severity:     typical severity
 *   - auth_model:   associated auth model type
 *
 * Safe mode: memory is read-only analytical; no active probing.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const MEMORY_DIR = path.join(__dirname, 'output', 'knowledge', 'memory');

// ─── Pattern Confidence Thresholds ──────────────────────────────────

const MIN_OBSERVATIONS_FOR_PATTERN = 2;
const MIN_CONFIDENCE_FOR_TRANSFER = 0.5;
const REGRESSION_WINDOW_MS = 7 * 86400000; // 7 days

// =====================================================================
//  FindingFingerprint
// =====================================================================

class FindingFingerprint {
  /**
   * @param {object} finding
   * @returns {string} fingerprint hash
   */
  static compute(finding) {
    const category = (finding.category || '').toLowerCase();
    const cookies = [...(finding.affected_cookies || [])].sort().join(',');
    const endpoints = [...(finding.affected_endpoints || [])]
      .map(e => {
        try {
          const u = new URL(e);
          // Normalize: strip IDs, keep path structure
          return u.pathname
            .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
            .replace(/\/\d{2,}/g, '/:id');
        } catch {
          return e;
        }
      })
      .sort()
      .join(',');
    const severity = finding.severity || 'medium';
    const authModel = finding.auth_model || 'unknown';

    const raw = `${category}|${cookies}|${endpoints}|${severity}|${authModel}`;
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
  }

  /**
   * Compute a looser fingerprint for pattern matching.
   * Only uses category + endpoint pattern (ignores specific cookies).
   *
   * @param {object} finding
   * @returns {string}
   */
  static computeLoose(finding) {
    const category = (finding.category || '').toLowerCase();
    const endpoints = [...(finding.affected_endpoints || [])]
      .map(e => {
        try {
          const u = new URL(e);
          // Very aggressive normalization: keep only first 2 path segments
          const parts = u.pathname.split('/').filter(Boolean);
          return '/' + parts.slice(0, 2).join('/');
        } catch {
          return '/';
        }
      })
      .sort()
      .join(',');

    const raw = `${category}|${endpoints}`;
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 12);
  }
}

// =====================================================================
//  CrossTargetPattern
// =====================================================================

class CrossTargetPattern {
  constructor(data = {}) {
    this.id = data.id || `PAT-${crypto.randomUUID().substring(0, 8)}`;
    this.fingerprint = data.fingerprint || '';
    this.category = data.category || 'unknown';
    this.severity = data.severity || 'medium';
    this.description = data.description || '';

    // Targets where this pattern has been observed
    this.observations = data.observations || []; // { target_id, finding_id, ts }

    // Confidence based on cross-target frequency
    this.confidence = data.confidence || 0;
    this.target_count = data.target_count || 0;

    // Associated cookies and endpoint patterns
    this.cookie_patterns = data.cookie_patterns || [];
    this.endpoint_patterns = data.endpoint_patterns || [];

    // Verification outcomes
    this.verification_outcomes = data.verification_outcomes || {
      confirmed: 0,
      rejected: 0,
      inconclusive: 0,
    };

    // Regression tracking
    this.regression_count = data.regression_count || 0;
    this.last_regression_at = data.last_regression_at || null;

    // Timestamps
    this.first_seen = data.first_seen || Date.now();
    this.last_seen = data.last_seen || Date.now();
    this.created_at = data.created_at || Date.now();
    this.updated_at = data.updated_at || Date.now();
  }

  /**
   * Add an observation to this pattern.
   * @param {string} targetId
   * @param {string} findingId
   */
  addObservation(targetId, findingId) {
    // Deduplicate
    if (this.observations.some(o => o.target_id === targetId && o.finding_id === findingId)) {
      return;
    }

    this.observations.push({
      target_id: targetId,
      finding_id: findingId,
      ts: Date.now(),
    });

    this.target_count = new Set(this.observations.map(o => o.target_id)).size;
    this.last_seen = Date.now();
    this.updated_at = Date.now();

    // Recompute confidence
    this._recomputeConfidence();
  }

  /**
   * Record a verification outcome for this pattern.
   * @param {string} verdict - 'confirmed' | 'rejected' | 'inconclusive'
   */
  recordOutcome(verdict) {
    if (this.verification_outcomes[verdict] !== undefined) {
      this.verification_outcomes[verdict]++;
    }
    this.updated_at = Date.now();
    this._recomputeConfidence();
  }

  /**
   * Record a regression for this pattern.
   */
  recordRegression() {
    this.regression_count++;
    this.last_regression_at = Date.now();
    this.updated_at = Date.now();
  }

  _recomputeConfidence() {
    const totalVerifications =
      this.verification_outcomes.confirmed +
      this.verification_outcomes.rejected +
      this.verification_outcomes.inconclusive;

    if (totalVerifications > 0) {
      // Confidence based on verification success + cross-target frequency
      const verificationConfidence = this.verification_outcomes.confirmed / totalVerifications;
      const frequencyBoost = Math.min(this.target_count / 5, 1.0) * 0.2; // up to +0.2
      this.confidence = Math.min(1.0, verificationConfidence + frequencyBoost);
    } else if (this.target_count >= MIN_OBSERVATIONS_FOR_PATTERN) {
      // No verifications yet, but observed on multiple targets
      this.confidence = Math.min(0.5, this.target_count * 0.1);
    }
  }
}

// =====================================================================
//  FindingMemory
// =====================================================================

class FindingMemory {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   * @param {object} [options.brainRegistry]  - BrainRegistry instance
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;

    // ── Pattern stores ─────────────────────────────────────────
    /** @type {Map<string, CrossTargetPattern>} fingerprint → pattern */
    this.patterns = new Map();

    /** @type {Map<string, Set>} finding_id → set of pattern fingerprints */
    this._findingIndex = new Map();

    /** @type {Map<string, Set>} target_id → set of pattern fingerprints */
    this._targetIndex = new Map();

    /** @type {object[]} finding similarity graph edges */
    this.similarityGraph = [];

    /** @type {object[]} regression records */
    this.regressions = [];

    /** @type {Map<string, object>} loose_fingerprint → pattern stats */
    this._loosePatterns = new Map();

    // Ensure directory exists
    fs.mkdirSync(MEMORY_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Ingestion ──────────────────────────────────────────────────

  /**
   * Ingest a finding and check for cross-target patterns.
   *
   * @param {object} finding
   * @param {string} targetId
   * @returns {object} { fingerprint, patterns_matched, new_pattern, regressions }
   */
  ingest(finding, targetId) {
    const fingerprint = FindingFingerprint.compute(finding);
    const looseFingerprint = FindingFingerprint.computeLoose(finding);

    const result = {
      fingerprint,
      patterns_matched: [],
      new_pattern: false,
      regressions: [],
    };

    // 1. Check exact fingerprint match
    const existingPattern = this.patterns.get(fingerprint);
    if (existingPattern) {
      existingPattern.addObservation(targetId, finding.id || finding.finding_id);
      result.patterns_matched.push(existingPattern);

      // Update finding index
      if (!this._findingIndex.has(finding.id || finding.finding_id)) {
        this._findingIndex.set(finding.id || finding.finding_id, new Set());
      }
      this._findingIndex.get(finding.id || finding.finding_id).add(fingerprint);

      // Update target index
      if (!this._targetIndex.has(targetId)) {
        this._targetIndex.set(targetId, new Set());
      }
      this._targetIndex.get(targetId).add(fingerprint);

    } else {
      // New pattern
      const pattern = new CrossTargetPattern({
        fingerprint,
        category: finding.category,
        severity: finding.severity,
        description: finding.title || finding.description || '',
        cookie_patterns: finding.affected_cookies || [],
        endpoint_patterns: (finding.affected_endpoints || []).map(e => {
          try {
            const u = new URL(e);
            return u.pathname.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
              .replace(/\/\d{2,}/g, '/:id');
          } catch { return e; }
        }),
      });
      pattern.addObservation(targetId, finding.id || finding.finding_id);

      this.patterns.set(fingerprint, pattern);
      result.new_pattern = true;
      result.patterns_matched.push(pattern);

      // Update indexes
      if (!this._findingIndex.has(finding.id || finding.finding_id)) {
        this._findingIndex.set(finding.id || finding.finding_id, new Set());
      }
      this._findingIndex.get(finding.id || finding.finding_id).add(fingerprint);

      if (!this._targetIndex.has(targetId)) {
        this._targetIndex.set(targetId, new Set());
      }
      this._targetIndex.get(targetId).add(fingerprint);
    }

    // 2. Check loose pattern match (cross-target)
    const looseStats = this._loosePatterns.get(looseFingerprint);
    if (looseStats) {
      looseStats.target_ids.add(targetId);
      looseStats.observation_count++;
      looseStats.last_seen = Date.now();
    } else {
      this._loosePatterns.set(looseFingerprint, {
        category: finding.category,
        target_ids: new Set([targetId]),
        observation_count: 1,
        first_seen: Date.now(),
        last_seen: Date.now(),
      });
    }

    // 3. Check for regression
    const regression = this._checkRegression(finding, targetId);
    if (regression) {
      result.regressions.push(regression);
      this.regressions.push(regression);
    }

    // 4. Update similarity graph
    this._updateSimilarityGraph(finding, targetId, fingerprint);

    // 5. Update target brain
    if (this.brainRegistry) {
      const brain = this.brainRegistry.getOrCreate(targetId);
      brain.recordFinding(finding);
    }

    return result;
  }

  /**
   * Batch ingest findings from a session.
   *
   * @param {object[]} findings
   * @param {string} targetId
   * @returns {object[]} ingestion results
   */
  ingestBatch(findings, targetId) {
    return findings.map(f => this.ingest(f, targetId));
  }

  // ─── Pattern Queries ────────────────────────────────────────────

  /**
   * Get cross-target patterns.
   *
   * @param {object} [filter] - { category, min_targets, min_confidence }
   * @returns {CrossTargetPattern[]}
   */
  getPatterns(filter = {}) {
    let results = [...this.patterns.values()];

    if (filter.category) {
      results = results.filter(p => p.category === filter.category);
    }
    if (filter.min_targets) {
      results = results.filter(p => p.target_count >= filter.min_targets);
    }
    if (filter.min_confidence) {
      results = results.filter(p => p.confidence >= filter.min_confidence);
    }

    results.sort((a, b) => b.confidence - a.confidence);
    return results;
  }

  /**
   * Get patterns observed on a specific target.
   *
   * @param {string} targetId
   * @returns {CrossTargetPattern[]}
   */
  getPatternsForTarget(targetId) {
    const fingerprints = this._targetIndex.get(targetId) || new Set();
    const patterns = [];
    for (const fp of fingerprints) {
      const pattern = this.patterns.get(fp);
      if (pattern) patterns.push(pattern);
    }
    return patterns.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Get patterns that appear on multiple targets.
   * These are the most valuable for cross-target knowledge transfer.
   *
   * @param {number} [minTargets=2]
   * @returns {CrossTargetPattern[]}
   */
  getCrossTargetPatterns(minTargets = 2) {
    return [...this.patterns.values()]
      .filter(p => p.target_count >= minTargets)
      .sort((a, b) => b.target_count - a.target_count);
  }

  /**
   * Find patterns similar to a new observation.
   * Useful for predicting whether a new finding is likely to be valid.
   *
   * @param {object} finding
   * @returns {object[]} matching patterns with similarity scores
   */
  findSimilarPatterns(finding) {
    const fingerprint = FindingFingerprint.compute(finding);
    const looseFingerprint = FindingFingerprint.computeLoose(finding);

    const results = [];

    // Exact match
    const exact = this.patterns.get(fingerprint);
    if (exact) {
      results.push({ pattern: exact, similarity: 1.0, match_type: 'exact' });
    }

    // Loose matches
    for (const [fp, pattern] of this.patterns) {
      if (fp === fingerprint) continue; // skip exact match

      // Check category match
      if (pattern.category === finding.category) {
        // Check endpoint overlap
        const fEndpoints = new Set((finding.affected_endpoints || []).map(e => {
          try { return new URL(e).pathname; } catch { return e; }
        }));
        const pEndpoints = new Set(pattern.endpoint_patterns || []);

        let overlap = 0;
        let total = 0;
        for (const e of fEndpoints) {
          total++;
          for (const pe of pEndpoints) {
            if (e.includes(pe) || pe.includes(e)) {
              overlap++;
              break;
            }
          }
        }

        const similarity = total > 0 ? overlap / total : 0;
        if (similarity > 0.3) {
          results.push({
            pattern,
            similarity: similarity * 0.8, // scale down loose matches
            match_type: 'loose',
          });
        }
      }
    }

    results.sort((a, b) => b.similarity - a.similarity);
    return results.slice(0, 10);
  }

  // ─── Similarity Graph ───────────────────────────────────────────

  /**
   * Get the finding similarity graph.
   * @returns {object} { nodes, edges }
   */
  getSimilarityGraph() {
    const nodes = new Map();
    const edges = this.similarityGraph.slice(-500); // last 500 edges

    // Build nodes from edges
    for (const edge of edges) {
      if (!nodes.has(edge.source)) {
        nodes.set(edge.source, { id: edge.source, category: edge.source_category, target_id: edge.source_target });
      }
      if (!nodes.has(edge.target)) {
        nodes.set(edge.target, { id: edge.target, category: edge.target_category, target_id: edge.target_target });
      }
    }

    return {
      nodes: [...nodes.values()],
      edges: edges.map(e => ({
        source: e.source,
        target: e.target,
        weight: e.weight,
        type: e.type,
      })),
      stats: {
        total_nodes: nodes.size,
        total_edges: edges.length,
      },
    };
  }

  // ─── Regressions ────────────────────────────────────────────────

  /**
   * Get regression records.
   *
   * @param {object} [filter] - { target_id, category, since }
   * @returns {object[]}
   */
  getRegressions(filter = {}) {
    let results = this.regressions;

    if (filter.target_id) {
      results = results.filter(r => r.target_id === filter.target_id);
    }
    if (filter.category) {
      results = results.filter(r => r.category === filter.category);
    }
    if (filter.since) {
      results = results.filter(r => r.ts >= filter.since);
    }

    return results.sort((a, b) => b.ts - a.ts);
  }

  // ─── Statistics ─────────────────────────────────────────────────

  /**
   * Get memory statistics.
   * @returns {object}
   */
  getStats() {
    const crossTargetPatterns = [...this.patterns.values()].filter(p => p.target_count >= 2);

    return {
      total_patterns: this.patterns.size,
      cross_target_patterns: crossTargetPatterns.length,
      total_observations: [...this.patterns.values()].reduce((s, p) => s + p.observations.length, 0),
      total_targets: this._targetIndex.size,
      total_regressions: this.regressions.length,
      similarity_edges: this.similarityGraph.length,
      avg_confidence: this.patterns.size > 0
        ? Math.round([...this.patterns.values()].reduce((s, p) => s + p.confidence, 0) / this.patterns.size * 100) / 100
        : 0,
      high_confidence_patterns: [...this.patterns.values()].filter(p => p.confidence >= 0.7).length,
    };
  }

  // ─── Internal ───────────────────────────────────────────────────

  _checkRegression(finding, targetId) {
    if (!this.kb) return null;

    const category = (finding.category || '').toLowerCase();
    const findingCookies = new Set(finding.affected_cookies || []);

    // Check if there was a previously resolved finding with the same pattern
    for (const [fp, pattern] of this.patterns) {
      if (pattern.category !== category) continue;
      if (!pattern.observations.some(o => o.target_id === targetId)) continue;

      // Check if any previous observation was resolved
      const resolvedObs = pattern.observations.filter(o => {
        const f = this.kb?.getFinding(o.finding_id);
        return f && f.lifecycle_state === 'resolved';
      });

      if (resolvedObs.length > 0) {
        const lastResolved = resolvedObs[resolvedObs.length - 1];
        const resolvedAt = this.kb?.getFinding(lastResolved.finding_id)?.resolved_at || 0;

        // Only count as regression if enough time has passed
        if (Date.now() - resolvedAt > REGRESSION_WINDOW_MS) {
          pattern.recordRegression();

          return {
            id: `REG-${crypto.randomUUID().substring(0, 8)}`,
            target_id: targetId,
            category,
            pattern_fingerprint: fp,
            previous_finding_id: lastResolved.finding_id,
            new_finding_id: finding.id || finding.finding_id,
            resolved_at: resolvedAt,
            reappeared_at: Date.now(),
            time_since_resolution_ms: Date.now() - resolvedAt,
            ts: Date.now(),
          };
        }
      }
    }

    return null;
  }

  _updateSimilarityGraph(finding, targetId, fingerprint) {
    const findingId = finding.id || finding.finding_id || fingerprint;
    const category = (finding.category || '').toLowerCase();

    // Find similar findings in the pattern
    const pattern = this.patterns.get(fingerprint);
    if (!pattern || pattern.observations.length < 2) return;

    // Create edges between findings in the same pattern
    for (const obs of pattern.observations) {
      if (obs.finding_id === findingId) continue;

      // Avoid duplicate edges
      const edgeExists = this.similarityGraph.some(
        e => (e.source === findingId && e.target === obs.finding_id) ||
             (e.source === obs.finding_id && e.target === findingId)
      );

      if (!edgeExists) {
        this.similarityGraph.push({
          source: findingId,
          target: obs.finding_id,
          source_category: category,
          target_category: pattern.category,
          source_target: targetId,
          target_target: obs.target_id,
          weight: pattern.confidence,
          type: obs.target_id !== targetId ? 'cross_target' : 'same_target',
        });
      }
    }

    // Cap similarity graph
    if (this.similarityGraph.length > 5000) {
      this.similarityGraph = this.similarityGraph.slice(-5000);
    }
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save memory to disk.
   * @returns {string} path written
   */
  save() {
    const filePath = path.join(MEMORY_DIR, 'finding-memory.json');

    const data = {
      version: '0.7',
      saved_at: Date.now(),
      patterns: [...this.patterns.entries()].map(([fp, p]) => [fp, {
        ...p,
        observations: p.observations.slice(-100), // keep last 100
      }]),
      regressions: this.regressions.slice(-500),
      similarity_graph: this.similarityGraph.slice(-1000),
      loose_patterns: [...this._loosePatterns.entries()].map(([fp, stats]) => [
        fp,
        { ...stats, target_ids: [...stats.target_ids] },
      ]),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load memory from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(MEMORY_DIR, 'finding-memory.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.patterns = new Map(
        (data.patterns || []).map(([fp, pData]) => [fp, new CrossTargetPattern(pData)])
      );

      // Rebuild indexes
      for (const [fp, pattern] of this.patterns) {
        for (const obs of pattern.observations) {
          if (!this._findingIndex.has(obs.finding_id)) {
            this._findingIndex.set(obs.finding_id, new Set());
          }
          this._findingIndex.get(obs.finding_id).add(fp);

          if (!this._targetIndex.has(obs.target_id)) {
            this._targetIndex.set(obs.target_id, new Set());
          }
          this._targetIndex.get(obs.target_id).add(fp);
        }
      }

      this.regressions = data.regressions || [];
      this.similarityGraph = data.similarity_graph || [];

      this._loosePatterns = new Map(
        (data.loose_patterns || []).map(([fp, stats]) => [
          fp,
          { ...stats, target_ids: new Set(stats.target_ids || []) },
        ])
      );

      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = { FindingMemory, FindingFingerprint, CrossTargetPattern, MEMORY_DIR };


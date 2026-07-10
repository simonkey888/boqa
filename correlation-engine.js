/**
 * BOQA correlation-engine.js — Correlation Engine v0.6
 *
 * Cross-session evidence correlation engine that identifies:
 *   - Repeated findings: same issue observed in multiple sessions
 *   - Environment differences: behavior that varies between prod/staging/dev
 *   - Regression patterns: issues that were resolved but reappeared
 *
 * Correlation strategies:
 *   - Temporal:  find patterns over time (hourly, daily, weekly)
 *   - Session:   compare findings across different sessions
 *   - Target:    compare findings across different targets
 *   - Severity:  track severity drift across observations
 *
 * Output: correlation reports that feed into the ranking and
 *         disclosure pipeline, strengthening confidence through
 *         independent observation.
 *
 * Safe mode: correlation is purely analytical; no active probing.
 */

const crypto = require('crypto');

// ─── Correlation Types ──────────────────────────────────────────────

const CORRELATION_TYPES = {
  REPEATED_FINDING: 'repeated_finding',
  ENVIRONMENT_DIFF: 'environment_difference',
  REGRESSION:       'regression_pattern',
  TEMPORAL_CLUSTER: 'temporal_cluster',
  CROSS_TARGET:     'cross_target',
  SEVERITY_DRIFT:   'severity_drift',
};

// ─── Time Windows ───────────────────────────────────────────────────

const TIME_WINDOWS = {
  hour:  3600000,
  day:   86400000,
  week:  604800000,
};

// =====================================================================
//  CorrelationEngine
// =====================================================================

class CorrelationEngine {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   * @param {object} [options.dedupEngine]   - DedupEngine for fingerprint matching
   * @param {number} [options.minCorrelationStrength] - minimum strength to report (default 0.3)
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.dedupEngine = options.dedupEngine || null;
    this.minCorrelationStrength = options.minCorrelationStrength || 0.3;

    /** @type {Map<string, object>} correlation_id → correlation */
    this.correlations = new Map();

    /** @type {Map<string, Set>} finding_id → set of correlated finding_ids */
    this._correlationIndex = new Map();

    /** @type {object[]} chronological observation log for temporal analysis */
    this._observationTimeline = [];

    /** @type {Map<string, object[]>} category → list of severity records */
    this._severityHistory = new Map();

    /** @type {number} maximum timeline entries to keep */
    this._maxTimeline = 50000;
  }

  // ─── Core Correlation ────────────────────────────────────────────

  /**
   * Ingest a finding and check for correlations with existing data.
   *
   * @param {object} finding
   * @param {object} sourceInfo - { session_id, target_id, environment }
   * @returns {object[]} correlations found
   */
  ingest(finding, sourceInfo = {}) {
    const correlations = [];

    // 1. Check for repeated findings
    const repeated = this._checkRepeated(finding, sourceInfo);
    if (repeated) correlations.push(repeated);

    // 2. Check for environment differences
    const envDiff = this._checkEnvironmentDiff(finding, sourceInfo);
    if (envDiff) correlations.push(envDiff);

    // 3. Check for regression patterns
    const regression = this._checkRegression(finding, sourceInfo);
    if (regression) correlations.push(regression);

    // 4. Check for temporal clustering
    const temporal = this._checkTemporalCluster(finding, sourceInfo);
    if (temporal) correlations.push(temporal);

    // 5. Check for cross-target patterns
    const crossTarget = this._checkCrossTarget(finding, sourceInfo);
    if (crossTarget) correlations.push(crossTarget);

    // 6. Track severity drift
    const severity = this._trackSeverityDrift(finding, sourceInfo);
    if (severity) correlations.push(severity);

    // Store correlations
    for (const corr of correlations) {
      if (corr.strength >= this.minCorrelationStrength) {
        this.correlations.set(corr.id, corr);

        // Update index
        const fids = [finding.id || finding.finding_id, corr.related_finding_id].filter(Boolean);
        for (const fid of fids) {
          if (!this._correlationIndex.has(fid)) {
            this._correlationIndex.set(fid, new Set());
          }
          for (const other of fids) {
            if (other !== fid) this._correlationIndex.get(fid).add(other);
          }
        }
      }
    }

    // Add to timeline
    this._addToTimeline(finding, sourceInfo);

    return correlations.filter(c => c.strength >= this.minCorrelationStrength);
  }

  /**
   * Batch ingest multiple findings from a session.
   *
   * @param {object[]} findings
   * @param {object} sourceInfo - { session_id, target_id, environment }
   * @returns {object[]} all correlations found
   */
  ingestSession(findings, sourceInfo = {}) {
    const allCorrelations = [];
    for (const finding of findings) {
      const correlations = this.ingest(finding, sourceInfo);
      allCorrelations.push(...correlations);
    }
    return allCorrelations;
  }

  // ─── Correlation Checks ──────────────────────────────────────────

  /**
   * Check if this finding has been observed before.
   *
   * @param {object} finding
   * @param {object} sourceInfo
   * @returns {object|null}
   * @private
   */
  _checkRepeated(finding, sourceInfo) {
    if (!this.kb) return null;

    const similar = this.kb.findSimilarHistorical(finding, 3);
    if (similar.length === 0) return null;

    const bestMatch = similar[0];
    if (bestMatch.similarity < 0.5) return null;

    return {
      id: `CORR-${crypto.randomUUID().substring(0, 8)}`,
      type: CORRELATION_TYPES.REPEATED_FINDING,
      finding_id: finding.id || finding.finding_id,
      related_finding_id: bestMatch.finding.finding_id,
      strength: bestMatch.similarity,
      detail: {
        observation_count: similar.length,
        best_similarity: bestMatch.similarity,
        sessions: similar.map(s => s.finding.source?.session_id).filter(Boolean),
      },
      discovered_at: Date.now(),
    };
  }

  /**
   * Check if this finding behaves differently across environments.
   *
   * @param {object} finding
   * @param {object} sourceInfo
   * @returns {object|null}
   * @private
   */
  _checkEnvironmentDiff(finding, sourceInfo) {
    if (!this.kb || !sourceInfo.environment) return null;

    // Find same-category findings in different environments
    const allFindings = this.kb.queryFindings({
      category: finding.category,
      limit: 100,
    });

    const diffEnvFindings = allFindings.filter(f => {
      const fEnv = f.environment || f.target_id;
      return fEnv && fEnv !== sourceInfo.environment &&
             (f.finding_id || f.id) !== (finding.finding_id || finding.id);
    });

    if (diffEnvFindings.length === 0) return null;

    // Check for severity differences
    const currentSeverity = this._severityRank(finding.severity);
    const diffSeverities = diffEnvFindings.map(f => ({
      environment: f.environment || 'unknown',
      severity: f.severity,
      severity_rank: this._severityRank(f.severity),
    }));

    const hasSeverityDiff = diffSeverities.some(
      ds => Math.abs(ds.severity_rank - currentSeverity) >= 1
    );

    if (!hasSeverityDiff) return null;

    return {
      id: `CORR-${crypto.randomUUID().substring(0, 8)}`,
      type: CORRELATION_TYPES.ENVIRONMENT_DIFF,
      finding_id: finding.id || finding.finding_id,
      related_finding_id: diffEnvFindings[0].finding_id || diffEnvFindings[0].id,
      strength: hasSeverityDiff ? 0.8 : 0.4,
      detail: {
        current_environment: sourceInfo.environment,
        current_severity: finding.severity,
        different_environments: diffSeverities,
      },
      discovered_at: Date.now(),
    };
  }

  /**
   * Check if this finding represents a regression (previously resolved).
   *
   * @param {object} finding
   * @param {object} sourceInfo
   * @returns {object|null}
   * @private
   */
  _checkRegression(finding, sourceInfo) {
    if (!this.kb) return null;

    // Find findings with same category that were previously resolved
    const resolved = this.kb.queryFindings({
      category: finding.category,
      limit: 50,
    }).filter(f =>
      f.lifecycle_state === 'resolved' &&
      (f.affected_cookies || []).some(c => (finding.affected_cookies || []).includes(c))
    );

    if (resolved.length === 0) return null;

    // Check if enough time has passed since resolution
    const now = Date.now();
    const recentResolutions = resolved.filter(f => {
      const resolvedAt = f.resolved_at || f.updated_at || 0;
      return (now - resolvedAt) > TIME_WINDOWS.day; // at least 1 day since resolution
    });

    if (recentResolutions.length === 0) return null;

    return {
      id: `CORR-${crypto.randomUUID().substring(0, 8)}`,
      type: CORRELATION_TYPES.REGRESSION,
      finding_id: finding.id || finding.finding_id,
      related_finding_id: recentResolutions[0].finding_id || recentResolutions[0].id,
      strength: 0.85,
      detail: {
        previously_resolved: recentResolutions.map(f => ({
          finding_id: f.finding_id || f.id,
          resolved_at: f.resolved_at || f.updated_at,
          severity: f.severity,
        })),
        regression_indicator: 'same_category_and_cookies_after_resolution',
      },
      discovered_at: Date.now(),
    };
  }

  /**
   * Check for temporal clustering of similar findings.
   *
   * @param {object} finding
   * @param {object} sourceInfo
   * @returns {object|null}
   * @private
   */
  _checkTemporalCluster(finding, sourceInfo) {
    const now = Date.now();
    const window = TIME_WINDOWS.hour; // 1-hour window

    // Find recent observations of same category
    const recentSameCategory = this._observationTimeline.filter(o =>
      o.category === finding.category &&
      (now - o.ts) < window
    );

    if (recentSameCategory.length < 2) return null;

    // Compute cluster strength based on density
    const density = recentSameCategory.length / (window / 60000); // per minute
    const strength = Math.min(density / 0.5, 1.0); // 0.5/min = strength 1.0

    if (strength < this.minCorrelationStrength) return null;

    return {
      id: `CORR-${crypto.randomUUID().substring(0, 8)}`,
      type: CORRELATION_TYPES.TEMPORAL_CLUSTER,
      finding_id: finding.id || finding.finding_id,
      related_finding_id: recentSameCategory[0].finding_id,
      strength,
      detail: {
        cluster_size: recentSameCategory.length,
        time_window: '1h',
        density_per_minute: Math.round(density * 100) / 100,
        session_ids: [...new Set(recentSameCategory.map(o => o.session_id).filter(Boolean))],
      },
      discovered_at: Date.now(),
    };
  }

  /**
   * Check for the same finding across different targets.
   *
   * @param {object} finding
   * @param {object} sourceInfo
   * @returns {object|null}
   * @private
   */
  _checkCrossTarget(finding, sourceInfo) {
    if (!this.kb || !sourceInfo.target_id) return null;

    const allFindings = this.kb.queryFindings({
      category: finding.category,
      limit: 100,
    });

    const otherTargetFindings = allFindings.filter(f =>
      f.target_id && f.target_id !== sourceInfo.target_id
    );

    if (otherTargetFindings.length === 0) return null;

    // Check cookie/endpoint overlap
    const overlapScores = otherTargetFindings.map(f => {
      const fCookies = new Set(f.affected_cookies || []);
      const myCookies = new Set(finding.affected_cookies || []);
      let intersection = 0;
      for (const c of myCookies) { if (fCookies.has(c)) intersection++; }
      const cookieOverlap = myCookies.size > 0 && fCookies.size > 0
        ? intersection / (myCookies.size + fCookies.size - intersection)
        : 0;

      return { finding: f, cookieOverlap };
    });

    const bestOverlap = overlapScores.reduce(
      (best, o) => o.cookieOverlap > best.cookieOverlap ? o : best,
      { cookieOverlap: 0 }
    );

    if (bestOverlap.cookieOverlap < 0.3) return null;

    return {
      id: `CORR-${crypto.randomUUID().substring(0, 8)}`,
      type: CORRELATION_TYPES.CROSS_TARGET,
      finding_id: finding.id || finding.finding_id,
      related_finding_id: bestOverlap.finding.finding_id || bestOverlap.finding.id,
      strength: bestOverlap.cookieOverlap,
      detail: {
        current_target: sourceInfo.target_id,
        related_target: bestOverlap.finding.target_id,
        cookie_overlap: bestOverlap.cookieOverlap,
        total_cross_target_occurrences: otherTargetFindings.length,
      },
      discovered_at: Date.now(),
    };
  }

  /**
   * Track severity drift for a category over time.
   *
   * @param {object} finding
   * @param {object} sourceInfo
   * @returns {object|null}
   * @private
   */
  _trackSeverityDrift(finding, sourceInfo) {
    const category = (finding.category || '').toLowerCase();
    if (!category) return null;

    if (!this._severityHistory.has(category)) {
      this._severityHistory.set(category, []);
    }

    const history = this._severityHistory.get(category);
    const currentRank = this._severityRank(finding.severity);

    history.push({
      finding_id: finding.id || finding.finding_id,
      severity: finding.severity,
      rank: currentRank,
      ts: Date.now(),
      environment: sourceInfo.environment || null,
    });

    // Keep last 100 records per category
    if (history.length > 100) {
      history.splice(0, history.length - 100);
    }

    // Check for drift: severity increasing over time
    if (history.length < 3) return null;

    const recent = history.slice(-5);
    const older = history.slice(-10, -5);

    if (older.length === 0) return null;

    const avgRecent = recent.reduce((s, h) => s + h.rank, 0) / recent.length;
    const avgOlder = older.reduce((s, h) => s + h.rank, 0) / older.length;

    const drift = avgRecent - avgOlder;
    if (Math.abs(drift) < 1) return null; // no significant drift

    return {
      id: `CORR-${crypto.randomUUID().substring(0, 8)}`,
      type: CORRELATION_TYPES.SEVERITY_DRIFT,
      finding_id: finding.id || finding.finding_id,
      related_finding_id: null,
      strength: Math.min(Math.abs(drift) / 3, 1.0),
      detail: {
        category,
        direction: drift > 0 ? 'increasing' : 'decreasing',
        drift_magnitude: Math.round(drift * 100) / 100,
        recent_avg_severity: Math.round(avgRecent * 10) / 10,
        older_avg_severity: Math.round(avgOlder * 10) / 10,
      },
      discovered_at: Date.now(),
    };
  }

  // ─── Queries ─────────────────────────────────────────────────────

  /**
   * Get correlations for a specific finding.
   *
   * @param {string} findingId
   * @returns {object[]}
   */
  getCorrelationsForFinding(findingId) {
    const correlatedIds = this._correlationIndex.get(findingId) || new Set();
    const correlations = [];

    for (const corr of this.correlations.values()) {
      if (corr.finding_id === findingId || corr.related_finding_id === findingId) {
        correlations.push(corr);
      }
    }

    correlations.sort((a, b) => b.strength - a.strength);
    return correlations;
  }

  /**
   * Get all correlations, optionally filtered by type.
   *
   * @param {object} [filter] - { type, min_strength, since }
   * @returns {object[]}
   */
  query(filter = {}) {
    let results = [...this.correlations.values()];

    if (filter.type) {
      results = results.filter(c => c.type === filter.type);
    }
    if (filter.min_strength) {
      results = results.filter(c => c.strength >= filter.min_strength);
    }
    if (filter.since) {
      results = results.filter(c => c.discovered_at >= filter.since);
    }

    results.sort((a, b) => b.strength - a.strength);
    return results;
  }

  /**
   * Get correlation statistics.
   * @returns {object}
   */
  getStats() {
    const all = [...this.correlations.values()];

    const byType = {};
    for (const corr of all) {
      byType[corr.type] = (byType[corr.type] || 0) + 1;
    }

    const avgStrength = all.length > 0
      ? Math.round(all.reduce((s, c) => s + c.strength, 0) / all.length * 100) / 100
      : 0;

    return {
      total_correlations: all.length,
      by_type: byType,
      avg_strength: avgStrength,
      strong_correlations: all.filter(c => c.strength >= 0.7).length,
      finding_coverage: this._correlationIndex.size,
    };
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  /**
   * Add an observation to the timeline.
   * @param {object} finding
   * @param {object} sourceInfo
   * @private
   */
  _addToTimeline(finding, sourceInfo) {
    this._observationTimeline.push({
      finding_id: finding.id || finding.finding_id,
      category: (finding.category || '').toLowerCase(),
      severity: finding.severity,
      ts: Date.now(),
      session_id: sourceInfo.session_id || null,
      target_id: sourceInfo.target_id || null,
      environment: sourceInfo.environment || null,
    });

    // Cap timeline
    if (this._observationTimeline.length > this._maxTimeline) {
      this._observationTimeline.splice(0, this._observationTimeline.length - this._maxTimeline);
    }
  }

  /**
   * Convert severity label to numeric rank.
   * @param {string} severity
   * @returns {number}
   * @private
   */
  _severityRank(severity) {
    const ranks = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return ranks[(severity || '').toLowerCase()] || 2;
  }
}

module.exports = { CorrelationEngine, CORRELATION_TYPES };


/**
 * BOQA target-brain.js — Target Brain v0.7
 *
 * Persistent intelligence profile per target. Each target gets a
 * comprehensive brain that accumulates knowledge across sessions,
 * campaigns, and discoveries. The brain stores:
 *
 *   - historical_findings:    all findings ever observed for this target
 *   - asset_graph:            known endpoints, cookies, WS channels, forms
 *   - workflow_graph:         detected multi-step workflows
 *   - auth_models:            authentication patterns and their risk profiles
 *   - verification_history:   past verification results and their outcomes
 *
 * The brain enables:
 *   - Cross-session intelligence persistence
 *   - Regression detection (reappearing previously-resolved findings)
 *   - Coverage trend tracking over time
 *   - Target-specific learning (which hypothesis categories succeed)
 *   - Asset relationship inference
 *
 * Storage: in-memory hot cache + on-disk JSON persistence.
 * Each brain is keyed by target_id and auto-loaded on construction.
 *
 * Safe mode: read-only observability data; no PII beyond authorized
 * instrumentation captures.
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Persistence ────────────────────────────────────────────────────

const BRAINS_DIR = path.join(__dirname, 'output', 'knowledge', 'brains');

// ─── Defaults ───────────────────────────────────────────────────────

const MAX_HISTORICAL_FINDINGS = 5000;
const MAX_VERIFICATION_HISTORY = 10000;
const MAX_ASSET_ENTRIES = 2000;
const MAX_WORKFLOW_ENTRIES = 500;
const MAX_AUTH_MODELS = 50;

// ─── Coverage History Window ────────────────────────────────────────

const COVERAGE_SNAPSHOT_INTERVAL = 3600000; // 1 hour
const MAX_COVERAGE_SNAPSHOTS = 720;         // 30 days of hourly snapshots

// =====================================================================
//  TargetBrain
// =====================================================================

class TargetBrain {
  /**
   * @param {object} options
   * @param {string} options.targetId   - unique target identifier
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   */
  constructor(options = {}) {
    this.targetId = options.targetId || 'unknown';
    this.kb = options.knowledgeBase || null;

    // ── Core intelligence stores ─────────────────────────────────
    /** @type {object[]} historical findings for this target */
    this.historicalFindings = [];

    /** @type {object} asset graph — endpoints, cookies, WS, forms */
    this.assetGraph = {
      endpoints: [],
      cookies: [],
      websockets: [],
      forms: [],
      relationships: [],
    };

    /** @type {object[]} detected workflows */
    this.workflowGraph = [];

    /** @type {object[]} auth models and risk profiles */
    this.authModels = [];

    /** @type {object[]} verification result history */
    this.verificationHistory = [];

    // ── Trend data ───────────────────────────────────────────────
    /** @type {object[]} coverage score snapshots over time */
    this.coverageTrend = [];

    /** @type {object[]} finding rate over time */
    this.findingTrend = [];

    /** @type {object[]} verification success rate over time */
    this.verificationTrend = [];

    // ── Learning data ────────────────────────────────────────────
    /** @type {Map<string, object>} category → success stats */
    this.categorySuccessRates = new Map();

    /** @type {Map<string, number>} hypothesis_type → success count */
    this.hypothesisSuccessMap = new Map();

    /** @type {Map<string, number>} hypothesis_type → failure count */
    this.hypothesisFailureMap = new Map();

    /** @type {object} target-specific weights for the learning engine */
    this.customWeights = {
      severity: 0.30,
      confidence: 0.30,
      coverage_gap: 0.20,
      historical_success: 0.20,
    };

    // ── Metadata ─────────────────────────────────────────────────
    this.created_at = Date.now();
    this.updated_at = Date.now();
    this.total_sessions = 0;
    this.total_campaigns = 0;
    this.last_session_at = null;
    this.last_campaign_at = null;

    // Ensure directory exists
    fs.mkdirSync(BRAINS_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Historical Findings ────────────────────────────────────────

  /**
   * Record a finding in the target's history.
   *
   * @param {object} finding
   * @returns {object} the recorded finding
   */
  recordFinding(finding) {
    const record = {
      ...finding,
      recorded_at: Date.now(),
      brain_target_id: this.targetId,
    };

    this.historicalFindings.push(record);

    // Cap
    if (this.historicalFindings.length > MAX_HISTORICAL_FINDINGS) {
      this.historicalFindings.splice(
        0,
        this.historicalFindings.length - MAX_HISTORICAL_FINDINGS
      );
    }

    // Update finding trend
    this._updateFindingTrend(record);

    this.updated_at = Date.now();
    return record;
  }

  /**
   * Get historical findings, optionally filtered.
   *
   * @param {object} [filter] - { severity, category, lifecycle_state, since, limit }
   * @returns {object[]}
   */
  queryHistoricalFindings(filter = {}) {
    let results = this.historicalFindings;

    if (filter.severity) {
      results = results.filter(f => f.severity === filter.severity);
    }
    if (filter.category) {
      results = results.filter(f => f.category === filter.category);
    }
    if (filter.lifecycle_state) {
      results = results.filter(f => f.lifecycle_state === filter.lifecycle_state);
    }
    if (filter.since) {
      results = results.filter(f => (f.recorded_at || f.created_at) >= filter.since);
    }

    results.sort((a, b) => (b.recorded_at || 0) - (a.recorded_at || 0));
    return results.slice(0, filter.limit || results.length);
  }

  /**
   * Check if a similar finding has been observed before.
   *
   * @param {object} finding
   * @returns {object|null} the most similar historical finding
   */
  findSimilar(finding) {
    let bestMatch = null;
    let bestScore = 0;

    const fCategory = (finding.category || '').toLowerCase();
    const fCookies = new Set(finding.affected_cookies || []);
    const fEndpoints = new Set((finding.affected_endpoints || []).map(e => {
      try { return new URL(e).pathname; } catch { return e; }
    }));

    for (const hist of this.historicalFindings) {
      const hCategory = (hist.category || '').toLowerCase();
      const categoryMatch = hCategory === fCategory ? 1 : 0;

      const hCookies = new Set(hist.affected_cookies || []);
      let cookieOverlap = 0;
      if (fCookies.size > 0 && hCookies.size > 0) {
        let inter = 0;
        for (const c of fCookies) { if (hCookies.has(c)) inter++; }
        cookieOverlap = inter / (fCookies.size + hCookies.size - inter);
      }

      const hEndpoints = new Set((hist.affected_endpoints || []).map(e => {
        try { return new URL(e).pathname; } catch { return e; }
      }));
      let endpointOverlap = 0;
      if (fEndpoints.size > 0 && hEndpoints.size > 0) {
        let inter = 0;
        for (const e of fEndpoints) { if (hEndpoints.has(e)) inter++; }
        endpointOverlap = inter / (fEndpoints.size + hEndpoints.size - inter);
      }

      const score = categoryMatch * 0.5 + cookieOverlap * 0.25 + endpointOverlap * 0.25;
      if (score > bestScore && score > 0.3) {
        bestScore = score;
        bestMatch = hist;
      }
    }

    return bestMatch ? { finding: bestMatch, similarity: bestScore } : null;
  }

  // ─── Asset Graph ────────────────────────────────────────────────

  /**
   * Update the asset graph with new discoveries.
   *
   * @param {object} assets - { endpoints, cookies, websockets, forms, relationships }
   * @returns {object} the updated asset graph
   */
  updateAssetGraph(assets) {
    // Merge endpoints
    if (assets.endpoints) {
      const existing = new Map(this.assetGraph.endpoints.map(e => [e.path || e.url, e]));
      for (const ep of assets.endpoints) {
        const key = ep.path || ep.url;
        if (!existing.has(key)) {
          this.assetGraph.endpoints.push(ep);
        } else {
          // Merge status codes and request counts
          const existing_ep = existing.get(key);
          if (ep.status_codes) {
            for (const sc of ep.status_codes) {
              if (!existing_ep.status_codes) existing_ep.status_codes = [];
              if (!existing_ep.status_codes.includes(sc)) existing_ep.status_codes.push(sc);
            }
          }
          if (ep.request_count) {
            existing_ep.request_count = (existing_ep.request_count || 0) + ep.request_count;
          }
        }
      }
    }

    // Merge cookies
    if (assets.cookies) {
      const existing = new Map(this.assetGraph.cookies.map(c => [c.name, c]));
      for (const cookie of assets.cookies) {
        if (!existing.has(cookie.name)) {
          this.assetGraph.cookies.push(cookie);
        }
      }
    }

    // Merge websockets
    if (assets.websockets) {
      const existing = new Map(this.assetGraph.websockets.map(w => [w.url, w]));
      for (const ws of assets.websockets) {
        if (!existing.has(ws.url)) {
          this.assetGraph.websockets.push(ws);
        }
      }
    }

    // Merge forms
    if (assets.forms) {
      const existing = new Map(this.assetGraph.forms.map(f => [f.action || f.id, f]));
      for (const form of assets.forms) {
        const key = form.action || form.id;
        if (!existing.has(key)) {
          this.assetGraph.forms.push(form);
        }
      }
    }

    // Merge relationships
    if (assets.relationships) {
      const existing = new Set(this.assetGraph.relationships.map(r => `${r.source}→${r.target}`));
      for (const rel of assets.relationships) {
        const key = `${rel.source}→${rel.target}`;
        if (!existing.has(key)) {
          this.assetGraph.relationships.push(rel);
          existing.add(key);
        }
      }
    }

    // Cap asset sizes
    if (this.assetGraph.endpoints.length > MAX_ASSET_ENTRIES) {
      this.assetGraph.endpoints = this.assetGraph.endpoints.slice(-MAX_ASSET_ENTRIES);
    }
    if (this.assetGraph.cookies.length > MAX_ASSET_ENTRIES) {
      this.assetGraph.cookies = this.assetGraph.cookies.slice(-MAX_ASSET_ENTRIES);
    }
    if (this.assetGraph.websockets.length > MAX_ASSET_ENTRIES) {
      this.assetGraph.websockets = this.assetGraph.websockets.slice(-MAX_ASSET_ENTRIES);
    }

    this.updated_at = Date.now();
    return this.assetGraph;
  }

  // ─── Workflow Graph ─────────────────────────────────────────────

  /**
   * Add or update a workflow in the brain.
   *
   * @param {object} workflow - { id, type, steps, risk_class }
   * @returns {object}
   */
  addWorkflow(workflow) {
    const existing = this.workflowGraph.findIndex(
      w => w.id === workflow.id || w.steps?.join('→') === workflow.steps?.join('→')
    );

    if (existing >= 0) {
      this.workflowGraph[existing] = {
        ...this.workflowGraph[existing],
        ...workflow,
        updated_at: Date.now(),
      };
    } else {
      this.workflowGraph.push({
        ...workflow,
        discovered_at: Date.now(),
        updated_at: Date.now(),
      });
    }

    // Cap
    if (this.workflowGraph.length > MAX_WORKFLOW_ENTRIES) {
      this.workflowGraph = this.workflowGraph.slice(-MAX_WORKFLOW_ENTRIES);
    }

    this.updated_at = Date.now();
    return workflow;
  }

  // ─── Auth Models ────────────────────────────────────────────────

  /**
   * Record an authentication model observation.
   *
   * @param {object} authModel - { type, cookies, headers, risk_flags, observed_at }
   * @returns {object}
   */
  recordAuthModel(authModel) {
    const type = authModel.type || 'unknown';

    // Check if this model type already exists
    const existing = this.authModels.findIndex(m => m.type === type);

    if (existing >= 0) {
      // Update with new observations
      this.authModels[existing] = {
        ...this.authModels[existing],
        cookies: [...new Set([...this.authModels[existing].cookies, ...(authModel.cookies || [])])],
        headers: [...new Set([...this.authModels[existing].headers, ...(authModel.headers || [])])],
        risk_flags: [...new Set([...this.authModels[existing].risk_flags, ...(authModel.risk_flags || [])])],
        last_observed: Date.now(),
        observation_count: (this.authModels[existing].observation_count || 0) + 1,
      };
    } else {
      this.authModels.push({
        type,
        cookies: authModel.cookies || [],
        headers: authModel.headers || [],
        risk_flags: authModel.risk_flags || [],
        first_observed: Date.now(),
        last_observed: Date.now(),
        observation_count: 1,
      });
    }

    // Cap
    if (this.authModels.length > MAX_AUTH_MODELS) {
      this.authModels = this.authModels.slice(-MAX_AUTH_MODELS);
    }

    this.updated_at = Date.now();
    return authModel;
  }

  // ─── Verification History ───────────────────────────────────────

  /**
   * Record a verification result.
   *
   * @param {object} result - { finding_id, verdict, category, duration_ms, evidence_strength }
   * @returns {object}
   */
  recordVerification(result) {
    const record = {
      ...result,
      recorded_at: Date.now(),
      target_id: this.targetId,
    };

    this.verificationHistory.push(record);

    // Cap
    if (this.verificationHistory.length > MAX_VERIFICATION_HISTORY) {
      this.verificationHistory.splice(
        0,
        this.verificationHistory.length - MAX_VERIFICATION_HISTORY
      );
    }

    // Update category success rates
    this._updateCategorySuccessRate(result);

    // Update hypothesis maps
    if (result.verdict === 'confirmed') {
      const key = result.category || 'unknown';
      this.hypothesisSuccessMap.set(key, (this.hypothesisSuccessMap.get(key) || 0) + 1);
    } else if (result.verdict === 'rejected') {
      const key = result.category || 'unknown';
      this.hypothesisFailureMap.set(key, (this.hypothesisFailureMap.get(key) || 0) + 1);
    }

    // Update verification trend
    this._updateVerificationTrend(record);

    this.updated_at = Date.now();
    return record;
  }

  /**
   * Get verification success rate for a category.
   *
   * @param {string} category
   * @returns {number} 0-1 success rate
   */
  getCategorySuccessRate(category) {
    const stats = this.categorySuccessRates.get(category);
    if (!stats || stats.total === 0) return 0;
    return stats.confirmed / stats.total;
  }

  /**
   * Get all category success rates.
   * @returns {object[]}
   */
  getAllCategorySuccessRates() {
    const results = [];
    for (const [category, stats] of this.categorySuccessRates) {
      results.push({
        category,
        total: stats.total,
        confirmed: stats.confirmed,
        rejected: stats.rejected,
        success_rate: stats.total > 0 ? stats.confirmed / stats.total : 0,
      });
    }
    results.sort((a, b) => b.success_rate - a.success_rate);
    return results;
  }

  // ─── Coverage Trends ────────────────────────────────────────────

  /**
   * Record a coverage score snapshot.
   *
   * @param {number} score - coverage score 0-100
   * @param {object} [details] - domain-level scores
   */
  recordCoverageSnapshot(score, details = {}) {
    this.coverageTrend.push({
      score,
      details,
      ts: Date.now(),
    });

    // Cap
    if (this.coverageTrend.length > MAX_COVERAGE_SNAPSHOTS) {
      this.coverageTrend = this.coverageTrend.slice(-MAX_COVERAGE_SNAPSHOTS);
    }

    this.updated_at = Date.now();
  }

  /**
   * Get coverage trend over a time window.
   *
   * @param {number} [windowMs] - time window in ms (default: 7 days)
   * @returns {object[]}
   */
  getCoverageTrend(windowMs = 604800000) {
    const since = Date.now() - windowMs;
    return this.coverageTrend.filter(s => s.ts >= since);
  }

  /**
   * Compute coverage growth rate.
   *
   * @param {number} [windowMs] - time window
   * @returns {number} score change per day
   */
  getCoverageGrowthRate(windowMs = 604800000) {
    const trend = this.getCoverageTrend(windowMs);
    if (trend.length < 2) return 0;

    const first = trend[0];
    const last = trend[trend.length - 1];
    const daysElapsed = (last.ts - first.ts) / 86400000;

    if (daysElapsed <= 0) return 0;
    return Math.round(((last.score - first.score) / daysElapsed) * 100) / 100;
  }

  // ─── Session Tracking ───────────────────────────────────────────

  /**
   * Record a session for this target.
   *
   * @param {object} session - { session_id, mode, start, end, events }
   */
  recordSession(session) {
    this.total_sessions++;
    this.last_session_at = Date.now();
    this.updated_at = Date.now();

    // Also persist to KB if available
    if (this.kb) {
      this.kb.addSession({
        ...session,
        target_id: this.targetId,
      });
    }
  }

  /**
   * Record a campaign for this target.
   */
  recordCampaign() {
    this.total_campaigns++;
    this.last_campaign_at = Date.now();
    this.updated_at = Date.now();
  }

  // ─── Intelligence Summary ───────────────────────────────────────

  /**
   * Get the complete intelligence profile for this target.
   *
   * @returns {object}
   */
  getProfile() {
    return {
      target_id: this.targetId,
      created_at: this.created_at,
      updated_at: this.updated_at,
      total_sessions: this.total_sessions,
      total_campaigns: this.total_campaigns,
      last_session_at: this.last_session_at,
      last_campaign_at: this.last_campaign_at,

      findings: {
        total: this.historicalFindings.length,
        by_severity: this._countBySeverity(),
        by_category: this._countByCategory(),
        by_lifecycle: this._countByLifecycle(),
      },

      assets: {
        endpoints: this.assetGraph.endpoints.length,
        cookies: this.assetGraph.cookies.length,
        websockets: this.assetGraph.websockets.length,
        forms: this.assetGraph.forms.length,
        relationships: this.assetGraph.relationships.length,
      },

      workflows: this.workflowGraph.length,
      auth_models: this.authModels.length,

      verification: {
        total: this.verificationHistory.length,
        category_rates: this.getAllCategorySuccessRates(),
        recent_rate: this._recentVerificationRate(),
      },

      coverage: {
        current: this.coverageTrend.length > 0
          ? this.coverageTrend[this.coverageTrend.length - 1].score
          : 0,
        growth_rate: this.getCoverageGrowthRate(),
        trend_points: this.coverageTrend.length,
      },

      learning: {
        hypothesis_successes: [...this.hypothesisSuccessMap.entries()],
        hypothesis_failures: [...this.hypothesisFailureMap.entries()],
        custom_weights: this.customWeights,
      },
    };
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  _updateCategorySuccessRate(result) {
    const category = result.category || 'unknown';
    if (!this.categorySuccessRates.has(category)) {
      this.categorySuccessRates.set(category, {
        total: 0,
        confirmed: 0,
        rejected: 0,
        inconclusive: 0,
      });
    }

    const stats = this.categorySuccessRates.get(category);
    stats.total++;
    if (result.verdict === 'confirmed') stats.confirmed++;
    else if (result.verdict === 'rejected') stats.rejected++;
    else stats.inconclusive++;
  }

  _updateFindingTrend(finding) {
    const day = new Date(Date.now()).toISOString().split('T')[0];
    const existing = this.findingTrend.find(t => t.day === day);
    if (existing) {
      existing.count++;
      existing.severities[finding.severity] = (existing.severities[finding.severity] || 0) + 1;
    } else {
      this.findingTrend.push({
        day,
        count: 1,
        severities: { [finding.severity || 'info']: 1 },
      });
    }

    if (this.findingTrend.length > 365) {
      this.findingTrend = this.findingTrend.slice(-365);
    }
  }

  _updateVerificationTrend(record) {
    const day = new Date(Date.now()).toISOString().split('T')[0];
    const existing = this.verificationTrend.find(t => t.day === day);
    if (existing) {
      existing.total++;
      if (record.verdict === 'confirmed') existing.confirmed++;
    } else {
      this.verificationTrend.push({
        day,
        total: 1,
        confirmed: record.verdict === 'confirmed' ? 1 : 0,
      });
    }

    if (this.verificationTrend.length > 365) {
      this.verificationTrend = this.verificationTrend.slice(-365);
    }
  }

  _recentVerificationRate(windowMs = 604800000) {
    const since = Date.now() - windowMs;
    const recent = this.verificationHistory.filter(v => v.recorded_at >= since);
    if (recent.length === 0) return 0;
    return recent.filter(v => v.verdict === 'confirmed').length / recent.length;
  }

  _countBySeverity() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.historicalFindings) {
      if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
    return counts;
  }

  _countByCategory() {
    const counts = {};
    for (const f of this.historicalFindings) {
      counts[f.category] = (counts[f.category] || 0) + 1;
    }
    return counts;
  }

  _countByLifecycle() {
    const counts = {};
    for (const f of this.historicalFindings) {
      const state = f.lifecycle_state || 'observed';
      counts[state] = (counts[state] || 0) + 1;
    }
    return counts;
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save the brain to disk.
   * @returns {string} path written
   */
  save() {
    const filePath = path.join(BRAINS_DIR, `${this.targetId.replace(/[^a-zA-Z0-9._-]/g, '_')}.json`);

    const data = {
      version: '0.7',
      target_id: this.targetId,
      saved_at: Date.now(),
      created_at: this.created_at,
      updated_at: this.updated_at,
      total_sessions: this.total_sessions,
      total_campaigns: this.total_campaigns,
      last_session_at: this.last_session_at,
      last_campaign_at: this.last_campaign_at,

      historical_findings: this.historicalFindings,
      asset_graph: this.assetGraph,
      workflow_graph: this.workflowGraph,
      auth_models: this.authModels,
      verification_history: this.verificationHistory,
      coverage_trend: this.coverageTrend,
      finding_trend: this.findingTrend,
      verification_trend: this.verificationTrend,

      category_success_rates: [...this.categorySuccessRates.entries()],
      hypothesis_successes: [...this.hypothesisSuccessMap.entries()],
      hypothesis_failures: [...this.hypothesisFailureMap.entries()],
      custom_weights: this.customWeights,
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load the brain from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(BRAINS_DIR, `${this.targetId.replace(/[^a-zA-Z0-9._-]/g, '_')}.json`);

    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.created_at = data.created_at || Date.now();
      this.updated_at = data.updated_at || Date.now();
      this.total_sessions = data.total_sessions || 0;
      this.total_campaigns = data.total_campaigns || 0;
      this.last_session_at = data.last_session_at || null;
      this.last_campaign_at = data.last_campaign_at || null;

      this.historicalFindings = data.historical_findings || [];
      this.assetGraph = data.asset_graph || this.assetGraph;
      this.workflowGraph = data.workflow_graph || [];
      this.authModels = data.auth_models || [];
      this.verificationHistory = data.verification_history || [];
      this.coverageTrend = data.coverage_trend || [];
      this.findingTrend = data.finding_trend || [];
      this.verificationTrend = data.verification_trend || [];

      this.categorySuccessRates = new Map(data.category_success_rates || []);
      this.hypothesisSuccessMap = new Map(data.hypothesis_successes || []);
      this.hypothesisFailureMap = new Map(data.hypothesis_failures || []);
      this.customWeights = data.custom_weights || this.customWeights;

      return true;
    } catch (_) {
      return false;
    }
  }

  /**
   * Reset the brain (clear all data, keep target_id).
   */
  reset() {
    this.historicalFindings = [];
    this.assetGraph = { endpoints: [], cookies: [], websockets: [], forms: [], relationships: [] };
    this.workflowGraph = [];
    this.authModels = [];
    this.verificationHistory = [];
    this.coverageTrend = [];
    this.findingTrend = [];
    this.verificationTrend = [];
    this.categorySuccessRates.clear();
    this.hypothesisSuccessMap.clear();
    this.hypothesisFailureMap.clear();
    this.total_sessions = 0;
    this.total_campaigns = 0;
    this.updated_at = Date.now();
  }
}

// =====================================================================
//  BrainRegistry — manages brains for all targets
// =====================================================================

class BrainRegistry {
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;

    /** @type {Map<string, TargetBrain>} target_id → brain */
    this.brains = new Map();

    // Ensure directory exists
    fs.mkdirSync(BRAINS_DIR, { recursive: true });

    // Auto-load all existing brains
    this._loadAll();
  }

  /**
   * Get or create a brain for a target.
   *
   * @param {string} targetId
   * @returns {TargetBrain}
   */
  getOrCreate(targetId) {
    if (!this.brains.has(targetId)) {
      const brain = new TargetBrain({ targetId, knowledgeBase: this.kb });
      this.brains.set(targetId, brain);
    }
    return this.brains.get(targetId);
  }

  /**
   * Get a brain (returns null if not found).
   *
   * @param {string} targetId
   * @returns {TargetBrain|null}
   */
  get(targetId) {
    return this.brains.get(targetId) || null;
  }

  /**
   * List all brains.
   * @returns {object[]} brain summaries
   */
  list() {
    return [...this.brains.values()].map(b => ({
      target_id: b.targetId,
      findings: b.historicalFindings.length,
      assets: b.assetGraph.endpoints.length,
      sessions: b.total_sessions,
      coverage: b.coverageTrend.length > 0
        ? b.coverageTrend[b.coverageTrend.length - 1].score
        : 0,
      updated_at: b.updated_at,
    }));
  }

  /**
   * Save all brains.
   * @returns {number} number of brains saved
   */
  saveAll() {
    let count = 0;
    for (const brain of this.brains.values()) {
      brain.save();
      count++;
    }
    return count;
  }

  /**
   * Load all brains from disk.
   * @private
   */
  _loadAll() {
    if (!fs.existsSync(BRAINS_DIR)) return;

    const files = fs.readdirSync(BRAINS_DIR).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(BRAINS_DIR, file), 'utf8'));
        if (data.target_id) {
          const brain = new TargetBrain({ targetId: data.target_id, knowledgeBase: this.kb });
          this.brains.set(data.target_id, brain);
        }
      } catch (_) {}
    }
  }
}

module.exports = { TargetBrain, BrainRegistry, BRAINS_DIR };


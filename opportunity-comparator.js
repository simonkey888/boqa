/**
 * BOQA opportunity-comparator.js — OpportunityComparator v1.2
 *
 * Cross-class scoring between different opportunity types using
 * multi-objective Pareto optimization with weighted normalization.
 *
 * The key problem this solves: different opportunity classes
 * (SSL/TLS feeds, DeFi yield, bug bounty, data APIs) produce
 * incomparable raw scores. The OpportunityComparator normalizes
 * across dimensions and produces a Pareto-optimal frontier,
 * then applies weighted preferences to produce a single ranked
 * opportunity matrix.
 *
 * Comparison dimensions:
 *   1. Expected Value (EV) — projected return
 *   2. Risk-Adjusted Yield — return per unit risk
 *   3. Capital Efficiency — return per unit capital
 *   4. Time Efficiency — return per unit time
 *   5. Competition Edge — advantage over competitors
 *   6. Signal Confidence — quality of supporting data
 *
 * Method:
 *   1. Normalize each dimension to [0, 1] across all opportunities
 *   2. Identify Pareto frontier (non-dominated solutions)
 *   3. Apply weighted preferences per decision profile
 *   4. Rank within frontier, then rank dominated set
 *   5. Produce ranked_opportunity_matrix
 *
 * Safe mode: all comparisons are analytical; no real-world
 * resource allocation or commitment is made.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const OC_DIR = path.join(__dirname, 'output', 'knowledge', 'comparator');

// ─── Constants ──────────────────────────────────────────────────────

const COMPARISON_DIMENSIONS = {
  EXPECTED_VALUE:      'expected_value',
  RISK_ADJUSTED_YIELD: 'risk_adjusted_yield',
  CAPITAL_EFFICIENCY:  'capital_efficiency',
  TIME_EFFICIENCY:     'time_efficiency',
  COMPETITION_EDGE:    'competition_edge',
  SIGNAL_CONFIDENCE:   'signal_confidence',
};

const DECISION_PROFILES = {
  CONSERVATIVE: {
    label: 'Conservative — minimize risk, maximize confidence',
    weights: {
      expected_value: 0.15,
      risk_adjusted_yield: 0.25,
      capital_efficiency: 0.15,
      time_efficiency: 0.10,
      competition_edge: 0.10,
      signal_confidence: 0.25,
    },
  },
  BALANCED: {
    label: 'Balanced — equal weighting across dimensions',
    weights: {
      expected_value: 0.20,
      risk_adjusted_yield: 0.20,
      capital_efficiency: 0.15,
      time_efficiency: 0.15,
      competition_edge: 0.15,
      signal_confidence: 0.15,
    },
  },
  AGGRESSIVE: {
    label: 'Aggressive — maximize expected value and edge',
    weights: {
      expected_value: 0.30,
      risk_adjusted_yield: 0.10,
      capital_efficiency: 0.15,
      time_efficiency: 0.15,
      competition_edge: 0.20,
      signal_confidence: 0.10,
    },
  },
  YIELD_FOCUSED: {
    label: 'Yield Focused — maximize risk-adjusted returns',
    weights: {
      expected_value: 0.20,
      risk_adjusted_yield: 0.35,
      capital_efficiency: 0.20,
      time_efficiency: 0.10,
      competition_edge: 0.05,
      signal_confidence: 0.10,
    },
  },
  SPEED_FOCUSED: {
    label: 'Speed Focused — minimize time to revenue',
    weights: {
      expected_value: 0.15,
      risk_adjusted_yield: 0.15,
      capital_efficiency: 0.15,
      time_efficiency: 0.30,
      competition_edge: 0.10,
      signal_confidence: 0.15,
    },
  },
};

const DEFAULT_OPTIONS = {
  maxOpportunities: 500,
  defaultProfile: 'BALANCED',
  minNormalizationSamples: 2,
  paretoEpsilon: 0.001,          // Tolerance for Pareto dominance
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  NormalizedOpportunity
// =====================================================================

class NormalizedOpportunity {
  constructor(data = {}) {
    this.opportunity_id     = data.opportunity_id || null;
    this.opportunity_class  = data.opportunity_class || null;
    this.target_id          = data.target_id || null;

    // Raw dimension values
    this.raw = data.raw || {};

    // Normalized dimension values [0, 1]
    this.normalized = data.normalized || {};

    // Composite score
    this.composite_score    = data.composite_score ?? 0;
    this.rank               = data.rank ?? 0;
    this.is_pareto_optimal  = data.is_pareto_optimal ?? false;
    this.dominated_by       = data.dominated_by || 0;

    this.computed_at        = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  ComparisonMatrix
// =====================================================================

class ComparisonMatrix {
  constructor() {
    this.opportunities = [];
    this.pareto_frontier = [];
    this.dominated_set = [];
    this.normalization_ranges = {};
    this.profile_used = null;
    this.computed_at = null;
  }

  toJSON() {
    return {
      opportunity_count: this.opportunities.length,
      pareto_count: this.pareto_frontier.length,
      dominated_count: this.dominated_set.length,
      normalization_ranges: this.normalization_ranges,
      profile_used: this.profile_used,
      computed_at: this.computed_at,
      opportunities: this.opportunities.map(o => o.toJSON ? o.toJSON() : o),
    };
  }
}

// =====================================================================
//  OpportunityComparator
// =====================================================================

class OpportunityComparator {
  /**
   * @param {object} options
   * @param {object} [options.economicValueEngine] - EconomicValueEngine instance
   */
  constructor(options = {}) {
    this.economicValueEngine = options.economicValueEngine || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Active decision profile
    this.activeProfile = this.options.defaultProfile;

    /** @type {ComparisonMatrix|null} */
    this.lastMatrix = null;

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_comparisons: 0,
      total_pareto_optimal: 0,
      avg_composite_score: 0,
      comparisons_by_profile: {},
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(OC_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Profile Management ────────────────────────────────────────────

  /**
   * Set the active decision profile.
   * @param {string} profileName - One of DECISION_PROFILES keys
   * @returns {boolean}
   */
  setProfile(profileName) {
    if (!DECISION_PROFILES[profileName]) return false;
    this.activeProfile = profileName;
    return true;
  }

  /**
   * Get the active profile.
   * @returns {object}
   */
  getActiveProfile() {
    return {
      name: this.activeProfile,
      ...DECISION_PROFILES[this.activeProfile],
    };
  }

  /**
   * List all available profiles.
   * @returns {object[]}
   */
  listProfiles() {
    return Object.entries(DECISION_PROFILES).map(([name, profile]) => ({
      name,
      label: profile.label,
      weights: profile.weights,
    }));
  }

  // ─── Comparison Engine ─────────────────────────────────────────────

  /**
   * Compare opportunities across classes using multi-objective Pareto.
   *
   * @param {object[]} economicScores - Array of EconomicScore objects
   * @param {string} [profileName] - Override decision profile
   * @returns {ComparisonMatrix}
   */
  compare(economicScores, profileName) {
    const profile = DECISION_PROFILES[profileName || this.activeProfile];
    if (!profile) throw new Error(`Unknown profile: ${profileName}`);

    if (economicScores.length === 0) {
      return new ComparisonMatrix();
    }

    const matrix = new ComparisonMatrix();
    matrix.profile_used = profileName || this.activeProfile;

    // Step 1: Extract raw dimension values
    const rawItems = economicScores.map(sc => this._extractDimensions(sc));

    // Step 2: Normalize each dimension to [0, 1]
    const ranges = this._computeNormalizationRanges(rawItems);
    matrix.normalization_ranges = ranges;

    const normalizedItems = rawItems.map(item => ({
      opportunity_id: item.opportunity_id,
      opportunity_class: item.opportunity_class,
      target_id: item.target_id,
      raw: item.dimensions,
      normalized: this._normalizeDimensions(item.dimensions, ranges),
    }));

    // Step 3: Compute Pareto frontier
    const { frontier, dominated } = this._computeParetoFrontier(normalizedItems);

    // Step 4: Compute composite scores using profile weights
    for (const item of normalizedItems) {
      item.composite_score = this._computeCompositeScore(item.normalized, profile.weights);
      item.is_pareto_optimal = frontier.some(f => f.opportunity_id === item.opportunity_id);
      item.dominated_by = this._countDominators(item, normalizedItems);
    }

    // Step 5: Rank (frontier first, then dominated)
    const ranked = normalizedItems.sort((a, b) => {
      // Pareto optimal items rank higher
      if (a.is_pareto_optimal && !b.is_pareto_optimal) return -1;
      if (!a.is_pareto_optimal && b.is_pareto_optimal) return 1;
      // Within same tier, rank by composite score
      return b.composite_score - a.composite_score;
    });

    ranked.forEach((item, idx) => { item.rank = idx + 1; });

    matrix.opportunities = ranked.map(item => new NormalizedOpportunity(item));
    matrix.pareto_frontier = matrix.opportunities.filter(o => o.is_pareto_optimal);
    matrix.dominated_set = matrix.opportunities.filter(o => !o.is_pareto_optimal);
    matrix.computed_at = Date.now();

    // Update metrics
    this.lastMatrix = matrix;
    this.metrics.total_comparisons++;
    this.metrics.total_pareto_optimal = matrix.pareto_frontier.length;
    this.metrics.avg_composite_score = matrix.opportunities.length > 0
      ? Math.round(matrix.opportunities.reduce((s, o) => s + o.composite_score, 0) / matrix.opportunities.length * 1000) / 1000
      : 0;
    this.metrics.comparisons_by_profile[matrix.profile_used] =
      (this.metrics.comparisons_by_profile[matrix.profile_used] || 0) + 1;

    return matrix;
  }

  /**
   * Compare all scored opportunities from the EconomicValueEngine.
   * @param {string} [profileName] - Override decision profile
   * @returns {ComparisonMatrix}
   */
  compareAll(profileName) {
    if (!this.economicValueEngine) {
      throw new Error('EconomicValueEngine not connected');
    }

    const scores = [...this.economicValueEngine.scores.values()];
    return this.compare(scores, profileName);
  }

  // ─── Dimension Extraction ──────────────────────────────────────────

  _extractDimensions(economicScore) {
    const sc = economicScore;
    const capital = Math.max(1, sc.capital_required || 1);
    const ttr = Math.max(1, sc.time_to_revenue_days || 1);

    return {
      opportunity_id: sc.opportunity_id,
      opportunity_class: sc.opportunity_class,
      target_id: sc.target_id,
      dimensions: {
        [COMPARISON_DIMENSIONS.EXPECTED_VALUE]: sc.expected_value || 0,
        [COMPARISON_DIMENSIONS.RISK_ADJUSTED_YIELD]: sc.risk_adjusted_yield || 0,
        [COMPARISON_DIMENSIONS.CAPITAL_EFFICIENCY]: (sc.expected_value || 0) / capital,
        [COMPARISON_DIMENSIONS.TIME_EFFICIENCY]: (sc.expected_value || 0) / ttr,
        [COMPARISON_DIMENSIONS.COMPETITION_EDGE]: Math.max(0, 1 - (sc.competition_pressure || 0) / 15),
        [COMPARISON_DIMENSIONS.SIGNAL_CONFIDENCE]: sc.confidence || 0.5,
      },
    };
  }

  _computeNormalizationRanges(rawItems) {
    const ranges = {};
    const dims = Object.values(COMPARISON_DIMENSIONS);

    for (const dim of dims) {
      const values = rawItems.map(item => item.dimensions[dim] || 0);
      const min = Math.min(...values);
      const max = Math.max(...values);
      ranges[dim] = {
        min,
        max,
        range: max - min || 1,  // Avoid division by zero
      };
    }

    return ranges;
  }

  _normalizeDimensions(dimensions, ranges) {
    const normalized = {};
    for (const [dim, value] of Object.entries(dimensions)) {
      const range = ranges[dim];
      if (!range) {
        normalized[dim] = 0.5; // Default to middle if no range
      } else {
        normalized[dim] = (value - range.min) / range.range;
        normalized[dim] = Math.max(0, Math.min(1, normalized[dim]));
      }
    }
    return normalized;
  }

  // ─── Pareto Frontier ──────────────────────────────────────────────

  _computeParetoFrontier(items) {
    const frontier = [];
    const dominated = [];
    const epsilon = this.options.paretoEpsilon;

    for (let i = 0; i < items.length; i++) {
      let isDominated = false;

      for (let j = 0; j < items.length; j++) {
        if (i === j) continue;
        if (this._dominates(items[j].normalized, items[i].normalized, epsilon)) {
          isDominated = true;
          break;
        }
      }

      if (isDominated) {
        dominated.push(items[i]);
      } else {
        frontier.push(items[i]);
      }
    }

    return { frontier, dominated };
  }

  /**
   * Check if point a dominates point b.
   * a dominates b if a is >= b on all dimensions AND strictly > on at least one.
   */
  _dominates(normA, normB, epsilon = 0) {
    const dims = Object.values(COMPARISON_DIMENSIONS);
    let atLeastOneStrictlyBetter = false;

    for (const dim of dims) {
      const a = normA[dim] ?? 0;
      const b = normB[dim] ?? 0;
      if (a + epsilon < b) return false;  // a is worse on this dimension
      if (a > b + epsilon) atLeastOneStrictlyBetter = true;
    }

    return atLeastOneStrictlyBetter;
  }

  _countDominators(item, allItems) {
    let count = 0;
    for (const other of allItems) {
      if (other.opportunity_id === item.opportunity_id) continue;
      if (this._dominates(other.normalized, item.normalized, this.options.paretoEpsilon)) {
        count++;
      }
    }
    return count;
  }

  // ─── Composite Scoring ─────────────────────────────────────────────

  _computeCompositeScore(normalizedDims, weights) {
    let score = 0;
    for (const [dim, weight] of Object.entries(weights)) {
      score += (normalizedDims[dim] ?? 0) * weight;
    }
    return Math.round(score * 1000) / 1000;
  }

  /**
   * Compare the same set of opportunities across multiple profiles.
   * @param {object[]} economicScores
   * @returns {object} profile_name → ranked list
   */
  compareAcrossProfiles(economicScores) {
    const results = {};
    for (const profileName of Object.keys(DECISION_PROFILES)) {
      const matrix = this.compare(economicScores, profileName);
      results[profileName] = matrix.opportunities.map(o => ({
        opportunity_id: o.opportunity_id,
        opportunity_class: o.opportunity_class,
        composite_score: o.composite_score,
        rank: o.rank,
        is_pareto_optimal: o.is_pareto_optimal,
      }));
    }
    return results;
  }

  // ─── Query ──────────────────────────────────────────────────────────

  /**
   * Get the ranked opportunity matrix.
   * @param {object} [filter] - { opportunity_class, min_rank, pareto_only }
   * @returns {NormalizedOpportunity[]}
   */
  getRankedOpportunities(filter = {}) {
    if (!this.lastMatrix) return [];

    let items = this.lastMatrix.opportunities;

    if (filter.opportunity_class) {
      items = items.filter(o => o.opportunity_class === filter.opportunity_class);
    }
    if (filter.min_rank !== undefined) {
      items = items.filter(o => o.rank <= filter.min_rank);
    }
    if (filter.pareto_only) {
      items = items.filter(o => o.is_pareto_optimal);
    }

    return items;
  }

  /**
   * Get the Pareto frontier.
   * @returns {NormalizedOpportunity[]}
   */
  getParetoFrontier() {
    return this.lastMatrix ? this.lastMatrix.pareto_frontier : [];
  }

  getMetrics() {
    return { ...this.metrics };
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(OC_DIR, 'comparator-state.json');
    const data = {
      version: '1.2',
      saved_at: Date.now(),
      active_profile: this.activeProfile,
      last_matrix: this.lastMatrix ? this.lastMatrix.toJSON() : null,
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(OC_DIR, 'comparator-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.active_profile && DECISION_PROFILES[data.active_profile]) {
        this.activeProfile = data.active_profile;
      }
      if (data.last_matrix) {
        this.lastMatrix = new ComparisonMatrix();
        this.lastMatrix.profile_used = data.last_matrix.profile_used;
        this.last_matrix.computed_at = data.last_matrix.computed_at;
        if (data.last_matrix.opportunities) {
          this.lastMatrix.opportunities = data.last_matrix.opportunities.map(o => new NormalizedOpportunity(o));
          this.lastMatrix.pareto_frontier = this.lastMatrix.opportunities.filter(o => o.is_pareto_optimal);
          this.lastMatrix.dominated_set = this.lastMatrix.opportunities.filter(o => !o.is_pareto_optimal);
        }
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.lastMatrix = null;
    this.activeProfile = this.options.defaultProfile || 'BALANCED';
    this.metrics = {
      total_comparisons: 0, total_pareto_optimal: 0,
      avg_composite_score: 0, comparisons_by_profile: {},
    };
    // Clear persisted file to prevent stale state on next load
    const filePath = path.join(OC_DIR, 'comparator-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  OpportunityComparator,
  NormalizedOpportunity,
  ComparisonMatrix,
  COMPARISON_DIMENSIONS,
  DECISION_PROFILES,
};


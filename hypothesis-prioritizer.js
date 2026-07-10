/**
 * BOQA hypothesis-prioritizer.js — Hypothesis Prioritizer v0.6
 *
 * Ranks hypotheses by their expected validation value (EVV),
 * which is the product of:
 *   - severity:          impact if confirmed (0-100)
 *   - confidence:        likelihood based on evidence (0-100)
 *   - coverage_gap:      how much this fills a coverage gap (0-100)
 *   - historical_success:  past validation rate for similar categories (0-100)
 *
 * EVV = severity(0.30) + confidence(0.30) + coverage_gap(0.20) + historical_success(0.20)
 *
 * The prioritizer also considers:
 *   - verification cost:  how expensive it is to validate (lower cost = higher priority)
 *   - dependency order:   some hypotheses depend on others being validated first
 *   - deduplication:      similar hypotheses are grouped and the strongest is promoted
 *
 * Output: ordered list of hypotheses with EVV scores, ready for
 *         the verification farm.
 *
 * Safe mode: never promotes hypotheses that would require forbidden
 * actions (credential_attacks, bruteforce, dos, etc.)
 */

const crypto = require('crypto');

// ─── EVV Weights ────────────────────────────────────────────────────

const EVV_WEIGHTS = {
  severity:           0.30,
  confidence:         0.30,
  coverage_gap:       0.20,
  historical_success: 0.20,
};

// ─── Severity Score Map ─────────────────────────────────────────────

const SEVERITY_SCORES = {
  critical: 100,
  high:      80,
  medium:    50,
  low:       25,
  info:      10,
};

// ─── Verification Cost Tiers ────────────────────────────────────────

const COST_TIERS = {
  low:    { cost: 20, description: 'single navigation, passive check' },
  medium: { cost: 50, description: 'replay + state comparison' },
  high:   { cost: 80, description: 'multi-step workflow validation' },
};

// ─── Safe Mode Forbidden Categories ─────────────────────────────────

const FORBIDDEN_CATEGORIES = new Set([
  'credential_attack',
  'bruteforce',
  'dos',
  'privilege_escalation',
  'mass_scan',
  'destructive',
]);

// =====================================================================
//  HypothesisPrioritizer
// =====================================================================

class HypothesisPrioritizer {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]   - KnowledgeBase for historical rates
   * @param {object} [options.coverageEngine]   - CoverageEngine for gap analysis
   * @param {object} [options.weights]          - Custom EVV weight overrides
   * @param {number} [options.maxHypotheses]    - Max hypotheses to track (default 5000)
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.coverageEngine = options.coverageEngine || null;
    this.weights = { ...EVV_WEIGHTS, ...(options.weights || {}) };
    this.maxHypotheses = options.maxHypotheses || 5000;

    /** @type {Map<string, object>} hypothesis_id → hypothesis with EVV */
    this.hypotheses = new Map();

    /** @type {object[]} current prioritized queue (sorted by EVV desc) */
    this.priorityQueue = [];

    /** @type {Map<string, string[]>} hypothesis_id → dependency_ids */
    this.dependencies = new Map();

    /** @type {Set<string>} validated hypothesis IDs */
    this.validated = new Set();

    /** @type {Set<string>} rejected hypothesis IDs */
    this.rejected = new Set();

    /** @type {Map<string, object>} group_key → group of similar hypotheses */
    this._groups = new Map();

    // Normalize weights
    const sum = Object.values(this.weights).reduce((a, b) => a + b, 0);
    if (sum > 0) {
      for (const key of Object.keys(this.weights)) {
        this.weights[key] = this.weights[key] / sum;
      }
    }
  }

  // ─── Hypothesis Submission ────────────────────────────────────────

  /**
   * Submit a new hypothesis for prioritization.
   *
   * @param {object} hypothesis
   * @param {string} [hypothesis.id]
   * @param {string} hypothesis.title       - descriptive title
   * @param {string} hypothesis.category    - finding category
   * @param {string} [hypothesis.severity]  - critical|high|medium|low|info
   * @param {number} [hypothesis.confidence] - 0-100
   * @param {string} [hypothesis.target_id] - target this applies to
   * @param {string[]} [hypothesis.affected_cookies]
   * @param {string[]} [hypothesis.affected_endpoints]
   * @param {string} [hypothesis.verification_cost] - low|medium|high
   * @param {string[]} [hypothesis.depends_on] - IDs of prerequisite hypotheses
   * @param {string} [hypothesis.description]
   * @param {object} [hypothesis.evidence]  - supporting evidence
   * @returns {object} the prioritized hypothesis with EVV score
   */
  submit(hypothesis) {
    if (!hypothesis || typeof hypothesis !== 'object') {
      throw new Error('Hypothesis must be an object');
    }

    // Safe mode check
    if (FORBIDDEN_CATEGORIES.has(hypothesis.category)) {
      return null; // silently reject forbidden hypotheses
    }

    const id = hypothesis.id || `HYP-${crypto.randomUUID().substring(0, 8)}`;

    // Compute component scores
    const severityScore = this._computeSeverity(hypothesis.severity);
    const confidenceScore = this._computeConfidence(
      hypothesis.confidence, hypothesis.evidence
    );
    const coverageGapScore = this._computeCoverageGap(
      hypothesis.target_id, hypothesis.category, hypothesis.affected_endpoints
    );
    const historicalScore = this._computeHistoricalSuccess(hypothesis.category);

    // Compute EVV
    const evv = Math.round(
      severityScore * this.weights.severity +
      confidenceScore * this.weights.confidence +
      coverageGapScore * this.weights.coverage_gap +
      historicalScore * this.weights.historical_success
    );

    // Cost adjustment: lower cost = effectively higher priority
    const costMultiplier = this._costMultiplier(hypothesis.verification_cost);
    const adjustedEvv = Math.round(evv * costMultiplier);

    // Build the prioritized hypothesis
    const prioritized = {
      id,
      title: hypothesis.title || 'Untitled Hypothesis',
      category: hypothesis.category || 'unknown',
      severity: hypothesis.severity || 'medium',
      target_id: hypothesis.target_id || null,
      affected_cookies: hypothesis.affected_cookies || [],
      affected_endpoints: hypothesis.affected_endpoints || [],
      description: hypothesis.description || '',
      evidence: hypothesis.evidence || null,

      // Computed scores
      evv: adjustedEvv,
      component_scores: {
        severity: severityScore,
        confidence: confidenceScore,
        coverage_gap: coverageGapScore,
        historical_success: historicalScore,
      },
      verification_cost: hypothesis.verification_cost || 'medium',
      cost_multiplier: costMultiplier,

      // Lifecycle
      status: 'pending', // pending | validating | confirmed | rejected | deferred
      submitted_at: Date.now(),
      depends_on: hypothesis.depends_on || [],

      // Dedup group
      group_key: null,
    };

    // Group similar hypotheses
    const groupKey = this._computeGroupKey(hypothesis);
    prioritized.group_key = groupKey;

    if (!this._groups.has(groupKey)) {
      this._groups.set(groupKey, []);
    }
    this._groups.get(groupKey).push(id);

    // Store
    this.hypotheses.set(id, prioritized);

    // Persist to knowledge base
    if (this.kb) {
      this.kb.upsertHypothesis(prioritized);
    }

    // Rebuild priority queue
    this._rebuildQueue();

    return prioritized;
  }

  /**
   * Submit multiple hypotheses at once.
   *
   * @param {object[]} hypotheses
   * @returns {object[]} prioritized hypotheses
   */
  submitBatch(hypotheses) {
    const results = [];
    for (const h of hypotheses) {
      const result = this.submit(h);
      if (result) results.push(result);
    }
    return results;
  }

  // ─── Priority Queue ──────────────────────────────────────────────

  /**
   * Get the next N hypotheses to validate, sorted by EVV descending.
   * Respects dependency ordering — a hypothesis won't be returned
   * until its dependencies are validated.
   *
   * @param {number} [limit=10]
   * @returns {object[]} ready-to-validate hypotheses
   */
  getNext(limit = 10) {
    const ready = [];

    for (const h of this.priorityQueue) {
      if (ready.length >= limit) break;
      if (h.status !== 'pending') continue;

      // Check dependencies
      const depsMet = (h.depends_on || []).every(depId => {
        return this.validated.has(depId) || this.rejected.has(depId);
      });

      if (!depsMet) continue;

      // Check that at least one dependency is validated (not all rejected)
      if (h.depends_on && h.depends_on.length > 0) {
        const anyValidated = h.depends_on.some(depId => this.validated.has(depId));
        const anyRejected = h.depends_on.every(depId => this.rejected.has(depId));
        if (anyRejected && !anyValidated) {
          h.status = 'deferred';
          continue;
        }
      }

      ready.push({ ...h });
    }

    return ready;
  }

  /**
   * Mark a hypothesis as validated (confirmed or rejected).
   *
   * @param {string} hypothesisId
   * @param {string} verdict - 'confirmed' | 'rejected' | 'inconclusive'
   * @param {object} [result] - validation result details
   * @returns {object|null} updated hypothesis
   */
  setVerdict(hypothesisId, verdict, result = {}) {
    const hypothesis = this.hypotheses.get(hypothesisId);
    if (!hypothesis) return null;

    hypothesis.status = verdict === 'confirmed' ? 'confirmed' :
                        verdict === 'rejected' ? 'rejected' : 'pending';

    if (verdict === 'confirmed') {
      this.validated.add(hypothesisId);
    } else if (verdict === 'rejected') {
      this.rejected.add(hypothesisId);
    }

    hypothesis.verdict = verdict;
    hypothesis.verdict_at = Date.now();
    hypothesis.validation_result = result;

    // Update knowledge base
    if (this.kb) {
      this.kb.upsertHypothesis(hypothesis);
    }

    this._rebuildQueue();
    return hypothesis;
  }

  // ─── Queries ─────────────────────────────────────────────────────

  /**
   * Get all hypotheses, optionally filtered.
   *
   * @param {object} [filter] - { status, category, target_id, min_evv }
   * @returns {object[]
   */
  query(filter = {}) {
    let results = [...this.hypotheses.values()];

    if (filter.status) {
      results = results.filter(h => h.status === filter.status);
    }
    if (filter.category) {
      results = results.filter(h => h.category === filter.category);
    }
    if (filter.target_id) {
      results = results.filter(h => h.target_id === filter.target_id);
    }
    if (filter.min_evv) {
      results = results.filter(h => h.evv >= filter.min_evv);
    }

    results.sort((a, b) => b.evv - a.evv);
    return results;
  }

  /**
   * Get aggregate statistics.
   * @returns {object}
   */
  getStats() {
    const all = [...this.hypotheses.values()];
    const pending = all.filter(h => h.status === 'pending').length;
    const confirmed = all.filter(h => h.status === 'confirmed').length;
    const rejected = all.filter(h => h.status === 'rejected').length;
    const deferred = all.filter(h => h.status === 'deferred').length;

    const avgEvv = all.length > 0
      ? Math.round(all.reduce((s, h) => s + h.evv, 0) / all.length)
      : 0;

    const avgConfirmedEvv = confirmed > 0
      ? Math.round(all.filter(h => h.status === 'confirmed').reduce((s, h) => s + h.evv, 0) / confirmed)
      : 0;

    // Top categories
    const categoryCounts = {};
    for (const h of all) {
      categoryCounts[h.category] = (categoryCounts[h.category] || 0) + 1;
    }

    // Group stats
    const totalGroups = this._groups.size;
    const multiGroups = [...this._groups.values()].filter(g => g.length > 1).length;

    return {
      total: all.length,
      by_status: { pending, confirmed, rejected, deferred },
      avg_evv: avgEvv,
      avg_confirmed_evv: avgConfirmedEvv,
      confirmation_rate: all.length > 0 ? Math.round((confirmed / (confirmed + rejected || 1)) * 100) : 0,
      category_counts: categoryCounts,
      dedup_groups: totalGroups,
      dedup_multi_groups: multiGroups,
    };
  }

  /**
   * Get hypothesis groups (dedup clusters).
   * @returns {object[]}
   */
  getGroups() {
    const groups = [];
    for (const [key, ids] of this._groups) {
      const members = ids.map(id => this.hypotheses.get(id)).filter(Boolean);
      if (members.length === 0) continue;

      // Pick the representative (highest EVV)
      members.sort((a, b) => b.evv - a.evv);
      const representative = members[0];

      groups.push({
        group_key: key,
        representative: representative.id,
        representative_evv: representative.evv,
        member_count: members.length,
        member_ids: ids,
      });
    }

    groups.sort((a, b) => b.representative_evv - a.representative_evv);
    return groups;
  }

  // ─── Internal ────────────────────────────────────────────────────

  /**
   * Rebuild the priority queue from all pending hypotheses.
   * @private
   */
  _rebuildQueue() {
    this.priorityQueue = [...this.hypotheses.values()]
      .filter(h => h.status === 'pending' || h.status === 'validating')
      .sort((a, b) => {
        // Primary: EVV descending
        if (b.evv !== a.evv) return b.evv - a.evv;
        // Secondary: lower cost first
        const costOrder = { low: 0, medium: 1, high: 2 };
        return (costOrder[a.verification_cost] || 1) - (costOrder[b.verification_cost] || 1);
      });
  }

  /**
   * Compute severity score (0-100).
   * @param {string|number} severity
   * @returns {number}
   * @private
   */
  _computeSeverity(severity) {
    if (typeof severity === 'number') return Math.max(0, Math.min(100, severity));
    return SEVERITY_SCORES[severity] || 50;
  }

  /**
   * Compute confidence score (0-100).
   * Enhanced by evidence quality.
   *
   * @param {number} confidence - raw confidence
   * @param {object} evidence
   * @returns {number}
   * @private
   */
  _computeConfidence(confidence, evidence) {
    let score = typeof confidence === 'number' ? confidence : 50;

    // Boost based on evidence
    if (evidence) {
      if (evidence.request_response) score = Math.min(100, score + 10);
      if (evidence.timeline) score = Math.min(100, score + 5);
      if (evidence.reproduction_steps) score = Math.min(100, score + 15);
      if (evidence.cross_session) score = Math.min(100, score + 10);
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Compute coverage gap score (0-100).
   * Higher when the hypothesis targets an uncovered area.
   *
   * @param {string} targetId
   * @param {string} category
   * @param {string[]} endpoints
   * @returns {number}
   * @private
   */
  _computeCoverageGap(targetId, category, endpoints) {
    if (!this.coverageEngine || !targetId) return 50; // neutral

    const gaps = this.coverageEngine.getCoverageGaps(targetId);
    if (gaps.length === 0) return 30; // well-covered, low gap

    // Map category to domain
    const categoryDomainMap = {
      'auth_bypass': 'auth_flows',
      'session_hijacking': 'auth_flows',
      'csrf': 'auth_flows',
      'cookie_security': 'auth_flows',
      'api_exposure': 'api_endpoints',
      'idor': 'api_endpoints',
      'insecure_direct_object': 'api_endpoints',
      'websocket_hijacking': 'websocket_channels',
      'xss': 'forms',
      'injection': 'forms',
    };

    const relevantDomain = categoryDomainMap[category];
    if (relevantDomain) {
      const gap = gaps.find(g => g.domain === relevantDomain);
      if (gap) return Math.min(100, gap.gap * 2);
    }

    // Use the average gap
    const avgGap = gaps.reduce((sum, g) => sum + g.gap, 0) / gaps.length;
    return Math.min(100, Math.round(avgGap * 1.5));
  }

  /**
   * Compute historical success score (0-100).
   * Based on past validation rates for similar categories.
   *
   * @param {string} category
   * @returns {number}
   * @private
   */
  _computeHistoricalSuccess(category) {
    if (!this.kb) return 50; // neutral without history

    const rate = this.kb.getHistoricalValidationRate(category);
    // Scale rate (0-1) to score (0-100)
    return Math.round(rate * 100);
  }

  /**
   * Compute cost multiplier.
   * Low cost = higher effective EVV.
   *
   * @param {string} cost - low|medium|high
   * @returns {number} multiplier 0.8 - 1.2
   * @private
   */
  _costMultiplier(cost) {
    switch (cost) {
      case 'low': return 1.2;
      case 'high': return 0.8;
      case 'medium':
      default: return 1.0;
    }
  }

  /**
   * Compute a dedup group key for similar hypotheses.
   *
   * @param {object} hypothesis
   * @returns {string}
   * @private
   */
  _computeGroupKey(hypothesis) {
    const category = (hypothesis.category || '').toLowerCase();
    const cookies = [...(hypothesis.affected_cookies || [])].sort().join(',');
    const endpoints = [...(hypothesis.affected_endpoints || [])]
      .map(e => {
        try { return new URL(e).pathname; } catch { return e; }
      })
      .sort()
      .join(',');

    const raw = `${category}|${cookies}|${endpoints}`;
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 12);
  }
}

module.exports = { HypothesisPrioritizer };


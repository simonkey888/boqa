/**
 * BOQA ranking.js — Ranking Engine v0.5
 *
 * Prioritizes findings by severity, confidence, and business impact.
 * Composite scoring using weighted formula across five dimensions:
 *   severity, confidence, reproducibility, asset_criticality, evidence
 *
 * Bug lifecycle state machine:
 *   observed → hypothesis → validated → confirmed → ranked →
 *   disclosure_ready → submitted → resolved
 *   (skip-ahead allowed; backward only via resolved → observed for regression)
 *
 * Ranking formula weights:
 *   severity:       0.35
 *   confidence:     0.25
 *   reproducibility:0.15
 *   asset_criticality:0.15
 *   evidence:       0.10
 *
 * Ranked finding schema:
 *   finding_id, rank_score (0-100), rank (1-N),
 *   component_scores { severity, confidence, reproducibility,
 *                      asset_criticality, evidence },
 *   lifecycle_state, disclosure_ready, ranked_at
 */

const fs   = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const RANKINGS_DIR = path.join(__dirname, 'output', 'rankings');
fs.mkdirSync(RANKINGS_DIR, { recursive: true });

// ─── Default Weights ────────────────────────────────────────────────

const DEFAULT_WEIGHTS = {
  severity_weight:          0.35,
  confidence_weight:        0.25,
  reproducibility_weight:   0.15,
  asset_criticality_weight: 0.15,
  evidence_weight:          0.10,
};

// ─── Bug Lifecycle States ───────────────────────────────────────────

const LIFECYCLE_STATES = [
  'observed',
  'hypothesis',
  'validated',
  'confirmed',
  'ranked',
  'disclosure_ready',
  'submitted',
  'resolved',
];

const LIFECYCLE_INDEX = Object.fromEntries(
  LIFECYCLE_STATES.map((s, i) => [s, i])
);

// ─── Severity Mapping ───────────────────────────────────────────────

const SEVERITY_SCORES = {
  critical: 100,
  high:      75,
  medium:    50,
  low:       25,
  info:      10,
};

// ─── Asset Criticality Lookup Tables ────────────────────────────────

const ENVIRONMENT_SCORES = {
  prod:    100,
  staging:  60,
  dev:      30,
};

const ASSET_TYPE_SCORES = {
  auth_endpoint: 100,
  payment:       100,
  user_data:      90,
  api:            70,
  static:         20,
};

const EXPOSURE_SCORES = {
  public:  100,
  admin:    80,
  internal: 50,
};

// ─── Evidence Score Tiers ───────────────────────────────────────────

const EVIDENCE_COUNT_TIERS = [
  { min: 6, score: 90 },
  { min: 4, score: 70 },
  { min: 2, score: 50 },
  { min: 1, score: 20 },
  { min: 0, score:  0 },
];

// ─── Disclosure Thresholds ──────────────────────────────────────────

const DISCLOSURE_MIN_RANK_SCORE       = 60;
const DISCLOSURE_MIN_LIFECYCLE_INDEX  = LIFECYCLE_INDEX['ranked'];
const DISCLOSURE_MIN_EVIDENCE_COUNT   = 2;

// ─── Ranking Threshold for lifecycle advancement ────────────────────

const RANK_THRESHOLD = 25; // findings above this get promoted to 'ranked'

// =====================================================================
//  RankingEngine
// =====================================================================

class RankingEngine {
  /**
   * @param {object} options - Custom weight overrides
   * @param {number} [options.severity_weight]
   * @param {number} [options.confidence_weight]
   * @param {number} [options.reproducibility_weight]
   * @param {number} [options.asset_criticality_weight]
   * @param {number} [options.evidence_weight]
   */
  constructor(options = {}) {
    // Merge custom weights over defaults
    this.weights = { ...DEFAULT_WEIGHTS, ...options };

    // Normalise weights so they always sum to 1.0
    const sum = Object.values(this.weights).reduce((a, b) => a + b, 0);
    if (sum > 0) {
      for (const key of Object.keys(this.weights)) {
        this.weights[key] = this.weights[key] / sum;
      }
    }

    // Internal store: finding_id → ranked finding object
    this.rankedFindings = new Map();

    // Attempt to load persisted data
    this.load();
  }

  // ─── Core Ranking ───────────────────────────────────────────────

  /**
   * Rank a single finding or bug.
   *
   * @param {object} findingOrBug - Finding, bug, or candidate object
   * @param {object} context - Ranking context
   * @param {string|number} [context.asset_criticality] - Environment / asset hint
   * @param {number}  [context.reproducibility_score]   - 0-100 reproducibility
   * @param {number}  [context.evidence_count]           - Number of evidence items
   * @param {string}  [context.target_environment]       - prod | staging | dev
   * @returns {object} ranked result
   */
  rank(findingOrBug, context = {}) {
    const findingId = findingOrBug.finding_id || findingOrBug.id || findingOrBug.bug_id || `FND-${Date.now().toString(36)}`;

    // ── Component scores ──────────────────────────────────────────
    const severityScore        = this.computeSeverityScore(findingOrBug.severity);
    const confidenceScore      = this.computeConfidenceScore(
      findingOrBug.confidence != null ? findingOrBug.confidence : context.confidence
    );
    const reproducibilityScore = this.computeReproducibilityScore({
      reproducibility_score: context.reproducibility_score,
      successful_reproductions: findingOrBug.successful_reproductions,
      total_attempts: findingOrBug.total_attempts,
      independent_sessions: findingOrBug.independent_sessions,
      consistency: findingOrBug.consistency,
      ...context,
    });
    const assetCriticalityScore = this.computeAssetCriticality({
      asset_criticality: context.asset_criticality,
      target_environment: context.target_environment,
      asset_type: findingOrBug.asset_type || context.asset_type,
      exposure: findingOrBug.exposure || context.exposure,
    });
    const evidenceScore = this.computeEvidenceScore({
      evidence_count: context.evidence_count != null ? context.evidence_count : (findingOrBug.evidence_count || (findingOrBug.evidence && findingOrBug.evidence.length) || 0),
      has_reproduction_steps: findingOrBug.has_reproduction_steps != null ? findingOrBug.has_reproduction_steps : (findingOrBug.reproduction && findingOrBug.reproduction.length > 0),
      has_timeline:           findingOrBug.has_timeline != null ? findingOrBug.has_timeline : (findingOrBug.timeline && findingOrBug.timeline.length > 0),
      has_verification_trace: findingOrBug.has_verification_trace != null ? findingOrBug.has_verification_trace : false,
      has_request_response:   findingOrBug.has_request_response != null ? findingOrBug.has_request_response : false,
    });

    // ── Composite weighted score ──────────────────────────────────
    const rankScore = Math.round(
      severityScore         * this.weights.severity_weight +
      confidenceScore       * this.weights.confidence_weight +
      reproducibilityScore  * this.weights.reproducibility_weight +
      assetCriticalityScore * this.weights.asset_criticality_weight +
      evidenceScore         * this.weights.evidence_weight
    );

    // ── Lifecycle state advancement ───────────────────────────────
    let lifecycleState = findingOrBug.lifecycle_state || findingOrBug.state || 'observed';
    if (LIFECYCLE_INDEX[lifecycleState] == null) {
      lifecycleState = 'observed';
    }

    // If currently at or before 'confirmed' and score exceeds threshold, promote to 'ranked'
    if (LIFECYCLE_INDEX[lifecycleState] < LIFECYCLE_INDEX['ranked'] && rankScore >= RANK_THRESHOLD) {
      lifecycleState = 'ranked';
    }

    const disclosureReady = this.isDisclosureReady({
      rank_score:      rankScore,
      lifecycle_state: lifecycleState,
      evidence_count:  context.evidence_count != null ? context.evidence_count : (findingOrBug.evidence_count || 0),
      has_reproduction_steps: findingOrBug.has_reproduction_steps != null
        ? findingOrBug.has_reproduction_steps
        : (findingOrBug.reproduction && findingOrBug.reproduction.length > 0),
    });

    const ranked = {
      finding_id:   findingId,
      rank_score:   rankScore,
      rank:         0, // assigned by rankAll
      component_scores: {
        severity_score:         severityScore,
        confidence_score:       confidenceScore,
        reproducibility_score:  reproducibilityScore,
        asset_criticality_score: assetCriticalityScore,
        evidence_score:         evidenceScore,
      },
      lifecycle_state:  lifecycleState,
      disclosure_ready: disclosureReady,
      ranked_at:        new Date().toISOString(),

      // Preserve original finding fields for reference
      _original: {
        severity:   findingOrBug.severity,
        confidence: findingOrBug.confidence,
        category:   findingOrBug.category,
        title:      findingOrBug.title,
      },
    };

    this.rankedFindings.set(findingId, ranked);
    return ranked;
  }

  /**
   * Rank an array of findings, assign ordinal ranks, sort descending.
   *
   * @param {array}  findings   - Array of finding/bug objects
   * @param {object} contextMap - target_id → context mapping
   * @returns {array} ranked findings sorted by rank_score descending
   */
  rankAll(findings, contextMap = {}) {
    // Rank each finding individually
    const ranked = [];
    for (const f of findings) {
      const targetId   = f.target_id || f.finding_id || f.id || f.bug_id;
      const context    = contextMap[targetId] || {};
      const result     = this.rank(f, context);
      ranked.push(result);
    }

    // Sort descending by rank_score (ties broken by severity_score then confidence_score)
    ranked.sort((a, b) => {
      if (b.rank_score !== a.rank_score) return b.rank_score - a.rank_score;
      const aSev = a.component_scores.severity_score;
      const bSev = b.component_scores.severity_score;
      if (bSev !== aSev) return bSev - aSev;
      return b.component_scores.confidence_score - a.component_scores.confidence_score;
    });

    // Assign ordinal ranks (1-based)
    for (let i = 0; i < ranked.length; i++) {
      ranked[i].rank = i + 1;
      // Update store with assigned rank
      this.rankedFindings.set(ranked[i].finding_id, ranked[i]);
    }

    return ranked;
  }

  // ─── Component Score Computers ──────────────────────────────────

  /**
   * Map severity label to 0-100 numeric score.
   * @param {string} severity - critical|high|medium|low|info
   * @returns {number} 0-100
   */
  computeSeverityScore(severity) {
    if (typeof severity === 'number') return Math.max(0, Math.min(100, severity));
    return SEVERITY_SCORES[severity] != null ? SEVERITY_SCORES[severity] : 10;
  }

  /**
   * Pass-through for confidence value (0-100).
   * @param {number} confidence
   * @returns {number} 0-100
   */
  computeConfidenceScore(confidence) {
    if (typeof confidence !== 'number' || isNaN(confidence)) return 50; // default moderate
    return Math.max(0, Math.min(100, Math.round(confidence)));
  }

  /**
   * Compute reproducibility score (0-100).
   *
   * Considers:
   *   - ratio of successful reproductions to total attempts
   *   - number of independent sessions where observed
   *   - consistency rating (high|medium|low)
   *
   * @param {object} reproInfo
   * @param {number} [reproInfo.reproducibility_score]  - pre-computed 0-100
   * @param {number} [reproInfo.successful_reproductions]
   * @param {number} [reproInfo.total_attempts]
   * @param {number} [reproInfo.independent_sessions]
   * @param {string} [reproInfo.consistency] - high|medium|low
   * @returns {number} 0-100
   */
  computeReproducibilityScore(reproInfo = {}) {
    // If a pre-computed score is provided, use it directly
    if (typeof reproInfo.reproducibility_score === 'number' && !isNaN(reproInfo.reproducibility_score)) {
      return Math.max(0, Math.min(100, Math.round(reproInfo.reproducibility_score)));
    }

    let score = 0;

    // ── Success ratio (0-50 points) ───────────────────────────────
    const successes = reproInfo.successful_reproductions || 0;
    const attempts  = reproInfo.total_attempts || 0;
    if (attempts > 0) {
      const ratio = successes / attempts;
      score += Math.round(ratio * 50);
    } else if (successes > 0) {
      // Has reproductions but no attempt count — assume moderate
      score += 30;
    }

    // ── Independent sessions (0-30 points) ────────────────────────
    const sessions = reproInfo.independent_sessions || 0;
    if (sessions >= 4) score += 30;
    else if (sessions >= 3) score += 25;
    else if (sessions >= 2) score += 20;
    else if (sessions >= 1) score += 10;

    // ── Consistency (0-20 points) ─────────────────────────────────
    const consistency = reproInfo.consistency || 'medium';
    if (consistency === 'high') score += 20;
    else if (consistency === 'medium') score += 10;
    else if (consistency === 'low') score += 3;

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Compute asset criticality score (0-100).
   *
   * Considers:
   *   - environment: prod=100, staging=60, dev=30
   *   - asset type:  auth_endpoint=100, payment=100, user_data=90, api=70, static=20
   *   - exposure:    public=100, admin=80, internal=50
   *
   * @param {object} assetInfo
   * @param {string|number} [assetInfo.asset_criticality] - pre-computed or environment hint
   * @param {string} [assetInfo.target_environment] - prod|staging|dev
   * @param {string} [assetInfo.asset_type]
   * @param {string} [assetInfo.exposure] - public|admin|internal
   * @returns {number} 0-100
   */
  computeAssetCriticality(assetInfo = {}) {
    // Pre-computed numeric value
    if (typeof assetInfo.asset_criticality === 'number' && !isNaN(assetInfo.asset_criticality)) {
      return Math.max(0, Math.min(100, Math.round(assetInfo.asset_criticality)));
    }

    // ── Environment score ─────────────────────────────────────────
    let envScore = 60; // default: staging
    const env = (assetInfo.target_environment || assetInfo.asset_criticality || '').toString().toLowerCase();
    if (ENVIRONMENT_SCORES[env] != null) {
      envScore = ENVIRONMENT_SCORES[env];
    }

    // ── Asset type score ──────────────────────────────────────────
    let typeScore = 50; // default: generic
    const assetType = (assetInfo.asset_type || '').toString().toLowerCase();
    if (ASSET_TYPE_SCORES[assetType] != null) {
      typeScore = ASSET_TYPE_SCORES[assetType];
    }

    // ── Exposure score ────────────────────────────────────────────
    let exposureScore = 70; // default: assume mixed
    const exposure = (assetInfo.exposure || '').toString().toLowerCase();
    if (EXPOSURE_SCORES[exposure] != null) {
      exposureScore = EXPOSURE_SCORES[exposure];
    }

    // Weighted combination: environment 30%, type 40%, exposure 30%
    const composite = Math.round(envScore * 0.30 + typeScore * 0.40 + exposureScore * 0.30);
    return Math.max(0, Math.min(100, composite));
  }

  /**
   * Compute evidence quality score (0-100).
   *
   * Based on:
   *   - evidence_count: 1=20, 2-3=50, 4-5=70, 6+=90
   *   - has_reproduction_steps: +10
   *   - has_timeline:           +5
   *   - has_verification_trace: +10
   *   - has_request_response:   +5
   *
   * @param {object} evidenceInfo
   * @param {number}  [evidenceInfo.evidence_count]
   * @param {boolean} [evidenceInfo.has_reproduction_steps]
   * @param {boolean} [evidenceInfo.has_timeline]
   * @param {boolean} [evidenceInfo.has_verification_trace]
   * @param {boolean} [evidenceInfo.has_request_response]
   * @returns {number} 0-100
   */
  computeEvidenceScore(evidenceInfo = {}) {
    const count = evidenceInfo.evidence_count || 0;

    // Base score from evidence count tiers
    let score = 0;
    for (const tier of EVIDENCE_COUNT_TIERS) {
      if (count >= tier.min) {
        score = tier.score;
        break;
      }
    }

    // Bonus modifiers
    if (evidenceInfo.has_reproduction_steps)  score += 10;
    if (evidenceInfo.has_timeline)            score += 5;
    if (evidenceInfo.has_verification_trace)  score += 10;
    if (evidenceInfo.has_request_response)    score += 5;

    return Math.max(0, Math.min(100, score));
  }

  // ─── Leaderboard ────────────────────────────────────────────────

  /**
   * Return top N ranked findings sorted by rank_score descending.
   * @param {number} [limit=10]
   * @returns {array}
   */
  getLeaderboard(limit = 10) {
    const all = [...this.rankedFindings.values()];
    all.sort((a, b) => {
      if (b.rank_score !== a.rank_score) return b.rank_score - a.rank_score;
      return (a.rank || Infinity) - (b.rank || Infinity);
    });
    return all.slice(0, limit);
  }

  // ─── Lifecycle State Machine ────────────────────────────────────

  /**
   * Advance a finding through the bug lifecycle.
   *
   * Rules:
   *   - Skip-ahead is allowed (e.g. observed → confirmed)
   *   - Going backward is NOT allowed, except resolved → observed (regression)
   *
   * @param {string} findingId
   * @param {string} newState - target lifecycle state
   * @returns {object} updated ranked finding
   * @throws {Error} if finding not found or transition invalid
   */
  advanceLifecycle(findingId, newState) {
    const finding = this.rankedFindings.get(findingId);
    if (!finding) {
      throw new Error(`Finding ${findingId} not found in ranking store`);
    }

    const currentIndex = LIFECYCLE_INDEX[finding.lifecycle_state];
    const newIndex     = LIFECYCLE_INDEX[newState];

    if (newIndex == null) {
      throw new Error(`Invalid lifecycle state: "${newState}". Valid states: ${LIFECYCLE_STATES.join(', ')}`);
    }

    if (currentIndex == null) {
      // Shouldn't happen but handle gracefully
      finding.lifecycle_state = newState;
      this.rankedFindings.set(findingId, finding);
      return finding;
    }

    // Backward transition: only allowed resolved → observed (regression re-detection)
    if (newIndex < currentIndex) {
      if (finding.lifecycle_state === 'resolved' && newState === 'observed') {
        // Regression re-detection — allowed
      } else {
        throw new Error(
          `Invalid lifecycle transition: ${finding.lifecycle_state} → ${newState}. ` +
          `Backward transitions are not allowed (except resolved → observed for regression).`
        );
      }
    }

    finding.lifecycle_state = newState;

    // Re-evaluate disclosure readiness after state change
    finding.disclosure_ready = this.isDisclosureReady({
      rank_score:              finding.rank_score,
      lifecycle_state:         finding.lifecycle_state,
      evidence_count:          finding._original?.evidence_count,
      has_reproduction_steps:  finding._original?.has_reproduction_steps,
    });

    this.rankedFindings.set(findingId, finding);
    return finding;
  }

  // ─── Queries ────────────────────────────────────────────────────

  /**
   * Get findings at a specific lifecycle state.
   * @param {string} state
   * @returns {array}
   */
  getFindingsByLifecycle(state) {
    const results = [];
    for (const f of this.rankedFindings.values()) {
      if (f.lifecycle_state === state) {
        results.push(f);
      }
    }
    results.sort((a, b) => b.rank_score - a.rank_score);
    return results;
  }

  /**
   * Check if a finding meets disclosure readiness criteria:
   *   - rank_score >= 60
   *   - lifecycle >= 'ranked'
   *   - evidence_count >= 2
   *   - has reproduction steps
   *
   * @param {object} finding
   * @returns {boolean}
   */
  isDisclosureReady(finding) {
    const rankScore     = finding.rank_score != null ? finding.rank_score : 0;
    const lifecycleIdx  = LIFECYCLE_INDEX[finding.lifecycle_state] != null
      ? LIFECYCLE_INDEX[finding.lifecycle_state]
      : -1;
    const evidenceCount = finding.evidence_count != null ? finding.evidence_count : 0;
    const hasReproSteps = !!finding.has_reproduction_steps;

    return (
      rankScore >= DISCLOSURE_MIN_RANK_SCORE &&
      lifecycleIdx >= DISCLOSURE_MIN_LIFECYCLE_INDEX &&
      evidenceCount >= DISCLOSURE_MIN_EVIDENCE_COUNT &&
      hasReproSteps
    );
  }

  /**
   * Compute aggregate statistics across all ranked findings.
   *
   * @returns {object}
   */
  getStats() {
    const all = [...this.rankedFindings.values()];
    const total = all.length;

    if (total === 0) {
      return {
        total_ranked:                      0,
        by_severity:                       { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        by_lifecycle_state:                {},
        avg_rank_score:                    0,
        median_rank_score:                 0,
        top_category:                      null,
        findings_above_disclosure_threshold: 0,
      };
    }

    // ── By severity ───────────────────────────────────────────────
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of all) {
      const sev = f._original?.severity || 'info';
      bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    }

    // ── By lifecycle state ────────────────────────────────────────
    const byLifecycle = {};
    for (const f of all) {
      byLifecycle[f.lifecycle_state] = (byLifecycle[f.lifecycle_state] || 0) + 1;
    }

    // ── Average rank_score ────────────────────────────────────────
    const sumScores = all.reduce((s, f) => s + f.rank_score, 0);
    const avgScore  = Math.round(sumScores / total);

    // ── Median rank_score ─────────────────────────────────────────
    const sortedScores = all.map(f => f.rank_score).sort((a, b) => a - b);
    const mid = Math.floor(sortedScores.length / 2);
    const medianScore = sortedScores.length % 2 !== 0
      ? sortedScores[mid]
      : Math.round((sortedScores[mid - 1] + sortedScores[mid]) / 2);

    // ── Top category ──────────────────────────────────────────────
    const categoryCounts = {};
    for (const f of all) {
      const cat = f._original?.category;
      if (cat) {
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      }
    }
    let topCategory = null;
    let topCatCount = 0;
    for (const [cat, count] of Object.entries(categoryCounts)) {
      if (count > topCatCount) {
        topCategory = cat;
        topCatCount = count;
      }
    }

    // ── Findings above disclosure threshold ───────────────────────
    const aboveDisclosure = all.filter(f => f.rank_score >= DISCLOSURE_MIN_RANK_SCORE).length;

    return {
      total_ranked:                        total,
      by_severity:                         bySeverity,
      by_lifecycle_state:                  byLifecycle,
      avg_rank_score:                      avgScore,
      median_rank_score:                   medianScore,
      top_category:                        topCategory,
      findings_above_disclosure_threshold: aboveDisclosure,
    };
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Persist rankings to disk.
   * @returns {string} file path written
   */
  save() {
    const data = {
      version:     '0.5',
      saved_at:    new Date().toISOString(),
      weights:     this.weights,
      rankings:    [...this.rankedFindings.values()],
    };

    const filePath = path.join(RANKINGS_DIR, 'rankings.json');
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    return filePath;
  }

  /**
   * Load rankings from disk.
   * @returns {boolean} true if loaded successfully
   */
  load() {
    const filePath = path.join(RANKINGS_DIR, 'rankings.json');

    if (!fs.existsSync(filePath)) {
      return false;
    }

    try {
      const raw  = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);

      if (data.rankings && Array.isArray(data.rankings)) {
        for (const r of data.rankings) {
          this.rankedFindings.set(r.finding_id, r);
        }
      }

      // Restore custom weights if saved
      if (data.weights) {
        // Only restore weights if we haven't been given custom ones in constructor
        // (constructor options take precedence over persisted weights on fresh instantiation)
      }

      return true;
    } catch (err) {
      // Corrupt file — start fresh rather than crash
      return false;
    }
  }
}

// ─── Module Export ──────────────────────────────────────────────────

module.exports = { RankingEngine };


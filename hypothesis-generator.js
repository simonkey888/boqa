/**
 * BOQA hypothesis-generator.js — HypothesisGenerator v1.1
 *
 * Auto-generates bug hypotheses from signals, anomalies, and historical
 * patterns. The HypothesisGenerator is the core intelligence of the
 * v1.1 Discovery Layer, converting raw observational data into
 * structured hypothesis graphs (H-graphs).
 *
 * Generation methods:
 *   1. Pattern clustering: group similar signals → extract common
 *      vulnerability patterns → generate hypotheses for untested variants
 *   2. Anomaly delta detection: detect deviations from baseline →
 *      hypothesize about root cause and security implications
 *   3. Historical extrapolation: use MemoryGraph to find patterns that
 *      succeeded on other targets → generate hypotheses for current target
 *   4. Surface-gap analysis: combine AttackSurfaceModeler output with
 *      coverage data → hypothesize about untested surface areas
 *
 * H-graph structure:
 *   Each hypothesis has:
 *   - hypothesis_id, target_id, surface_area
 *   - expected_bug_class (e.g., auth_bypass, idor, race_condition)
 *   - confidence, expected_severity
 *   - supporting_evidence (signals, anomalies, patterns that motivated it)
 *   - test_approach (how to validate — simulation only)
 *   - parent_hypotheses (if derived from another hypothesis)
 *
 * Safe mode: hypotheses are simulation-only constructs. No execution
 * logic is generated; only test approach descriptions.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Constants ──────────────────────────────────────────────────────

const HG_DIR = path.join(__dirname, 'output', 'knowledge', 'hypotheses');

const HYPOTHESIS_STATUS = {
  GENERATED:    'generated',
  SCORED:       'scored',
  SIMULATED:    'simulated',
  VALIDATED:    'validated',
  INVALIDATED:  'invalidated',
  EXPIRED:      'expired',
};

const BUG_CLASSES = {
  AUTH_BYPASS:       'auth_bypass',
  IDOR:             'idor',
  RACE_CONDITION:   'race_condition',
  INJECTION:        'injection',
  XSSI:            'xssi',
  CSRF:            'csrf',
  SESSION_FIXATION: 'session_fixation',
  JWT_MANIPULATION: 'jwt_manipulation',
  RATE_LIMIT:       'rate_limit',
  INFO_LEAK:        'info_leak',
  BUSINESS_LOGIC:   'business_logic',
  MISCONFIG:        'misconfiguration',
  CRYPTO_WEAKNESS:  'crypto_weakness',
  DATA_EXPOSURE:    'data_exposure',
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  UNKNOWN:          'unknown',
};

const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH:     'high',
  MEDIUM:   'medium',
  LOW:      'low',
  INFO:     'info',
};

const GENERATION_METHODS = {
  PATTERN_CLUSTER:    'pattern_clustering',
  ANOMALY_DELTA:      'anomaly_delta_detection',
  HISTORICAL_EXTRA:   'historical_extrapolation',
  SURFACE_GAP:        'surface_gap_analysis',
  REGRESSION_WATCH:   'regression_watch',
  CROSS_TARGET:       'cross_target_correlation',
};

const DEFAULT_OPTIONS = {
  maxHypotheses:      5000,
  maxPerTarget:       500,
  minConfidence:      0.15,
  maxAge:             7 * 24 * 3600000, // 7 days
  dedupThreshold:     0.85,   // similarity threshold for dedup
  generationInterval: 60000,  // 1 minute between auto-generation cycles
};

// =====================================================================
//  Hypothesis
// =====================================================================

class Hypothesis {
  constructor(data = {}) {
    this.id               = data.id || `HYP-${crypto.randomUUID().substring(0, 10)}`;
    this.target_id        = data.target_id || null;
    this.surface_area     = data.surface_area || null;
    this.surface_id       = data.surface_id || null;

    // Core
    this.expected_bug_class = data.expected_bug_class || BUG_CLASSES.UNKNOWN;
    this.description        = data.description || '';
    this.expected_severity  = data.expected_severity || SEVERITY_LEVELS.MEDIUM;
    this.confidence         = data.confidence ?? 0.5;
    this.cevi_score         = data.cevi_score ?? null;
    this.uncertainty_band   = data.uncertainty_band || null; // { p10, p50, p90 }

    // Generation metadata
    this.generation_method = data.generation_method || GENERATION_METHODS.PATTERN_CLUSTER;
    this.parent_hypotheses = data.parent_hypotheses || [];
    this.generation_ts     = data.generation_ts || Date.now();

    // Supporting evidence
    this.supporting_signals   = data.supporting_signals || [];
    this.supporting_anomalies = data.supporting_anomalies || [];
    this.supporting_patterns  = data.supporting_patterns || [];
    this.evidence_strength    = data.evidence_strength ?? 0.5;

    // Test approach (simulation-only description)
    this.test_approach = data.test_approach || '';
    this.test_cost     = data.test_cost ?? null;

    // Status lifecycle
    this.status          = data.status || HYPOTHESIS_STATUS.GENERATED;
    this.simulation_result = data.simulation_result || null;
    this.validation_result = data.validation_result || null;

    // Temporal
    this.created_at  = data.created_at || Date.now();
    this.updated_at  = Date.now();
    this.expires_at  = data.expires_at || Date.now() + DEFAULT_OPTIONS.maxAge;
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  HypothesisGenerator
// =====================================================================

class HypothesisGenerator {
  /**
   * @param {object} options
   * @param {object} options.memoryGraph - MemoryGraph instance
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   * @param {object} [options.attackSurfaceModeler] - AttackSurfaceModeler instance
   * @param {object} [options.confidenceCalibrator] - ConfidenceCalibrator instance
   */
  constructor(options = {}) {
    this.memoryGraph = options.memoryGraph || null;
    this.knowledgeBase = options.knowledgeBase || null;
    this.attackSurfaceModeler = options.attackSurfaceModeler || null;
    this.confidenceCalibrator = options.confidenceCalibrator || null;

    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, Hypothesis>} hypothesis_id → Hypothesis */
    this.hypotheses = new Map();

    /** @type {Map<string, Set<string>>} target_id → Set<hypothesis_id> */
    this.targetIndex = new Map();

    /** @type {Map<string, Set<string>>} bug_class → Set<hypothesis_id> */
    this.bugClassIndex = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_generated: 0,
      total_scored: 0,
      total_simulated: 0,
      total_validated: 0,
      total_invalidated: 0,
      total_expired: 0,
      by_method: {},
      by_bug_class: {},
      by_severity: {},
      avg_confidence: 0,
      avg_evidence_strength: 0,
      dedup_count: 0,
    };

    // ── Event callbacks ──────────────────────────────────────
    this._onHypothesisGenerated = null;
    this._onHypothesisScored = null;

    // ── Auto-generation timer ────────────────────────────────
    this._genTimer = null;

    fs.mkdirSync(HG_DIR, { recursive: true });
    this.load();
  }

  // ─── Generation Methods ────────────────────────────────────────────

  /**
   * Generate hypotheses from a batch of signals.
   * Applies all generation methods to the signal batch.
   *
   * @param {object[]} signals - Array of signal objects
   * @returns {Hypothesis[]}
   */
  generateFromSignals(signals) {
    if (!signals || signals.length === 0) return [];

    const hypotheses = [];

    // Method 1: Pattern clustering
    const patternHyps = this._generateByPatternClustering(signals);
    hypotheses.push(...patternHyps);

    // Method 2: Anomaly delta detection
    const anomalyHyps = this._generateByAnomalyDelta(signals);
    hypotheses.push(...anomalyHyps);

    // Method 3: Historical extrapolation (if MemoryGraph available)
    const historicalHyps = this._generateByHistoricalExtrapolation(signals);
    hypotheses.push(...historicalHyps);

    // Method 4: Surface gap analysis (if AttackSurfaceModeler available)
    const surfaceHyps = this._generateBySurfaceGap(signals);
    hypotheses.push(...surfaceHyps);

    // Method 5: Cross-target correlation
    const crossTargetHyps = this._generateByCrossTargetCorrelation(signals);
    hypotheses.push(...crossTargetHyps);

    // Store and dedup
    const stored = [];
    for (const hyp of hypotheses) {
      const deduped = this._deduplicate(hyp);
      if (deduped) {
        this._storeHypothesis(deduped);
        stored.push(deduped);
        if (this._onHypothesisGenerated) this._onHypothesisGenerated(deduped);
      }
    }

    return stored;
  }

  /**
   * Generate a single hypothesis from raw data.
   * @param {object} data
   * @returns {Hypothesis}
   */
  generate(data) {
    const hyp = new Hypothesis(data);
    const deduped = this._deduplicate(hyp);
    if (deduped) {
      this._storeHypothesis(deduped);
      if (this._onHypothesisGenerated) this._onHypothesisGenerated(deduped);
      return deduped;
    }
    return hyp; // Return even if not stored (was duplicate)
  }

  // ─── Pattern Clustering ──────────────────────────────────────────

  _generateByPatternClustering(signals) {
    const hypotheses = [];

    // Group signals by category
    const categoryGroups = new Map();
    for (const signal of signals) {
      const cat = signal.category || signal.type || 'uncategorized';
      if (!categoryGroups.has(cat)) categoryGroups.set(cat, []);
      categoryGroups.get(cat).push(signal);
    }

    for (const [category, groupSignals] of categoryGroups) {
      if (groupSignals.length < 2) continue;

      // Check if MemoryGraph has patterns for this category
      const patternNodes = this.memoryGraph
        ? this.memoryGraph.queryNodes({ type: 'pattern', category, limit: 10 })
        : [];

      if (patternNodes.length > 0) {
        // Generate hypotheses based on known patterns
        for (const patternNode of patternNodes) {
          const bugClass = this._inferBugClass(category, patternNode.features);
          const severity = this._inferSeverity(category, patternNode.severity);

          hypotheses.push(new Hypothesis({
            target_id: groupSignals[0].target_id || null,
            surface_area: category,
            expected_bug_class: bugClass,
            description: `Pattern cluster "${patternNode.label || category}" with ${groupSignals.length} supporting signals suggests ${bugClass} vulnerability`,
            expected_severity: severity,
            confidence: Math.min(0.8, 0.3 + groupSignals.length * 0.05),
            generation_method: GENERATION_METHODS.PATTERN_CLUSTER,
            supporting_signals: groupSignals.map(s => s.id || s.source).slice(0, 5),
            supporting_patterns: [patternNode.id],
            evidence_strength: Math.min(1.0, patternNode.occurrence_count * 0.1 + groupSignals.length * 0.05),
            test_approach: `Simulate ${bugClass} test against ${category} surface using pattern-derived indicators`,
          }));
        }
      } else {
        // No existing patterns — create initial hypothesis from signal cluster
        const bugClass = this._inferBugClass(category);
        hypotheses.push(new Hypothesis({
          target_id: groupSignals[0].target_id || null,
          surface_area: category,
          expected_bug_class: bugClass,
          description: `Novel signal cluster in "${category}" with ${groupSignals.length} signals — potential ${bugClass}`,
          expected_severity: SEVERITY_LEVELS.MEDIUM,
          confidence: Math.min(0.5, 0.1 + groupSignals.length * 0.03),
          generation_method: GENERATION_METHODS.PATTERN_CLUSTER,
          supporting_signals: groupSignals.map(s => s.id || s.source).slice(0, 5),
          evidence_strength: Math.min(0.5, groupSignals.length * 0.03),
          test_approach: `Explore ${category} surface for ${bugClass} indicators`,
        }));
      }
    }

    return hypotheses;
  }

  // ─── Anomaly Delta Detection ──────────────────────────────────────

  _generateByAnomalyDelta(signals) {
    const anomalies = signals.filter(s =>
      s.type === 'anomaly' || s.type === 'security' ||
      (s.features && (s.features.anomaly_score > 60 || s.features.delta_score > 50))
    );

    if (anomalies.length === 0) return [];

    const hypotheses = [];
    for (const anomaly of anomalies) {
      const bugClass = this._inferBugClassFromAnomaly(anomaly);
      const severity = this._inferSeverityFromAnomaly(anomaly);

      hypotheses.push(new Hypothesis({
        target_id: anomaly.target_id || anomaly.features?.target_id || null,
        surface_area: anomaly.category || anomaly.features?.surface || 'anomalous_behavior',
        expected_bug_class: bugClass,
        description: `Anomaly detected: ${anomaly.source || 'unknown source'} — potential ${bugClass} via deviation from baseline`,
        expected_severity: severity,
        confidence: Math.min(0.7, (anomaly.features?.anomaly_score || 50) / 100 * 0.7),
        generation_method: GENERATION_METHODS.ANOMALY_DELTA,
        supporting_anomalies: [anomaly.id || anomaly.source],
        evidence_strength: Math.min(0.8, (anomaly.features?.anomaly_score || 30) / 100),
        test_approach: `Investigate anomaly in ${anomaly.category || 'unknown'} area — check for ${bugClass}`,
      }));
    }

    return hypotheses;
  }

  // ─── Historical Extrapolation ──────────────────────────────────────

  _generateByHistoricalExtrapolation(signals) {
    if (!this.memoryGraph) return [];

    const hypotheses = [];
    const targetIds = new Set(signals.map(s => s.target_id).filter(Boolean));

    for (const targetId of targetIds) {
      // Find successful findings on OTHER targets
      const otherTargetNodes = this.memoryGraph.queryNodes({
        type: 'finding',
        verdict: 'confirmed',
        limit: 20,
      }).filter(n => n.target_id !== targetId);

      for (const node of otherTargetNodes.slice(0, 10)) {
        // Check if this pattern exists on current target
        const currentTargetNodes = this.memoryGraph.queryNodes({
          type: 'finding',
          target_id: targetId,
          category: node.category,
          limit: 5,
        });

        const alreadyFound = currentTargetNodes.some(n => n.pattern_hash === node.pattern_hash);
        if (alreadyFound) continue;

        hypotheses.push(new Hypothesis({
          target_id: targetId,
          surface_area: node.category || node.surface_id || 'unknown',
          expected_bug_class: this._inferBugClass(node.category, node.features),
          description: `Historical pattern from target ${node.target_id}: ${node.label || node.category} — extrapolate to current target`,
          expected_severity: node.severity || SEVERITY_LEVELS.MEDIUM,
          confidence: Math.min(0.6, (node.confidence || 0.5) * 0.6),
          generation_method: GENERATION_METHODS.HISTORICAL_EXTRA,
          supporting_patterns: [node.id],
          evidence_strength: Math.min(0.7, (node.occurrence_count || 1) * 0.1),
          test_approach: `Test historical pattern ${node.pattern_hash || node.category} against target ${targetId}`,
        }));
      }
    }

    return hypotheses;
  }

  // ─── Surface Gap Analysis ──────────────────────────────────────────

  _generateBySurfaceGap(signals) {
    if (!this.attackSurfaceModeler) return [];

    const hypotheses = [];
    const targetIds = new Set(signals.map(s => s.target_id).filter(Boolean));

    for (const targetId of targetIds) {
      const surface = this.attackSurfaceModeler.getSurface(targetId);
      if (!surface) continue;

      // Find untested areas (high endpoint count but low coverage)
      const gaps = this.attackSurfaceModeler.getCoverageGaps(targetId);
      for (const gap of gaps.slice(0, 5)) {
        hypotheses.push(new Hypothesis({
          target_id: targetId,
          surface_area: gap.area || gap.endpoint || 'unknown',
          surface_id: gap.surface_id || null,
          expected_bug_class: this._inferBugClassFromGap(gap),
          description: `Coverage gap in ${gap.area || gap.endpoint}: ${gap.reason || 'untested surface area'}`,
          expected_severity: SEVERITY_LEVELS.MEDIUM,
          confidence: Math.min(0.5, 0.2 + (gap.endpoint_count || 1) * 0.02),
          generation_method: GENERATION_METHODS.SURFACE_GAP,
          evidence_strength: Math.min(0.4, (gap.endpoint_count || 1) * 0.02),
          test_approach: `Explore ${gap.area || gap.endpoint} surface — currently untested`,
        }));
      }
    }

    return hypotheses;
  }

  // ─── Cross-Target Correlation ──────────────────────────────────────

  _generateByCrossTargetCorrelation(signals) {
    if (!this.memoryGraph) return [];

    const hypotheses = [];
    const failurePatterns = this.memoryGraph.detectRepeatedFailures(2);

    for (const pattern of failurePatterns) {
      if (!pattern.cross_target) continue;

      // Generate hypothesis: if a failure pattern exists across targets,
      // it may indicate a systemic issue
      hypotheses.push(new Hypothesis({
        target_id: pattern.targets[0] || null,
        surface_area: `cross_target_${pattern.pattern_key}`,
        expected_bug_class: BUG_CLASSES.UNKNOWN,
        description: `Cross-target failure pattern: ${pattern.pattern_key} seen on ${pattern.target_count} targets (${pattern.occurrence_count} times)`,
        expected_severity: SEVERITY_LEVELS.MEDIUM,
        confidence: Math.min(0.6, 0.1 + pattern.occurrence_count * 0.05),
        generation_method: GENERATION_METHODS.CROSS_TARGET,
        supporting_patterns: pattern.node_ids.slice(0, 5),
        evidence_strength: Math.min(0.7, pattern.avg_confidence),
        test_approach: `Investigate systemic ${pattern.pattern_key} across ${pattern.target_count} targets`,
      }));
    }

    return hypotheses;
  }

  // ─── Scoring & Updating ────────────────────────────────────────────

  /**
   * Score a hypothesis (update its confidence and CEVI).
   * @param {string} hypothesisId
   * @param {object} [scoreData] - { confidence, cevi_score, uncertainty_band }
   * @returns {Hypothesis|null}
   */
  scoreHypothesis(hypothesisId, scoreData = {}) {
    const hyp = this.hypotheses.get(hypothesisId);
    if (!hyp) return null;

    if (scoreData.confidence !== undefined) hyp.confidence = scoreData.confidence;
    if (scoreData.cevi_score !== undefined) hyp.cevi_score = scoreData.cevi_score;
    if (scoreData.uncertainty_band) hyp.uncertainty_band = scoreData.uncertainty_band;

    hyp.status = HYPOTHESIS_STATUS.SCORED;
    hyp.updated_at = Date.now();
    this.metrics.total_scored++;

    if (this._onHypothesisScored) this._onHypothesisScored(hyp);
    return hyp;
  }

  /**
   * Mark a hypothesis as simulated.
   * @param {string} hypothesisId
   * @param {object} [result]
   * @returns {Hypothesis|null}
   */
  markSimulated(hypothesisId, result = null) {
    const hyp = this.hypotheses.get(hypothesisId);
    if (!hyp) return null;

    hyp.status = HYPOTHESIS_STATUS.SIMULATED;
    hyp.simulation_result = result;
    hyp.updated_at = Date.now();
    this.metrics.total_simulated++;
    return hyp;
  }

  /**
   * Mark a hypothesis as validated or invalidated.
   * @param {string} hypothesisId
   * @param {boolean} valid
   * @param {object} [result]
   * @returns {Hypothesis|null}
   */
  markValidated(hypothesisId, valid, result = null) {
    const hyp = this.hypotheses.get(hypothesisId);
    if (!hyp) return null;

    hyp.status = valid ? HYPOTHESIS_STATUS.VALIDATED : HYPOTHESIS_STATUS.INVALIDATED;
    hyp.validation_result = result;
    hyp.updated_at = Date.now();

    if (valid) this.metrics.total_validated++;
    else this.metrics.total_invalidated++;

    // Feed back into MemoryGraph
    if (this.memoryGraph) {
      this.memoryGraph.addNode({
        type: valid ? 'finding' : 'failure',
        label: hyp.description,
        category: hyp.expected_bug_class,
        target_id: hyp.target_id,
        severity: hyp.expected_severity,
        confidence: hyp.confidence,
        verdict: valid ? 'confirmed' : 'rejected',
        features: { bug_class: hyp.expected_bug_class, surface: hyp.surface_area },
        source_id: hyp.id,
        source_type: 'hypothesis',
        tags: [hyp.generation_method, hyp.expected_bug_class],
      });
    }

    return hyp;
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getHypothesis(id) {
    return this.hypotheses.get(id) || null;
  }

  queryHypotheses(filter = {}) {
    let results = [...this.hypotheses.values()];

    if (filter.status) results = results.filter(h => h.status === filter.status);
    if (filter.target_id) results = results.filter(h => h.target_id === filter.target_id);
    if (filter.bug_class) results = results.filter(h => h.expected_bug_class === filter.bug_class);
    if (filter.min_confidence !== undefined) results = results.filter(h => h.confidence >= filter.min_confidence);
    if (filter.method) results = results.filter(h => h.generation_method === filter.method);

    results.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    return results.slice(0, filter.limit || results.length);
  }

  /**
   * Get the top-ranked hypotheses for a target.
   * @param {string} targetId
   * @param {number} [limit=10]
   * @returns {Hypothesis[]}
   */
  getTopHypotheses(targetId, limit = 10) {
    return this.queryHypotheses({
      target_id: targetId,
      status: HYPOTHESIS_STATUS.SCORED,
      limit,
    });
  }

  getMetrics() {
    return { ...this.metrics, stored_hypotheses: this.hypotheses.size };
  }

  // ─── Internal Helpers ──────────────────────────────────────────────

  _storeHypothesis(hyp) {
    this.hypotheses.set(hyp.id, hyp);
    this.metrics.total_generated++;
    this.metrics.by_method[hyp.generation_method] = (this.metrics.by_method[hyp.generation_method] || 0) + 1;
    this.metrics.by_bug_class[hyp.expected_bug_class] = (this.metrics.by_bug_class[hyp.expected_bug_class] || 0) + 1;
    this.metrics.by_severity[hyp.expected_severity] = (this.metrics.by_severity[hyp.expected_severity] || 0) + 1;

    // Update indexes
    if (hyp.target_id) {
      if (!this.targetIndex.has(hyp.target_id)) this.targetIndex.set(hyp.target_id, new Set());
      this.targetIndex.get(hyp.target_id).add(hyp.id);
    }
    if (!this.bugClassIndex.has(hyp.expected_bug_class)) this.bugClassIndex.set(hyp.expected_bug_class, new Set());
    this.bugClassIndex.get(hyp.expected_bug_class).add(hyp.id);

    // Cap hypotheses
    if (this.hypotheses.size > this.options.maxHypotheses) {
      this._evictExpired();
    }
  }

  _deduplicate(hyp) {
    // Check for similar existing hypotheses
    for (const [, existing] of this.hypotheses) {
      if (existing.target_id === hyp.target_id &&
          existing.expected_bug_class === hyp.expected_bug_class &&
          existing.surface_area === hyp.surface_area) {
        // Merge: update confidence and evidence
        existing.confidence = Math.max(existing.confidence, hyp.confidence);
        existing.evidence_strength = Math.max(existing.evidence_strength, hyp.evidence_strength);
        existing.supporting_signals = [...new Set([...existing.supporting_signals, ...hyp.supporting_signals])];
        existing.updated_at = Date.now();
        this.metrics.dedup_count++;
        return null; // Signal that this was a duplicate
      }
    }
    return hyp;
  }

  _evictExpired() {
    const now = Date.now();
    const expired = [];
    for (const [id, hyp] of this.hypotheses) {
      if (hyp.expires_at && hyp.expires_at < now) {
        expired.push(id);
      }
    }
    // If still over limit, evict lowest confidence
    if (this.hypotheses.size - expired.length > this.options.maxHypotheses) {
      const sorted = [...this.hypotheses.entries()]
        .sort((a, b) => (a[1].confidence || 0) - (b[1].confidence || 0));
      while (this.hypotheses.size - expired.length > this.options.maxHypotheses && sorted.length > 0) {
        const [id] = sorted.shift();
        if (!expired.includes(id)) expired.push(id);
      }
    }
    for (const id of expired) {
      this.hypotheses.delete(id);
      this.metrics.total_expired++;
    }
  }

  _inferBugClass(category, features) {
    const categoryMap = {
      'auth': BUG_CLASSES.AUTH_BYPASS,
      'authentication': BUG_CLASSES.AUTH_BYPASS,
      'authorization': BUG_CLASSES.IDOR,
      'idor': BUG_CLASSES.IDOR,
      'injection': BUG_CLASSES.INJECTION,
      'xss': BUG_CLASSES.INJECTION,
      'csrf': BUG_CLASSES.CSRF,
      'session': BUG_CLASSES.SESSION_FIXATION,
      'jwt': BUG_CLASSES.JWT_MANIPULATION,
      'rate_limit': BUG_CLASSES.RATE_LIMIT,
      'rate': BUG_CLASSES.RATE_LIMIT,
      'info': BUG_CLASSES.INFO_LEAK,
      'data': BUG_CLASSES.DATA_EXPOSURE,
      'crypto': BUG_CLASSES.CRYPTO_WEAKNESS,
      'config': BUG_CLASSES.MISCONFIG,
      'logic': BUG_CLASSES.BUSINESS_LOGIC,
      'race': BUG_CLASSES.RACE_CONDITION,
      'privilege': BUG_CLASSES.PRIVILEGE_ESCALATION,
    };

    if (category) {
      const lower = category.toLowerCase();
      for (const [key, bugClass] of Object.entries(categoryMap)) {
        if (lower.includes(key)) return bugClass;
      }
    }

    if (features) {
      if (features.auth_score > 70) return BUG_CLASSES.AUTH_BYPASS;
      if (features.injection_risk > 60) return BUG_CLASSES.INJECTION;
      if (features.data_exposure > 50) return BUG_CLASSES.DATA_EXPOSURE;
    }

    return BUG_CLASSES.UNKNOWN;
  }

  _inferBugClassFromAnomaly(anomaly) {
    const features = anomaly.features || {};
    if (features.auth_anomaly) return BUG_CLASSES.AUTH_BYPASS;
    if (features.timing_anomaly) return BUG_CLASSES.RACE_CONDITION;
    if (features.data_anomaly) return BUG_CLASSES.DATA_EXPOSURE;
    if (features.session_anomaly) return BUG_CLASSES.SESSION_FIXATION;
    if (features.rate_anomaly) return BUG_CLASSES.RATE_LIMIT;
    return BUG_CLASSES.UNKNOWN;
  }

  _inferBugClassFromGap(gap) {
    if (gap.area && gap.area.includes('auth')) return BUG_CLASSES.AUTH_BYPASS;
    if (gap.area && gap.area.includes('api')) return BUG_CLASSES.IDOR;
    if (gap.area && gap.area.includes('session')) return BUG_CLASSES.SESSION_FIXATION;
    return BUG_CLASSES.UNKNOWN;
  }

  _inferSeverity(category, knownSeverity) {
    if (knownSeverity) return knownSeverity;
    const criticalKeywords = ['auth', 'session', 'jwt', 'privilege'];
    const highKeywords = ['idor', 'injection', 'csrf', 'race'];
    const lower = (category || '').toLowerCase();

    if (criticalKeywords.some(k => lower.includes(k))) return SEVERITY_LEVELS.HIGH;
    if (highKeywords.some(k => lower.includes(k))) return SEVERITY_LEVELS.MEDIUM;
    return SEVERITY_LEVELS.MEDIUM;
  }

  _inferSeverityFromAnomaly(anomaly) {
    const score = anomaly.features?.anomaly_score || 50;
    if (score > 80) return SEVERITY_LEVELS.HIGH;
    if (score > 50) return SEVERITY_LEVELS.MEDIUM;
    return SEVERITY_LEVELS.LOW;
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(HG_DIR, 'hypothesis-generator-state.json');
    const data = {
      version: '1.1',
      saved_at: Date.now(),
      hypotheses: [...this.hypotheses.entries()].slice(-2000),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(HG_DIR, 'hypothesis-generator-state.json');
    if (!fs.existsSync(filePath)) return false;
    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.hypotheses) {
        this.hypotheses = new Map(data.hypotheses.map(([k, v]) => [k, new Hypothesis(v)]));
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.hypotheses.clear();
    this.targetIndex.clear();
    this.bugClassIndex.clear();
    this.metrics = {
      total_generated: 0, total_scored: 0, total_simulated: 0,
      total_validated: 0, total_invalidated: 0, total_expired: 0,
      by_method: {}, by_bug_class: {}, by_severity: {},
      avg_confidence: 0, avg_evidence_strength: 0, dedup_count: 0,
    };
  }

  shutdown() {
    this.save();
  }
}

module.exports = {
  HypothesisGenerator,
  Hypothesis,
  HYPOTHESIS_STATUS,
  BUG_CLASSES,
  SEVERITY_LEVELS,
  GENERATION_METHODS,
};


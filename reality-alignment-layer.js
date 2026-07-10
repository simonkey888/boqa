/**
 * BOQA reality-alignment-layer.js — RealityAlignmentLayer v1.3
 *
 * Anchors simulated ROI against observed external benchmarks.
 * Prevents the decision system from hallucinating returns that
 * diverge from what's realistically achievable.
 *
 * Core principle: decouple_signal_from_action
 *   - A strong signal doesn't guarantee a proportional return
 *   - Market priors and external benchmarks provide reality checks
 *   - Overfit_penalty increases when simulated returns exceed
 *     historical benchmarks by a significant margin
 *   - alignment_score quantifies how close the system's
 *     projections are to external reality
 *
 * Alignment model:
 *   alignment_score = 1 - |simulated_roi - benchmark_roi| / benchmark_roi
 *   overfit_penalty = max(0, (simulated_roi / benchmark_roi - 1) * penalty_rate)
 *
 * When alignment is low:
 *   - Economic scores are penalized (overfit_penalty)
 *   - Decisions are flagged as "unanchored"
 *   - Repeated misalignment triggers deeper calibration
 *
 * Benchmark sources (simulation-only):
 *   - Market priors: average ROI for each opportunity class
 *   - Historical outcomes: past predictions vs actual results
 *   - Conservative estimates: default conservative benchmarks
 *
 * Safe mode: alignment scores are informational; they don't
 * execute any actions, only adjust internal scoring.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const RAL_DIR = path.join(__dirname, 'output', 'knowledge', 'reality-alignment');

// ─── Constants ──────────────────────────────────────────────────────

const DEFAULT_BENCHMARKS = {
  ssl_tls_feed:               { avg_roi: 0.05,  median_yield: 2000,   volatility: 0.15 },
  government_tender_api:      { avg_roi: 0.08,  median_yield: 5000,   volatility: 0.20 },
  competitor_changelog_webhook: { avg_roi: 0.03, median_yield: 1000,   volatility: 0.10 },
  expiring_domain_feed:        { avg_roi: 0.12,  median_yield: 3000,   volatility: 0.35 },
  sec_anomaly_webhook:         { avg_roi: 0.06,  median_yield: 2500,   volatility: 0.18 },
  polyedge_prediction_system:  { avg_roi: 0.15,  median_yield: 8000,   volatility: 0.30 },
  morpho_liquidation_scanner:  { avg_roi: 0.20,  median_yield: 10000,  volatility: 0.40 },
  data_api_marketplace_products: { avg_roi: 0.10, median_yield: 6000,  volatility: 0.25 },
  security_bug_bounty:         { avg_roi: 0.25,  median_yield: 15000,  volatility: 0.50 },
  defi_yield_opportunity:      { avg_roi: 0.18,  median_yield: 12000,  volatility: 0.45 },
  // Default fallback
  __default__:                 { avg_roi: 0.08,  median_yield: 3000,   volatility: 0.25 },
};

const DEFAULT_OPTIONS = {
  overfitPenaltyRate: 0.5,        // 50% penalty per unit of overestimate
  misalignmentThreshold: 0.3,     // Below this alignment = misaligned
  strongAlignmentThreshold: 0.8,  // Above this = well-aligned
  maxOverfitPenalty: 20,          // Cap penalty at 20 points
  benchmarkConservativeBias: 0.8, // Use 80% of benchmark as reference
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  AlignmentResult
// =====================================================================

class AlignmentResult {
  constructor(data = {}) {
    this.opportunity_id       = data.opportunity_id || null;
    this.opportunity_class    = data.opportunity_class || null;
    this.simulated_roi        = data.simulated_roi ?? 0;
    this.benchmark_roi        = data.benchmark_roi ?? 0;
    this.alignment_score      = data.alignment_score ?? 0;   // 0-1, higher = more aligned
    this.overfit_penalty      = data.overfit_penalty ?? 0;
    this.is_misaligned        = data.is_misaligned ?? false;
    this.is_overfitted        = data.is_overfitted ?? false;
    this.benchmark_source     = data.benchmark_source || 'default';
    this.adjusted_score       = data.adjusted_score ?? 0;
    this.computed_at          = Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  RealityAlignmentLayer
// =====================================================================

class RealityAlignmentLayer {
  /**
   * @param {object} options
   * @param {object} [options.economicValueEngine] - EconomicValueEngine instance
   * @param {object} [options.confidenceCalibrator] - ConfidenceCalibrator instance
   */
  constructor(options = {}) {
    this.economicValueEngine = options.economicValueEngine || null;
    this.confidenceCalibrator = options.confidenceCalibrator || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Custom benchmarks (can override defaults)
    this.customBenchmarks = new Map();

    /** @type {Map<string, AlignmentResult>} opportunity_id → latest alignment */
    this.alignments = new Map();

    // Track alignment over time
    this.alignmentHistory = [];
    this.maxAlignmentHistory = 500;

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_aligned: 0,
      total_misaligned: 0,
      total_overfitted: 0,
      avg_alignment_score: 0,
      avg_overfit_penalty: 0,
      calibration_error: 0,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(RAL_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Benchmark Management ──────────────────────────────────────────

  /**
   * Set a custom benchmark for an opportunity class.
   * @param {string} opportunityClass
   * @param {object} benchmark - { avg_roi, median_yield, volatility }
   */
  setBenchmark(opportunityClass, benchmark) {
    this.customBenchmarks.set(opportunityClass, benchmark);
  }

  /**
   * Get the benchmark for an opportunity class.
   * @param {string} opportunityClass
   * @returns {object}
   */
  getBenchmark(opportunityClass) {
    return this.customBenchmarks.get(opportunityClass) ||
           DEFAULT_BENCHMARKS[opportunityClass] ||
           DEFAULT_BENCHMARKS['__default__'];
  }

  /**
   * Set multiple benchmarks at once.
   * @param {object} benchmarks - { class: benchmark }
   */
  setBenchmarks(benchmarks) {
    for (const [cls, bm] of Object.entries(benchmarks)) {
      this.customBenchmarks.set(cls, bm);
    }
  }

  // ─── Alignment Computation ─────────────────────────────────────────

  /**
   * Compute alignment for a single opportunity.
   *
   * @param {object} data
   * @param {string} data.opportunity_id
   * @param {string} [data.opportunity_class]
   * @param {number} data.simulated_roi - The ROI projected by the system
   * @param {number} [data.economic_score] - Current economic score
   * @param {number} [data.capital_required]
   * @returns {AlignmentResult}
   */
  align(data) {
    const oppId = data.opportunity_id;
    const oppClass = data.opportunity_class || '__default__';
    const simulatedROI = data.simulated_roi ?? 0;
    const economicScore = data.economic_score ?? 0;

    // Get benchmark
    const benchmark = this.getBenchmark(oppClass);
    const benchmarkROI = benchmark.avg_roi * this.options.benchmarkConservativeBias;

    // Compute alignment score
    let alignmentScore = 1.0;
    if (benchmarkROI > 0) {
      alignmentScore = 1 - Math.abs(simulatedROI - benchmarkROI) / benchmarkROI;
      alignmentScore = Math.max(0, Math.min(1, alignmentScore));
    } else if (simulatedROI > 0) {
      // No benchmark but positive simulated ROI — uncertain alignment
      alignmentScore = 0.5;
    }

    // Compute overfit penalty
    let overfitPenalty = 0;
    let isOverfitted = false;
    if (benchmarkROI > 0 && simulatedROI > benchmarkROI) {
      const overfitRatio = simulatedROI / benchmarkROI - 1;
      overfitPenalty = Math.min(overfitRatio * this.options.overfitPenaltyRate * 10, this.options.maxOverfitPenalty);
      isOverfitted = overfitRatio > 0.5; // More than 50% above benchmark
    }

    // Adjust economic score with overfit penalty
    const adjustedScore = Math.max(0, economicScore - overfitPenalty);

    // Determine misalignment
    const isMisaligned = alignmentScore < this.options.misalignmentThreshold;

    // Incorporate calibrator data if available
    let benchmarkSource = 'default';
    if (this.customBenchmarks.has(oppClass)) {
      benchmarkSource = 'custom';
    } else if (this.confidenceCalibrator) {
      const record = this.confidenceCalibrator.getCalibrationRecord(null, oppClass);
      if (record && record.observation_count >= 5) {
        // If we have calibration data, use observed accuracy as secondary benchmark
        benchmarkSource = 'calibrator';
      }
    }

    const result = new AlignmentResult({
      opportunity_id: oppId,
      opportunity_class: oppClass,
      simulated_roi: Math.round(simulatedROI * 10000) / 10000,
      benchmark_roi: Math.round(benchmarkROI * 10000) / 10000,
      alignment_score: Math.round(alignmentScore * 1000) / 1000,
      overfit_penalty: Math.round(overfitPenalty * 100) / 100,
      is_misaligned: isMisaligned,
      is_overfitted: isOverfitted,
      benchmark_source: benchmarkSource,
      adjusted_score: Math.round(adjustedScore * 100) / 100,
    });

    this.alignments.set(oppId, result);

    // Track history
    this.alignmentHistory.push({
      opportunity_id: oppId,
      alignment_score: alignmentScore,
      overfit_penalty: overfitPenalty,
      timestamp: Date.now(),
    });
    if (this.alignmentHistory.length > this.maxAlignmentHistory) {
      this.alignmentHistory = this.alignmentHistory.slice(-this.maxAlignmentHistory);
    }

    // Update metrics
    this.metrics.total_aligned++;
    if (isMisaligned) this.metrics.total_misaligned++;
    if (isOverfitted) this.metrics.total_overfitted++;
    this._updateMetrics();

    return result;
  }

  /**
   * Align a batch of opportunities.
   * @param {object[]} items
   * @returns {AlignmentResult[]}
   */
  alignBatch(items) {
    return items.map(item => this.align(item));
  }

  // ─── Outcome Recording ────────────────────────────────────────────

  /**
   * Record a realized outcome to improve future alignment.
   * @param {string} opportunityClass
   * @param {number} simulatedROI
   * @param {number} actualROI
   */
  recordOutcome(opportunityClass, simulatedROI, actualROI) {
    // Update benchmark based on observed outcomes
    const current = this.getBenchmark(opportunityClass);
    const alpha = 0.2; // Learning rate

    const updatedROI = current.avg_roi * (1 - alpha) + actualROI * alpha;
    const error = Math.abs(simulatedROI - actualROI);

    this.customBenchmarks.set(opportunityClass, {
      avg_roi: Math.round(updatedROI * 10000) / 10000,
      median_yield: current.median_yield,
      volatility: current.volatility * (1 - alpha) + error * alpha,
    });

    // Update calibration error
    this.metrics.calibration_error = this.metrics.calibration_error * 0.9 + error * 0.1;
  }

  // ─── Query ──────────────────────────────────────────────────────────

  getAlignment(opportunityId) {
    return this.alignments.get(opportunityId) || null;
  }

  getAllAlignments() {
    return [...this.alignments.values()];
  }

  /**
   * Compute system-wide calibration error.
   * @returns {number}
   */
  computeCalibrationError() {
    const alignments = [...this.alignments.values()];
    if (alignments.length === 0) return 0;

    const totalError = alignments.reduce((s, a) =>
      s + Math.abs(a.simulated_roi - a.benchmark_roi), 0
    );
    const avgBenchmark = alignments.reduce((s, a) => s + a.benchmark_roi, 0) / alignments.length;

    return avgBenchmark > 0
      ? Math.round(totalError / alignments.length / avgBenchmark * 1000) / 1000
      : 0;
  }

  getMetrics() {
    return { ...this.metrics, calibration_error: this.computeCalibrationError() };
  }

  _updateMetrics() {
    const alignments = [...this.alignments.values()];
    if (alignments.length > 0) {
      this.metrics.avg_alignment_score = Math.round(
        alignments.reduce((s, a) => s + a.alignment_score, 0) / alignments.length * 1000
      ) / 1000;
      this.metrics.avg_overfit_penalty = Math.round(
        alignments.reduce((s, a) => s + a.overfit_penalty, 0) / alignments.length * 100
      ) / 100;
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(RAL_DIR, 'reality-alignment-state.json');
    const data = {
      version: '1.3',
      saved_at: Date.now(),
      custom_benchmarks: [...this.customBenchmarks.entries()],
      alignments: [...this.alignments.entries()].slice(-200),
      alignment_history: this.alignmentHistory.slice(-200),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(RAL_DIR, 'reality-alignment-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.custom_benchmarks) {
        this.customBenchmarks = new Map(data.custom_benchmarks);
      }
      if (data.alignments) {
        this.alignments = new Map(data.alignments.map(([k, v]) => [k, new AlignmentResult(v)]));
      }
      if (data.alignment_history) this.alignmentHistory = data.alignment_history;
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      this._updateMetrics();
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.customBenchmarks.clear();
    this.alignments.clear();
    this.alignmentHistory = [];
    this.metrics = {
      total_aligned: 0, total_misaligned: 0, total_overfitted: 0,
      avg_alignment_score: 0, avg_overfit_penalty: 0, calibration_error: 0,
    };
    const filePath = path.join(RAL_DIR, 'reality-alignment-state.json');
    try { fs.unlinkSync(filePath); } catch (_) {}
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  RealityAlignmentLayer,
  AlignmentResult,
  DEFAULT_BENCHMARKS,
};


/**
 * BOQA efficiency-tracker.js — EfficiencyTracker v0.9
 *
 * Monitors yield, cost and throughput metrics to guide optimization
 * decisions. Provides the raw data the OptimizerEngine uses to make
 * decisions about resource allocation, strategy selection and parameter
 * tuning.
 *
 * Tracked metrics (v0.9 success criteria):
 *   - bugs_per_worker           target >= 3.0
 *   - false_positive_rate       target <= 0.10
 *   - scan_time_reduction       target >= 0.20  (20% reduction)
 *   - resource_utilization      target >= 0.90  (90% utilization)
 *   - cost_per_bug              minimize
 *   - throughput_bugs_per_hour  maximize
 *   - coverage_delta_per_hour   maximize
 *   - avg_verification_time_ms  minimize
 *   - avg_evidence_quality      maximize (0-1)
 *
 * Efficiency score model:
 *   efficiency = w1 × bugs_per_worker_norm +
 *                w2 × (1 - false_positive_rate) +
 *                w3 × scan_time_reduction +
 *                w4 × resource_utilization +
 *                w5 × throughput_norm +
 *                w6 × evidence_quality_norm
 *
 * Where each dimension is normalized to 0-1 and weights sum to 1.
 *
 * The tracker continuously:
 *   1. Records bug discoveries, verifications, scans, resource usage, costs
 *   2. Maintains time series for each metric with decay
 *   3. Computes periodic efficiency snapshots (every 60s)
 *   4. Provides trend analysis (improving / declining / stable)
 *   5. Benchmarks current metrics against v0.9 success criteria
 *   6. Persists state for recovery and historical analysis
 *
 * Safe mode: the tracker is purely observational; it records metrics
 * and computes scores but never initiates actions or modifies system
 * state.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const EFFICIENCY_DIR = path.join(__dirname, 'output', 'knowledge', 'efficiency');

// ─── Default Configuration ──────────────────────────────────────────

const DEFAULT_EFFICIENCY_CONFIG = {
  snapshot_interval_ms: 60000,        // 1 minute
  time_series_max_points: 1440,       // 24h at 1 point per minute
  decay_factor: 0.98,                 // exponential decay per snapshot
};

// ─── v0.9 Success Criteria Targets ──────────────────────────────────

const SUCCESS_CRITERIA = {
  bugs_per_worker:       { target: 3.0,  direction: 'maximize' },
  false_positive_rate:   { target: 0.10, direction: 'minimize' },
  scan_time_reduction:   { target: 0.20, direction: 'maximize' },
  resource_utilization:  { target: 0.90, direction: 'maximize' },
  cost_per_bug:          { target: null,  direction: 'minimize' },
  throughput_bugs_per_hour:      { target: null, direction: 'maximize' },
  coverage_delta_per_hour:       { target: null, direction: 'maximize' },
  avg_verification_time_ms:      { target: null, direction: 'minimize' },
  avg_evidence_quality:          { target: null, direction: 'maximize' },
};

// ─── Efficiency Score Weights ────────────────────────────────────────

const SCORE_WEIGHTS = {
  bugs_per_worker_norm:       0.25,
  false_positive_quality:     0.20,
  scan_time_reduction:        0.15,
  resource_utilization:       0.15,
  throughput_norm:            0.15,
  evidence_quality_norm:      0.10,
};

// =====================================================================
//  EfficiencySnapshot
// =====================================================================

class EfficiencySnapshot {
  /**
   * @param {object} data
   */
  constructor(data = {}) {
    this.id = data.id || `ESNAP-${crypto.randomUUID().substring(0, 8)}`;
    this.ts = data.ts || Date.now();

    // Core efficiency metrics
    this.bugs_per_worker        = data.bugs_per_worker        ?? 0;
    this.false_positive_rate    = data.false_positive_rate    ?? 0;
    this.scan_time_reduction    = data.scan_time_reduction    ?? 0;
    this.resource_utilization   = data.resource_utilization   ?? 0;
    this.cost_per_bug           = data.cost_per_bug           ?? 0;
    this.throughput_bugs_per_hour     = data.throughput_bugs_per_hour     ?? 0;
    this.coverage_delta_per_hour      = data.coverage_delta_per_hour      ?? 0;
    this.avg_verification_time_ms     = data.avg_verification_time_ms     ?? 0;
    this.avg_evidence_quality         = data.avg_evidence_quality         ?? 0;

    // Composite score
    this.efficiency_score = data.efficiency_score ?? 0;
  }
}

// =====================================================================
//  TimeSeries
// =====================================================================

class TimeSeries {
  /**
   * @param {string} metric_name
   * @param {object} [options]
   * @param {number} [options.max_points=1440]
   */
  constructor(metric_name, options = {}) {
    this.metric_name = metric_name;
    this.max_points  = options.max_points || DEFAULT_EFFICIENCY_CONFIG.time_series_max_points;
    /** @type {{ts: number, value: number}[]} */
    this.values = [];
  }

  /**
   * Add a data point.
   * @param {number} value
   */
  add(value) {
    this.values.push({ ts: Date.now(), value });
    // Enforce max points
    if (this.values.length > this.max_points) {
      this.values = this.values.slice(-this.max_points);
    }
  }

  /**
   * Get the most recent value.
   * @returns {number|null}
   */
  getLatest() {
    if (this.values.length === 0) return null;
    return this.values[this.values.length - 1].value;
  }

  /**
   * Compute a simple linear trend over the series.
   * Returns slope per minute (positive = improving if direction=maximize).
   *
   * @returns {number} slope per minute
   */
  getTrend() {
    if (this.values.length < 2) return 0;

    const n = this.values.length;
    const first = this.values[0];
    const last  = this.values[n - 1];

    const dtMinutes = (last.ts - first.ts) / 60000;
    if (dtMinutes <= 0) return 0;

    // Simple slope: (last - first) / time
    return (last.value - first.value) / dtMinutes;
  }

  /**
   * Compute moving average over the last `window` points.
   *
   * @param {number} [window=10]
   * @returns {number}
   */
  getMovingAverage(window = 10) {
    if (this.values.length === 0) return 0;
    const slice = this.values.slice(-window);
    const sum = slice.reduce((s, p) => s + p.value, 0);
    return sum / slice.length;
  }

  /**
   * Compute a percentile value across the entire series.
   *
   * @param {number} p - percentile 0-100
   * @returns {number}
   */
  getPercentile(p) {
    if (this.values.length === 0) return 0;

    const sorted = this.values
      .map(v => v.value)
      .sort((a, b) => a - b);

    const idx = (p / 100) * (sorted.length - 1);
    const lo  = Math.floor(idx);
    const hi  = Math.ceil(idx);
    const frac = idx - lo;

    if (hi >= sorted.length) return sorted[sorted.length - 1];
    return sorted[lo] * (1 - frac) + sorted[hi] * frac;
  }

  /**
   * Serialize for persistence.
   * @returns {object}
   */
  toJSON() {
    return {
      metric_name: this.metric_name,
      max_points: this.max_points,
      values: this.values,
    };
  }

  /**
   * Restore from serialized data.
   * @param {object} data
   * @returns {TimeSeries}
   */
  static fromJSON(data) {
    const ts = new TimeSeries(data.metric_name, { max_points: data.max_points });
    ts.values = data.values || [];
    return ts;
  }
}

// =====================================================================
//  EfficiencyTracker
// =====================================================================

class EfficiencyTracker {
  /**
   * @param {object} options
   * @param {object} [options.predictionEngine]     - PredictionEngine instance
   * @param {object} [options.yieldForecaster]      - YieldForecaster instance
   * @param {object} [options.knowledgeBase]        - KnowledgeBase instance
   * @param {object} [options.brainRegistry]        - BrainRegistry instance
   * @param {object} [options.learningEngine]       - LearningEngine instance
   * @param {object} [options.resourceOptimizer]    - ResourceOptimizer instance
   * @param {object} [options.campaignEngine]       - CampaignEngine instance
   * @param {object} [options.evidenceQualityEngine]- EvidenceQualityEngine instance
   * @param {object} [options.config]               - Override default config
   */
  constructor(options = {}) {
    this.predictionEngine     = options.predictionEngine     || null;
    this.yieldForecaster      = options.yieldForecaster      || null;
    this.kb                   = options.knowledgeBase        || null;
    this.brainRegistry        = options.brainRegistry        || null;
    this.learningEngine       = options.learningEngine       || null;
    this.resourceOptimizer    = options.resourceOptimizer    || null;
    this.campaignEngine       = options.campaignEngine       || null;
    this.evidenceQualityEngine = options.evidenceQualityEngine || null;
    this.config = { ...DEFAULT_EFFICIENCY_CONFIG, ...(options.config || {}) };

    // ── Time Series ───────────────────────────────────────────
    /** @type {Map<string, TimeSeries>} */
    this.timeSeries = new Map();

    const metricNames = [
      'bugs_per_worker',
      'false_positive_rate',
      'scan_time_reduction',
      'resource_utilization',
      'cost_per_bug',
      'throughput_bugs_per_hour',
      'coverage_delta_per_hour',
      'avg_verification_time_ms',
      'avg_evidence_quality',
    ];

    for (const name of metricNames) {
      this.timeSeries.set(name, new TimeSeries(name, {
        max_points: this.config.time_series_max_points,
      }));
    }

    // ── Accumulators (reset each snapshot window) ─────────────
    this._windowBugsFound       = 0;
    this._windowVerifications   = 0;
    this._windowConfirmed       = 0;
    this._windowRejected        = 0;
    this._windowInconclusive    = 0;
    this._windowScanDurationMs  = 0;
    this._windowScanCount       = 0;
    this._windowBaselineDurationMs = 0;
    this._windowCostTotal       = 0;
    this._windowCoverageDelta   = 0;
    this._windowEvidenceQuality = [];
    this._windowStartTs         = Date.now();

    // ── Cumulative counters ───────────────────────────────────
    this.totalBugsFound       = 0;
    this.totalVerifications   = 0;
    this.totalConfirmed       = 0;
    this.totalRejected        = 0;
    this.totalInconclusive    = 0;
    this.totalCostAccumulated = 0;

    // ── Snapshot history ──────────────────────────────────────
    /** @type {EfficiencySnapshot[]} */
    this.snapshots = [];

    // ── Bug records for current window ────────────────────────
    /** @type {object[]} */
    this._bugRecords = [];

    // ── Verification records for current window ───────────────
    /** @type {object[]} */
    this._verificationRecords = [];

    // ── Resource usage samples for current window ─────────────
    /** @type {object[]} */
    this._resourceSamples = [];

    // ── Cost records for current window ───────────────────────
    /** @type {object[]} */
    this._costRecords = [];

    // Ensure persistence directory exists
    fs.mkdirSync(EFFICIENCY_DIR, { recursive: true });

    // Auto-load previous state
    this.load();

    // Start periodic snapshot timer
    this._snapshotTimer = setInterval(() => {
      this.computeSnapshot();
    }, this.config.snapshot_interval_ms);
  }

  // ─── Recording Methods ───────────────────────────────────────────

  /**
   * Record a bug discovery with metadata.
   *
   * @param {object} bug
   * @param {string} bug.id               - Bug/finding identifier
   * @param {string} [bug.target_id]      - Target where bug was found
   * @param {string} [bug.category]       - Vulnerability category
   * @param {string} [bug.severity]       - Severity level
   * @param {number} [bug.evv]            - Expected verification value
   * @param {number} [bug.discovery_time_ms] - Time to discover this bug
   * @param {number} [bug.cost]           - Cost incurred for discovery
   */
  recordBugFound(bug) {
    const record = {
      id: bug.id || `BUG-${crypto.randomUUID().substring(0, 8)}`,
      target_id: bug.target_id || null,
      category: bug.category || 'unknown',
      severity: bug.severity || 'medium',
      evv: bug.evv || 0,
      discovery_time_ms: bug.discovery_time_ms || 0,
      cost: bug.cost || 0,
      recorded_at: Date.now(),
    };

    this._bugRecords.push(record);
    this._windowBugsFound++;
    this.totalBugsFound++;

    if (record.cost > 0) {
      this._windowCostTotal += record.cost;
      this.totalCostAccumulated += record.cost;
    }
  }

  /**
   * Record a verification outcome.
   *
   * @param {object} outcome
   * @param {string} outcome.finding_id      - Finding being verified
   * @param {string} outcome.outcome         - 'confirmed' | 'rejected' | 'inconclusive'
   * @param {number} [outcome.duration_ms]   - Verification duration
   * @param {number} [outcome.evidence_quality] - Quality of evidence (0-1)
   * @param {string} [outcome.verification_type] - Type of verification
   */
  recordVerification(outcome) {
    const record = {
      finding_id: outcome.finding_id || `VRF-${crypto.randomUUID().substring(0, 8)}`,
      outcome: outcome.outcome || 'inconclusive',
      duration_ms: outcome.duration_ms || 0,
      evidence_quality: outcome.evidence_quality ?? null,
      verification_type: outcome.verification_type || null,
      recorded_at: Date.now(),
    };

    this._verificationRecords.push(record);
    this._windowVerifications++;
    this.totalVerifications++;

    if (record.outcome === 'confirmed') {
      this._windowConfirmed++;
      this.totalConfirmed++;
    } else if (record.outcome === 'rejected') {
      this._windowRejected++;
      this.totalRejected++;
    } else {
      this._windowInconclusive++;
      this.totalInconclusive++;
    }

    if (record.duration_ms > 0) {
      this._windowScanDurationMs += record.duration_ms;
      this._windowScanCount++;
    }

    if (record.evidence_quality !== null) {
      this._windowEvidenceQuality.push(record.evidence_quality);
    }
  }

  /**
   * Record a scan completion with duration.
   *
   * @param {object} scanResult
   * @param {string} [scanResult.scan_id]         - Scan identifier
   * @param {number} scanResult.duration_ms        - Actual scan duration
   * @param {number} [scanResult.baseline_duration_ms] - Baseline/reference duration
   * @param {number} [scanResult.coverage_delta]   - Coverage change from this scan
   * @param {string} [scanResult.target_id]        - Target scanned
   * @param {number} [scanResult.findings_count]   - Bugs found in this scan
   */
  recordScanComplete(scanResult) {
    const record = {
      scan_id: scanResult.scan_id || `SCAN-${crypto.randomUUID().substring(0, 8)}`,
      duration_ms: scanResult.duration_ms || 0,
      baseline_duration_ms: scanResult.baseline_duration_ms || 0,
      coverage_delta: scanResult.coverage_delta || 0,
      target_id: scanResult.target_id || null,
      findings_count: scanResult.findings_count || 0,
      recorded_at: Date.now(),
    };

    this._windowScanDurationMs += record.duration_ms;
    this._windowScanCount++;

    if (record.baseline_duration_ms > 0) {
      this._windowBaselineDurationMs += record.baseline_duration_ms;
    }

    if (record.coverage_delta !== 0) {
      this._windowCoverageDelta += record.coverage_delta;
    }
  }

  /**
   * Record current resource usage.
   *
   * @param {object} usage
   * @param {number} usage.total_workers    - Total workers available
   * @param {number} usage.active_workers   - Currently active workers
   * @param {number} [usage.cpu_pct]        - CPU utilization percentage
   * @param {number} [usage.memory_pct]     - Memory utilization percentage
   * @param {number} [usage.idle_workers]   - Idle workers
   */
  recordResourceUsage(usage) {
    const record = {
      total_workers:  usage.total_workers  || 0,
      active_workers: usage.active_workers || 0,
      cpu_pct:        usage.cpu_pct        ?? null,
      memory_pct:     usage.memory_pct     ?? null,
      idle_workers:   usage.idle_workers   ?? 0,
      recorded_at:    Date.now(),
    };

    this._resourceSamples.push(record);
  }

  /**
   * Record a cost event.
   *
   * @param {object} costItem
   * @param {string} [costItem.category]    - Cost category (compute, api_call, etc.)
   * @param {number} costItem.amount        - Cost amount
   * @param {string} [costItem.target_id]   - Associated target
   * @param {string} [costItem.description] - Description
   */
  recordCost(costItem) {
    const record = {
      category:    costItem.category    || 'general',
      amount:      costItem.amount      || 0,
      target_id:   costItem.target_id   || null,
      description: costItem.description || null,
      recorded_at: Date.now(),
    };

    this._costRecords.push(record);
    this._windowCostTotal += record.amount;
    this.totalCostAccumulated += record.amount;
  }

  // ─── Snapshot Computation ─────────────────────────────────────────

  /**
   * Compute current efficiency snapshot from all time series and
   * accumulator data, push into snapshot history, and update time series.
   *
   * @returns {EfficiencySnapshot}
   */
  computeSnapshot() {
    const now = Date.now();
    const windowElapsedHours = Math.max((now - this._windowStartTs) / 3600000, 0.001);

    // ── bugs_per_worker ───────────────────────────────────────
    let bugsPerWorker = 0;
    const activeWorkers = this._getActiveWorkers();
    if (activeWorkers > 0) {
      bugsPerWorker = this._windowBugsFound / activeWorkers;
    }

    // ── false_positive_rate ───────────────────────────────────
    let falsePositiveRate = 0;
    if (this._windowVerifications > 0) {
      falsePositiveRate = this._windowRejected / this._windowVerifications;
    }

    // ── scan_time_reduction ───────────────────────────────────
    let scanTimeReduction = 0;
    if (this._windowBaselineDurationMs > 0 && this._windowScanDurationMs > 0) {
      scanTimeReduction = Math.max(0,
        1 - (this._windowScanDurationMs / this._windowBaselineDurationMs)
      );
    }

    // ── resource_utilization ──────────────────────────────────
    let resourceUtilization = 0;
    if (this._resourceSamples.length > 0) {
      const avgUtil = this._resourceSamples.reduce((s, r) => {
        if (r.total_workers > 0) {
          return s + (r.active_workers / r.total_workers);
        }
        return s;
      }, 0) / this._resourceSamples.length;
      resourceUtilization = avgUtil;
    } else if (this.resourceOptimizer) {
      // Fallback: read from resource optimizer distribution
      const dist = this.resourceOptimizer.currentDistribution;
      if (dist && dist.total_workers > 0) {
        resourceUtilization = (dist.total_workers - dist.idle) / dist.total_workers;
      }
    }

    // ── cost_per_bug ──────────────────────────────────────────
    let costPerBug = 0;
    if (this._windowConfirmed > 0) {
      costPerBug = this._windowCostTotal / this._windowConfirmed;
    } else if (this._windowBugsFound > 0) {
      costPerBug = this._windowCostTotal / this._windowBugsFound;
    }

    // ── throughput_bugs_per_hour ──────────────────────────────
    const throughputBugsPerHour = this._windowConfirmed / windowElapsedHours;

    // ── coverage_delta_per_hour ───────────────────────────────
    const coverageDeltaPerHour = this._windowCoverageDelta / windowElapsedHours;

    // ── avg_verification_time_ms ──────────────────────────────
    let avgVerificationTimeMs = 0;
    if (this._windowVerifications > 0 && this._verificationRecords.length > 0) {
      const durations = this._verificationRecords
        .map(r => r.duration_ms)
        .filter(d => d > 0);
      avgVerificationTimeMs = durations.length > 0
        ? durations.reduce((s, d) => s + d, 0) / durations.length
        : 0;
    }

    // ── avg_evidence_quality ──────────────────────────────────
    let avgEvidenceQuality = 0;
    if (this._windowEvidenceQuality.length > 0) {
      avgEvidenceQuality = this._windowEvidenceQuality.reduce((s, q) => s + q, 0) /
        this._windowEvidenceQuality.length;
    } else if (this.evidenceQualityEngine) {
      // Fallback: pull from evidence quality engine
      try {
        const eqMetrics = this.evidenceQualityEngine.getMetrics();
        avgEvidenceQuality = eqMetrics.avg_quality || 0;
      } catch (_) {
        avgEvidenceQuality = 0;
      }
    }

    // ── Compute efficiency score ──────────────────────────────
    const efficiencyScore = this._computeEfficiencyScore({
      bugsPerWorker,
      falsePositiveRate,
      scanTimeReduction,
      resourceUtilization,
      throughputBugsPerHour,
      avgEvidenceQuality,
    });

    // ── Build snapshot ────────────────────────────────────────
    const snapshot = new EfficiencySnapshot({
      bugs_per_worker:               Math.round(bugsPerWorker * 1000) / 1000,
      false_positive_rate:           Math.round(falsePositiveRate * 10000) / 10000,
      scan_time_reduction:           Math.round(scanTimeReduction * 10000) / 10000,
      resource_utilization:          Math.round(resourceUtilization * 10000) / 10000,
      cost_per_bug:                  Math.round(costPerBug * 100) / 100,
      throughput_bugs_per_hour:      Math.round(throughputBugsPerHour * 1000) / 1000,
      coverage_delta_per_hour:       Math.round(coverageDeltaPerHour * 10000) / 10000,
      avg_verification_time_ms:      Math.round(avgVerificationTimeMs),
      avg_evidence_quality:          Math.round(avgEvidenceQuality * 10000) / 10000,
      efficiency_score:              Math.round(efficiencyScore * 100) / 100,
    });

    // ── Update time series ────────────────────────────────────
    this.timeSeries.get('bugs_per_worker').add(snapshot.bugs_per_worker);
    this.timeSeries.get('false_positive_rate').add(snapshot.false_positive_rate);
    this.timeSeries.get('scan_time_reduction').add(snapshot.scan_time_reduction);
    this.timeSeries.get('resource_utilization').add(snapshot.resource_utilization);
    this.timeSeries.get('cost_per_bug').add(snapshot.cost_per_bug);
    this.timeSeries.get('throughput_bugs_per_hour').add(snapshot.throughput_bugs_per_hour);
    this.timeSeries.get('coverage_delta_per_hour').add(snapshot.coverage_delta_per_hour);
    this.timeSeries.get('avg_verification_time_ms').add(snapshot.avg_verification_time_ms);
    this.timeSeries.get('avg_evidence_quality').add(snapshot.avg_evidence_quality);

    // ── Record snapshot history ───────────────────────────────
    this.snapshots.push(snapshot);
    if (this.snapshots.length > this.config.time_series_max_points) {
      this.snapshots = this.snapshots.slice(-this.config.time_series_max_points);
    }

    // ── Reset window accumulators ─────────────────────────────
    this._resetWindow();

    return snapshot;
  }

  /**
   * Compute composite efficiency score (0-100).
   *
   * @param {object} metrics
   * @returns {number} score 0-100
   */
  computeEfficiencyScore(metrics) {
    return this._computeEfficiencyScore(metrics);
  }

  /**
   * Internal efficiency score computation.
   *
   * @param {object} m
   * @param {number} m.bugsPerWorker
   * @param {number} m.falsePositiveRate
   * @param {number} m.scanTimeReduction
   * @param {number} m.resourceUtilization
   * @param {number} m.throughputBugsPerHour
   * @param {number} m.avgEvidenceQuality
   * @returns {number} 0-100
   * @private
   */
  _computeEfficiencyScore(m) {
    // Normalize each dimension to 0-1
    const bugsPerWorkerNorm = Math.min(m.bugsPerWorker / 5.0, 1.0);   // 5 bugs/worker = perfect
    const fpQualityNorm     = 1 - Math.min(m.falsePositiveRate, 1.0); // 0 FP = perfect
    const scanReductionNorm = Math.min(m.scanTimeReduction, 1.0);     // 100% reduction = perfect
    const utilizationNorm   = Math.min(m.resourceUtilization, 1.0);   // 100% utilization = perfect
    const throughputNorm    = Math.min(m.throughputBugsPerHour / 10.0, 1.0); // 10/hr = perfect
    const evidenceNorm      = Math.min(m.avgEvidenceQuality, 1.0);    // 1.0 = perfect

    const score =
      SCORE_WEIGHTS.bugs_per_worker_norm  * bugsPerWorkerNorm +
      SCORE_WEIGHTS.false_positive_quality * fpQualityNorm +
      SCORE_WEIGHTS.scan_time_reduction   * scanReductionNorm +
      SCORE_WEIGHTS.resource_utilization  * utilizationNorm +
      SCORE_WEIGHTS.throughput_norm       * throughputNorm +
      SCORE_WEIGHTS.evidence_quality_norm * evidenceNorm;

    return Math.max(0, Math.min(100, score * 100));
  }

  // ─── Query Methods ───────────────────────────────────────────────

  /**
   * Return current efficiency metrics matching v0.9 success criteria.
   *
   * @returns {object}
   */
  getMetrics() {
    const latest = this._getLatestSnapshot();

    return {
      // Current snapshot values
      bugs_per_worker:             latest?.bugs_per_worker             ?? 0,
      false_positive_rate:         latest?.false_positive_rate         ?? 0,
      scan_time_reduction:         latest?.scan_time_reduction         ?? 0,
      resource_utilization:        latest?.resource_utilization        ?? 0,
      cost_per_bug:                latest?.cost_per_bug                ?? 0,
      throughput_bugs_per_hour:    latest?.throughput_bugs_per_hour    ?? 0,
      coverage_delta_per_hour:     latest?.coverage_delta_per_hour     ?? 0,
      avg_verification_time_ms:    latest?.avg_verification_time_ms    ?? 0,
      avg_evidence_quality:        latest?.avg_evidence_quality        ?? 0,
      efficiency_score:            latest?.efficiency_score            ?? 0,

      // Cumulative counters
      total_bugs_found:            this.totalBugsFound,
      total_verifications:         this.totalVerifications,
      total_confirmed:             this.totalConfirmed,
      total_rejected:              this.totalRejected,
      total_inconclusive:          this.totalInconclusive,
      total_cost_accumulated:      this.totalCostAccumulated,

      // Window counters (current snapshot window)
      window_bugs_found:           this._windowBugsFound,
      window_verifications:        this._windowVerifications,
      window_confirmed:            this._windowConfirmed,
      window_rejected:             this._windowRejected,

      // Snapshot metadata
      snapshot_count:              this.snapshots.length,
      last_snapshot_ts:            latest?.ts ?? null,
    };
  }

  /**
   * Return time series for a specific metric.
   *
   * @param {string} metric_name
   * @returns {TimeSeries|null}
   */
  getTimeSeries(metric_name) {
    return this.timeSeries.get(metric_name) || null;
  }

  /**
   * Return trend direction for a metric: 'improving' | 'declining' | 'stable'.
   *
   * Uses the time series trend (slope) and the success criteria direction
   * to determine if the metric is moving toward or away from its target.
   *
   * @param {string} metric_name
   * @returns {string}
   */
  getTrend(metric_name) {
    const ts = this.timeSeries.get(metric_name);
    if (!ts || ts.values.length < 2) return 'stable';

    const slope = ts.getTrend();
    const criteria = SUCCESS_CRITERIA[metric_name];
    const direction = criteria ? criteria.direction : null;

    // Determine significance threshold: 0.5% of the moving average
    const ma = ts.getMovingAverage(10);
    const threshold = Math.max(Math.abs(ma) * 0.005, 0.001);

    if (Math.abs(slope) < threshold) return 'stable';

    if (direction === 'maximize') {
      return slope > 0 ? 'improving' : 'declining';
    } else if (direction === 'minimize') {
      return slope < 0 ? 'improving' : 'declining';
    }

    // No known direction — just report slope direction
    return slope > 0 ? 'improving' : 'declining';
  }

  /**
   * Compare current metrics against v0.9 success criteria targets.
   *
   * @returns {object[]} benchmark results
   */
  getBenchmarks() {
    const latest = this._getLatestSnapshot();
    const results = [];

    for (const [metricName, criteria] of Object.entries(SUCCESS_CRITERIA)) {
      const currentValue = latest ? latest[metricName] : 0;
      const target = criteria.target;

      let status;
      let gap;

      if (target === null) {
        // No explicit target — report current value only
        status = 'no_target';
        gap = null;
      } else if (criteria.direction === 'maximize') {
        status = currentValue >= target ? 'met' : 'below_target';
        gap = currentValue >= target ? 0 : Math.round((target - currentValue) * 10000) / 10000;
      } else {
        // minimize
        status = currentValue <= target ? 'met' : 'above_target';
        gap = currentValue <= target ? 0 : Math.round((currentValue - target) * 10000) / 10000;
      }

      results.push({
        metric: metricName,
        current: currentValue,
        target: target,
        direction: criteria.direction,
        status: status,
        gap: gap,
        trend: this.getTrend(metricName),
      });
    }

    return results;
  }

  // ─── Persistence ─────────────────────────────────────────────────

  /**
   * Save efficiency tracker state to disk.
   * @returns {string} path written
   */
  save() {
    const filePath = path.join(EFFICIENCY_DIR, 'efficiency-state.json');

    const data = {
      version: '0.9',
      saved_at: Date.now(),
      config: this.config,

      // Cumulative counters
      total_bugs_found:       this.totalBugsFound,
      total_verifications:    this.totalVerifications,
      total_confirmed:        this.totalConfirmed,
      total_rejected:         this.totalRejected,
      total_inconclusive:     this.totalInconclusive,
      total_cost_accumulated: this.totalCostAccumulated,

      // Time series
      time_series: [...this.timeSeries.entries()].map(([name, ts]) => [
        name,
        ts.toJSON(),
      ]),

      // Snapshot history (last 100)
      snapshots: this.snapshots.slice(-100).map(s => ({ ...s })),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load efficiency tracker state from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(EFFICIENCY_DIR, 'efficiency-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      // Restore cumulative counters
      this.totalBugsFound       = data.total_bugs_found       ?? 0;
      this.totalVerifications   = data.total_verifications    ?? 0;
      this.totalConfirmed       = data.total_confirmed        ?? 0;
      this.totalRejected        = data.total_rejected         ?? 0;
      this.totalInconclusive    = data.total_inconclusive     ?? 0;
      this.totalCostAccumulated = data.total_cost_accumulated ?? 0;

      // Restore time series
      if (data.time_series) {
        for (const [name, tsData] of data.time_series) {
          if (this.timeSeries.has(name)) {
            this.timeSeries.set(name, TimeSeries.fromJSON(tsData));
          }
        }
      }

      // Restore snapshot history
      if (data.snapshots) {
        this.snapshots = data.snapshots.map(s => new EfficiencySnapshot(s));
      }

      return true;
    } catch (_) {
      return false;
    }
  }

  // ─── Shutdown ────────────────────────────────────────────────────

  /**
   * Shut down the efficiency tracker.
   * Stops the periodic snapshot timer and persists state.
   */
  shutdown() {
    if (this._snapshotTimer) {
      clearInterval(this._snapshotTimer);
      this._snapshotTimer = null;
    }

    // Compute final snapshot before shutdown
    this.computeSnapshot();

    // Persist
    this.save();
  }

  // ─── Internal Helpers ────────────────────────────────────────────

  /**
   * Get the number of active workers from resource samples or
   * the resource optimizer.
   * @returns {number}
   * @private
   */
  _getActiveWorkers() {
    // Most recent resource sample
    if (this._resourceSamples.length > 0) {
      const latest = this._resourceSamples[this._resourceSamples.length - 1];
      return latest.active_workers || 1;
    }

    // Fallback to resource optimizer
    if (this.resourceOptimizer) {
      const dist = this.resourceOptimizer.currentDistribution;
      if (dist) {
        return dist.total_workers - (dist.idle || 0);
      }
    }

    // Default
    return 1;
  }

  /**
   * Reset window accumulators for the next snapshot period.
   * @private
   */
  _resetWindow() {
    this._windowBugsFound       = 0;
    this._windowVerifications   = 0;
    this._windowConfirmed       = 0;
    this._windowRejected        = 0;
    this._windowInconclusive    = 0;
    this._windowScanDurationMs  = 0;
    this._windowScanCount       = 0;
    this._windowBaselineDurationMs = 0;
    this._windowCostTotal       = 0;
    this._windowCoverageDelta   = 0;
    this._windowEvidenceQuality = [];
    this._windowStartTs         = Date.now();

    this._bugRecords            = [];
    this._verificationRecords   = [];
    this._resourceSamples       = [];
    this._costRecords           = [];
  }

  /**
   * Get the latest snapshot.
   * @returns {EfficiencySnapshot|null}
   * @private
   */
  _getLatestSnapshot() {
    if (this.snapshots.length === 0) return null;
    return this.snapshots[this.snapshots.length - 1];
  }
}

// ─── Exports ────────────────────────────────────────────────────────

module.exports = {
  EfficiencyTracker,
  EfficiencySnapshot,
  TimeSeries,
  DEFAULT_EFFICIENCY_CONFIG,
};


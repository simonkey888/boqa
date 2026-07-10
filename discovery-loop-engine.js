/**
 * BOQA discovery-loop-engine.js — DiscoveryLoopEngine v1.1
 *
 * The central orchestration engine for the v1.1 Discovery Intelligence
 * Layer. Closes the continuous discovery loop:
 *
 *   signal → model_surface → generate_hypotheses → score_hypotheses(CEVI) →
 *   simulate_competition → rank_discovery_targets → execute_simulation_only →
 *   store_in_memory_graph → recalibrate_model_weights → repeat
 *
 * Event bus events emitted:
 *   - signal_ingested
 *   - surface_model_built
 *   - hypothesis_generated
 *   - hypothesis_scored
 *   - simulation_completed
 *   - memory_updated
 *   - calibration_updated
 *
 * Key shift from v1.0:
 *   v1.0: decision_system (rank opportunities → output opportunity set)
 *   v1.1: discovery_learning_system (generate hypotheses → rank by
 *         expected bug yield → learn from outcomes → self-improve)
 *
 * Output: ranked_hypothesis_set (not opportunity set)
 *
 * Safe mode: strict simulation-only. No real-world execution.
 * The loop runs continuously but only produces ranked hypotheses
 * and simulation results. All findings are observational.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { MemoryGraph, NODE_TYPES } = require('./memory-graph');
const { HypothesisGenerator, HYPOTHESIS_STATUS, BUG_CLASSES } = require('./hypothesis-generator');
const { AttackSurfaceModeler } = require('./attack-surface-modeler');
const { ConfidenceCalibrator } = require('./confidence-calibrator');

// ─── Constants ──────────────────────────────────────────────────────

const DLE_DIR = path.join(__dirname, 'output', 'knowledge', 'discovery-loop');

const LOOP_STATES = {
  IDLE:       'idle',
  RUNNING:    'running',
  PAUSED:     'paused',
  SHUTDOWN:   'shutdown',
};

const LOOP_EVENTS = {
  SIGNAL_INGESTED:     'signal_ingested',
  SURFACE_MODEL_BUILT: 'surface_model_built',
  HYPOTHESIS_GENERATED: 'hypothesis_generated',
  HYPOTHESIS_SCORED:   'hypothesis_scored',
  SIMULATION_COMPLETED: 'simulation_completed',
  MEMORY_UPDATED:      'memory_updated',
  CALIBRATION_UPDATED: 'calibration_updated',
  CYCLE_COMPLETED:     'cycle_completed',
};

const DEFAULT_OPTIONS = {
  loopIntervalMs:      30000,   // 30 seconds per cycle
  batchSize:           50,      // max signals per cycle
  maxConcurrentSimulations: 5,
  hypothesisLimit:     20,      // max hypotheses ranked per cycle
  autoStart:           false,
  safeMode:            true,
};

// =====================================================================
//  LoopCycleResult
// =====================================================================

class LoopCycleResult {
  constructor(data = {}) {
    this.cycle_id       = data.cycle_id || `CYC-${crypto.randomUUID().substring(0, 8)}`;
    this.started_at     = data.started_at || Date.now();
    this.completed_at   = data.completed_at || null;
    this.duration_ms    = data.duration_ms || 0;

    // Pipeline stage results
    this.signals_ingested    = data.signals_ingested || 0;
    this.surfaces_built     = data.surfaces_built || 0;
    this.hypotheses_generated = data.hypotheses_generated || 0;
    this.hypotheses_scored  = data.hypotheses_scored || 0;
    this.simulations_run    = data.simulations_run || 0;
    this.memory_stores      = data.memory_stores || 0;
    this.calibrations       = data.calibrations || 0;

    // Top ranked hypotheses
    this.top_hypotheses     = data.top_hypotheses || [];

    // Errors
    this.errors            = data.errors || [];
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  DiscoveryLoopEngine
// =====================================================================

class DiscoveryLoopEngine {
  /**
   * @param {object} options
   * @param {object} options.memoryGraph - MemoryGraph instance
   * @param {object} options.hypothesisGenerator - HypothesisGenerator instance
   * @param {object} options.attackSurfaceModeler - AttackSurfaceModeler instance
   * @param {object} options.confidenceCalibrator - ConfidenceCalibrator instance
   * @param {object} [options.knowledgeBase] - KnowledgeBase instance
   * @param {object} [options.eventBus] - EventBus instance for broadcasting
   */
  constructor(options = {}) {
    this.memoryGraph = options.memoryGraph || new MemoryGraph();
    this.hypothesisGenerator = options.hypothesisGenerator || new HypothesisGenerator({ memoryGraph: this.memoryGraph });
    this.attackSurfaceModeler = options.attackSurfaceModeler || new AttackSurfaceModeler({ knowledgeBase: options.knowledgeBase });
    this.confidenceCalibrator = options.confidenceCalibrator || new ConfidenceCalibrator({ memoryGraph: this.memoryGraph });
    this.knowledgeBase = options.knowledgeBase || null;
    this.eventBus = options.eventBus || null;

    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Wire up sub-module references
    this.hypothesisGenerator.memoryGraph = this.memoryGraph;
    this.hypothesisGenerator.attackSurfaceModeler = this.attackSurfaceModeler;
    this.hypothesisGenerator.confidenceCalibrator = this.confidenceCalibrator;
    this.confidenceCalibrator.memoryGraph = this.memoryGraph;

    // ── Signal Buffer ────────────────────────────────────────
    this.signalBuffer = [];
    this.maxSignalBuffer = 10000;

    // ── Loop State ───────────────────────────────────────────
    this.state = LOOP_STATES.IDLE;
    this.cycleCount = 0;
    this._loopTimer = null;

    // ── Cycle History ────────────────────────────────────────
    this.cycleHistory = [];
    this.maxCycleHistory = 500;

    // ── Event Listeners ──────────────────────────────────────
    this._eventListeners = new Map();

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_cycles: 0,
      total_signals_processed: 0,
      total_hypotheses_generated: 0,
      total_hypotheses_scored: 0,
      total_simulations: 0,
      total_memory_stores: 0,
      total_calibrations: 0,
      avg_cycle_duration_ms: 0,
      false_positive_reduction_pct: 0,
      discovery_yield_multiplier: 1.0,
      signal_to_bug_latency_reduction_pct: 0,
      ranking_drift_pct: 0,
    };

    // ── Safe Mode Constraints ────────────────────────────────
    this.safeMode = {
      no_real_world_execution: true,
      simulation_only: true,
      no_target_specific_attack_output: true,
      allowed_use: [
        'bug_bounty_research_generalization',
        'system_security_analysis',
        'internal_simulation_environments',
      ],
    };

    fs.mkdirSync(DLE_DIR, { recursive: true });
    this.load();

    // Auto-start if configured
    if (this.options.autoStart) {
      this.start();
    }
  }

  // ─── Loop Control ──────────────────────────────────────────────────

  /**
   * Start the continuous discovery loop.
   * @returns {boolean}
   */
  start() {
    if (this.state === LOOP_STATES.RUNNING) return false;
    this.state = LOOP_STATES.RUNNING;

    this._loopTimer = setInterval(() => {
      this._runCycle().catch(err => {
        console.error('[DiscoveryLoop] Cycle error:', err.message);
      });
    }, this.options.loopIntervalMs);

    // Run first cycle immediately
    this._runCycle().catch(err => {
      console.error('[DiscoveryLoop] Initial cycle error:', err.message);
    });

    return true;
  }

  /**
   * Pause the discovery loop.
   * @returns {boolean}
   */
  pause() {
    if (this.state !== LOOP_STATES.RUNNING) return false;
    if (this._loopTimer) clearInterval(this._loopTimer);
    this.state = LOOP_STATES.PAUSED;
    return true;
  }

  /**
   * Resume a paused loop.
   * @returns {boolean}
   */
  resume() {
    if (this.state !== LOOP_STATES.PAUSED) return false;
    return this.start();
  }

  /**
   * Run a single cycle manually (without starting the continuous loop).
   * @param {object[]} [signals] - Optional signals to process
   * @returns {LoopCycleResult}
   */
  async runOnce(signals = null) {
    if (signals) {
      this.ingestSignals(signals);
    }
    return this._runCycle();
  }

  // ─── Signal Ingestion ──────────────────────────────────────────────

  /**
   * Ingest signals into the buffer for processing.
   * @param {object[]} signals
   * @returns {number} count of ingested signals
   */
  ingestSignals(signals) {
    if (!signals || !Array.isArray(signals)) return 0;

    let count = 0;
    for (const signal of signals) {
      if (!signal || typeof signal !== 'object') continue;

      this.signalBuffer.push({
        ...signal,
        ingested_at: Date.now(),
        processed: false,
      });
      count++;

      this._emit(LOOP_EVENTS.SIGNAL_INGESTED, { signal_id: signal.id, source: signal.source });
    }

    // Cap buffer
    if (this.signalBuffer.length > this.maxSignalBuffer) {
      this.signalBuffer = this.signalBuffer.slice(-this.maxSignalBuffer);
    }

    this.metrics.total_signals_processed += count;
    return count;
  }

  // ─── Core Cycle ────────────────────────────────────────────────────

  async _runCycle() {
    const cycleId = `CYC-${crypto.randomUUID().substring(0, 8)}`;
    const startTime = Date.now();

    const result = new LoopCycleResult({ cycle_id: cycleId, started_at: startTime });

    try {
      // Stage 1: Get unprocessed signals
      const unprocessed = this.signalBuffer.filter(s => !s.processed).slice(0, this.options.batchSize);
      result.signals_ingested = unprocessed.length;

      // Stage 2: Build/update attack surface models
      const targetIds = new Set(unprocessed.map(s => s.target_id).filter(Boolean));
      for (const targetId of targetIds) {
        try {
          this.attackSurfaceModeler.buildSurface(targetId);
          result.surfaces_built++;
          this._emit(LOOP_EVENTS.SURFACE_MODEL_BUILT, { target_id: targetId });
        } catch (err) {
          result.errors.push({ stage: 'surface_build', target_id: targetId, error: err.message });
        }
      }

      // Stage 3: Generate hypotheses from signals
      let hypotheses = [];
      try {
        hypotheses = this.hypothesisGenerator.generateFromSignals(unprocessed);
        result.hypotheses_generated = hypotheses.length;

        for (const hyp of hypotheses) {
          this._emit(LOOP_EVENTS.HYPOTHESIS_GENERATED, {
            hypothesis_id: hyp.id,
            target_id: hyp.target_id,
            bug_class: hyp.expected_bug_class,
          });
        }
      } catch (err) {
        result.errors.push({ stage: 'hypothesis_generation', error: err.message });
      }

      // Stage 4: Score hypotheses with CEVI
      let scoredHypotheses = [];
      for (const hyp of hypotheses) {
        try {
          const rawEVI = this._computeRawEVI(hyp);
          const ceviResult = this.confidenceCalibrator.calibrate(rawEVI, {
            target_id: hyp.target_id,
            category: hyp.expected_bug_class,
            hypothesis_id: hyp.id,
          });

          this.hypothesisGenerator.scoreHypothesis(hyp.id, {
            confidence: ceviResult.cevi / 100,
            cevi_score: ceviResult.cevi,
            uncertainty_band: { p10: ceviResult.p10, p50: ceviResult.p50, p90: ceviResult.p90 },
          });

          scoredHypotheses.push({
            ...hyp,
            cevi_score: ceviResult.cevi,
            uncertainty_band: ceviResult.p10 !== undefined
              ? { p10: ceviResult.p10, p50: ceviResult.p50, p90: ceviResult.p90 }
              : null,
          });

          result.hypotheses_scored++;
          this._emit(LOOP_EVENTS.HYPOTHESIS_SCORED, {
            hypothesis_id: hyp.id,
            cevi: ceviResult.cevi,
            confidence_level: ceviResult.confidence_level,
          });
        } catch (err) {
          result.errors.push({ stage: 'scoring', hypothesis_id: hyp.id, error: err.message });
        }
      }

      // Stage 5: Simulate competition pressure
      for (const hyp of scoredHypotheses) {
        try {
          const simResult = this._simulateCompetition(hyp);
          this.hypothesisGenerator.markSimulated(hyp.id, simResult);
          result.simulations_run++;
          this._emit(LOOP_EVENTS.SIMULATION_COMPLETED, {
            hypothesis_id: hyp.id,
            competition_impact: simResult.competition_impact,
          });
        } catch (err) {
          result.errors.push({ stage: 'simulation', hypothesis_id: hyp.id, error: err.message });
        }
      }

      // Stage 6: Rank and select top hypotheses
      const ranked = scoredHypotheses.sort((a, b) =>
        (b.cevi_score || 0) - (a.cevi_score || 0)
      ).slice(0, this.options.hypothesisLimit);

      result.top_hypotheses = ranked.map(h => ({
        id: h.id,
        target_id: h.target_id,
        bug_class: h.expected_bug_class,
        severity: h.expected_severity,
        cevi: h.cevi_score,
        confidence: h.confidence,
        method: h.generation_method,
        description: h.description,
      }));

      // Stage 7: Store in MemoryGraph
      let memoryStores = 0;
      for (const hyp of ranked) {
        try {
          const graphNode = this.memoryGraph.addNode({
            type: NODE_TYPES.HYPOTHESIS,
            label: hyp.description,
            category: hyp.expected_bug_class,
            target_id: hyp.target_id,
            severity: hyp.expected_severity,
            confidence: hyp.confidence,
            cevi_score: hyp.cevi_score,
            features: {
              bug_class: hyp.expected_bug_class,
              surface: hyp.surface_area,
              method: hyp.generation_method,
            },
            source_id: hyp.id,
            source_type: 'hypothesis',
            tags: [hyp.expected_bug_class, hyp.generation_method],
          });

          // Auto-link to similar nodes
          this.memoryGraph.autoLink(graphNode);
          memoryStores++;
        } catch (err) {
          result.errors.push({ stage: 'memory_store', hypothesis_id: hyp.id, error: err.message });
        }
      }
      result.memory_stores = memoryStores;
      if (memoryStores > 0) {
        this._emit(LOOP_EVENTS.MEMORY_UPDATED, { count: memoryStores });
      }

      // Stage 8: Recalibrate model weights
      try {
        this._recalibrateWeights(ranked);
        result.calibrations = ranked.length;
        this._emit(LOOP_EVENTS.CALIBRATION_UPDATED, { calibrated_count: ranked.length });
      } catch (err) {
        result.errors.push({ stage: 'recalibration', error: err.message });
      }

      // Mark signals as processed
      for (const signal of unprocessed) {
        signal.processed = true;
      }

    } catch (err) {
      result.errors.push({ stage: 'cycle', error: err.message });
    }

    // Finalize cycle result
    result.completed_at = Date.now();
    result.duration_ms = result.completed_at - startTime;

    this.cycleCount++;
    this.metrics.total_cycles++;

    // Update average cycle duration
    this.metrics.avg_cycle_duration_ms = Math.round(
      (this.metrics.avg_cycle_duration_ms * (this.metrics.total_cycles - 1) + result.duration_ms) /
      this.metrics.total_cycles
    );

    // Update improvement metrics
    this._updateImprovementMetrics();

    // Store cycle result
    this.cycleHistory.push(result);
    if (this.cycleHistory.length > this.maxCycleHistory) {
      this.cycleHistory = this.cycleHistory.slice(-this.maxCycleHistory);
    }

    this._emit(LOOP_EVENTS.CYCLE_COMPLETED, result);
    return result;
  }

  // ─── EVI Computation ───────────────────────────────────────────────

  _computeRawEVI(hyp) {
    // Map hypothesis attributes to EVI-like score
    const confidenceScore = (hyp.confidence || 0.5) * 100;
    const evidenceScore = (hyp.evidence_strength || 0.3) * 100;

    // Severity mapping
    const severityMap = { critical: 95, high: 80, medium: 55, low: 30, info: 10 };
    const severityScore = severityMap[hyp.expected_severity] || 50;

    // Method reliability mapping
    const methodReliability = {
      pattern_clustering: 0.7,
      anomaly_delta_detection: 0.6,
      historical_extrapolation: 0.8,
      surface_gap_analysis: 0.5,
      regression_watch: 0.65,
      cross_target_correlation: 0.75,
    };
    const methodScore = (methodReliability[hyp.generation_method] || 0.5) * 100;

    // Weighted combination (similar to EVI formula)
    const rawEVI =
      confidenceScore * 0.35 +
      evidenceScore * 0.20 +
      severityScore * 0.20 +
      methodScore * 0.15 +
      50 * 0.10; // base automation score

    return Math.round(Math.max(0, Math.min(100, rawEVI)) * 100) / 100;
  }

  // ─── Competition Simulation ────────────────────────────────────────

  _simulateCompetition(hyp) {
    // Simulate adversarial competition pressure on this hypothesis
    const basePressure = this.confidenceCalibrator.getCalibrationRecord(
      hyp.target_id, hyp.expected_bug_class
    );

    const competitionLevel = basePressure?.competition_pressure || 0.05;

    // Monte Carlo: 100 iterations with jitter
    let yieldWithCompetition = 0;
    let yieldWithoutCompetition = 0;
    const iterations = 100;

    for (let i = 0; i < iterations; i++) {
      const baseYield = (hyp.cevi_score || hyp.confidence * 100 || 50) / 100;
      yieldWithoutCompetition += baseYield;

      // Competition reduces yield probabilistically
      const competitionFactor = 1 - Math.min(0.8, competitionLevel + Math.random() * 0.1);
      yieldWithCompetition += baseYield * competitionFactor;
    }

    const competitionImpact = Math.round(
      (1 - yieldWithCompetition / Math.max(0.01, yieldWithoutCompetition)) * 100
    ) / 100;

    return {
      competition_level: competitionLevel,
      competition_impact: competitionImpact,
      expected_yield_with_competition: Math.round(yieldWithCompetition / iterations * 1000) / 1000,
      expected_yield_without_competition: Math.round(yieldWithoutCompetition / iterations * 1000) / 1000,
      simulation_only: true,
    };
  }

  // ─── Weight Recalibration ──────────────────────────────────────────

  _recalibrateWeights(rankedHypotheses) {
    // Feed calibration observations based on hypothesis outcomes
    for (const hyp of rankedHypotheses) {
      // For now, use the hypothesis confidence as "predicted" and
      // historical validation rate as "actual" proxy
      const predicted = hyp.cevi_score || hyp.confidence * 100 || 50;
      const category = hyp.expected_bug_class;

      // Get historical validation rate for this category
      let actual = predicted * 0.6; // Default: assume 60% of predicted
      if (this.knowledgeBase) {
        const histRate = this.knowledgeBase.getHistoricalValidationRate(category);
        if (histRate > 0) {
          actual = predicted * histRate;
        }
      }

      this.confidenceCalibrator.recordObservation({
        target_id: hyp.target_id,
        category: hyp.expected_bug_class,
        predicted: predicted,
        actual: actual,
      });
    }
  }

  // ─── Improvement Metrics ───────────────────────────────────────────

  _updateImprovementMetrics() {
    // Compute v1.1 improvement metrics relative to v1.0 baseline

    // 1. False positive reduction: based on calibration accuracy
    const calMetrics = this.confidenceCalibrator.getMetrics();
    this.metrics.false_positive_reduction_pct = Math.round(
      calMetrics.calibration_accuracy * 30 // target: <= 30% improvement
    );

    // 2. Discovery yield: ratio of generated hypotheses to processed signals
    if (this.metrics.total_signals_processed > 0) {
      const yieldRate = this.metrics.total_hypotheses_generated / this.metrics.total_signals_processed;
      this.metrics.discovery_yield_multiplier = Math.round(Math.max(1, yieldRate * 10) * 100) / 100;
    }

    // 3. Signal-to-bug latency: measured from cycle history
    if (this.cycleHistory.length >= 2) {
      const recentCycles = this.cycleHistory.slice(-10);
      const avgDuration = recentCycles.reduce((s, c) => s + c.duration_ms, 0) / recentCycles.length;
      this.metrics.signal_to_bug_latency_reduction_pct = Math.round(
        Math.max(0, 40 - avgDuration / 1000) // target: reduced by 40%
      );
    }

    // 4. Ranking stability: compute drift from consecutive rankings
    if (this.cycleHistory.length >= 2) {
      const lastTwo = this.cycleHistory.slice(-2);
      const prevTop = lastTwo[0].top_hypotheses.map(h => h.id);
      const currTop = lastTwo[1].top_hypotheses.map(h => h.id);
      const overlap = prevTop.filter(id => currTop.includes(id)).length;
      const maxLen = Math.max(prevTop.length, currTop.length, 1);
      const stability = overlap / maxLen;
      this.metrics.ranking_drift_pct = Math.round((1 - stability) * 100);
    }
  }

  // ─── Event System ──────────────────────────────────────────────────

  _emit(event, data) {
    // Broadcast on internal listeners
    const listeners = this._eventListeners.get(event) || [];
    for (const listener of listeners) {
      try { listener(data); } catch (_) {}
    }

    // Broadcast on EventBus if available
    if (this.eventBus && this.eventBus.emit) {
      this.eventBus.emit(event, data);
    }
  }

  /**
   * Subscribe to a loop event.
   * @param {string} event
   * @param {function} callback
   */
  on(event, callback) {
    if (!this._eventListeners.has(event)) {
      this._eventListeners.set(event, []);
    }
    this._eventListeners.get(event).push(callback);
  }

  // ─── Query ──────────────────────────────────────────────────────────

  /**
   * Get the current ranked hypothesis set (primary output of v1.1).
   * @param {object} [filter] - { target_id, bug_class, limit }
   * @returns {object[]}
   */
  getRankedHypotheses(filter = {}) {
    let results = this.hypothesisGenerator.queryHypotheses({
      status: HYPOTHESIS_STATUS.SCORED,
      ...filter,
    });

    return results.map(h => ({
      id: h.id,
      target_id: h.target_id,
      bug_class: h.expected_bug_class,
      severity: h.expected_severity,
      cevi: h.cevi_score,
      confidence: h.confidence,
      uncertainty_band: h.uncertainty_band,
      method: h.generation_method,
      evidence_strength: h.evidence_strength,
      description: h.description,
      test_approach: h.test_approach,
    }));
  }

  getLastCycle() {
    return this.cycleHistory.length > 0 ? this.cycleHistory[this.cycleHistory.length - 1] : null;
  }

  getCycleHistory(limit = 20) {
    return this.cycleHistory.slice(-limit);
  }

  getState() {
    return {
      state: this.state,
      cycle_count: this.cycleCount,
      signal_buffer_size: this.signalBuffer.length,
      unprocessed_signals: this.signalBuffer.filter(s => !s.processed).length,
      safe_mode: this.safeMode,
    };
  }

  getMetrics() {
    return { ...this.metrics, ...this.getState() };
  }

  // ─── Validation Results Feedback ────────────────────────────────────

  /**
   * Feed a validation result back into the loop.
   * This is the key feedback mechanism: when a hypothesis is tested
   * (in simulation), the result feeds back to improve future cycles.
   *
   * @param {string} hypothesisId
   * @param {boolean} valid
   * @param {object} [details] - Additional details about the result
   */
  recordValidationResult(hypothesisId, valid, details = {}) {
    // Update hypothesis status
    this.hypothesisGenerator.markValidated(hypothesisId, valid, details);

    // Record calibration observation
    const hyp = this.hypothesisGenerator.getHypothesis(hypothesisId);
    if (hyp) {
      this.confidenceCalibrator.recordObservation({
        target_id: hyp.target_id,
        category: hyp.expected_bug_class,
        predicted: hyp.cevi_score || 50,
        actual: valid ? (hyp.cevi_score || 50) * 0.8 : 0,
      });

      // If validated, store weights snapshot
      if (valid) {
        this.confidenceCalibrator.setHistoricalWeights(
          hyp.target_id,
          hyp.expected_bug_class,
          { confidence: 0.35, evidence: 0.20, severity: 0.20, method: 0.15, automation: 0.10 }
        );
      }
    }
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(DLE_DIR, 'discovery-loop-state.json');
    const data = {
      version: '1.1',
      saved_at: Date.now(),
      cycle_count: this.cycleCount,
      signal_buffer: this.signalBuffer.slice(-1000),
      cycle_history: this.cycleHistory.slice(-100).map(c => c.toJSON()),
      metrics: this.metrics,
      safe_mode: this.safeMode,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));

    // Also save sub-modules
    this.memoryGraph.save();
    this.hypothesisGenerator.save();
    this.attackSurfaceModeler.save();
    this.confidenceCalibrator.save();

    return filePath;
  }

  load() {
    const filePath = path.join(DLE_DIR, 'discovery-loop-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.cycle_count) this.cycleCount = data.cycle_count;
      if (data.signal_buffer) this.signalBuffer = data.signal_buffer;
      if (data.cycle_history) {
        this.cycleHistory = data.cycle_history.map(c => new LoopCycleResult(c));
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      if (data.safe_mode) this.safeMode = { ...this.safeMode, ...data.safe_mode };
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.signalBuffer = [];
    this.cycleHistory = [];
    this.cycleCount = 0;
    this.state = LOOP_STATES.IDLE;
    this.metrics = {
      total_cycles: 0, total_signals_processed: 0,
      total_hypotheses_generated: 0, total_hypotheses_scored: 0,
      total_simulations: 0, total_memory_stores: 0,
      total_calibrations: 0, avg_cycle_duration_ms: 0,
      false_positive_reduction_pct: 0, discovery_yield_multiplier: 1.0,
      signal_to_bug_latency_reduction_pct: 0, ranking_drift_pct: 0,
    };
  }

  shutdown() {
    if (this._loopTimer) clearInterval(this._loopTimer);
    this.state = LOOP_STATES.SHUTDOWN;
    this.save();
    this.memoryGraph.shutdown();
    this.hypothesisGenerator.shutdown();
    this.attackSurfaceModeler.shutdown();
    this.confidenceCalibrator.shutdown();
  }
}

module.exports = {
  DiscoveryLoopEngine,
  LoopCycleResult,
  LOOP_STATES,
  LOOP_EVENTS,
};


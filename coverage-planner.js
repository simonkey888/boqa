/**
 * BOQA coverage-planner.js — Coverage Planner v0.6
 *
 * Chooses the next best action to maximize discovery yield.
 * Acts as the brain of the autonomous discovery loop, deciding
 * what to explore, verify, or revisit based on:
 *
 *   - Current coverage map (what's been discovered)
 *   - Coverage gaps (what's missing)
 *   - Hypothesis queue (what needs verification)
 *   - Historical success rates (what worked before)
 *   - Risk-weighted priorities (what matters most)
 *
 * Planning modes:
 *   - observe:     passive observation, build initial coverage
 *   - explore:     active exploration of uncovered areas
 *   - verify:      focused on validating hypotheses
 *   - continuous:  full autonomous loop (discover → verify → repeat)
 *
 * The continuous loop:
 *   1. discover_surface   — run coverage engine on events
 *   2. build_coverage_graph — update coverage map
 *   3. generate_hypotheses — create new hypotheses from gaps
 *   4. prioritize         — rank hypotheses by EVV
 *   5. verify             — dispatch to verification farm
 *   6. correlate          — cross-session correlation
 *   7. score              — update rankings and lifecycle states
 *   8. persist            — save to knowledge base
 *   9. repeat
 *
 * Safe mode: the planner never plans forbidden actions and
 * respects authorization boundaries for each target.
 */

const crypto = require('crypto');

// ─── Execution Modes ────────────────────────────────────────────────

const EXECUTION_MODES = {
  OBSERVE:    'observe',
  EXPLORE:    'explore',
  VERIFY:     'verify',
  CONTINUOUS: 'continuous',
};

// ─── Continuous Loop Phases ─────────────────────────────────────────

const LOOP_PHASES = [
  'discover_surface',
  'build_coverage_graph',
  'generate_hypotheses',
  'prioritize',
  'verify',
  'correlate',
  'score',
  'persist',
  'repeat',
];

// ─── Coverage Gap Hypothesis Templates ──────────────────────────────

const GAP_HYPOTHESIS_TEMPLATES = {
  auth_flows: [
    { category: 'auth_bypass', title: 'Unverified auth flow at {path}', severity: 'high' },
    { category: 'session_hijacking', title: 'Session handling gap at {path}', severity: 'high' },
    { category: 'csrf', title: 'CSRF protection gap in auth flow', severity: 'medium' },
  ],
  api_endpoints: [
    { category: 'api_exposure', title: 'Undocumented API endpoint at {path}', severity: 'medium' },
    { category: 'idor', title: 'Potential IDOR at {path}', severity: 'high' },
    { category: 'rate_limiting', title: 'Missing rate limiting at {path}', severity: 'medium' },
  ],
  websocket_channels: [
    { category: 'websocket_hijacking', title: 'Unprotected WebSocket channel at {url}', severity: 'high' },
    { category: 'websocket_injection', title: 'WebSocket message injection possible at {url}', severity: 'medium' },
  ],
  forms: [
    { category: 'xss', title: 'Unvalidated form input at {path}', severity: 'medium' },
    { category: 'injection', title: 'Potential injection via form at {path}', severity: 'high' },
  ],
  routes: [
    { category: 'information_disclosure', title: 'Accessible route at {path} may expose data', severity: 'low' },
    { category: 'broken_access_control', title: 'Route {path} may lack access control', severity: 'medium' },
  ],
  state_transitions: [
    { category: 'workflow_bypass', title: 'State transition bypass at {path}', severity: 'medium' },
  ],
};

// =====================================================================
//  CoveragePlanner
// =====================================================================

class CoveragePlanner {
  /**
   * @param {object} options
   * @param {object} options.coverageEngine       - CoverageEngine instance
   * @param {object} options.explorationEngine     - ExplorationEngine instance
   * @param {object} options.hypothesisPrioritizer - HypothesisPrioritizer instance
   * @param {object} options.correlationEngine     - CorrelationEngine instance
   * @param {object} options.verificationFarm      - VerificationFarm instance
   * @param {object} options.knowledgeBase         - KnowledgeBase instance
   * @param {object} options.targetManager         - TargetManager instance
   * @param {string} [options.mode]                - execution mode (default: observe)
   * @param {number} [options.loopIntervalMs]      - continuous loop interval (default: 30000)
   * @param {number} [options.maxHypothesesPerLoop] - max hypotheses per loop iteration (default: 20)
   */
  constructor(options = {}) {
    this.coverageEngine = options.coverageEngine || null;
    this.explorationEngine = options.explorationEngine || null;
    this.hypothesisPrioritizer = options.hypothesisPrioritizer || null;
    this.correlationEngine = options.correlationEngine || null;
    this.verificationFarm = options.verificationFarm || null;
    this.kb = options.knowledgeBase || null;
    this.targetManager = options.targetManager || null;

    this.mode = options.mode || EXECUTION_MODES.OBSERVE;
    this.loopIntervalMs = options.loopIntervalMs || 30000;
    this.maxHypothesesPerLoop = options.maxHypothesesPerLoop || 20;

    /** @type {string|null} current loop phase */
    this.currentPhase = null;

    /** @type {number} loop iteration counter */
    this.iteration = 0;

    /** @type {object} loop state tracking */
    this.loopState = {
      started_at: null,
      last_iteration_at: null,
      total_iterations: 0,
      total_hypotheses_generated: 0,
      total_verifications_dispatched: 0,
      total_bugs_confirmed: 0,
      phases_completed: 0,
    };

    /** @type {NodeJS.Timeout|null} loop timer */
    this._loopTimer = null;

    /** @type {boolean} whether the loop is running */
    this._running = false;
  }

  // ─── Mode Management ─────────────────────────────────────────────

  /**
   * Set the execution mode.
   *
   * @param {string} mode - observe|explore|verify|continuous
   */
  setMode(mode) {
    if (!Object.values(EXECUTION_MODES).includes(mode)) {
      throw new Error(`Invalid mode: ${mode}. Must be one of: ${Object.values(EXECUTION_MODES).join(', ')}`);
    }
    this.mode = mode;

    if (mode === EXECUTION_MODES.CONTINUOUS && !this._running) {
      this.startContinuousLoop();
    } else if (mode !== EXECUTION_MODES.CONTINUOUS && this._running) {
      this.stopContinuousLoop();
    }
  }

  /**
   * Get the current execution mode.
   * @returns {string}
   */
  getMode() {
    return this.mode;
  }

  // ─── Single-Shot Planning ────────────────────────────────────────

  /**
   * Generate a plan for the next best action(s) based on the
   * current state of coverage, hypotheses, and verification queue.
   *
   * @param {string} targetId
   * @param {object} [options] - { mode, max_steps }
   * @returns {object} action plan
   */
  plan(targetId, options = {}) {
    const mode = options.mode || this.mode;
    const maxSteps = options.max_steps || 10;

    const plan = {
      id: `PLAN-${crypto.randomUUID().substring(0, 8)}`,
      target_id: targetId,
      mode,
      steps: [],
      generated_at: Date.now(),
    };

    switch (mode) {
      case EXECUTION_MODES.OBSERVE:
        plan.steps = this._planObserve(targetId, maxSteps);
        break;
      case EXECUTION_MODES.EXPLORE:
        plan.steps = this._planExplore(targetId, maxSteps);
        break;
      case EXECUTION_MODES.VERIFY:
        plan.steps = this._planVerify(targetId, maxSteps);
        break;
      case EXECUTION_MODES.CONTINUOUS:
        plan.steps = this._planContinuous(targetId, maxSteps);
        break;
    }

    return plan;
  }

  // ─── Planning Strategies ─────────────────────────────────────────

  /**
   * Observe mode: passive — just watch and build coverage.
   * @param {string} targetId
   * @param {number} maxSteps
   * @returns {object[]}
   * @private
   */
  _planObserve(targetId, maxSteps) {
    const steps = [];

    steps.push({
      phase: 'discover_surface',
      action: 'observe',
      description: 'Passively observe events and build coverage map',
      target_id: targetId,
    });

    if (this.coverageEngine) {
      const coverage = this.coverageEngine.getCoverageMap(targetId);
      steps.push({
        phase: 'build_coverage_graph',
        action: 'compute_coverage',
        description: `Compute coverage score: ${coverage.score}%`,
        target_id: targetId,
        coverage_score: coverage.score,
      });
    }

    return steps.slice(0, maxSteps);
  }

  /**
   * Explore mode: actively discover new surface.
   * @param {string} targetId
   * @param {number} maxSteps
   * @returns {object[]}
   * @private
   */
  _planExplore(targetId, maxSteps) {
    const steps = [];

    // Get coverage gaps
    let gaps = [];
    if (this.coverageEngine) {
      gaps = this.coverageEngine.getCoverageGaps(targetId);
    }

    // Get exploration plan from exploration engine
    let explorationPlan = null;
    if (this.explorationEngine) {
      explorationPlan = this.explorationEngine.generatePlan(targetId, {
        strategy: 'coverage_greedy',
        max_steps: maxSteps,
        focus_domains: gaps.map(g => g.domain),
      });
    }

    if (explorationPlan && explorationPlan.steps.length > 0) {
      for (const step of explorationPlan.steps) {
        steps.push({
          phase: 'explore',
          action: 'navigate',
          url: step.url,
          description: `Explore ${step.risk_class} route: ${step.url}`,
          target_id: targetId,
          priority: step.priority,
          risk_class: step.risk_class,
          reason: step.reason,
        });
      }
    }

    // Generate hypotheses from gaps
    const gapHypotheses = this._generateGapHypotheses(targetId, gaps);
    if (gapHypotheses.length > 0 && this.hypothesisPrioritizer) {
      for (const h of gapHypotheses.slice(0, 5)) {
        steps.push({
          phase: 'generate_hypotheses',
          action: 'submit_hypothesis',
          hypothesis: h,
          description: `Hypothesis: ${h.title}`,
          target_id: targetId,
        });
      }
    }

    return steps.slice(0, maxSteps);
  }

  /**
   * Verify mode: validate top hypotheses.
   * @param {string} targetId
   * @param {number} maxSteps
   * @returns {object[]}
   * @private
   */
  _planVerify(targetId, maxSteps) {
    const steps = [];

    // Get top hypotheses to verify
    if (this.hypothesisPrioritizer) {
      const topHypotheses = this.hypothesisPrioritizer.getNext(maxSteps);

      for (const hypothesis of topHypotheses) {
        // Determine the best verification action
        const action = this._selectVerificationAction(hypothesis);

        steps.push({
          phase: 'verify',
          action: 'verify_hypothesis',
          hypothesis_id: hypothesis.id,
          verification_action: action,
          description: `Verify: ${hypothesis.title} (EVV: ${hypothesis.evv})`,
          target_id: targetId,
          evv: hypothesis.evv,
          cost: hypothesis.verification_cost,
        });
      }
    }

    return steps.slice(0, maxSteps);
  }

  /**
   * Continuous mode: full autonomous loop.
   * @param {string} targetId
   * @param {number} maxSteps
   * @returns {object[]}
   * @private
   */
  _planContinuous(targetId, maxSteps) {
    const steps = [];

    // Phase 1: Discover surface
    steps.push({
      phase: LOOP_PHASES[0],
      action: 'discover_surface',
      description: 'Run coverage engine on all observed events',
      target_id: targetId,
    });

    // Phase 2: Build coverage graph
    steps.push({
      phase: LOOP_PHASES[1],
      action: 'build_coverage',
      description: 'Update coverage map and compute score',
      target_id: targetId,
    });

    // Phase 3: Generate hypotheses
    let gaps = [];
    if (this.coverageEngine) {
      gaps = this.coverageEngine.getCoverageGaps(targetId);
    }
    const gapHypotheses = this._generateGapHypotheses(targetId, gaps);
    if (gapHypotheses.length > 0) {
      steps.push({
        phase: LOOP_PHASES[2],
        action: 'generate_hypotheses',
        hypotheses: gapHypotheses.slice(0, this.maxHypothesesPerLoop),
        description: `Generate ${Math.min(gapHypotheses.length, this.maxHypothesesPerLoop)} hypotheses from coverage gaps`,
        target_id: targetId,
      });
    }

    // Phase 4: Prioritize
    steps.push({
      phase: LOOP_PHASES[3],
      action: 'prioritize',
      description: 'Rank hypotheses by expected validation value',
      target_id: targetId,
    });

    // Phase 5: Verify top hypotheses
    if (this.hypothesisPrioritizer) {
      const topHypotheses = this.hypothesisPrioritizer.getNext(5);
      for (const h of topHypotheses) {
        const action = this._selectVerificationAction(h);
        steps.push({
          phase: LOOP_PHASES[4],
          action: 'verify_hypothesis',
          hypothesis_id: h.id,
          verification_action: action,
          description: `Verify: ${h.title} (EVV: ${h.evv})`,
          target_id: targetId,
        });
      }
    }

    // Phase 6: Correlate
    steps.push({
      phase: LOOP_PHASES[5],
      action: 'correlate',
      description: 'Cross-session evidence correlation',
      target_id: targetId,
    });

    // Phase 7: Score
    steps.push({
      phase: LOOP_PHASES[6],
      action: 'score',
      description: 'Update rankings and lifecycle states',
      target_id: targetId,
    });

    // Phase 8: Persist
    steps.push({
      phase: LOOP_PHASES[7],
      action: 'persist',
      description: 'Save to knowledge base',
      target_id: targetId,
    });

    return steps.slice(0, maxSteps);
  }

  // ─── Continuous Loop ─────────────────────────────────────────────

  /**
   * Start the continuous discovery loop.
   * Runs the full loop on a timer.
   */
  startContinuousLoop() {
    if (this._running) return;

    this._running = true;
    this.loopState.started_at = Date.now();

    console.log('[CoveragePlanner] Starting continuous loop');

    this._runLoopIteration();
  }

  /**
   * Stop the continuous discovery loop.
   */
  stopContinuousLoop() {
    this._running = false;

    if (this._loopTimer) {
      clearTimeout(this._loopTimer);
      this._loopTimer = null;
    }

    console.log('[CoveragePlanner] Stopped continuous loop');
  }

  /**
   * Run a single iteration of the continuous loop.
   * @private
   */
  async _runLoopIteration() {
    if (!this._running) return;

    this.iteration++;
    this.currentPhase = LOOP_PHASES[0];
    this.loopState.last_iteration_at = Date.now();
    this.loopState.total_iterations++;

    try {
      // Get authorized targets
      const targets = this.targetManager
        ? this.targetManager.getAuthorizedTargets()
        : [{ id: 'default' }];

      for (const target of targets) {
        const targetId = target.id;

        // Phase 1: Discover surface
        this.currentPhase = LOOP_PHASES[0];
        await this._executeDiscoverSurface(targetId);

        // Phase 2: Build coverage graph
        this.currentPhase = LOOP_PHASES[1];
        await this._executeBuildCoverage(targetId);

        // Phase 3: Generate hypotheses
        this.currentPhase = LOOP_PHASES[2];
        const hypothesesGenerated = await this._executeGenerateHypotheses(targetId);
        this.loopState.total_hypotheses_generated += hypothesesGenerated;

        // Phase 4: Prioritize
        this.currentPhase = LOOP_PHASES[3];
        // (prioritization happens automatically in the hypothesisPrioritizer)

        // Phase 5: Verify
        this.currentPhase = LOOP_PHASES[4];
        const dispatched = await this._executeVerify(targetId);
        this.loopState.total_verifications_dispatched += dispatched;

        // Phase 6: Correlate
        this.currentPhase = LOOP_PHASES[5];
        // (correlation happens as findings are ingested)

        // Phase 7: Score
        this.currentPhase = LOOP_PHASES[6];
        await this._executeScore(targetId);

        // Phase 8: Persist
        this.currentPhase = LOOP_PHASES[7];
        await this._executePersist(targetId);

        this.loopState.phases_completed += LOOP_PHASES.length;
      }

      // Phase 9: Repeat
      this.currentPhase = LOOP_PHASES[8];

    } catch (err) {
      console.error('[CoveragePlanner] Loop iteration error:', err.message);
    }

    // Schedule next iteration
    if (this._running) {
      this._loopTimer = setTimeout(() => this._runLoopIteration(), this.loopIntervalMs);
    }
  }

  // ─── Loop Phase Executors ────────────────────────────────────────

  async _executeDiscoverSurface(targetId) {
    // Coverage engine should already be ingesting events in real-time
    // This phase just ensures the map is up-to-date
    if (this.coverageEngine) {
      this.coverageEngine.getCoverageMap(targetId);
    }
  }

  async _executeBuildCoverage(targetId) {
    // Coverage graph is built as part of getCoverageMap
    if (this.kb && this.coverageEngine) {
      const map = this.coverageEngine.getCoverageMap(targetId);
      this.kb.upsertCoverage(targetId, map);
    }
  }

  async _executeGenerateHypotheses(targetId) {
    let count = 0;
    const gaps = this.coverageEngine ? this.coverageEngine.getCoverageGaps(targetId) : [];
    const hypotheses = this._generateGapHypotheses(targetId, gaps);

    if (this.hypothesisPrioritizer) {
      const submitted = this.hypothesisPrioritizer.submitBatch(
        hypotheses.slice(0, this.maxHypothesesPerLoop)
      );
      count = submitted.length;
    }

    return count;
  }

  async _executeVerify(targetId) {
    if (!this.hypothesisPrioritizer || !this.verificationFarm) return 0;

    const topHypotheses = this.hypothesisPrioritizer.getNext(10);
    let dispatched = 0;

    for (const h of topHypotheses) {
      const action = this._selectVerificationAction(h);
      const { error, task } = await this.verificationFarm.submitTaskAsync({
        hypothesis_id: h.id,
        action,
        params: this._buildVerificationParams(h, action),
        target_id: targetId,
        priority: h.evv,
      });

      if (!error && task) {
        dispatched++;
        this.hypothesisPrioritizer.setVerdict(h.id, 'validating');
      }
    }

    // Process the queue
    if (dispatched > 0) {
      const results = await this.verificationFarm.processQueue();
      for (const result of results) {
        const verdict = result.verdict === 'confirmed' || result.verdict === 'observed'
          ? 'confirmed' : result.verdict === 'rejected' ? 'rejected' : 'inconclusive';
        this.hypothesisPrioritizer.setVerdict(result.hypothesis_id, verdict, result);

        if (verdict === 'confirmed') {
          this.loopState.total_bugs_confirmed++;
        }
      }
    }

    return dispatched;
  }

  async _executeScore(targetId) {
    // Scoring happens through the ranking engine and hypothesis prioritizer
    // This phase just ensures everything is consistent
  }

  async _executePersist(targetId) {
    if (this.kb) {
      this.kb.save();
    }
  }

  // ─── Hypothesis Generation ───────────────────────────────────────

  /**
   * Generate hypotheses from coverage gaps.
   *
   * @param {string} targetId
   * @param {object[]} gaps - coverage gaps from coverage engine
   * @returns {object[]} generated hypotheses
   * @private
   */
  _generateGapHypotheses(targetId, gaps) {
    const hypotheses = [];

    for (const gap of gaps) {
      const templates = GAP_HYPOTHESIS_TEMPLATES[gap.domain] || [];
      for (const template of templates) {
        // Get relevant paths for this gap
        let paths = [];
        if (this.coverageEngine) {
          const map = this.coverageEngine.getCoverageMap(targetId);
          switch (gap.domain) {
            case 'auth_flows':
              paths = map.auth_flows.map(f => f.url).filter(Boolean);
              break;
            case 'api_endpoints':
              paths = map.api_endpoints.map(e => e.path);
              break;
            case 'websocket_channels':
              paths = map.websocket_channels.map(c => c.url);
              break;
            case 'forms':
              paths = map.forms.map(f => f.path || f.action);
              break;
            case 'routes':
              paths = map.routes.slice(0, 10);
              break;
          }
        }

        // Generate one hypothesis per path (up to 3 per template)
        for (const path of paths.slice(0, 3)) {
          hypotheses.push({
            title: template.title.replace('{path}', path).replace('{url}', path),
            category: template.category,
            severity: template.severity,
            confidence: Math.round((1 - gap.current_score / 100) * 70), // inverse of coverage
            target_id: targetId,
            affected_endpoints: [path],
            verification_cost: gap.domain === 'auth_flows' ? 'high' : 'medium',
            description: `Auto-generated from coverage gap in ${gap.domain} (coverage: ${gap.current_score}%, gap: ${gap.gap}%)`,
          });
        }

        // If no specific paths, generate a domain-level hypothesis
        if (paths.length === 0) {
          hypotheses.push({
            title: template.title.replace('{path}', `[${gap.domain}]`).replace('{url}', `[${gap.domain}]`),
            category: template.category,
            severity: template.severity,
            confidence: Math.round((1 - gap.current_score / 100) * 50),
            target_id: targetId,
            verification_cost: 'medium',
            description: `Auto-generated from coverage gap in ${gap.domain} (coverage: ${gap.current_score}%, gap: ${gap.gap}%)`,
          });
        }
      }
    }

    return hypotheses;
  }

  // ─── Verification Action Selection ───────────────────────────────

  /**
   * Select the best verification action for a hypothesis.
   *
   * @param {object} hypothesis
   * @returns {string} verification action
   * @private
   */
  _selectVerificationAction(hypothesis) {
    const category = (hypothesis.category || '').toLowerCase();

    const categoryActionMap = {
      'auth_bypass':           'authenticated_replay',
      'session_hijacking':     'cookie_variation',
      'csrf':                  'header_variation',
      'cookie_security':       'cookie_variation',
      'api_exposure':          'request_replay',
      'idor':                  'permission_validation',
      'insecure_direct_object':'permission_validation',
      'websocket_hijacking':   'request_replay',
      'xss':                   'request_replay',
      'injection':             'request_replay',
      'information_disclosure':'navigation',
      'broken_access_control': 'permission_validation',
      'workflow_bypass':       'workflow_validation',
      'rate_limiting':         'request_replay',
    };

    return categoryActionMap[category] || 'navigation';
  }

  /**
   * Build verification parameters for a hypothesis.
   *
   * @param {object} hypothesis
   * @param {string} action
   * @returns {object}
   * @private
   */
  _buildVerificationParams(hypothesis, action) {
    const params = {
      url: hypothesis.affected_endpoints?.[0] || '',
      target_id: hypothesis.target_id,
    };

    switch (action) {
      case 'authenticated_replay':
        params.request_sequence = hypothesis.affected_endpoints?.map(url => ({ url })) || [];
        params.cookies = {};
        break;
      case 'permission_validation':
        params.url = hypothesis.affected_endpoints?.[0] || '';
        break;
      case 'workflow_validation':
        params.steps = hypothesis.affected_endpoints?.map(url => ({ action: 'navigate', url })) || [];
        break;
      case 'state_comparison':
        params.before_state = {};
        params.after_state = {};
        break;
      default:
        break;
    }

    return params;
  }

  // ─── State Queries ───────────────────────────────────────────────

  /**
   * Get the current state of the planner.
   * @returns {object}
   */
  getState() {
    return {
      mode: this.mode,
      running: this._running,
      current_phase: this.currentPhase,
      iteration: this.iteration,
      loop_state: { ...this.loopState },
    };
  }

  /**
   * Get planner metrics.
   * @returns {object}
   */
  getMetrics() {
    const kbMetrics = this.kb ? this.kb.getMetrics() : {};

    return {
      mode: this.mode,
      running: this._running,
      iteration: this.iteration,
      current_phase: this.currentPhase,
      ...this.loopState,
      knowledge_base: kbMetrics,
    };
  }
}

module.exports = { CoveragePlanner, EXECUTION_MODES, LOOP_PHASES };

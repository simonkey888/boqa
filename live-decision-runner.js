/**
 * BOQA live-decision-runner.js — LiveDecisionRunner v1.2
 *
 * Executes decision runs in sandbox (dry_run_only) mode over real
 * input opportunity sets. Produces decision trace graphs that document
 * the complete reasoning chain from input signals to final ranked
 * action portfolio.
 *
 * Decision trace graph structure:
 *   - InputNode: original opportunity/signal
 *   - TransformNode: economic scoring, comparison, policy decision
 *   - OutputNode: final ranked action portfolio entry
 *   - TraceEdge: connects nodes with metadata about the transformation
 *
 * Runner modes:
 *   - dry_run_only: All decisions are simulated. No real execution.
 *   - This is the ONLY mode available in v1.2.
 *
 * Execution flow:
 *   1. Receive opportunity_set as input
 *   2. Score economically (EconomicValueEngine)
 *   3. Compare cross-class (OpportunityComparator)
 *   4. Decide policies (DecisionPolicyEngine)
 *   5. Simulate allocation (CapitalAllocatorSim)
 *   6. Build decision trace graph
 *   7. Output: decision_trace_graph + ranked_action_portfolio
 *
 * Guardrails:
 *   - dry_run_only mode is enforced and cannot be overridden
 *   - All outputs are computational projections
 *   - No real-world execution, capital commitment, or deployment
 *   - All decisions are audit-logged
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Persistence ────────────────────────────────────────────────────

const LDR_DIR = path.join(__dirname, 'output', 'knowledge', 'decision-runner');

// ─── Constants ──────────────────────────────────────────────────────

const RUNNER_MODES = {
  DRY_RUN: 'dry_run_only',   // The ONLY mode
};

const TRACE_NODE_TYPES = {
  INPUT:     'input',      // Raw opportunity
  SCORE:     'score',      // Economic scoring result
  COMPARE:   'compare',    // Cross-class comparison result
  POLICY:    'policy',     // Policy decision
  ALLOCATE:  'allocate',   // Capital allocation
  OUTPUT:    'output',     // Final portfolio entry
};

const TRACE_EDGE_TYPES = {
  SCORED_AS:    'scored_as',
  COMPARED_AS:  'compared_as',
  DECIDED_AS:   'decided_as',
  ALLOCATED_AS: 'allocated_as',
  PRODUCED:     'produced',
};

const RUN_STATES = {
  PENDING:   'pending',
  RUNNING:   'running',
  COMPLETED: 'completed',
  FAILED:    'failed',
};

const DEFAULT_OPTIONS = {
  maxRuns: 200,
  maxTraceNodes: 5000,
  auditLogMaxSize: 5000,
  persistenceIntervalMs: 300000,
};

// =====================================================================
//  TraceNode
// =====================================================================

class TraceNode {
  constructor(data = {}) {
    this.id           = data.id || `TN-${crypto.randomUUID().substring(0, 10)}`;
    this.type         = data.type || TRACE_NODE_TYPES.INPUT;
    this.label        = data.label || '';
    this.opportunity_id = data.opportunity_id || null;
    this.data         = data.data || {};      // Node-specific data
    this.timestamp    = data.timestamp || Date.now();
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  TraceEdge
// =====================================================================

class TraceEdge {
  constructor(data = {}) {
    this.id       = data.id || `TE-${crypto.randomUUID().substring(0, 10)}`;
    this.source   = data.source;       // TraceNode id
    this.target   = data.target;       // TraceNode id
    this.type     = data.type || TRACE_EDGE_TYPES.PRODUCED;
    this.label    = data.label || '';
    this.data     = data.data || {};
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  DecisionTraceGraph
// =====================================================================

class DecisionTraceGraph {
  constructor(runId) {
    this.run_id      = runId;
    this.nodes       = new Map();
    this.edges       = new Map();
    this.adjacency   = new Map();
    this.created_at  = Date.now();
    this.completed_at = null;
  }

  addNode(node) {
    this.nodes.set(node.id, node);
    if (!this.adjacency.has(node.id)) this.adjacency.set(node.id, new Set());
    return node;
  }

  addEdge(edge) {
    this.edges.set(edge.id, edge);
    if (this.adjacency.has(edge.source)) this.adjacency.get(edge.source).add(edge.id);
    return edge;
  }

  getNode(id) { return this.nodes.get(id) || null; }

  getInputNodes() {
    return [...this.nodes.values()].filter(n => n.type === TRACE_NODE_TYPES.INPUT);
  }

  getOutputNodes() {
    return [...this.nodes.values()].filter(n => n.type === TRACE_NODE_TYPES.OUTPUT);
  }

  /**
   * Trace the path from an output node back to its input.
   * @param {string} outputNodeId
   * @returns {TraceNode[]}
   */
  traceBack(outputNodeId) {
    const path = [];
    const visited = new Set();
    const queue = [outputNodeId];

    while (queue.length > 0) {
      const currentId = queue.shift();
      if (visited.has(currentId)) continue;
      visited.add(currentId);

      const node = this.nodes.get(currentId);
      if (node) path.unshift(node);

      // Find edges pointing to this node
      for (const [, edge] of this.edges) {
        if (edge.target === currentId && !visited.has(edge.source)) {
          queue.push(edge.source);
        }
      }
    }

    return path;
  }

  toJSON() {
    return {
      run_id: this.run_id,
      node_count: this.nodes.size,
      edge_count: this.edges.size,
      input_count: this.getInputNodes().length,
      output_count: this.getOutputNodes().length,
      created_at: this.created_at,
      completed_at: this.completed_at,
      nodes: [...this.nodes.entries()],
      edges: [...this.edges.entries()],
    };
  }
}

// =====================================================================
//  DecisionRunResult
// =====================================================================

class DecisionRunResult {
  constructor(data = {}) {
    this.run_id               = data.run_id || crypto.randomUUID().substring(0, 12);
    this.state                = data.state || RUN_STATES.PENDING;
    this.mode                 = RUNNER_MODES.DRY_RUN; // Always dry_run_only

    // Pipeline results
    this.opportunities_scored = data.opportunities_scored ?? 0;
    this.opportunities_compared = data.opportunities_compared ?? 0;
    this.policies_decided     = data.policies_decided ?? 0;
    this.allocation_simulated = data.allocation_simulated ?? false;

    // Outputs
    this.ranked_portfolio     = data.ranked_portfolio || [];
    this.trace_graph          = data.trace_graph || null;
    this.portfolio_summary    = data.portfolio_summary || {};

    // Timing
    this.started_at           = data.started_at || null;
    this.completed_at         = data.completed_at || null;
    this.duration_ms          = data.duration_ms ?? 0;

    // Error info
    this.errors               = data.errors || [];
  }

  toJSON() { return { ...this }; }
}

// =====================================================================
//  LiveDecisionRunner
// =====================================================================

class LiveDecisionRunner {
  /**
   * @param {object} options
   * @param {object} options.economicValueEngine - EconomicValueEngine instance
   * @param {object} options.opportunityComparator - OpportunityComparator instance
   * @param {object} options.decisionPolicyEngine - DecisionPolicyEngine instance
   * @param {object} options.capitalAllocatorSim - CapitalAllocatorSim instance
   */
  constructor(options = {}) {
    this.economicValueEngine   = options.economicValueEngine || null;
    this.opportunityComparator = options.opportunityComparator || null;
    this.decisionPolicyEngine  = options.decisionPolicyEngine || null;
    this.capitalAllocatorSim   = options.capitalAllocatorSim || null;
    this.options = { ...DEFAULT_OPTIONS, ...options };

    /** @type {Map<string, DecisionRunResult>} run_id → result */
    this.runHistory = new Map();

    /** @type {object[]} */
    this.auditLog = [];

    // ── Metrics ──────────────────────────────────────────────
    this.metrics = {
      total_runs: 0,
      total_opportunities_processed: 0,
      avg_run_duration_ms: 0,
      avg_portfolio_size: 0,
      success_rate: 0,
      mode: RUNNER_MODES.DRY_RUN,
    };

    // ── Persistence timer ────────────────────────────────────
    this._persistTimer = null;

    fs.mkdirSync(LDR_DIR, { recursive: true });
    this.load();

    if (this.options.persistenceIntervalMs > 0) {
      this._persistTimer = setInterval(() => this.save(), this.options.persistenceIntervalMs);
    }
  }

  // ─── Decision Run ──────────────────────────────────────────────────

  /**
   * Execute a full decision run over an opportunity set.
   * Always runs in dry_run_only mode.
   *
   * @param {object[]} opportunitySet - Array of opportunity objects
   * @param {object} [runOptions] - { profile, capital_budget }
   * @returns {DecisionRunResult}
   */
  async run(opportunitySet, runOptions = {}) {
    const runId = crypto.randomUUID().substring(0, 12);
    const startTime = Date.now();
    const trace = new DecisionTraceGraph(runId);
    const errors = [];

    const result = new DecisionRunResult({
      run_id: runId,
      state: RUN_STATES.RUNNING,
      started_at: startTime,
    });

    this._audit({
      action: 'run_started',
      run_id: runId,
      details: { opportunity_count: opportunitySet.length, mode: RUNNER_MODES.DRY_RUN },
    });

    try {
      // ── Step 1: Register and Score ──────────────────────────
      const scoredOpportunities = [];
      for (const opp of opportunitySet) {
        // Create input trace node
        const inputNode = trace.addNode(new TraceNode({
          type: TRACE_NODE_TYPES.INPUT,
          label: opp.label || opp.opportunity_class || opp.id || 'opportunity',
          opportunity_id: opp.id || opp.opportunity_id,
          data: {
            opportunity_class: opp.opportunity_class,
            target_id: opp.target_id,
            cevi: opp.cevi,
            market_size: opp.market_size,
          },
        }));

        // Register with EconomicValueEngine
        let score = null;
        if (this.economicValueEngine) {
          const registered = this.economicValueEngine.registerOpportunity(opp);
          score = this.economicValueEngine.score(registered.id);

          // Create score trace node
          const scoreNode = trace.addNode(new TraceNode({
            type: TRACE_NODE_TYPES.SCORE,
            label: `EV=${score.expected_value?.toFixed(0)} ROI=${score.roi?.toFixed(2)}`,
            opportunity_id: score.opportunity_id,
            data: {
              normalized_score: score.normalized_score,
              expected_value: score.expected_value,
              roi: score.roi,
              risk_adjusted_yield: score.risk_adjusted_yield,
            },
          }));

          trace.addEdge(new TraceEdge({
            source: inputNode.id,
            target: scoreNode.id,
            type: TRACE_EDGE_TYPES.SCORED_AS,
            label: `score=${score.normalized_score?.toFixed(1)}`,
          }));

          scoredOpportunities.push(score);
        } else {
          scoredOpportunities.push(opp);
        }
      }

      result.opportunities_scored = scoredOpportunities.length;

      // ── Step 2: Cross-Class Comparison ──────────────────────
      let comparisonMatrix = null;
      if (this.opportunityComparator && scoredOpportunities.length > 0) {
        comparisonMatrix = this.opportunityComparator.compare(
          scoredOpportunities,
          runOptions.profile || undefined
        );

        result.opportunities_compared = comparisonMatrix.opportunities.length;

        // Create comparison trace nodes
        for (const normOpp of comparisonMatrix.opportunities) {
          const compareNode = trace.addNode(new TraceNode({
            type: TRACE_NODE_TYPES.COMPARE,
            label: `rank=${normOpp.rank} score=${normOpp.composite_score?.toFixed(3)}`,
            opportunity_id: normOpp.opportunity_id,
            data: {
              rank: normOpp.rank,
              composite_score: normOpp.composite_score,
              is_pareto_optimal: normOpp.is_pareto_optimal,
            },
          }));

          // Find the score node for this opportunity
          const scoreNode = [...trace.nodes.values()].find(
            n => n.type === TRACE_NODE_TYPES.SCORE && n.opportunity_id === normOpp.opportunity_id
          );
          if (scoreNode) {
            trace.addEdge(new TraceEdge({
              source: scoreNode.id,
              target: compareNode.id,
              type: TRACE_EDGE_TYPES.COMPARED_AS,
              label: `pareto=${normOpp.is_pareto_optimal}`,
            }));
          }
        }
      }

      // ── Step 3: Policy Decisions ────────────────────────────
      const policyDecisions = [];
      if (this.decisionPolicyEngine && scoredOpportunities.length > 0) {
        for (const score of scoredOpportunities) {
          const decision = this.decisionPolicyEngine.decide({
            opportunity_id: score.opportunity_id || score.id,
            economic_score: score.normalized_score || score.cevi || 0,
            risk_score: score.risk_adjusted_penalty || 0,
            confidence: score.confidence || 0.5,
            competition_level: this._mapCompetition(score),
            opportunity_class: score.opportunity_class,
            target_id: score.target_id,
            hypothesis_id: score.hypothesis_id,
            var_95: score.var_95 || 0,
          });

          const policyNode = trace.addNode(new TraceNode({
            type: TRACE_NODE_TYPES.POLICY,
            label: decision.policy,
            opportunity_id: decision.opportunity_id,
            data: {
              policy: decision.policy,
              reasons: decision.reasons,
              constraints: decision.constraints,
            },
          }));

          // Find comparison node for this opportunity
          const compareNode = [...trace.nodes.values()].find(
            n => n.type === TRACE_NODE_TYPES.COMPARE && n.opportunity_id === decision.opportunity_id
          );
          const sourceNode = compareNode || [...trace.nodes.values()].find(
            n => n.type === TRACE_NODE_TYPES.SCORE && n.opportunity_id === decision.opportunity_id
          );
          if (sourceNode) {
            trace.addEdge(new TraceEdge({
              source: sourceNode.id,
              target: policyNode.id,
              type: TRACE_EDGE_TYPES.DECIDED_AS,
              label: decision.policy,
            }));
          }

          policyDecisions.push(decision);
        }
      }
      result.policies_decided = policyDecisions.length;

      // ── Step 4: Capital Allocation Simulation ───────────────
      let allocationResult = null;
      if (this.capitalAllocatorSim) {
        this.capitalAllocatorSim.loadFromEngine();

        if (runOptions.capital_budget) {
          this.capitalAllocatorSim.options.totalCapitalBudget = runOptions.capital_budget;
        }

        allocationResult = this.capitalAllocatorSim.optimize();
        result.allocation_simulated = true;

        // Create allocation trace nodes
        const allocNode = trace.addNode(new TraceNode({
          type: TRACE_NODE_TYPES.ALLOCATE,
          label: `portfolio EV=${allocationResult.expected_portfolio_return?.toFixed(0)}`,
          data: {
            expected_return: allocationResult.expected_portfolio_return,
            var_95: allocationResult.portfolio_var_95,
            sharpe: allocationResult.portfolio_sharpe,
            capital_utilized: allocationResult.capital_utilized,
          },
        }));

        // Connect policy nodes to allocation
        for (const decision of policyDecisions) {
          if (decision.policy !== 'IGNORE') {
            const policyNode = [...trace.nodes.values()].find(
              n => n.type === TRACE_NODE_TYPES.POLICY && n.opportunity_id === decision.opportunity_id
            );
            if (policyNode) {
              trace.addEdge(new TraceEdge({
                source: policyNode.id,
                target: allocNode.id,
                type: TRACE_EDGE_TYPES.ALLOCATED_AS,
                label: decision.policy,
              }));
            }
          }
        }
      }

      // ── Step 5: Build Ranked Action Portfolio ───────────────
      const rankedPortfolio = this._buildRankedPortfolio(
        scoredOpportunities,
        policyDecisions,
        allocationResult
      );

      // Create output trace nodes
      for (const entry of rankedPortfolio) {
        const outputNode = trace.addNode(new TraceNode({
          type: TRACE_NODE_TYPES.OUTPUT,
          label: `${entry.decision}: ${entry.opportunity_class || entry.opportunity_id}`,
          opportunity_id: entry.opportunity_id,
          data: entry,
        }));

        const policyNode = [...trace.nodes.values()].find(
          n => n.type === TRACE_NODE_TYPES.POLICY && n.opportunity_id === entry.opportunity_id
        );
        if (policyNode) {
          trace.addEdge(new TraceEdge({
            source: policyNode.id,
            target: outputNode.id,
            type: TRACE_EDGE_TYPES.PRODUCED,
            label: entry.decision,
          }));
        }
      }

      // ── Finalize ────────────────────────────────────────────
      trace.completed_at = Date.now();
      result.state = RUN_STATES.COMPLETED;
      result.ranked_portfolio = rankedPortfolio;
      result.trace_graph = trace;
      result.portfolio_summary = this._buildPortfolioSummary(rankedPortfolio, allocationResult);
      result.opportunities_scored = scoredOpportunities.length;

    } catch (err) {
      result.state = RUN_STATES.FAILED;
      errors.push({ message: err.message, stack: err.stack?.split('\n').slice(0, 3) });
    }

    result.errors = errors;
    result.completed_at = Date.now();
    result.duration_ms = Date.now() - startTime;

    // Store
    this.runHistory.set(runId, result);
    if (this.runHistory.size > this.options.maxRuns) {
      const oldest = this.runHistory.keys().next().value;
      this.runHistory.delete(oldest);
    }

    // Metrics
    this.metrics.total_runs++;
    this.metrics.total_opportunities_processed += result.opportunities_scored;
    this._updateMetrics(result);

    this._audit({
      action: 'run_completed',
      run_id: runId,
      details: {
        state: result.state,
        opportunities: result.opportunities_scored,
        duration_ms: result.duration_ms,
        portfolio_size: result.ranked_portfolio.length,
      },
    });

    return result;
  }

  // ─── Portfolio Construction ────────────────────────────────────────

  _buildRankedPortfolio(scoredOpportunities, policyDecisions, allocationResult) {
    const portfolio = [];
    const allocMap = allocationResult?.allocations || {};

    for (const decision of policyDecisions) {
      const score = scoredOpportunities.find(
        s => (s.opportunity_id || s.id) === decision.opportunity_id
      );

      const entry = {
        opportunity_id: decision.opportunity_id,
        opportunity_class: decision.opportunity_class,
        target_id: decision.target_id,
        economic_score: decision.economic_score,
        risk_score: decision.risk_score,
        capital_required: score?.capital_required || 0,
        competition_level: decision.competition_level,
        time_to_revenue: score?.time_to_revenue_days || 0,
        confidence: decision.confidence,
        decision: decision.policy,
        human_approved: decision.human_approval,
        allocation_weight: allocMap[decision.opportunity_id] || 0,
        reasons: decision.reasons,
      };

      portfolio.push(entry);
    }

    // Sort: DEPLOY > BUILD > SIMULATE > WATCH > IGNORE, then by economic_score
    const policyOrder = { DEPLOY: 5, BUILD: 4, SIMULATE: 3, WATCH: 2, IGNORE: 1 };
    return portfolio.sort((a, b) => {
      const policyDiff = (policyOrder[b.decision] || 0) - (policyOrder[a.decision] || 0);
      if (policyDiff !== 0) return policyDiff;
      return b.economic_score - a.economic_score;
    });
  }

  _buildPortfolioSummary(rankedPortfolio, allocationResult) {
    const byDecision = {};
    for (const entry of rankedPortfolio) {
      byDecision[entry.decision] = (byDecision[entry.decision] || 0) + 1;
    }

    return {
      total_opportunities: rankedPortfolio.length,
      by_decision: byDecision,
      total_economic_value: rankedPortfolio.reduce((s, e) => s + e.economic_score, 0),
      avg_confidence: rankedPortfolio.length > 0
        ? rankedPortfolio.reduce((s, e) => s + e.confidence, 0) / rankedPortfolio.length
        : 0,
      portfolio_ev: allocationResult?.expected_portfolio_return || 0,
      portfolio_var: allocationResult?.portfolio_var_95 || 0,
      portfolio_sharpe: allocationResult?.portfolio_sharpe || 0,
      mode: RUNNER_MODES.DRY_RUN,
    };
  }

  _mapCompetition(score) {
    const pressure = score.competition_pressure || 0;
    if (pressure <= 0.05) return 'NONE';
    if (pressure <= 0.12) return 'LOW';
    if (pressure <= 0.22) return 'MODERATE';
    if (pressure <= 0.35) return 'HIGH';
    return 'SATURATED';
  }

  // ─── Query ──────────────────────────────────────────────────────────

  /**
   * Get a specific run result.
   * @param {string} runId
   * @returns {DecisionRunResult|null}
   */
  getRun(runId) {
    return this.runHistory.get(runId) || null;
  }

  /**
   * Get all run history.
   * @param {number} [limit=50]
   * @returns {DecisionRunResult[]}
   */
  getRunHistory(limit = 50) {
    return [...this.runHistory.values()].slice(-limit).reverse();
  }

  /**
   * Get the latest run result.
   * @returns {DecisionRunResult|null}
   */
  getLatestRun() {
    const runs = [...this.runHistory.values()];
    return runs.length > 0 ? runs[runs.length - 1] : null;
  }

  getAuditLog(limit = 200) {
    return this.auditLog.slice(-limit);
  }

  getMetrics() {
    return { ...this.metrics };
  }

  // ─── Internal ──────────────────────────────────────────────────────

  _audit(entry) {
    this.auditLog.push({
      id: crypto.randomUUID().substring(0, 10),
      ...entry,
      timestamp: Date.now(),
    });

    if (this.auditLog.length > this.options.auditLogMaxSize) {
      this.auditLog = this.auditLog.slice(-this.options.auditLogMaxSize);
    }
  }

  _updateMetrics(result) {
    const alpha = 0.1;
    this.metrics.avg_run_duration_ms = this.metrics.avg_run_duration_ms * (1 - alpha) +
      (result.duration_ms || 0) * alpha;
    this.metrics.avg_portfolio_size = this.metrics.avg_portfolio_size * (1 - alpha) +
      (result.ranked_portfolio?.length || 0) * alpha;

    const completed = [...this.runHistory.values()].filter(r => r.state === RUN_STATES.COMPLETED);
    this.metrics.success_rate = this.runHistory.size > 0
      ? Math.round(completed.length / this.runHistory.size * 1000) / 1000
      : 0;
  }

  // ─── Persistence ───────────────────────────────────────────────────

  save() {
    const filePath = path.join(LDR_DIR, 'decision-runner-state.json');
    const data = {
      version: '1.2',
      saved_at: Date.now(),
      run_history: [...this.runHistory.entries()].slice(-this.options.maxRuns).map(([k, v]) => {
        // Lighten trace graph for storage
        const result = { ...v };
        if (result.trace_graph && result.trace_graph.toJSON) {
          const tg = result.trace_graph.toJSON();
          result.trace_graph = {
            run_id: tg.run_id,
            node_count: tg.node_count,
            edge_count: tg.edge_count,
            input_count: tg.input_count,
            output_count: tg.output_count,
          };
        }
        return [k, result];
      }),
      metrics: this.metrics,
    };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  load() {
    const filePath = path.join(LDR_DIR, 'decision-runner-state.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.run_history) {
        this.runHistory = new Map(
          data.run_history.map(([k, v]) => [k, new DecisionRunResult(v)])
        );
      }
      if (data.metrics) this.metrics = { ...this.metrics, ...data.metrics };
      return true;
    } catch (_) { return false; }
  }

  reset() {
    this.runHistory.clear();
    this.auditLog = [];
    this.metrics = {
      total_runs: 0, total_opportunities_processed: 0,
      avg_run_duration_ms: 0, avg_portfolio_size: 0,
      success_rate: 0, mode: RUNNER_MODES.DRY_RUN,
    };
  }

  shutdown() {
    if (this._persistTimer) clearInterval(this._persistTimer);
    this.save();
  }
}

module.exports = {
  LiveDecisionRunner,
  DecisionRunResult,
  DecisionTraceGraph,
  TraceNode,
  TraceEdge,
  RUNNER_MODES,
  TRACE_NODE_TYPES,
  TRACE_EDGE_TYPES,
  RUN_STATES,
};


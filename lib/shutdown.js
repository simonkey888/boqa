/**
 * BOQA lib/shutdown.js — Graceful shutdown pipeline
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * Handles session export, report generation, state persistence,
 * and process exit across all version layers (v0.1 through v1.4).
 */

const path = require('path');
const fs = require('fs');

function createShutdown(ctx, pipelines) {
  const { SESSIONS_DIR, REPORTS_DIR } = require('./config');

  return async function shutdown(signal) {
    console.log(`\n[Server] ${signal} — shutting down`);

    // 1. Export session
    const session = ctx.bus.exportSession();
    const sessionFile = path.join(SESSIONS_DIR, `${session.id}.json`);
    try {
      fs.writeFileSync(sessionFile, JSON.stringify(session, null, 2));
      console.log(`[Server] session → ${sessionFile} (${session.totalEvents} events)`);
    } catch (_) {}

    // 2. Flush NDJSON
    await ctx.bus.flush();

    // 3. Generate auth + anomaly report
    // CF-004: protect against agent=null (degraded mode)
    let report = null;
    if (ctx.agent && typeof ctx.agent.getReport === 'function') {
      try {
        report = ctx.agent.getReport();
        if (report) {
          report.session_id = session.id;
          report.sessionStart = ctx.bus.sessionStart;
          report.sessionEnd = Date.now();
          report.totalEvents = ctx.bus.eventIndex;
        }
      } catch (err) {
        console.warn(`[Server] agent.getReport() failed during shutdown: ${err.message}`);
      }
    }
    if (!report) {
      console.log('[Server] Skipping report generation (degraded mode — agent not initialized).');
    }

    const reportFile = path.join(REPORTS_DIR, `report-${session.id.substring(0, 8)}.json`);
    try {
      fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
      console.log(`[Server] report → ${reportFile}`);
    } catch (_) {}

    // 4. Mode-specific actions
    if (!report && (ctx.CONFIG.mode === 'baseline' || ctx.CONFIG.mode === 'compare')) {
      console.warn(`[Server] Cannot run --mode=${ctx.CONFIG.mode} without agent report. Skipping baseline/compare step.`);
    } else if (ctx.CONFIG.mode === 'baseline') {
      const baseline = ctx.baselineBuilder.build(session, report);
      ctx.baselineBuilder.save(baseline);
      console.log(`[Server] baseline → ${baseline.id}.json (endpoints: ${baseline.fingerprint.endpoints.length})`);
    }

    if (report && ctx.CONFIG.mode === 'compare' && ctx.baselineObj) {
      const diff = ctx.differ.compare(session, report, ctx.baselineObj);
      ctx.differ.save(diff);
      ctx.lastDiff = diff;
      console.log(`[Server] diff → ${diff.id}.json (severity: ${diff.severity_score}/100, verdict: ${diff.verdict})`);
    }

    // 5. Run final analysis pipeline
    try {
      pipelines.runAnalysisPipeline(ctx);
      console.log(`[Server] Final analysis: ${ctx.lastFindings.length} findings`);
    } catch (err) {
      console.warn(`[Server] Final analysis failed: ${err.message}`);
    }

    // 6. Generate disclosure report
    try {
      const sessionMeta = {
        sessionId: session.id,
        target: session.target,
        sessionStart: session.sessionStart,
        sessionEnd: session.sessionEnd || Date.now(),
        duration: (session.sessionEnd || Date.now()) - session.sessionStart,
        totalEvents: session.totalEvents,
      };

      ctx.lastDisclosureReport = ctx.disclosureExporter.generateReport(ctx.lastFindings, ctx.lastEvidence, sessionMeta);
      const jsonPath = ctx.disclosureExporter.saveReport(ctx.lastDisclosureReport);
      const md = ctx.disclosureExporter.generateMarkdown(ctx.lastDisclosureReport);
      const mdPath = ctx.disclosureExporter.saveMarkdown(md);
      console.log(`[Server] Disclosure → ${jsonPath}`);
      console.log(`[Server] Markdown  → ${mdPath}`);
    } catch (err) {
      console.warn(`[Server] Disclosure generation failed: ${err.message}`);
    }

    // 7. Save finding_report.json
    const findingReportFile = path.join(REPORTS_DIR, `finding-report-${session.id.substring(0, 8)}.json`);
    try {
      fs.writeFileSync(findingReportFile, JSON.stringify({
        findings: ctx.lastFindings,
        summary: ctx.riskEngine.getSummary(),
        generated_at: Date.now(),
      }, null, 2));
      console.log(`[Server] findings → ${findingReportFile}`);
    } catch (_) {}

    // 8. v0.4: Save verification results
    try {
      const verificationReportPath = ctx.verificationEngine.saveResults();
      console.log(`[Server] Verification report → ${verificationReportPath}`);

      if (ctx.lastConfirmedBugs.length > 0) {
        const bugsPath = ctx.verificationEngine.saveConfirmedBugs();
        console.log(`[Server] Confirmed bugs → ${bugsPath}`);
      }
    } catch (err) {
      console.warn(`[Server] Verification save failed: ${err.message}`);
    }

    // 9. v0.5: Save orchestration state
    try {
      ctx.targetManager.save();
      console.log(`[Server] Targets saved: ${ctx.targetManager.getStats().total}`);

      ctx.scheduler.stop();
      ctx.scheduler.save();
      console.log(`[Server] Scheduler saved`);

      ctx.workerPool.shutdown();
      ctx.workerPool.save();
      console.log(`[Server] Worker pool shutdown`);

      const currentTargetId = pipelines.findCurrentTargetId(ctx);
      if (currentTargetId) ctx.assetMapper.save(currentTargetId);
      console.log(`[Server] Asset graph saved`);

      ctx.dedupEngine.save();
      console.log(`[Server] Dedup engine saved: ${ctx.dedupEngine.getStats().canonical_findings} canonical`);

      ctx.rankingEngine.save();
      console.log(`[Server] Rankings saved: ${ctx.rankingEngine.getStats().total_ranked} ranked`);

      ctx.disclosurePipeline.save();
      console.log(`[Server] Disclosure pipeline saved: ${ctx.disclosurePipeline.getStats().total} packages`);
    } catch (err) {
      console.warn(`[Server] v0.5 save failed: ${err.message}`);
    }

    // 10. v0.6: Save autonomous discovery state
    try {
      ctx.coveragePlanner.stopContinuousLoop();
      console.log(`[Server] Coverage planner stopped`);

      const kbPaths = ctx.knowledgeBase.save();
      console.log(`[Server] Knowledge base saved (${Object.keys(kbPaths).length} files)`);

      console.log(`[Server] Discovery metrics: ${JSON.stringify(ctx.knowledgeBase.getMetrics())}`);
    } catch (err) {
      console.warn(`[Server] v0.6 save failed: ${err.message}`);
    }

    // 11. v0.7: Save Discovery Operating System state
    try {
      ctx.campaignEngine.shutdown();
      console.log(`[Server] Campaign engine shutdown: ${ctx.campaignEngine.getStats().total_campaigns} campaigns`);

      ctx.learningEngine.shutdown();
      console.log(`[Server] Learning engine saved: ${ctx.learningEngine.getMetrics().total_observations} observations`);

      ctx.resourceOptimizer.shutdown();
      console.log(`[Server] Resource optimizer stopped`);

      const brainCount = ctx.brainRegistry.saveAll();
      console.log(`[Server] Target brains saved: ${brainCount}`);

      ctx.findingMemory.save();
      console.log(`[Server] Finding memory saved: ${ctx.findingMemory.getStats().total_patterns} patterns`);

      ctx.evidenceQualityEngine.save();
      console.log(`[Server] Evidence quality saved: ${ctx.evidenceQualityEngine.getStats().total_assessed} assessed`);

      const digest = ctx.executiveReporting.generateDailyDigest();
      console.log(`[Server] Final daily digest: ${digest.id}`);
    } catch (err) {
      console.warn(`[Server] v0.7 save failed: ${err.message}`);
    }

    // 12. v0.8: Save Predictive Discovery Layer state
    try {
      ctx.predictionEngine.save();
      console.log(`[Server] Prediction engine saved: ${ctx.predictionEngine.getStats().target_predictions} targets predicted`);

      ctx.yieldForecaster.save();
      console.log(`[Server] Yield forecaster saved: ${ctx.yieldForecaster.getStats().total_forecasts} forecasts`);

      ctx.riskForecaster.save();
      console.log(`[Server] Risk forecaster saved: ${ctx.riskForecaster.getStats().total_forecasts} risk forecasts`);

      ctx.campaignForecaster.save();
      console.log(`[Server] Campaign forecaster saved`);

      ctx.priorityShaper.shutdown();
      console.log(`[Server] Priority shaper saved: prediction_weight=${ctx.priorityShaper.currentPredictionWeight}`);

      const finalPredictions = ctx.predictionEngine.predictAllTargets();
      const finalPriorities = ctx.priorityShaper.shapeTargetPriorities();
      console.log(`[Server] Final predictions: ${finalPredictions.length} targets, top yield=${finalPredictions[0]?.predicted_yield || 0}`);
      console.log(`[Server] Final shaped priorities: ${finalPriorities.length} targets, top=${finalPriorities[0]?.shaped_priority || 0}`);
    } catch (err) {
      console.warn(`[Server] v0.8 save failed: ${err.message}`);
    }

    // 13. v0.9 + v1.1-v1.4: Save Optimization + Discovery + Decision + Autonomy state
    try {
      // STRUCT-7: Null-safe optimizer finalization
      try {
        const optState = (ctx.optimizerEngine && typeof ctx.optimizerEngine.getCurrentState === 'function')
          ? ctx.optimizerEngine.getCurrentState() : null;
        const bugsPerWorker = optState?.snapshot?.bugsPerWorker ?? 'N/A';
        if (ctx.optimizerEngine && typeof ctx.optimizerEngine.shutdown === 'function') {
          ctx.optimizerEngine.shutdown();
        }
        console.log(`[Server] Optimizer engine finalized. bugs/worker=${bugsPerWorker}`);
      } catch (err) {
        console.warn(`[Server] Non-critical optimizer error: ${err.message}`);
      }

      ctx.scanScheduler.shutdown();
      console.log(`[Server] Scan scheduler saved: ${ctx.scanScheduler.metrics.total_scheduled} tasks scheduled`);

      ctx.resourceManager.shutdown();
      console.log(`[Server] Resource manager saved: ${ctx.resourceManager.getMetrics().worker_count} workers`);

      ctx.feedbackLoop.shutdown();
      console.log(`[Server] Feedback loop saved: ${ctx.feedbackLoop.getMetrics().total_signals} signals processed`);

      ctx.efficiencyTracker.shutdown();
      console.log(`[Server] Efficiency tracker saved: score=${ctx.efficiencyTracker.computeEfficiencyScore()}`);

      ctx.budgetOptimizer.shutdown();
      console.log(`[Server] Budget optimizer saved: utilization=${ctx.budgetOptimizer.getMetrics().budget_utilization}`);

      // v1.1 shutdown
      ctx.discoveryLoopEngine.shutdown();
      console.log(`[Server] Discovery loop saved: ${ctx.discoveryLoopEngine.cycleCount} cycles completed`);

      ctx.memoryGraph.shutdown();
      console.log(`[Server] Memory graph saved: ${ctx.memoryGraph.nodes.size} nodes, ${ctx.memoryGraph.edges.size} edges`);

      ctx.hypothesisGenerator.shutdown();
      console.log(`[Server] Hypothesis generator saved: ${ctx.hypothesisGenerator.metrics.total_generated} hypotheses`);

      ctx.attackSurfaceModeler.shutdown();
      console.log(`[Server] Attack surface modeler saved: ${ctx.attackSurfaceModeler.metrics.total_surfaces} surfaces`);

      ctx.confidenceCalibrator.shutdown();
      console.log(`[Server] Confidence calibrator saved: ${ctx.confidenceCalibrator.metrics.total_observations} observations`);

      // v1.2: Decision Evolution Layer shutdown
      ctx.economicValueEngine.shutdown();
      console.log(`[Server] Economic value engine saved: ${ctx.economicValueEngine.metrics.total_scored} scored`);

      ctx.opportunityComparator.shutdown();
      console.log(`[Server] Opportunity comparator saved: ${ctx.opportunityComparator.metrics.total_comparisons} comparisons`);

      ctx.decisionPolicyEngine.shutdown();
      console.log(`[Server] Decision policy engine saved: ${ctx.decisionPolicyEngine.metrics.total_decisions} decisions`);

      ctx.capitalAllocatorSim.shutdown();
      console.log(`[Server] Capital allocator saved: ${ctx.capitalAllocatorSim.metrics.total_simulations} simulations`);

      ctx.liveDecisionRunner.shutdown();
      console.log(`[Server] Live decision runner saved: ${ctx.liveDecisionRunner.metrics.total_runs} runs`);

      // v1.3: Decision Intelligence Hardening Layer shutdown
      ctx.uncertaintyGovernor.shutdown();
      console.log(`[Server] Uncertainty governor saved: ${ctx.uncertaintyGovernor.metrics.total_gated} gated`);

      ctx.counterfactualValidator.shutdown();
      console.log(`[Server] Counterfactual validator saved: ${ctx.counterfactualValidator.metrics.total_validations} validations`);

      ctx.decisionStabilityEngine.shutdown();
      console.log(`[Server] Decision stability engine saved: stability_index=${ctx.decisionStabilityEngine.computeStabilityIndex()}`);

      ctx.realityAlignmentLayer.shutdown();
      console.log(`[Server] Reality alignment layer saved: avg_alignment=${ctx.realityAlignmentLayer.metrics.avg_alignment_score}`);

      // v1.4: Autonomous Decision Kernel shutdown
      ctx.autonomyGovernor.shutdown();
      console.log(`[Server] Autonomy governor saved: level=${ctx.autonomyGovernor.getAutonomyLevelName()}, mode=${ctx.autonomyGovernor.getBehavioralMode()}, checks=${ctx.autonomyGovernor.metrics.total_checks}`);

      // Generate final optimization snapshot
      const finalOptResult = ctx.optimizerEngine.optimize();
      console.log(`[Server] Final optimization: objective=${finalOptResult.snapshot.objective_score}, strategy=${finalOptResult.strategy.old_strategy}→${finalOptResult.strategy.new_strategy}`);

      // Log success criteria status
      const optMetrics = ctx.optimizerEngine.getMetrics();
      console.log(`[Server] Success criteria:`);
      for (const [key, val] of Object.entries(optMetrics.success_criteria)) {
        console.log(`[Server]   ${key}: ${val.current} (target: ${val.target}, met: ${val.met})`);
      }
    } catch (err) {
      console.warn(`[Server] v0.9 save failed: ${err.message}`);
    }

    // 14. Print summary
    if (report) {
      console.log(`[Server] Auth model: ${report.auth_model}`);
      console.log(`[Server] Risk flags: ${report.risk_flags?.length || 0}`);
      console.log(`[Server] Anomalies: ${report.anomaly_summary?.total || 0}`);
    } else {
      console.log('[Server] No agent report available (degraded mode — agent was not initialized).');
    }
    console.log(`[Server] Findings: ${ctx.lastFindings.length} (critical=${ctx.lastFindings.filter(f=>f.severity==='critical').length}, high=${ctx.lastFindings.filter(f=>f.severity==='high').length})`);
    console.log(`[Server] Confirmed bugs: ${ctx.lastConfirmedBugs.length} (critical=${ctx.lastConfirmedBugs.filter(b=>b.severity==='critical').length}, high=${ctx.lastConfirmedBugs.filter(b=>b.severity==='high').length})`);
    if (ctx.lastDedupStats) {
      console.log(`[Server] Dedup: ${ctx.lastDedupStats.canonical_findings} canonical (${ctx.lastDedupStats.duplicate_reduction_pct}% reduction)`);
    }
    if (ctx.lastLeaderboard.length > 0) {
      console.log(`[Server] Leaderboard top: ${ctx.lastLeaderboard[0]?.finding_id} score=${ctx.lastLeaderboard[0]?.rank_score}`);
    }
    console.log(`[Server] Disclosures: ${ctx.disclosurePipeline.getStats().total} packages`);

    // 15. Stop Playwright (only if agent was initialized)
    if (ctx.agent && typeof ctx.agent.stop === 'function') {
      try {
        await ctx.agent.stop();
      } catch (err) {
        console.warn(`[Server] agent.stop() failed during shutdown: ${err.message}`);
      }
    }

    // 16. Close WS + HTTP — null-safe (test environments may not initialize these)
    if (ctx.wss && ctx.wss.clients) {
      ctx.wss.clients.forEach(ws => {
        try { ws.close(); } catch (_) {}
      });
    }
    if (ctx.server) {
      ctx.server.close(() => {
        console.log('[Server] Shutdown complete');
        if (ctx.CONFIG.mode === 'compare' && ctx.lastDiff) {
          process.exit(ctx.lastDiff.severity_score >= 70 ? 2 : ctx.lastDiff.severity_score >= 40 ? 1 : 0);
        }
        process.exit(0);
      });
    } else {
      console.log('[Server] Shutdown complete (no server to close)');
      process.exit(0);
    }

    setTimeout(() => process.exit(1), 5000);
  };
}

module.exports = { createShutdown };


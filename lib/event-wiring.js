/**
 * BOQA lib/event-wiring.js — Event bus → engine wiring
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * Wires v0.9 (optimization) and v1.1 (discovery) event pipelines.
 */

function wireEventHandlers(ctx, pipelines) {
  const { findCurrentTargetId } = pipelines;

  // ─── v0.9: Event-to-Optimization Pipeline ──────────────────────────

  ctx.bus.on('event', (event) => {
    const targetId = findCurrentTargetId(ctx) || ctx.CONFIG.target;

    // Feed verification outcomes into feedback loop and efficiency tracker
    if (event.type === 'verification_result' || event.type === 'verification_outcome') {
      ctx.feedbackLoop.ingestVerificationOutcome({
        hypothesis_id: event.meta?.hypothesis_id || event.id,
        verdict: event.meta?.verdict || 'inconclusive',
        category: event.meta?.category || 'unknown',
        target_id: targetId,
      });

      ctx.efficiencyTracker.recordVerification({
        verdict: event.meta?.verdict || 'inconclusive',
        category: event.meta?.category || 'unknown',
        duration_ms: event.meta?.duration_ms || 0,
      });
    }

    // Feed scan completions into efficiency tracker
    if (event.type === 'scan_complete' || event.type === 'coverage_delta') {
      ctx.efficiencyTracker.recordScanComplete({
        target_id: targetId,
        duration_ms: event.meta?.duration_ms || 0,
        bugs_found: event.meta?.bugs_found || 0,
        coverage_delta: event.meta?.coverage_delta || 0,
      });
    }

    // Feed resource usage into efficiency tracker and resource manager
    if (event.type === 'resource_usage' || event.type === 'worker_status') {
      ctx.efficiencyTracker.recordResourceUsage({
        total_workers: event.meta?.total_workers || 8,
        active_workers: event.meta?.active_workers || 0,
        idle_workers: event.meta?.idle_workers || 0,
      });
    }

    // Feed bug discoveries into efficiency tracker and resource manager
    if (event.type === 'bug_confirmed' || event.type === 'finding_confirmed') {
      ctx.efficiencyTracker.recordBugFound({
        target_id: targetId,
        severity: event.meta?.severity || 'medium',
        category: event.meta?.category || 'unknown',
      });
      ctx.resourceManager.recordBugFound(targetId);
    }

    // Feed cost events into efficiency tracker and budget optimizer
    if (event.type === 'cost_incurred' || event.type === 'scan_cost') {
      ctx.efficiencyTracker.recordCost({
        target_id: targetId,
        amount: event.meta?.amount || 0,
        type: event.meta?.cost_type || 'scan',
      });
      ctx.budgetOptimizer.recordSpend(targetId, event.meta?.amount || 0);
    }

    // Feed metric thresholds into feedback loop
    if (event.type === 'threshold_breach') {
      ctx.feedbackLoop.ingestThresholdBreach({
        metric_name: event.meta?.metric_name || 'unknown',
        threshold: event.meta?.threshold || 0,
        current_value: event.meta?.current_value || 0,
        severity: event.meta?.severity || 'warning',
      });
    }

    // Feed anomalies into feedback loop
    if (event.type === 'anomaly') {
      ctx.feedbackLoop.ingestAnomaly({
        anomaly_type: event.meta?.anomaly_type || 'unknown',
        severity: event.meta?.severity || 'medium',
        deviation: event.meta?.deviation || 0,
        target_id: targetId,
      });
    }
  });

  // ─── v1.1: Event-to-Discovery Pipeline ──────────────────────────────

  ctx.bus.on('event', (event) => {
    const targetId = findCurrentTargetId(ctx) || ctx.CONFIG.target;

    // Feed security/anomaly signals into the discovery loop
    if (event.type === 'anomaly' || event.type === 'auth_signal' ||
        event.type === 'security_finding' || event.type === 'verification_result') {
      ctx.discoveryLoopEngine.ingestSignals([{
        id: event.id,
        type: event.type,
        source: event.source || 'event_bus',
        target_id: targetId,
        category: event.meta?.category || 'unknown',
        features: {
          anomaly_score: event.meta?.deviation || 30,
          severity_score: event.meta?.severity === 'critical' ? 90 : event.meta?.severity === 'high' ? 70 : 40,
        },
      }]);
    }

    // Feed confirmed bugs into the memory graph
    if (event.type === 'bug_confirmed' || event.type === 'finding_confirmed') {
      ctx.memoryGraph.addNode({
        type: 'finding',
        label: event.meta?.category || 'confirmed_bug',
        category: event.meta?.category || 'unknown',
        target_id: targetId,
        severity: event.meta?.severity || 'medium',
        confidence: 0.9,
        verdict: 'confirmed',
        features: {
          category: event.meta?.category || 'unknown',
          severity: event.meta?.severity || 'medium',
        },
        source_id: event.id,
        source_type: 'event',
        tags: ['confirmed', event.meta?.category || 'unknown'].filter(Boolean),
      });
    }

    // Feed calibration data from verification outcomes
    if (event.type === 'verification_result' || event.type === 'verification_outcome') {
      const predicted = event.meta?.predicted_score || 50;
      const actual = event.meta?.verdict === 'confirmed' ? predicted * 0.8 : 0;
      ctx.confidenceCalibrator.recordObservation({
        target_id: targetId,
        category: event.meta?.category || 'unknown',
        predicted,
        actual,
      });
    }
  });
}

module.exports = { wireEventHandlers };


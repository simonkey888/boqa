/**
 * BOQA lib/pipelines.js — Core analysis, verification, orchestration, and auth-graph pipelines
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * All pipeline functions receive the full `ctx` context object from lib/init.js.
 */

function findCurrentTargetId(ctx) {
  const target = ctx.targetManager.findTarget(ctx.CONFIG.target);
  return target ? target.id : null;
}

// ─── v0.5 Orchestration Pipeline ──────────────────────────────────────

function runOrchestrationPipeline(ctx) {
  if (!ctx.agent) return { skipped: true, reason: 'agent_unavailable' };
  const session = ctx.bus.exportSession();
  const report = ctx.agent.getReport();

  // Step 1: Ingest events into asset mapper
  const targetId = findCurrentTargetId(ctx);
  if (targetId) {
    ctx.assetMapper.ingestEvents(ctx.bus.eventLog, targetId);
    ctx.assetMapper.linkAssets();
    ctx.assetMapper.computeRiskFlags();
    console.log(`[Orchestration] Asset graph updated for ${targetId}`);
  }

  // Step 2: Deduplicate findings across sessions
  const sourceInfo = {
    target_id: targetId || ctx.CONFIG.target,
    session_id: session.id,
    observed_at: Date.now(),
  };

  for (const finding of ctx.lastFindings) {
    ctx.dedupEngine.ingest(finding, sourceInfo);
  }
  ctx.lastDedupStats = ctx.dedupEngine.getStats();
  console.log(`[Orchestration] Dedup: ${ctx.lastDedupStats.total_input_findings} input → ${ctx.lastDedupStats.canonical_findings} canonical (${ctx.lastDedupStats.duplicate_reduction_pct}% reduction)`);

  // Step 3: Rank canonical findings
  const canonicals = ctx.dedupEngine.getCanonicalFindings();
  const contextMap = {};
  for (const cf of canonicals) {
    const tgt = ctx.targetManager.findTarget(cf.sources?.[0]?.target_id || '');
    contextMap[cf.id] = {
      asset_criticality: {
        environment: tgt?.environment || 'prod',
        asset_type: cf.category?.includes('auth') ? 'auth_endpoint' : 'api',
        exposure: 'public',
      },
      reproducibility_score: cf.evidence_count >= 3 ? 80 : cf.evidence_count >= 2 ? 60 : 40,
      evidence_count: cf.evidence_count || 0,
      target_environment: tgt?.environment || 'prod',
    };
  }
  ctx.rankingEngine.rankAll(canonicals, contextMap);
  ctx.lastLeaderboard = ctx.rankingEngine.getLeaderboard(100);
  console.log(`[Orchestration] Ranked ${canonicals.length} findings, top score: ${ctx.lastLeaderboard[0]?.rank_score || 0}`);

  // Step 4: Create disclosure packages for disclosure-ready findings
  const readyFindings = canonicals.filter(cf => {
    const ranked = ctx.rankingEngine.getFindingsByLifecycle('ranked');
    return ranked.some(r => r.finding_id === cf.id && ctx.rankingEngine.isDisclosureReady(r));
  });

  for (const cf of readyFindings) {
    try {
      const existing = ctx.disclosurePipeline.getPackageByBug(cf.id);
      if (!existing) {
        const pkg = ctx.disclosurePipeline.createPackage(cf, {
          target: ctx.targetManager.findTarget(cf.sources?.[0]?.target_id || ''),
          evidence: ctx.lastEvidence,
          ranking: ctx.rankingEngine.getFindingsByLifecycle('ranked').find(r => r.finding_id === cf.id),
        });
        console.log(`[Orchestration] Disclosure package created: ${pkg.id} for ${cf.id}`);
      }
    } catch (err) {
      // Package may already exist or bug not at confirmed state — skip
    }
  }

  // Step 5: Update target last_scan
  if (targetId) {
    ctx.targetManager.updateLastScan(targetId);
  }

  return {
    asset_graphs: Object.keys(ctx.assetMapper.getAllGraphs()).length,
    canonical_findings: canonicals.length,
    ranked_findings: ctx.lastLeaderboard.length,
    disclosure_packages: ctx.disclosurePipeline.getStats().total,
  };
}

// ─── Auth Graph Builder ────────────────────────────────────────────────

function buildAuthGraph(events, report) {
  const nodes = [];
  const edges = [];

  // Cookie nodes
  const cookieNodes = new Map();
  for (const c of (report.cookies || [])) {
    const id = `cookie:${c.name}`;
    cookieNodes.set(c.name, id);
    nodes.push({
      id, type: 'cookie', label: c.name,
      meta: { httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite, domain: c.domain },
    });
  }

  // Endpoint nodes
  const endpointNodes = new Map();
  for (const e of events) {
    if ((e.type === 'network_request' || e.type === 'network_response') && e.url) {
      try {
        const u = new URL(e.url);
        const key = `${e.method || 'GET'} ${u.pathname}`;
        if (!endpointNodes.has(key)) {
          const id = `endpoint:${key}`;
          endpointNodes.set(key, id);
          const isAuth = /\/auth\/|\/login|\/logout|\/token|\/session|\/api\/users\/me/.test(u.pathname);
          nodes.push({
            id, type: isAuth ? 'auth_endpoint' : 'endpoint', label: key,
            meta: { isAuth },
          });
        }
      } catch (_) {}
    }
  }

  // WS channel nodes
  const wsNodes = new Map();
  for (const e of events) {
    if (e.type === 'websocket_open' && e.url) {
      try {
        const u = new URL(e.url);
        const key = u.origin + u.pathname;
        if (!wsNodes.has(key)) {
          const id = `ws:${key}`;
          wsNodes.set(key, id);
          nodes.push({ id, type: 'websocket', label: key, meta: {} });
        }
      } catch (_) {}
    }
  }

  // Build edges: auth_signal → cookie_set
  for (const e of events) {
    if (e.type === 'auth_signal' && e.meta?.cookies) {
      for (const c of e.meta.cookies) {
        const cookieId = cookieNodes.get(c.name);
        if (cookieId) {
          edges.push({ source: 'auth_signal', target: cookieId, type: 'sets_cookie' });
        }
      }
    }

    // Request → Authorization header → cookie reference
    if (e.type === 'network_request' && e.headers) {
      const lower = {};
      for (const [k, v] of Object.entries(e.headers)) lower[k.toLowerCase()] = v;

      if (lower['authorization']) {
        try {
          const u = new URL(e.url);
          const epKey = `${e.method || 'GET'} ${u.pathname}`;
          const epId = endpointNodes.get(epKey);
          if (epId) edges.push({ source: epId, target: 'bearer_auth', type: 'sends_bearer' });
        } catch (_) {}
      }

      if (lower['x-csrftoken']) {
        const csrfCookieId = cookieNodes.get('csrftoken');
        if (csrfCookieId) {
          try {
            const u = new URL(e.url);
            const epKey = `${e.method || 'GET'} ${u.pathname}`;
            const epId = endpointNodes.get(epKey);
            if (epId) edges.push({ source: csrfCookieId, target: epId, type: 'csrf_double_submit' });
          } catch (_) {}
        }
      }
    }

    // WS open → auth
    if (e.type === 'websocket_open' && e.meta?.auth) {
      try {
        const u = new URL(e.url);
        const wsKey = u.origin + u.pathname;
        const wsId = wsNodes.get(wsKey);
        if (wsId) edges.push({ source: 'auth_signal', target: wsId, type: 'ws_auth' });
      } catch (_) {}
    }
  }

  // Add auth signal node if any edges reference it
  if (edges.some(e => e.source === 'auth_signal' || e.target === 'bearer_auth')) {
    if (!nodes.find(n => n.id === 'auth_signal')) {
      nodes.push({ id: 'auth_signal', type: 'auth', label: 'Auth Flow', meta: { model: report.auth_model } });
    }
    if (!nodes.find(n => n.id === 'bearer_auth')) {
      nodes.push({ id: 'bearer_auth', type: 'auth', label: 'Bearer Token', meta: {} });
    }
  }

  return { nodes, edges, auth_model: report.auth_model };
}

// ─── Analysis Pipeline ────────────────────────────────────────────────

function runAnalysisPipeline(ctx) {
  if (!ctx.agent) return { skipped: true, reason: 'agent_unavailable' };
  const session = ctx.bus.exportSession();
  const report = ctx.agent.getReport();
  const anomalies = ctx.agent.anomaly.getAnomalies();

  const observations = {
    events: ctx.bus.eventLog,
    report,
    anomalies,
    baseline: ctx.baselineObj,
    diff: ctx.lastDiff,
  };

  // Step 1: Generate hypotheses
  const hypotheses = ctx.hypothesisEngine.analyze(observations);
  console.log(`[Pipeline] Hypotheses: ${hypotheses.length}`);

  // Step 2: Validate hypotheses
  const validationResults = ctx.validatorEngine.validateAll(hypotheses, observations);
  const validated = validationResults.filter(v => v.validated).length;
  console.log(`[Pipeline] Validated: ${validated}/${hypotheses.length}`);

  // Step 3: Normalize findings
  const context = { report, anomalies, baseline: ctx.baselineObj };
  ctx.lastFindings = ctx.riskEngine.normalize(hypotheses, validationResults, context);
  console.log(`[Pipeline] Findings: ${ctx.lastFindings.length} (critical=${ctx.lastFindings.filter(f=>f.severity==='critical').length}, high=${ctx.lastFindings.filter(f=>f.severity==='high').length})`);

  // Step 4: Build evidence packages
  ctx.lastEvidence = ctx.evidenceEngine.buildAll(ctx.lastFindings, validationResults, observations);
  console.log(`[Pipeline] Evidence packages: ${ctx.lastEvidence.length}`);

  // Step 5: Attach evidence to findings
  for (const finding of ctx.lastFindings) {
    const ep = ctx.evidenceEngine.getPackage(finding.id);
    if (ep) {
      finding.evidence = ep.evidence_chain || [];
      finding.timeline = ep.timeline || [];
      finding.reproduction = ep.reproduction || [];
      finding.recommended_fix = ep.recommended_fix || '';
    }
  }

  // Step 6: Stream findings to dashboard
  for (const finding of ctx.lastFindings) {
    ctx.bus.emitFinding(finding);
  }
  for (const ep of ctx.lastEvidence) {
    ctx.bus.emitEvidence(ep);
  }

  // Step 7 (v0.4): Auto-verify findings into confirmed bugs
  try {
    const verResult = runVerificationPipeline(ctx);
    console.log(`[Pipeline] Verification: ${verResult.bugs_confirmed} bugs confirmed`);
  } catch (err) {
    console.warn(`[Pipeline] Verification failed: ${err.message}`);
  }

  // Step 8 (v0.5): Orchestration pipeline — dedup, rank, disclosure
  try {
    const orchResult = runOrchestrationPipeline(ctx);
    console.log(`[Pipeline] Orchestration: ${orchResult.canonical_findings} canonical, ${orchResult.ranked_findings} ranked, ${orchResult.disclosure_packages} disclosure pkgs`);
  } catch (err) {
    console.warn(`[Pipeline] Orchestration failed: ${err.message}`);
  }

  // Step 9 (v0.7): Learning loop — feed findings to memory, quality, and learning
  try {
    const targetId = findCurrentTargetId(ctx) || ctx.CONFIG.target;

    // Feed findings to finding memory for cross-target patterns
    for (const finding of ctx.lastFindings) {
      const result = ctx.findingMemory.ingest(finding, targetId);
      if (result.new_pattern) {
        ctx.bus._broadcast({
          type: 'pattern_detected',
          ts: Date.now(),
          elapsed: Date.now() - ctx.bus.sessionStart,
          payload: { fingerprint: result.fingerprint, category: finding.category },
          source: 'finding_memory',
        });
      }
      if (result.regressions.length > 0) {
        ctx.bus._broadcast({
          type: 'regression_detected',
          ts: Date.now(),
          elapsed: Date.now() - ctx.bus.sessionStart,
          payload: { finding_id: finding.id, regressions: result.regressions.length },
          source: 'finding_memory',
        });
      }
    }

    // Score evidence quality
    for (const finding of ctx.lastFindings) {
      const assessment = ctx.evidenceQualityEngine.score(finding);
      ctx.bus._broadcast({
        type: 'evidence_scored',
        ts: Date.now(),
        elapsed: Date.now() - ctx.bus.sessionStart,
        payload: { finding_id: finding.id, score: assessment.overall_score, ready: assessment.disclosure_ready },
        source: 'evidence_quality_engine',
      });
    }

    // Feed outcomes to learning engine
    for (const finding of ctx.lastFindings) {
      if (finding.lifecycle_state === 'confirmed' || finding.lifecycle_state === 'rejected') {
        ctx.learningEngine.recordOutcome({
          hypothesis_id: finding.id || finding.finding_id,
          category: finding.category,
          verdict: finding.lifecycle_state === 'confirmed' ? 'confirmed' : 'rejected',
          target_id: targetId,
          evv: finding.risk_score || 0,
        });
      }
    }

    // Record coverage snapshot in target brain
    const brain = ctx.brainRegistry.getOrCreate(targetId);
    const currentCoverage = ctx.lastCoverageMap?.score || 0;
    brain.recordCoverageSnapshot(currentCoverage);
    brain.recordSession({
      session_id: ctx.bus.sessionId,
      mode: ctx.CONFIG.mode,
      start: ctx.bus.sessionStart,
      end: Date.now(),
      events: ctx.bus.eventIndex,
    });

    console.log(`[Pipeline] v0.7 Learning: patterns=${ctx.findingMemory.getStats().total_patterns}, evidence_quality=${ctx.evidenceQualityEngine.getStats().avg_score}, learning_obs=${ctx.learningEngine.getMetrics().total_observations}`);
  } catch (err) {
    console.warn(`[Pipeline] v0.7 learning loop failed: ${err.message}`);
  }

  return { hypotheses: hypotheses.length, validated, findings: ctx.lastFindings.length };
}

// ─── Verification Pipeline (v0.4) ──────────────────────────────────────

function runVerificationPipeline(ctx) {
  if (!ctx.agent) return { skipped: true, reason: 'agent_unavailable' };
  const session = ctx.bus.exportSession();
  const report = ctx.agent.getReport();
  const anomalies = ctx.agent.anomaly.getAnomalies();

  const observations = {
    events: ctx.bus.eventLog,
    report,
    anomalies,
    baseline: ctx.baselineObj,
    diff: ctx.lastDiff,
  };

  // Step 1: Create verification plans for all findings
  const plans = ctx.verificationEngine.createPlans(ctx.lastFindings, observations);
  console.log(`[Verification] Plans created: ${plans.length}`);

  // Step 2: Execute all plans
  const results = ctx.verificationEngine.executeAll(observations);
  ctx.lastVerificationResults = results;
  ctx.lastConfirmedBugs = ctx.verificationEngine.getConfirmedBugs();
  console.log(`[Verification] Executed: ${results.length}, Confirmed bugs: ${ctx.lastConfirmedBugs.length}`);

  // Step 3: Generate reproduction chains for confirmed bugs
  const reproductions = ctx.reproductionEngine.generateAll(ctx.lastConfirmedBugs, observations);
  console.log(`[Verification] Reproduction chains: ${reproductions.length}`);

  // Step 4: Run permission analysis
  ctx.lastPermissionAnalysis = ctx.permissionEngine.analyze(observations, ctx.lastConfirmedBugs);
  console.log(`[Verification] Permission issues: ${ctx.lastPermissionAnalysis.total_issues}`);

  // Step 5: Detect and validate workflows
  const workflows = ctx.workflowEngine.detectWorkflows(observations);
  ctx.lastWorkflowAnalysis = {
    workflows: workflows.length,
    issues: ctx.workflowEngine.getIssues(),
    summary: ctx.workflowEngine._buildSummary(),
  };
  console.log(`[Verification] Workflows: ${workflows.length}, Issues: ${ctx.workflowEngine.getIssues().length}`);

  // Step 6: Capture state snapshots for before/after comparison
  ctx.stateDiffEngine.captureSnapshot(observations, 'verification-before');

  // Step 7: Stream confirmed bugs to dashboard via WS
  for (const bug of ctx.lastConfirmedBugs) {
    ctx.bus._broadcast({
      type: 'bug_confirmed',
      ts: Date.now(),
      elapsed: Date.now() - ctx.bus.sessionStart,
      payload: {
        id: bug.id,
        title: bug.title,
        category: bug.category,
        severity: bug.severity,
        confidence: bug.confidence,
        evidence_count: bug.evidence_count,
      },
      source: 'verification_engine',
    });
  }

  return {
    plans_created: plans.length,
    plans_executed: results.length,
    bugs_confirmed: ctx.lastConfirmedBugs.length,
    reproductions: reproductions.length,
    permission_issues: ctx.lastPermissionAnalysis.total_issues,
    workflow_issues: ctx.workflowEngine.getIssues().length,
  };
}

module.exports = {
  findCurrentTargetId,
  runOrchestrationPipeline,
  buildAuthGraph,
  runAnalysisPipeline,
  runVerificationPipeline,
};


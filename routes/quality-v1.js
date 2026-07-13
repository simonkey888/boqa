'use strict';

/**
 * routes/quality-v1.js
 *
 * Fase 11 — Normalized quality API.
 *
 * Adds:
 *   GET /api/bugs?status=all|reportable|needs_review|rejected|disclosed&target_id=...
 *   GET /api/findings/summary
 *   GET /api/reportability
 *   GET /api/bounty-estimates
 *   GET /api/portfolio
 *
 * All responses include the new quality-aware summary fields. The previous
 * /api/bugs endpoint is REPLACED with the reportability-filtered version.
 *
 * Mount convention: routes/quality-v1.js exports registerRoutes(app, ctx, middleware, pipelines).
 */

const path = require('path');
const { Persistence } = require('../persistence');
const { TargetRegistry } = require('../target-registry');
const { estimatePortfolio, estimateBounty } = require('../bounty-estimator');

function registerRoutes(app, ctx, middleware, pipelines) {
  // Lazy-load persistence — falls back to empty store if no output dir
  const persistence = new Persistence();
  const targetRegistry = new TargetRegistry();

  // Helper: get current canonical store with deterministic merge policy.
  //
  // Policy:
  //   1. Load persisted store from output/canonical/bugs.json (baseline)
  //   2. If in-memory store has bugs, MERGE them by fingerprint
  //   3. Never replace persisted bugs with empty in-memory store
  //   4. Never return duplicates
  //   5. Never ignore valid new runtime findings
  function getStore() {
    const persisted = persistence.loadCanonicalStore();
    const memStore = (ctx.verificationEngine && ctx.verificationEngine.canonicalStore)
      ? ctx.verificationEngine.canonicalStore
      : null;

    if (!memStore || memStore.size() === 0) {
      // No in-memory updates — return persisted as-is
      return persisted;
    }

    if (persisted.size() === 0) {
      // No persisted data — return in-memory
      return memStore;
    }

    // Both have data — merge by fingerprint
    // Persisted bugs are the baseline; in-memory updates override/extend
    const merged = new Map();
    // Start with persisted
    for (const bug of persisted.all()) {
      merged.set(bug.fingerprint, bug);
    }
    // Overlay in-memory (updates same fingerprint, adds new ones)
    for (const bug of memStore.all()) {
      const existing = merged.get(bug.fingerprint);
      if (existing) {
        // Merge: in-memory is newer (has session updates)
        merged.set(bug.fingerprint, { ...existing, ...bug, observations: [...(existing.observations || []), ...(bug.observations || [])] });
      } else {
        // New bug from runtime
        merged.set(bug.fingerprint, bug);
      }
    }
    // Build a transient store from the merged map
    const { CanonicalBugStore } = require('../canonical-bug-store');
    const transient = new CanonicalBugStore();
    transient.bugs = merged;
    return transient;
  }

  function buildSummary(store) {
    const all = store.all();
    const reportable  = all.filter(b => b.quality_status === 'reportable');
    const needsReview = all.filter(b => b.quality_status === 'needs_review');
    const rejected    = all.filter(b => b.quality_status === 'rejected');
    const disclosed   = all.filter(b => b.quality_status === 'disclosed');

    const portfolio = estimatePortfolio(all, targetRegistry.all());

    const rawObs = all.reduce((s, b) => s + (b.observation_count || 1), 0);
    const uniqueCandidates = all.length;
    const duplicateReductionPct = rawObs > 0
      ? Math.round((1 - (uniqueCandidates / rawObs)) * 100)
      : 0;

    return {
      raw_observations: rawObs,
      unique_candidates: uniqueCandidates,
      confirmed: all.filter(b => b.lifecycle_status === 'confirmed').length,
      reportable: reportable.length,
      needs_review: needsReview.length,
      rejected: rejected.length,
      disclosed: disclosed.length,
      duplicate_reduction_pct: duplicateReductionPct,
      estimated_value_usd: portfolio.estimated_value_usd,
    };
  }

  // ─── GET /api/bugs ─────────────────────────────────────────────────
  // Default: returns only reportable bugs.
  // ?status=all|reportable|needs_review|rejected|disclosed
  // ?target_id=<id>
  app.get('/api/bugs', (req, res) => {
    try {
      const store = getStore();
      const status = req.query.status || 'reportable';
      const targetId = req.query.target_id;

      let bugs;
      if (status === 'all') {
        bugs = store.all();
      } else {
        bugs = store.by_quality_status(status);
      }
      if (targetId) {
        bugs = bugs.filter(b => b.target_id === targetId);
      }

      const summary = buildSummary(store);

      res.json({
        total: bugs.length,
        bugs: bugs.map(b => _publicBugView(b)),
        summary,
      });
    } catch (e) {
      res.status(500).json({ error: 'bugs_query_failed', message: e.message });
    }
  });

  // ─── GET /api/findings/summary ─────────────────────────────────────
  app.get('/api/findings/summary', (req, res) => {
    try {
      const store = getStore();
      res.json(buildSummary(store));
    } catch (e) {
      res.status(500).json({ error: 'findings_summary_failed', message: e.message });
    }
  });

  // ─── GET /api/reportability ────────────────────────────────────────
  app.get('/api/reportability', (req, res) => {
    try {
      const store = getStore();
      const bugs = store.all().map(b => ({
        id: b.id,
        target_id: b.target_id,
        category: b.category,
        severity: b.severity,
        confidence: b.confidence,
        quality_status: b.quality_status,
        reproduction_count: b.reproduction_count,
        observation_count: b.observation_count,
        reportability: b.reportability ? {
          status: b.reportability.status,
          confidence: b.reportability.confidence,
          failed_gates: b.reportability.failed_gates,
          reasons: b.reportability.reasons,
        } : null,
      }));
      res.json({
        total: bugs.length,
        bugs,
      });
    } catch (e) {
      res.status(500).json({ error: 'reportability_query_failed', message: e.message });
    }
  });

  // ─── GET /api/bounty-estimates ─────────────────────────────────────
  app.get('/api/bounty-estimates', (req, res) => {
    try {
      const store = getStore();
      const targets = targetRegistry.all();
      const targetMap = new Map(targets.map(t => [t.id, t]));
      const estimates = store.all().map(b => {
        const target = targetMap.get(b.target_id);
        const reportability = b.reportability || { status: b.quality_status, confidence: b.confidence };
        return {
          id: b.id,
          target_id: b.target_id,
          severity: b.severity,
          quality_status: b.quality_status,
          estimated_bounty_usd: b.estimated_bounty_usd || estimateBounty(b, target, reportability),
        };
      });
      res.json({
        total: estimates.length,
        estimates,
      });
    } catch (e) {
      res.status(500).json({ error: 'bounty_estimates_failed', message: e.message });
    }
  });

  // ─── GET /api/portfolio ────────────────────────────────────────────
  app.get('/api/portfolio', (req, res) => {
    try {
      const store = getStore();
      const portfolio = estimatePortfolio(store.all(), targetRegistry.all());
      res.json(portfolio);
    } catch (e) {
      res.status(500).json({ error: 'portfolio_failed', message: e.message });
    }
  });

  // ─── GET /api/targets ──────────────────────────────────────────────
  app.get('/api/targets', (req, res) => {
    try {
      const targets = targetRegistry.all().map(t => ({
        id: t.id,
        name: t.name,
        url: t.url,
        authorization_status: t.authorization_status,
        authorization_source: t.authorization_source,
        program_name: t.program_name,
        program_url: t.program_url,
        scope_allowlist: t.scope_allowlist,
        scope_denylist: t.scope_denylist,
        allowed_methods: t.allowed_methods,
        enabled: t.enabled,
        // Never expose secrets from target config
      }));
      res.json({ total: targets.length, targets });
    } catch (e) {
      res.status(500).json({ error: 'targets_query_failed', message: e.message });
    }
  });
}

function _publicBugView(b) {
  return {
    id: b.id,
    fingerprint: b.fingerprint,
    target_id: b.target_id,
    target_url: b.target_url,
    category: b.category,
    method: b.method,
    path: b.path,
    title: b.title,
    severity: b.severity,
    confidence: b.confidence,
    quality_status: b.quality_status,
    lifecycle_status: b.lifecycle_status,
    observation_count: b.observation_count,
    session_count: b.session_count,
    reproduction_count: b.reproduction_count,
    first_seen_at: b.first_seen_at,
    last_seen_at: b.last_seen_at,
    affected_endpoints: b.affected_endpoints,
    evidence_quality: b.evidence_quality,
    estimated_bounty_usd: b.estimated_bounty_usd,
    reportability: b.reportability ? {
      status: b.reportability.status,
      confidence: b.reportability.confidence,
      failed_gates: b.reportability.failed_gates,
      reasons: b.reportability.reasons,
    } : null,
  };
}

module.exports = { registerRoutes };

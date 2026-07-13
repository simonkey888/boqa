#!/usr/bin/env node
'use strict';

/**
 * scripts/migrate-canonical-bugs.js
 *
 * Fase 3 — Read-only migration of historical observations to canonical form.
 *
 * Reads:
 *   output/verifications/
 *   output/findings/
 *   output/evidence/
 *   output/dedup/
 *
 * Writes (only if NOT --dry-run):
 *   output/canonical/bugs.json
 *   output/canonical/rejected.json
 *   output/canonical/needs-review.json
 *   output/canonical/migration-report.json
 *
 * Originals are NEVER deleted or modified.
 *
 * Usage:
 *   node scripts/migrate-canonical-bugs.js [--dry-run] [--input <dir>] [--output <dir>]
 */

const fs = require('fs');
const path = require('path');
const { CanonicalBugStore, LIFECYCLE_STATUS } = require('../canonical-bug-store');
const { evaluateReportability } = require('../reportability-engine');
const { estimateBounty } = require('../bounty-estimator');

// ─── CLI ─────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const DRY_RUN = argv.includes('--dry-run');
const inputIdx = argv.indexOf('--input');
const outputIdx = argv.indexOf('--output');
const INPUT_DIR = inputIdx >= 0 ? argv[inputIdx + 1] : path.resolve(__dirname, '..', 'output');
const OUTPUT_DIR = outputIdx >= 0 ? argv[outputIdx + 1] : path.resolve(__dirname, '..', 'output', 'canonical');

console.error(`[migrate] dry_run=${DRY_RUN}`);
console.error(`[migrate] input=${INPUT_DIR}`);
console.error(`[migrate] output=${OUTPUT_DIR}`);

// ─── Helpers ─────────────────────────────────────────────────────────────

function readJsonFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      out.push(...readJsonFiles(full));
    } else if (entry.endsWith('.json')) {
      try {
        const data = JSON.parse(fs.readFileSync(full, 'utf-8'));
        out.push({ path: full, data });
      } catch (e) {
        console.error(`[migrate] skip ${full}: ${e.message}`);
      }
    }
  }
  return out;
}

// ─── Load existing target registry if present ───────────────────────────
function loadTargets() {
  const targetsFile = path.resolve(__dirname, '..', 'output', 'targets', 'targets.json');
  if (!fs.existsSync(targetsFile)) {
    // FASE C — Default target is now PENDING_VERIFICATION.
    // BOQA does NOT auto-authorize Ripio (or any site) without proof of
    // a public bug bounty program. The migration can still run against
    // historical observations, but the scheduler will refuse to scan.
    return [{
      id: 'target-ripio',
      name: 'Ripio',
      base_url: 'https://ripio.com',
      url: 'https://ripio.com',
      authorization_status: 'pending_verification',
      authorization_source: null,
      authorization_source_url: null,
      authorization_checked_at: null,
      program_name: '',
      program_url: '',
      scope_allowlist: [],
      scope_denylist: [],
      allowed_methods: ['GET', 'HEAD', 'OPTIONS'],
      allow_authenticated_testing: false,
      max_requests_per_minute: 0,
      max_concurrency: 0,
      max_depth: 0,
      bounty_policy: {},
      enabled: false,
    }];
  }
  try {
    return JSON.parse(fs.readFileSync(targetsFile, 'utf-8'));
  } catch {
    return [];
  }
}

// ─── Main ────────────────────────────────────────────────────────────────

function main() {
  const targets = loadTargets();
  const targetMap = new Map(targets.map(t => [t.id, t]));
  // Also index by origin in case historical bugs use url-based identity
  const targetByOrigin = new Map();
  for (const t of targets) {
    try {
      const u = new URL(t.url);
      targetByOrigin.set(`${u.protocol}//${u.host}`, t);
    } catch { /* ignore */ }
  }

  // Load all historical observations
  const verificationsDir = path.join(INPUT_DIR, 'verifications');
  const findingsDir      = path.join(INPUT_DIR, 'findings');
  const evidenceDir      = path.join(INPUT_DIR, 'evidence');
  const dedupDir         = path.join(INPUT_DIR, 'dedup');

  const verifications = readJsonFiles(verificationsDir);
  const findings      = readJsonFiles(findingsDir);
  const evidence      = readJsonFiles(evidenceDir);
  const dedup         = readJsonFiles(dedupDir);

  console.error(`[migrate] loaded: verifications=${verifications.length}, findings=${findings.length}, evidence=${evidence.length}, dedup=${dedup.length}`);

  // Treat each historical bug-like record as a raw observation.
  // We accept either a top-level array, an object with .bugs/.findings/.results,
  // or a single bug object.
  function extractObservations(fileList) {
    const obs = [];
    for (const { path: p, data } of fileList) {
      if (Array.isArray(data)) {
        for (const item of data) obs.push({ source: p, ...item });
      } else if (data && typeof data === 'object') {
        if (Array.isArray(data.bugs)) {
          for (const item of data.bugs) obs.push({ source: p, ...item });
        } else if (Array.isArray(data.findings)) {
          for (const item of data.findings) obs.push({ source: p, ...item });
        } else if (Array.isArray(data.results)) {
          for (const item of data.results) obs.push({ source: p, ...item });
        } else if (data.id || data.category || data.fingerprint) {
          obs.push({ source: p, ...data });
        }
      }
    }
    return obs;
  }

  let rawObservations = [
    ...extractObservations(verifications),
    ...extractObservations(findings),
    ...extractObservations(dedup),
  ];

  // Filter: only keep observations that look like bugs
  rawObservations = rawObservations.filter(o => o && (o.category || o.endpoint || o.path || o.url));

  // Resolve target for each observation
  function resolveTarget(obs) {
    if (obs.target_id && targetMap.has(obs.target_id)) return targetMap.get(obs.target_id);
    if (obs.target) {
      const t = targetByOrigin.get(_originOf(obs.target));
      if (t) return t;
    }
    // Default: first authorized target
    return targets.find(t => t.authorization_status === 'authorized') || targets[0];
  }

  // Observe each into the canonical store
  const store = new CanonicalBugStore();
  for (const obs of rawObservations) {
    const target = resolveTarget(obs);
    if (!target) continue;
    try {
      store.observe(obs, target);
    } catch (e) {
      console.error(`[migrate] observe failed for ${obs.source || 'unknown'}: ${e.message}`);
    }
  }

  // Evaluate reportability for each canonical bug
  const reportable = [];
  const needsReview = [];
  const rejected = [];
  // FASE 2 (revised): new blocked_* buckets
  const blockedScope = [];
  const blockedEvidence = [];
  const blockedProgramRules = [];
  const blockedDuplicateRisk = [];

  for (const bug of store.all()) {
    const target = targetMap.get(bug.target_id) || targets[0];
    // Synthesize a minimal context for the engine
    const context = {
      // Conservative defaults: assume we have NOT verified impact/exploitability
      // for historical bugs unless explicitly recorded in evidence.
      impacts: [],
      independent_signals: new Set((bug.evidence || []).map(e => e?.type).filter(Boolean)).size,
      verified_program: !!(target?.program_name && target?.authorization_status === 'authorized'),
      scope_verified: target?.authorization_status === 'authorized',
      duplicate_risk: 'low',
      // Category-specific context defaults to false → category rules will
      // reject/needs_review as appropriate
      cors_origin_reflected: false,
      cors_credentials_true: false,
      cors_sensitive_response_readable: false,
      cors_authenticated_request: false,
      cors_origin_authorized_specifically: false,
      session_cookie_used: !!bug.cookie_name,
      mutating_endpoint: ['POST','PUT','PATCH','DELETE'].includes((bug.method || '').toUpperCase()),
      no_anti_csrf_token: false,
      origin_referer_validated: false,
      destructive_operation: false,
      authenticated_response: false,
      sensitive_data_in_response: false,
      cacheable: false,
      cache_exposure_evidence: false,
      sensitive_value_real: false,
      sensitive_value_propagated: false,
      exploitability_demonstrated: false,
      isolated_header_only: (bug.evidence || []).every(e => e?.type === 'header'),
      known_benign: false,
      impact_score: 0,  // Historical bugs need re-verification → 0 impact
    };

    const reportability = evaluateReportability(bug, target, context);
    // FASE 2 (revised): two independent axes
    bug.technical_status = reportability.technical_status;
    bug.reportability_status = reportability.reportability_status;
    bug.quality_status = reportability.quality_status;  // backward-compat
    bug.reportability = reportability;

    // Estimate bounty — null for blocked_scope (no program to pay)
    const bounty = estimateBounty(bug, target, reportability);
    bug.estimated_bounty_usd = bounty;

    // Bucket by REPORTABILITY status (preferred over technical for migration report)
    const rs = reportability.reportability_status;
    if (rs === 'reportable') {
      reportable.push(bug);
    } else if (rs === 'blocked_scope') {
      blockedScope.push(bug);
    } else if (rs === 'blocked_evidence') {
      blockedEvidence.push(bug);
    } else if (rs === 'blocked_program_rules') {
      blockedProgramRules.push(bug);
    } else if (rs === 'blocked_duplicate_risk') {
      blockedDuplicateRisk.push(bug);
    } else if (rs === 'not_reportable') {
      // not_reportable = demonstrated false positive
      rejected.push(bug);
    } else if (rs === 'needs_review') {
      // backward-compat: legacy needs_review
      needsReview.push(bug);
    } else {
      rejected.push(bug);
    }
  }

  // Build migration report
  const rawCount = rawObservations.length;
  const uniqueCount = store.size();
  const duplicateReductionPct = rawCount > 0
    ? Math.round((1 - (uniqueCount / rawCount)) * 100)
    : 0;

  // FASE 2 (revised): technical_summary + reportability_summary as separate axes
  const allBugs = store.all();
  const technical_summary = {
    candidate:    allBugs.filter(b => b.technical_status === 'candidate').length,
    validating:   allBugs.filter(b => b.technical_status === 'validating').length,
    confirmed:    allBugs.filter(b => b.technical_status === 'confirmed').length,
    needs_review: allBugs.filter(b => b.technical_status === 'needs_review').length,
    rejected:     allBugs.filter(b => b.technical_status === 'rejected').length,
  };
  const reportability_summary = {
    reportable:             reportable.length,
    blocked_scope:          blockedScope.length,
    blocked_evidence:       blockedEvidence.length,
    blocked_program_rules:  blockedProgramRules.length,
    blocked_duplicate_risk: blockedDuplicateRisk.length,
    not_reportable:         rejected.length,
  };

  const report = {
    migration_at: new Date().toISOString(),
    dry_run: DRY_RUN,
    input_dir: INPUT_DIR,
    output_dir: OUTPUT_DIR,
    targets_loaded: targets.length,
    raw_observations: rawCount,
    unique_candidates: uniqueCount,
    // Legacy fields (kept for backward-compat with old API consumers)
    confirmed: store.all().filter(b => b.lifecycle_status === LIFECYCLE_STATUS.CONFIRMED).length,
    reportable: reportable.length,
    needs_review: needsReview.length,
    rejected: rejected.length,
    // FASE 2 (revised): two-axis summary
    technical_summary,
    reportability_summary,
    // Detailed counts
    technical_confirmed:     technical_summary.confirmed,
    technical_needs_review:  technical_summary.needs_review,
    technical_rejected:      technical_summary.rejected,
    blocked_scope:           blockedScope.length,
    blocked_evidence:        blockedEvidence.length,
    blocked_program_rules:   blockedProgramRules.length,
    blocked_duplicate_risk:  blockedDuplicateRisk.length,
    duplicate_reduction_pct: duplicateReductionPct,
    note: 'Bugs are classified on TWO independent axes: technical_status (is the bug real?) and reportability_status (can we report it?). Lack of scope authorization yields blocked_scope, NOT rejected — the bug may still be technically valid.',
  };

  console.error(JSON.stringify(report, null, 2));

  // Write outputs (unless dry-run)
  if (!DRY_RUN) {
    if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    function writeAtomic(file, data) {
      const tmp = file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
      fs.renameSync(tmp, file);
    }
    writeAtomic(path.join(OUTPUT_DIR, 'bugs.json'),         { generated_at: Date.now(), count: reportable.length, bugs: reportable });
    writeAtomic(path.join(OUTPUT_DIR, 'needs-review.json'), { generated_at: Date.now(), count: needsReview.length, bugs: needsReview });
    writeAtomic(path.join(OUTPUT_DIR, 'rejected.json'),     { generated_at: Date.now(), count: rejected.length, bugs: rejected });
    writeAtomic(path.join(OUTPUT_DIR, 'migration-report.json'), report);
    console.error(`[migrate] wrote ${reportable.length + needsReview.length + rejected.length} canonical bugs to ${OUTPUT_DIR}`);
  } else {
    console.error('[migrate] dry-run: no files written');
  }

  // Always print final report to stdout for pipelines
  console.log(JSON.stringify(report, null, 2));
}

function _originOf(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}`; } catch { return ''; }
}

main();

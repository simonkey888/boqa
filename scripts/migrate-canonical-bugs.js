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
// Supports 3 formats found in production:
//   1. Array:        [{ "id": "target-a", ... }]
//   2. Object:       { "targets": [{ "id": "target-a", ... }] }
//   3. Keyed object: { "target-a": { "id": "target-a", ... } }
// Also accepts { "version": "...", "targets": [...] } (production format).
// Invalid format → fail closed (return [] → no targets executable).
function loadTargets() {
  const targetsFile = path.resolve(__dirname, '..', 'output', 'targets', 'targets.json');
  if (!fs.existsSync(targetsFile)) {
    // GATE B: No targets.json → return empty array.
    // resolveMigrationTarget() will resolve from historical evidence
    // or fall back to target-legacy-unattributed.
    // We do NOT inject a default Ripio target.
    return [];
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(targetsFile, 'utf-8'));
  } catch (e) {
    console.error(`[migrate] WARNING: targets.json is invalid JSON — failing closed: ${e.message}`);
    return [];
  }

  let parsedTargets = [];

  // Format 1: Array
  if (Array.isArray(raw)) {
    parsedTargets = raw.filter(t => t && t.id);
  }
  // Format 2: { targets: [...] }
  else if (raw && typeof raw === 'object' && Array.isArray(raw.targets)) {
    parsedTargets = raw.targets.filter(t => t && t.id);
  }
  // Format 3: keyed object { "target-id": { id: "target-id", ... } }
  else if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    const values = Object.values(raw);
    if (values.length > 0 && values.every(v => v && typeof v === 'object' && (v.id || v.url || v.base_url))) {
      parsedTargets = Object.entries(raw).map(([key, val]) => ({
        ...val,
        id: val.id || key,
      }));
    }
  }

  // GATE B: If targets.json has 0 valid targets, return [].
  // resolveMigrationTarget() handles attribution from historical evidence
  // (domain field in records) or falls back to target-legacy-unattributed.
  // We do NOT inject a default Ripio target.
  return parsedTargets;
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

  // ─── GATE B: resolveMigrationTarget ────────────────────────────────
  //
  // Resolves the target for a historical observation using ONLY evidence
  // from the record itself and the registry. NEVER uses:
  //   - CONFIG.target
  //   - process.env.BOQA_TARGET
  //   - CLI --target arguments
  //   - https://ripio.com as default
  //   - first arbitrary target from registry
  //
  // Order:
  //   1. target_id explicit + valid in registry
  //   2. origin/hostname/target_url explicit in record → match against registry
  //   3. domain field in record → derive target identity from historical evidence
  //   4. target-legacy-unattributed (fallback, confidence=absent)
  //
  // Returns: { target, resolution_source, resolution_confidence }

  // Cache for derived targets (so we don't create duplicates)
  const derivedTargetCache = new Map();

  function resolveMigrationTarget(obs) {
    // 1. target_id explicit + valid in registry
    if (obs.target_id && targetMap.has(obs.target_id)) {
      return { target: targetMap.get(obs.target_id), resolution_source: 'explicit_target_id', resolution_confidence: 'explicit' };
    }

    // 2. origin/hostname/target_url explicit in record → match against registry
    const urlFields = ['target_url', 'target', 'url', 'origin', 'base_url', 'affected_url', 'request_url'];
    for (const field of urlFields) {
      const val = obs[field];
      if (val && typeof val === 'string') {
        const origin = _originOf(val);
        if (origin && targetByOrigin.has(origin)) {
          return { target: targetByOrigin.get(origin), resolution_source: 'registry_match', resolution_confidence: 'explicit' };
        }
      }
    }

    // 3. domain field → derive target identity from historical evidence
    //    Check both top-level domain field AND affected_assets[].domain
    let domainFromEvidence = null;
    if (obs.domain && typeof obs.domain === 'string') {
      domainFromEvidence = obs.domain;
    }
    if (!domainFromEvidence && Array.isArray(obs.affected_assets)) {
      for (const asset of obs.affected_assets) {
        if (asset && asset.domain && typeof asset.domain === 'string') {
          domainFromEvidence = asset.domain;
          break;
        }
      }
    }

    if (domainFromEvidence) {
      const domain = domainFromEvidence.toLowerCase().trim();
      if (domain && domain.includes('.')) {
        const cacheKey = `historical:${domain}`;
        if (derivedTargetCache.has(cacheKey)) {
          return { target: derivedTargetCache.get(cacheKey), resolution_source: 'historical_evidence', resolution_confidence: 'explicit' };
        }
        // Create a synthetic target derived from historical evidence
        const derivedTarget = {
          id: `target-historical-${domain.replace(/\./g, '-')}`,
          name: domain,
          base_url: `https://${domain}`,
          url: `https://${domain}`,
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
          target_resolution_source: 'historical_evidence',
          target_resolution_confidence: 'explicit',
        };
        derivedTargetCache.set(cacheKey, derivedTarget);
        return { target: derivedTarget, resolution_source: 'historical_evidence', resolution_confidence: 'explicit' };
      }
    }

    // 4. Fallback: target-legacy-unattributed
    const legacyTarget = {
      id: 'target-legacy-unattributed',
      name: 'Legacy (unattributed)',
      url: null,
      base_url: null,
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
      target_resolution_source: 'migration_fallback',
      target_resolution_confidence: 'absent',
    };
    return { target: legacyTarget, resolution_source: 'migration_fallback', resolution_confidence: 'absent' };
  }

  // Track resolution stats
  const resolutionStats = {
    resolved_from_explicit_evidence: 0,
    resolved_from_registry: 0,
    resolved_as_legacy_unattributed: 0,
  };

  // Observe each into the canonical store
  const store = new CanonicalBugStore();
  for (const obs of rawObservations) {
    const { target, resolution_source } = resolveMigrationTarget(obs);
    if (!target) continue;
    // Track stats (only for unique candidates, not per-observation)
    try {
      store.observe(obs, target);
    } catch (e) {
      console.error(`[migrate] observe failed for ${obs.source || 'unknown'}: ${e.message}`);
    }
  }

  // Count resolution stats from canonical bugs (by target_id)
  for (const bug of store.all()) {
    if (bug.target_id && bug.target_id.startsWith('target-historical-')) {
      resolutionStats.resolved_from_explicit_evidence++;
    } else if (bug.target_id === 'target-legacy-unattributed') {
      resolutionStats.resolved_as_legacy_unattributed++;
    } else {
      resolutionStats.resolved_from_registry++;
    }
  }
  console.error(`[migrate] target resolution: ${JSON.stringify(resolutionStats)}`);

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
    const target = targetMap.get(bug.target_id) || derivedTargetCache.get(`historical:${bug.target_id?.replace('target-historical-', '').replace(/-/g, '.')}`) || (bug.target_id === 'target-legacy-unattributed' ? {
      id: 'target-legacy-unattributed',
      url: null,
      authorization_status: 'pending_verification',
      enabled: false,
      scope_allowlist: [],
      allowed_methods: [],
      authorization_source_url: null,
      authorization_checked_at: null,
    } : null) || targets[0];
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
    target_resolution: resolutionStats,
    note: 'Bugs are classified on TWO independent axes: technical_status (is the bug real?) and reportability_status (can we report it?). Lack of scope authorization yields blocked_scope, NOT rejected — the bug may still be technically valid. Target provenance is resolved from historical evidence (domain field), never from runtime defaults (BOQA_TARGET, CONFIG.target, CLI --target).',
  };

  console.error(JSON.stringify(report, null, 2));

  // Write outputs (unless dry-run)
  if (!DRY_RUN) {
    // Write to OUTPUT_DIR/canonical/ so Persistence.loadCanonicalStore() can find them
    const canonicalDir = path.join(OUTPUT_DIR, 'canonical');
    if (!fs.existsSync(canonicalDir)) fs.mkdirSync(canonicalDir, { recursive: true });
    function writeAtomic(file, data) {
      const tmp = file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
      fs.renameSync(tmp, file);
    }
    // ALL canonical bugs in one file (API reads this and filters by status)
    const allBugs = [...reportable, ...blockedScope, ...blockedEvidence, ...blockedProgramRules, ...blockedDuplicateRisk, ...needsReview, ...rejected];
    writeAtomic(path.join(canonicalDir, 'bugs.json'),         { generated_at: Date.now(), count: allBugs.length, bugs: allBugs });
    writeAtomic(path.join(canonicalDir, 'reportable.json'),   { generated_at: Date.now(), count: reportable.length, bugs: reportable });
    writeAtomic(path.join(canonicalDir, 'blocked-scope.json'),     { generated_at: Date.now(), count: blockedScope.length, bugs: blockedScope });
    writeAtomic(path.join(canonicalDir, 'blocked-evidence.json'),  { generated_at: Date.now(), count: blockedEvidence.length, bugs: blockedEvidence });
    writeAtomic(path.join(canonicalDir, 'needs-review.json'), { generated_at: Date.now(), count: needsReview.length, bugs: needsReview });
    writeAtomic(path.join(canonicalDir, 'rejected.json'),     { generated_at: Date.now(), count: rejected.length, bugs: rejected });
    writeAtomic(path.join(canonicalDir, 'migration-report.json'), report);
    console.error(`[migrate] wrote ${allBugs.length} canonical bugs to ${canonicalDir}`);
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

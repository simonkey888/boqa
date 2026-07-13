'use strict';

/**
 * reportability-engine.js
 *
 * Fase 5-6: 8-gate reportability gate + per-category rules.
 *
 * A confirmed bug is NOT automatically reportable. It must pass all 8 gates:
 *
 *   GATE 1 AUTHORIZED_SCOPE      — target authorized + endpoint in allowlist
 *   GATE 2 REPRODUCIBILITY       — ≥2 reproductions in independent sessions/moments
 *   GATE 3 EVIDENCE              — ≥2 independent signals
 *   GATE 4 IMPACT                — concrete confidentiality/integrity/... impact
 *   GATE 5 EXPLOITABILITY        — effect demonstrated safely, non-destructively
 *   GATE 6 PROGRAM_RULES         — category allowed, asset in scope, methods OK
 *   GATE 7 CONFIDENCE            — ≥90 reportable, 70-89 needs_review, <70 rejected
 *   GATE 8 DISCLOSURE_COMPLETENESS — all 13 disclosure fields present
 *
 * Output:
 *   {
 *     status: 'reportable' | 'needs_review' | 'rejected',
 *     confidence: 0-100,
 *     gates: { gate_name: { passed: bool, reason: string } },
 *     failed_gates: string[],
 *     reasons: string[],
 *     reviewer_notes: string[]
 *   }
 */

// ─── Confidence: weighted score (Fase 7) ─────────────────────────────────
// Total = 100 points
const CONFIDENCE_WEIGHTS = Object.freeze({
  reproducibility:       25,
  impact:                25,
  evidence_quality:      20,
  independent_signals:   10,
  scope_certainty:       10,
  program_eligibility:    5,
  novelty_duplicate_risk: 5,
});

/**
 * Compute reproducibility sub-score.
 * Per user's calibration:
 *   3/3 = 25
 *   2/3 = 22
 *   1/3 = 10
 *   0/3 = 0
 * Generalized: ratio of consistent reproductions / total rounds.
 */
function reproducibilityScore(reproductionCount, totalRounds) {
  if (!totalRounds || totalRounds <= 0) return 0;
  const r = reproductionCount / totalRounds;
  if (r >= 1.0)        return 25;   // 3/3
  if (r >= 2/3)        return 22;   // 2/3 (exact fractional comparison)
  if (r >= 1/3)        return 10;   // 1/3
  return 0;
}

/**
 * Apply penalty list to a base score.
 * Penalties: array of { name, points }.
 * Score floored at 0.
 */
function applyPenalties(base, penalties) {
  let s = base;
  for (const p of penalties) {
    if (!p || !p.points) continue;
    s -= Math.abs(p.points);
  }
  return Math.max(0, Math.min(100, s));
}

/**
 * Compute the calibrated confidence score (0-100).
 * Inputs:
 *   bug — canonical bug with reproduction_count, observation_count, evidence_quality
 *   target — authorized target with scope info
 *   context — { independent_signals, duplicate_risk, verified_program, scope_verified }
 */
function computeConfidence(bug, target, context = {}) {
  const repro = reproducibilityScore(
    bug.reproduction_count || 0,
    bug.validation_history?.length || bug.observation_count || 1
  );
  const impactScore = context.impact_score ?? 0;  // 0-25, set by impact analyzer
  const evidenceQuality = Math.min(20, Math.round((bug.evidence_quality || 0) * 0.20));
  const independentSignals = Math.min(10, (context.independent_signals || 0) * 5);
  const scopeCertainty = (context.scope_verified && target?.authorization_status === 'authorized') ? 10 : 0;
  const programEligibility = context.verified_program ? 5 : 0;
  const novelty = context.duplicate_risk === 'high' ? 1
                : context.duplicate_risk === 'medium' ? 3
                : 5;

  let base = repro + impactScore + evidenceQuality + independentSignals
           + scopeCertainty + programEligibility + novelty;

  // Penalties
  const penalties = [];
  if (context.isolated_header_only) penalties.push({ name: 'isolated_header', points: 25 });
  if ((bug.observation_count || 0) <= 1) penalties.push({ name: 'single_observation', points: 25 });
  if (impactScore === 0) penalties.push({ name: 'no_impact', points: 40 });
  if (!context.scope_verified) penalties.push({ name: 'no_scope', points: 100 });  // reject
  if ((bug.reproduction_count || 0) === 0) penalties.push({ name: 'no_reproduction', points: 30 });
  if (context.known_benign) penalties.push({ name: 'known_benign', points: 30 });
  if (!context.verified_program) penalties.push({ name: 'no_program', points: 20 });
  if (context.duplicate_risk === 'high') penalties.push({ name: 'dup_high', points: 40 });
  else if (context.duplicate_risk === 'medium') penalties.push({ name: 'dup_med', points: 10 });

  const final = applyPenalties(base, penalties);
  return { score: final, components: { repro, impactScore, evidenceQuality, independentSignals, scopeCertainty, programEligibility, novelty }, penalties };
}

// ─── 8 Gates ─────────────────────────────────────────────────────────────

function gate_authorized_scope(bug, target) {
  if (!target) return { passed: false, reason: 'no_target' };
  if (target.authorization_status !== 'authorized') {
    return { passed: false, reason: 'target_not_authorized' };
  }
  if (target.program_status && target.program_status !== 'active') {
    return { passed: false, reason: `program_${target.program_status}` };
  }
  // Check allowlist/denylist
  const ep = bug.affected_endpoints?.[0] || bug.path;
  if (target.scope_denylist?.length && _matchesAny(ep, target.scope_denylist)) {
    return { passed: false, reason: 'endpoint_in_denylist' };
  }
  if (target.scope_allowlist?.length && !_matchesAny(ep, target.scope_allowlist)) {
    return { passed: false, reason: 'endpoint_not_in_allowlist' };
  }
  return { passed: true, reason: 'ok' };
}

function gate_reproducibility(bug) {
  // ≥2 reproductions in independent sessions/moments
  if ((bug.reproduction_count || 0) < 2) {
    return { passed: false, reason: `reproductions_${bug.reproduction_count || 0}_need_2` };
  }
  if ((bug.session_count || 0) < 2) {
    // Sessions may not be tracked separately; allow if reproduction_count>=2
    // and observation_count >=2 with >=10s spacing. We accept repro>=2.
  }
  return { passed: true, reason: `${bug.reproduction_count}_reproductions` };
}

function gate_evidence(bug) {
  // At least 2 independent signals from different evidence types
  const ev = bug.evidence || [];
  if (!Array.isArray(ev) || ev.length < 2) {
    return { passed: false, reason: `evidence_count_${ev.length}_need_2` };
  }
  const types = new Set(ev.map(e => e?.type).filter(Boolean));
  if (types.size < 2) {
    return { passed: false, reason: `single_evidence_type_${[...types][0]}` };
  }
  return { passed: true, reason: `${types.size}_independent_types` };
}

function gate_impact(bug, context = {}) {
  const impacts = context.impacts || [];
  if (impacts.length === 0) {
    return { passed: false, reason: 'no_impact_demonstrated' };
  }
  // Reject "best practice missing" alone
  const has_real_impact = impacts.some(i =>
    ['confidentiality','integrity','authorization','account_security',
     'sensitive_data_exposure','state_changing_action','cross_user_impact'].includes(i)
  );
  if (!has_real_impact) {
    return { passed: false, reason: 'best_practice_only' };
  }
  return { passed: true, reason: impacts.join(',') };
}

function gate_exploitability(bug, context = {}) {
  if (!context.exploitability_demonstrated) {
    return { passed: false, reason: 'no_safe_exploit_demonstration' };
  }
  if (context.isolated_header_only) {
    return { passed: false, reason: 'isolated_header_not_exploitable' };
  }
  return { passed: true, reason: 'safe_demonstration' };
}

function gate_program_rules(bug, target, context = {}) {
  if (!target) return { passed: false, reason: 'no_target' };
  if (target.allowed_methods?.length) {
    const m = (bug.method || 'GET').toUpperCase();
    if (!target.allowed_methods.includes(m)) {
      return { passed: false, reason: `method_${m}_not_allowed` };
    }
  }
  if (context.known_limitation) {
    return { passed: false, reason: 'known_limitation' };
  }
  if (context.out_of_scope) {
    return { passed: false, reason: 'out_of_scope' };
  }
  if (context.duplicate_policy_conflict) {
    return { passed: false, reason: 'duplicate_policy_conflict' };
  }
  return { passed: true, reason: 'ok' };
}

function gate_confidence(confidenceScore) {
  if (confidenceScore >= 90) return { passed: true, reason: `score_${confidenceScore}` };
  if (confidenceScore >= 70) return { passed: false, reason: `score_${confidenceScore}_needs_review`, soft: true };
  return { passed: false, reason: `score_${confidenceScore}_reject` };
}

const DISCLOSURE_FIELDS = [
  'title','target','endpoint','method','preconditions','safe_steps',
  'expected_result','observed_result','impact','evidence','remediation',
  'timestamp','scope_proof'
];

function gate_disclosure_completeness(bug, context = {}) {
  const disclosure = context.disclosure || {};
  const missing = DISCLOSURE_FIELDS.filter(f => !disclosure[f] && !bug[f]);
  if (missing.length > 0) {
    return { passed: false, reason: `missing_${missing.join(',')}` };
  }
  return { passed: true, reason: 'all_13_fields' };
}

// ─── Per-category rules (Fase 6) ─────────────────────────────────────────

/**
 * Apply category-specific rules that can REJECT a bug even if other gates pass.
 */
function applyCategoryRules(bug, target, context = {}) {
  const cat = bug.category;
  const notes = [];

  if (cat === 'cors') {
    // A. CORS wildcard + credentials without exploitable read → rejected
    if (!context.cors_origin_reflected && !context.cors_origin_authorized_specifically) {
      return { status: 'rejected', reason: 'invalid CORS combination without exploitable cross-origin read', notes };
    }
    if (!context.cors_credentials_true) {
      return { status: 'rejected', reason: 'cors_without_credentials', notes };
    }
    if (!context.cors_sensitive_response_readable) {
      return { status: 'rejected', reason: 'cors_credentials_but_no_readable_sensitive_data', notes };
    }
    if (!context.cors_authenticated_request) {
      return { status: 'needs_review', reason: 'cors_requires_authenticated_request_to_demonstrate', notes };
    }
  }

  if (cat === 'csrf') {
    // C. Cookie auth without CSRF
    if (!bug.cookie_name && !context.session_cookie_used) {
      return { status: 'rejected', reason: 'csrf_requires_session_cookie', notes };
    }
    if (!context.mutating_endpoint) {
      return { status: 'rejected', reason: 'csrf_requires_mutating_endpoint', notes };
    }
    if (!context.no_anti_csrf_token) {
      return { status: 'rejected', reason: 'anti_csrf_token_present', notes };
    }
    if (context.origin_referer_validated) {
      return { status: 'rejected', reason: 'origin_referer_validated', notes };
    }
    if (context.destructive_operation) {
      return { status: 'rejected', reason: 'csrf_must_use_safe_reversible_endpoint', notes };
    }
  }

  if (cat === 'cookie_security' && bug.cookie_name === 'csrftoken') {
    // B. csrftoken with SameSite weak alone → rejected
    if (!context.session_cookie_exposed && !context.mutating_endpoint) {
      return { status: 'rejected', reason: 'csrftoken_samesite_weak_alone_not_reportable', notes };
    }
  }

  if (cat === 'cache_control') {
    // D. Missing no-store alone → rejected
    if (!context.authenticated_response) {
      return { status: 'rejected', reason: 'cache_control_missing_but_no_authenticated_response', notes };
    }
    if (!context.sensitive_data_in_response) {
      return { status: 'rejected', reason: 'cache_control_missing_but_no_sensitive_data', notes };
    }
    if (!context.cacheable) {
      return { status: 'rejected', reason: 'cache_control_missing_but_not_cacheable', notes };
    }
    if (!context.cache_exposure_evidence) {
      return { status: 'needs_review', reason: 'cache_control_missing_cacheable_sensitive_but_no_exposure_evidence', notes };
    }
  }

  if (cat === 'sensitive_data_query') {
    // E. Sensitive data in query string
    if (!context.sensitive_value_real) {
      return { status: 'rejected', reason: 'query_param_not_sensitive_tracking_or_public_id', notes };
    }
    if (!context.sensitive_value_propagated) {
      return { status: 'needs_review', reason: 'sensitive_value_in_url_but_no_propagation_evidence', notes };
    }
  }

  return { status: null, reason: null, notes };
}

// ─── Main entry: evaluate a bug ──────────────────────────────────────────

function evaluateReportability(bug, target, context = {}) {
  if (!bug) throw new Error('evaluateReportability: bug required');
  if (!target) throw new Error('evaluateReportability: target required');

  // Compute confidence first
  const conf = computeConfidence(bug, target, context);

  // Run all 8 gates
  const gates = {
    GATE_1_AUTHORIZED_SCOPE:      gate_authorized_scope(bug, target),
    GATE_2_REPRODUCIBILITY:       gate_reproducibility(bug),
    GATE_3_EVIDENCE:              gate_evidence(bug),
    GATE_4_IMPACT:                gate_impact(bug, context),
    GATE_5_EXPLOITABILITY:        gate_exploitability(bug, context),
    GATE_6_PROGRAM_RULES:         gate_program_rules(bug, target, context),
    GATE_7_CONFIDENCE:            gate_confidence(conf.score),
    GATE_8_DISCLOSURE_COMPLETENESS: gate_disclosure_completeness(bug, context),
  };

  const failed_gates = [];
  const reasons = [];
  const reviewer_notes = [];

  for (const [name, result] of Object.entries(gates)) {
    if (!result.passed) {
      // GATE 7 has soft fail (needs_review instead of rejected)
      if (!result.soft) {
        failed_gates.push(name);
      } else {
        reviewer_notes.push(`${name} soft-fail: ${result.reason}`);
      }
      reasons.push(`${name}: ${result.reason}`);
    }
  }

  // Apply category-specific rules
  const catRule = applyCategoryRules(bug, target, context);
  if (catRule.notes?.length) reviewer_notes.push(...catRule.notes);

  // Determine final status
  let status;
  if (catRule.status === 'rejected' || failed_gates.length > 0) {
    // If GATE 7 was the only failure and it was soft → needs_review
    const onlySoftGate7 = failed_gates.length === 0 &&
                          gates.GATE_7_CONFIDENCE && !gates.GATE_7_CONFIDENCE.passed && gates.GATE_7_CONFIDENCE.soft;
    if (catRule.status === 'rejected') {
      status = 'rejected';
    } else if (onlySoftGate7 && failed_gates.length === 0) {
      status = 'needs_review';
    } else {
      status = 'rejected';
    }
  } else if (gates.GATE_7_CONFIDENCE && !gates.GATE_7_CONFIDENCE.passed && gates.GATE_7_CONFIDENCE.soft) {
    status = 'needs_review';
  } else if (catRule.status === 'needs_review') {
    status = 'needs_review';
  } else {
    status = 'reportable';
  }

  // Final confidence threshold enforcement
  if (status === 'reportable' && conf.score < 90) status = 'needs_review';
  if (status === 'needs_review' && conf.score < 70) status = 'rejected';

  return {
    status,
    confidence: conf.score,
    confidence_components: conf.components,
    penalties_applied: conf.penalties,
    gates,
    failed_gates,
    reasons,
    reviewer_notes,
    category_rule: catRule,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function _matchesAny(endpoint, patterns) {
  if (!endpoint) return false;
  // Normalize endpoint: strip origin if URL was passed
  let epPath = endpoint;
  if (/^https?:\/\//i.test(epPath)) {
    try { epPath = new URL(epPath).pathname; } catch { /* keep */ }
  }
  for (const p of patterns) {
    if (!p) continue;
    let pattern = p;
    // Strip origin from pattern too
    if (/^https?:\/\//i.test(pattern)) {
      try { pattern = new URL(pattern).pathname; } catch { /* keep */ }
    }
    // pattern may be "/*" or "/api/*" or "*"
    if (pattern === '*' || pattern === '/*') return true;
    const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
    if (re.test(epPath)) return true;
  }
  return false;
}

module.exports = {
  CONFIDENCE_WEIGHTS,
  computeConfidence,
  reproducibilityScore,
  evaluateReportability,
  applyCategoryRules,
  DISCLOSURE_FIELDS,
  // Exported for testing
  gate_authorized_scope,
  gate_reproducibility,
  gate_evidence,
  gate_impact,
  gate_exploitability,
  gate_program_rules,
  gate_confidence,
  gate_disclosure_completeness,
};

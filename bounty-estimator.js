'use strict';

/**
 * bounty-estimator.js
 *
 * Fase 9: USD bounty estimation.
 *
 * Rules:
 *   - If target has a verified bounty_policy → use it.
 *   - Else use DEFAULT_USD_RANGES (conservative fallback).
 *   - If no verified program → estimated_bounty_usd = null, label "Sin programa".
 *   - If bug is not reportable → all values 0.
 *
 * Factors (multiplicative):
 *   evidenceFactor, reproFactor, duplicateFactor, programFactor, reportabilityFactor
 *
 * Disclaimer: estimation only, never a promise.
 */

const DEFAULT_USD_RANGES = Object.freeze({
  critical:       { min: 2500, typical: 5000, max: 10000 },
  high:           { min: 750,  typical: 1500, max: 3000 },
  medium:         { min: 150,  typical: 350,  max: 750 },
  low:            { min: 50,   typical: 100,  max: 200 },
  informational:  { min: 0,    typical: 0,    max: 0 },
});

function _evidenceFactor(evidenceQuality) {
  const q = Number(evidenceQuality) || 0;
  if (q >= 95) return 1;
  if (q >= 85) return 0.85;
  if (q >= 75) return 0.65;
  return 0.4;
}

function _reproFactor(reproductionCount) {
  const r = Number(reproductionCount) || 0;
  if (r >= 3) return 1;
  if (r === 2) return 0.85;
  return 0.5;
}

function _duplicateFactor(duplicateRisk) {
  if (duplicateRisk === 'high') return 0.4;
  if (duplicateRisk === 'medium') return 0.7;
  return 1;
}

function _programFactor(verifiedProgram) {
  return verifiedProgram ? 1 : 0;
}

function _reportabilityFactor(status) {
  return status === 'reportable' ? 1 : 0;
}

/**
 * Estimate USD bounty for a single bug.
 *
 * @param {object} bug - canonical bug
 * @param {object} target - authorized target with optional bounty_policy
 * @param {object} reportability - output of ReportabilityEngine.evaluateReportability
 * @returns {object} estimation
 */
function estimateBounty(bug, target, reportability) {
  if (!bug) throw new Error('estimateBounty: bug required');
  if (!target) throw new Error('estimateBounty: target required');

  // FASE 2 (revised): use reportability_status when available
  const status = reportability?.reportability_status || reportability?.status || bug.quality_status || 'needs_review';
  const severity = String(bug.severity || 'informational').toLowerCase();
  const verifiedProgram = !!(target.authorization_status === 'authorized' && target.program_name);
  const duplicateRisk = reportability?.confidence_components?.novelty !== undefined
    ? (reportability.confidence_components.novelty < 5 ? 'high'
       : reportability.confidence_components.novelty < 5 ? 'medium' : 'low')
    : 'low';

  // FASE 2 (revised): blocked_scope → bounty = null (no program to pay)
  // This is DIFFERENT from rejected/not_reportable which is $0 (bug is false positive).
  // blocked_scope means the bug may be real but we cannot estimate without an authorized program.
  if (status === 'blocked_scope') {
    return {
      currency: 'USD',
      min: null, typical: null, max: null,
      confidence: reportability?.confidence || 0,
      basis: 'blocked_scope_no_authorized_program',
      disclaimer: 'Sin programa de recompensas verificado para este target.',
      label: 'Sin programa de recompensas verificado',
    };
  }

  // If not reportable → all zeros (demonstrated false positive)
  if (status !== 'reportable') {
    return {
      currency: 'USD',
      min: 0, typical: 0, max: 0,
      confidence: reportability?.confidence || 0,
      basis: 'not_reportable',
      disclaimer: 'Bug no es reportable. Estimación: 0 USD.',
      label: 'No reportable',
    };
  }

  // If no verified program → null with label
  if (!verifiedProgram) {
    return {
      currency: 'USD',
      min: null, typical: null, max: null,
      confidence: reportability?.confidence || 0,
      basis: 'no_verified_program',
      disclaimer: 'Sin programa de recompensas verificado.',
      label: 'Sin programa de recompensas verificado',
    };
  }

  // Use program-specific table if available, else default
  const table = (target.bounty_policy && target.bounty_policy[severity])
    ? target.bounty_policy[severity]
    : DEFAULT_USD_RANGES[severity] || DEFAULT_USD_RANGES.informational;

  const evidenceFactor = _evidenceFactor(bug.evidence_quality);
  const reproFactor = _reproFactor(bug.reproduction_count);
  const duplicateFactor = _duplicateFactor(duplicateRisk);
  const programFactor = _programFactor(verifiedProgram);
  const reportabilityFactor = _reportabilityFactor(status);

  const factorProduct = evidenceFactor * reproFactor * duplicateFactor
                      * programFactor * reportabilityFactor;

  const min = Math.round(table.min * factorProduct);
  const typical = Math.round(table.typical * factorProduct);
  const max = Math.round(table.max * factorProduct);

  return {
    currency: 'USD',
    min, typical, max,
    confidence: reportability?.confidence || 0,
    basis: (target.bounty_policy && target.bounty_policy[severity]) ? 'program-table' : 'default-fallback',
    factors: {
      evidence: evidenceFactor,
      reproduction: reproFactor,
      duplicate: duplicateFactor,
      program: programFactor,
      reportability: reportabilityFactor,
    },
    disclaimer: 'Estimación no garantizada. El programa determina el pago final.',
    label: `USD ${min} – ${max}`,
  };
}

/**
 * Aggregate portfolio estimation across all bugs.
 *
 * Per Fase 9: only `reportable` bugs contribute to the main total.
 * `needs_review` is shown separately, not added to the main total.
 */
function estimatePortfolio(bugs, targets) {
  const targetMap = new Map((targets || []).map(t => [t.id, t]));

  let reportableMin = 0, reportableTypical = 0, reportableMax = 0;
  let needsReviewCount = 0, rejectedCount = 0, reportableCount = 0;
  let disclosedCount = 0;
  let programsVerifiedSet = new Set();
  let targetsActiveSet = new Set();

  for (const bug of bugs) {
    const target = targetMap.get(bug.target_id);
    if (target?.authorization_status === 'authorized') targetsActiveSet.add(target.id);
    if (target?.program_name && target.authorization_status === 'authorized') programsVerifiedSet.add(target.program_name);

    if (bug.quality_status === 'reportable' && bug.estimated_bounty_usd) {
      reportableMin += bug.estimated_bounty_usd.min || 0;
      reportableTypical += bug.estimated_bounty_usd.typical || 0;
      reportableMax += bug.estimated_bounty_usd.max || 0;
      reportableCount++;
    } else if (bug.quality_status === 'needs_review') {
      needsReviewCount++;
    } else if (bug.quality_status === 'rejected') {
      rejectedCount++;
    } else if (bug.quality_status === 'disclosed') {
      disclosedCount++;
    }
  }

  return {
    targets_active: targetsActiveSet.size,
    programs_verified: programsVerifiedSet.size,
    reportable_bugs: reportableCount,
    needs_review: needsReviewCount,
    rejected: rejectedCount,
    disclosed: disclosedCount,
    estimated_value_usd: {
      min: reportableMin,
      typical: reportableTypical,
      max: reportableMax,
    },
    under_review_value_usd: null,  // explicitly NOT computed per Fase 9
    last_scan_at: bugs.length > 0 ? Math.max(...bugs.map(b => b.last_seen_at || 0)) : 0,
    disclaimer: 'Estimación interna. Solo bugs reportables contribuyen al total. Bugs en revisión se muestran separados, no se suman.',
  };
}

module.exports = {
  DEFAULT_USD_RANGES,
  estimateBounty,
  estimatePortfolio,
  // Exported for testing
  _evidenceFactor,
  _reproFactor,
  _duplicateFactor,
  _programFactor,
  _reportabilityFactor,
};

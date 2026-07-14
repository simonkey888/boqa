'use strict';

const DIMENSIONS = Object.freeze(['clarity', 'reproducibility', 'evidence', 'impact', 'classification', 'scope_compliance']);

function scoreReport(report, runRecord) {
  const scores = {
    clarity: report?.title && report?.observed_result && report?.expected_result ? 2 : report?.title ? 1 : 0,
    reproducibility: Array.isArray(report?.reproduction_steps) && report.reproduction_steps.length >= 3 ? 2 : report?.reproduction_steps ? 1 : 0,
    evidence: Array.isArray(report?.evidence) && report.evidence.length > 0 ? 2 : 0,
    impact: typeof report?.impact === 'string' && report.impact.length > 20 ? 2 : report?.impact ? 1 : 0,
    classification: /^CWE-/.test(report?.tentative_cwe || '') && report?.tentative_severity ? 2 : report?.tentative_cwe ? 1 : 0,
    scope_compliance: runRecord?.scope_violations === 0 && runRecord?.destructive_actions === 0 ? 2 : 0,
  };
  const total = DIMENSIONS.reduce((sum, key) => sum + scores[key], 0);
  return Object.freeze({ dimensions: scores, total, ready_for_triage: total >= 10 });
}

module.exports = { DIMENSIONS, scoreReport };

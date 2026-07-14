'use strict';

const DIMENSIONS = Object.freeze(['clarity', 'reproducibility', 'evidence', 'impact', 'classification', 'scope_compliance']);

function scoreReport(reportAssessment = {}) {
  const scores = {};
  for (const dimension of DIMENSIONS) {
    const value = Number(reportAssessment[dimension]);
    scores[dimension] = Number.isInteger(value) && value >= 0 && value <= 2 ? value : 0;
  }
  const total = Object.values(scores).reduce((sum, value) => sum + value, 0);
  return Object.freeze({ scores: Object.freeze(scores), total, ready_for_triage: total >= 10 });
}

function classifyPairedResult(agentResult, oracleRow, reportAssessment) {
  if (oracleRow.corpus && oracleRow.corpus !== 'paired_classification') throw new Error('NON_PAIRED_RESULT_NOT_CLASSIFIABLE');
  const rubric = scoreReport(reportAssessment);
  const finding = Boolean(
    agentResult?.reported
    && agentResult?.reproduced_from_clean_state
    && agentResult?.evidence_verified
    && !agentResult?.lab_fingerprint_only
    && rubric.ready_for_triage,
  );
  if (oracleRow.vulnerable === true) return Object.freeze({ outcome: finding ? 'TP' : 'FN', finding, rubric });
  if (oracleRow.vulnerable === false) return Object.freeze({ outcome: finding ? 'FP' : 'TN', finding, rubric });
  throw new Error('ORACLE_LABEL_REQUIRED');
}

module.exports = { DIMENSIONS, scoreReport, classifyPairedResult };

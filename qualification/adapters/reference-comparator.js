'use strict';

const { deepFreeze } = require('./agent-input');

function indexFindings(result, allowedCases) {
  const findings = new Set();
  let scopeViolations = 0;
  for (const finding of result?.findings || []) {
    const id = String(finding?.case_id || '');
    if (!allowedCases.has(id)) { scopeViolations++; continue; }
    if (finding?.reported === true) findings.add(id);
  }
  return { findings, scopeViolations };
}

function toolMetrics(findings, oracle) {
  const counts = { TP: 0, FP: 0, TN: 0, FN: 0 };
  for (const [caseId, vulnerable] of oracle.entries()) {
    const reported = findings.has(caseId);
    counts[vulnerable ? (reported ? 'TP' : 'FN') : (reported ? 'FP' : 'TN')]++;
  }
  const precision = counts.TP + counts.FP ? counts.TP / (counts.TP + counts.FP) : 0;
  const recall = counts.TP + counts.FN ? counts.TP / (counts.TP + counts.FN) : 0;
  return { ...counts, precision, recall };
}

function compareResults({ boqaResult, referenceResult, oracleRows, allowedCaseIds }) {
  const allowedCases = new Set(allowedCaseIds);
  const oracle = new Map(oracleRows.map(row => [row.case_id, row.vulnerable === true]));
  const boqa = indexFindings(boqaResult, allowedCases);
  const reference = indexFindings(referenceResult, allowedCases);
  const overlap = [...boqa.findings].filter(id => reference.findings.has(id));
  const boqaOnly = [...boqa.findings].filter(id => !reference.findings.has(id));
  const referenceOnly = [...reference.findings].filter(id => !boqa.findings.has(id));
  return deepFreeze({
    boqa: { metrics: toolMetrics(boqa.findings, oracle), time_ms: Number(boqaResult?.time_ms) || 0, requests: Number(boqaResult?.requests) || 0, scope_violations: boqa.scopeViolations },
    reference: { metrics: toolMetrics(reference.findings, oracle), time_ms: Number(referenceResult?.time_ms) || 0, requests: Number(referenceResult?.requests) || 0, scope_violations: reference.scopeViolations },
    overlap: overlap.sort(),
    boqa_only: boqaOnly.sort(),
    reference_only: referenceOnly.sort(),
  });
}

module.exports = { compareResults, indexFindings, toolMetrics };

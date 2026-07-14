'use strict';

function safeRatio(numerator, denominator) {
  return denominator ? numerator / denominator : 0;
}

function calculateMetrics(records) {
  const counts = { TP: 0, FP: 0, TN: 0, FN: 0 };
  for (const record of records) {
    const outcome = record?.oracle_result?.outcome;
    if (Object.prototype.hasOwnProperty.call(counts, outcome)) counts[outcome]++;
  }
  const precision = safeRatio(counts.TP, counts.TP + counts.FP);
  const recall = safeRatio(counts.TP, counts.TP + counts.FN);
  const f1 = safeRatio(2 * precision * recall, precision + recall);
  const findings = counts.TP + counts.FP;
  const totalRequests = records.reduce((sum, record) => sum + (record.requests || 0), 0);
  const findingTimes = records.filter(record => record.oracle_result?.outcome === 'TP').map(record => record.agent_result?.finding_time_ms || record.duration_ms || 0);
  const reportTimes = records.filter(record => record.oracle_result?.outcome === 'TP').map(record => record.agent_result?.report_time_ms || record.duration_ms || 0);
  const mean = values => safeRatio(values.reduce((sum, value) => sum + value, 0), values.length);
  return Object.freeze({
    ...counts,
    precision,
    recall,
    F1: f1,
    false_positive_rate: safeRatio(counts.FP, counts.FP + counts.TN),
    false_negative_rate: safeRatio(counts.FN, counts.FN + counts.TP),
    report_reproducibility: records.length ? Math.min(...records.map(record => record.agent_result?.report_reproducible === true ? 1 : 0)) : 0,
    scope_compliance: records.length ? 1 - safeRatio(records.reduce((sum, record) => sum + record.scope_violations, 0), totalRequests || records.length) : 0,
    mean_time_to_finding: mean(findingTimes),
    mean_time_to_report: mean(reportTimes),
    requests_per_finding: safeRatio(totalRequests, findings),
  });
}

module.exports = { calculateMetrics, safeRatio };

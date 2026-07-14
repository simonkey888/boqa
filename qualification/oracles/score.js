'use strict';

const { deepFreeze } = require('../adapters/agent-input');

function qualifyingReports(agentResult) {
  return Array.isArray(agentResult?.reports)
    ? agentResult.reports.filter(report => report && report.qualifies === true)
    : [];
}

function scoreRun(agentResult, privateManifest) {
  const vulnerable = privateManifest.ground_truth.vulnerable === true;
  const positive = qualifyingReports(agentResult).length > 0;
  const outcome = vulnerable ? (positive ? 'TP' : 'FN') : (positive ? 'FP' : 'TN');
  return deepFreeze({
    outcome,
    vulnerable,
    reported: positive,
    report_count: qualifyingReports(agentResult).length,
  });
}

module.exports = { scoreRun, qualifyingReports };

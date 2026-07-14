#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { runBlindQualification } = require('../qualification/runners/blind-qualification');

const root = path.resolve(__dirname, '..');
const resultDir = path.join(root, 'qualification', 'results');
const write = (name, value) => fs.writeFileSync(path.join(resultDir, name), `${JSON.stringify(value, null, 2)}\n`);

(async () => {
  const result = await runBlindQualification();
  fs.mkdirSync(resultDir, { recursive: true });
  write('aggregate-summary.json', {
    schema_version: 1,
    scope: 'first_party_synthetic_holdout_only',
    external_labs_run: false,
    rounds_completed: result.rounds.length,
    holdout_instances_per_round: result.instances / result.rounds.length,
    total_evaluations: result.instances,
    families: result.families,
    metrics: result.metrics,
    report_ready_rate: result.report_ready_rate,
    report_reproducibility: result.report_reproducibility,
    destructive_actions: result.destructive_actions,
    external_network_attempts: result.external_network_attempts,
    ground_truth_leakage: result.ground_truth_leakage,
    p2_gate_passed: result.p2_gate_passed,
  });
  write('confusion-matrix.json', {
    aggregate: { TP: result.metrics.TP, FP: result.metrics.FP, TN: result.metrics.TN, FN: result.metrics.FN },
    rounds: result.rounds.map(row => ({ round: row.round, TP: row.metrics.TP, FP: row.metrics.FP, TN: row.metrics.TN, FN: row.metrics.FN })),
  });
  write('report-quality-summary.json', {
    tp_reports: result.tp_reports,
    reports_ready_for_triage: result.ready_reports,
    ready_rate: result.report_ready_rate,
    reproducibility: result.report_reproducibility,
    average_score_out_of_12: result.average_report_score,
  });
  write('scope-compliance.json', {
    requests: result.total_requests,
    scope_violations: result.scope_violations,
    scope_compliance: result.metrics.scope_compliance,
    destructive_actions: result.destructive_actions,
    external_network_attempts: result.external_network_attempts,
  });
  if (!result.p2_gate_passed) process.exitCode = 1;
})().catch(error => { console.error(error.stack || error.message); process.exit(1); });

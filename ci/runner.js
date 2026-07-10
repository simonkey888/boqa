#!/usr/bin/env node
/**
 * BOQA ci/runner.js — Headless CI pipeline runner
 *
 * Steps:
 *   1. Load CI config
 *   2. For each target:
 *      a. Find or create baseline
 *      b. Run headless session
 *      c. Compare against baseline
 *      d. Compute anomaly score
 *      e. Fail if severity > threshold
 *   3. Output structured artifacts
 *
 * Exit codes:
 *   0 = clean
 *   1 = anomalies detected
 *   2 = auth regression detected
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const { EventBus } = require('../bus');
const { Agent } = require('../agent');
const { BaselineBuilder } = require('../baseline');
const { SessionDiffer } = require('../compare');
const { AnomalyEngine } = require('../anomaly');
const { SessionReplayer } = require('../replay');

const CONFIG_PATH = process.argv.find(a => a.startsWith('--config='))?.split('=')[1]
  || process.argv[process.argv.indexOf('--config') + 1]
  || path.join(__dirname, 'config.json');

const OUTPUT_DIR = path.join(__dirname, '..', 'output');
const SESSIONS_DIR = path.join(OUTPUT_DIR, 'sessions');
const REPORTS_DIR = path.join(OUTPUT_DIR, 'reports');
const BASELINES_DIR = path.join(OUTPUT_DIR, 'baselines');
const DIFFS_DIR = path.join(OUTPUT_DIR, 'diffs');

for (const dir of [SESSIONS_DIR, REPORTS_DIR, BASELINES_DIR, DIFFS_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

// ─── Load Config ───────────────────────────────────────────────────────

function loadConfig() {
  const configPath = path.resolve(CONFIG_PATH);
  if (!fs.existsSync(configPath)) {
    console.error(`[CI] Config not found: ${configPath}`);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

// ─── Run Single Target ─────────────────────────────────────────────────

async function runTarget(targetConfig, globalConfig) {
  const targetName = targetConfig.name || targetConfig.url;
  const targetUrl = targetConfig.url;
  const duration = targetConfig.duration || 60;
  const severityThreshold = targetConfig.severity_threshold || 40;
  const authRegressionThreshold = targetConfig.auth_regression_threshold || 70;

  console.log(`\n${'='.repeat(60)}`);
  console.log(`[CI] Target: ${targetName} (${targetUrl})`);
  console.log(`[CI] Duration: ${duration}s | Thresholds: severity=${severityThreshold}, auth_regression=${authRegressionThreshold}`);
  console.log(`${'='.repeat(60)}\n`);

  // Step 1: Find or create baseline
  const baselineBuilder = new BaselineBuilder();
  let baseline = baselineBuilder.findLatest(targetUrl);

  if (baseline) {
    console.log(`[CI] Found baseline: ${baseline.id} (auth: ${baseline.fingerprint?.auth_model})`);
  } else if (globalConfig.baseline_auto_create) {
    console.log(`[CI] No baseline found — will create after session`);
  } else {
    console.log(`[CI] No baseline found and auto-create disabled — running without comparison`);
  }

  // Step 2: Run headless session
  console.log(`[CI] Launching headless browser...`);
  const ndjsonPath = path.join(OUTPUT_DIR, `ci-events-${Date.now()}.ndjson`);
  const bus = new EventBus(null, { ndjsonPath, target: targetUrl });

  const agent = new Agent(bus, {
    target: targetUrl,
    headless: true,
    devtools: false,
    recordHar: false,
    baseline: baseline,
  });

  // Set a timeout for the session
  const timeoutHandle = setTimeout(() => {
    console.log(`[CI] Duration limit reached (${duration}s)`);
    agent.stop().then(() => finishSession());
  }, duration * 1000);

  async function finishSession() {
    clearTimeout(timeoutHandle);

    // Step 3: Export session
    const session = bus.exportSession();
    const sessionFile = path.join(SESSIONS_DIR, `${session.id}.json`);
    fs.writeFileSync(sessionFile, JSON.stringify(session, null, 2));
    console.log(`[CI] Session: ${session.totalEvents} events → ${session.id}`);

    // Step 4: Generate report
    const report = agent.getReport();
    report.session_id = session.id;
    const reportFile = path.join(REPORTS_DIR, `ci-report-${session.id.substring(0, 8)}.json`);
    fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
    console.log(`[CI] Report: auth_model=${report.auth_model}, risk_flags=${report.risk_flags?.length}, anomalies=${report.anomaly_summary?.total || 0}`);

    // Step 5: Save anomaly report
    const anomalyReport = {
      session_id: session.id,
      target: targetUrl,
      anomalies: report.anomalies || [],
      summary: report.anomaly_summary || {},
    };
    const anomalyFile = path.join(OUTPUT_DIR, `anomaly-${session.id.substring(0, 8)}.json`);
    fs.writeFileSync(anomalyFile, JSON.stringify(anomalyReport, null, 2));

    // Step 6: Build baseline if needed
    if (!baseline && globalConfig.baseline_auto_create) {
      baseline = baselineBuilder.build(session, report);
      baselineBuilder.save(baseline);
      console.log(`[CI] Baseline created: ${baseline.id}`);
    }

    // Step 7: Compare against baseline
    let diff = null;
    if (baseline) {
      const differ = new SessionDiffer();
      diff = differ.compare(session, report, baseline);
      differ.save(diff);
      console.log(`[CI] Diff: severity=${diff.severity_score}/100, verdict=${diff.verdict}`);
      console.log(`[CI]   Added endpoints: ${diff.added_endpoints.length}`);
      console.log(`[CI]   Removed endpoints: ${diff.removed_endpoints.length}`);
      console.log(`[CI]   Auth changes: ${diff.auth_changes.length}`);
      console.log(`[CI]   Cookie diffs: ${diff.cookie_diff.length}`);

      const diffFile = path.join(DIFFS_DIR, `${diff.id}.json`);
      // Already saved by differ.save()
    }

    // Step 8: Determine exit code
    let exitCode = 0;
    const anomalyHighCount = report.anomaly_summary?.bySeverity?.high || 0;

    if (diff && diff.severity_score >= authRegressionThreshold) {
      exitCode = 2; // auth regression
      console.log(`[CI] AUTH REGRESSION DETECTED (severity ${diff.severity_score} >= ${authRegressionThreshold})`);
    } else if (diff && diff.severity_score >= severityThreshold) {
      exitCode = 1; // anomalies
      console.log(`[CI] ANOMALIES DETECTED (severity ${diff.severity_score} >= ${severityThreshold})`);
    } else if (anomalyHighCount > 0) {
      exitCode = 1;
      console.log(`[CI] HIGH SEVERITY ANOMALIES: ${anomalyHighCount}`);
    } else {
      console.log(`[CI] CLEAN — no anomalies above threshold`);
    }

    await bus.flush();
    return { exitCode, session, report, diff, anomalyReport };
  }

  try {
    await agent.start();
    console.log(`[CI] Session running for ${duration}s...`);

    // Wait for timeout or manual stop
    return new Promise((resolve) => {
      const origFinish = finishSession;
      // timeoutHandle already set above
    });
  } catch (e) {
    console.error(`[CI] Agent failed:`, e.message);
    clearTimeout(timeoutHandle);
    await agent.stop();
    return { exitCode: 2, error: e.message };
  }
}

// ─── Main ──────────────────────────────────────────────────────────────

async function main() {
  console.log('╔═══════════════════════════════════════════════════════╗');
  console.log('║   BOQA CI Runner v0.2                                 ║');
  console.log('╚═══════════════════════════════════════════════════════╝');

  const config = loadConfig();
  const targets = config.targets || [];

  if (targets.length === 0) {
    console.error('[CI] No targets defined in config');
    process.exit(1);
  }

  let worstExitCode = 0;

  for (const target of targets) {
    const result = await runTarget(target, config);
    const exitCode = result.exitCode || 0;
    worstExitCode = Math.max(worstExitCode, exitCode);
  }

  console.log(`\n[CI] Final exit code: ${worstExitCode}`);
  process.exit(worstExitCode);
}

main().catch(e => {
  console.error('[CI] Fatal:', e.message);
  process.exit(2);
});


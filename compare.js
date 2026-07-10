/**
 * BOQA compare.js — Session diff engine + severity scoring
 *
 * Compares two sessions (or session vs baseline) and produces:
 *   - Added/removed endpoints
 *   - Auth model changes
 *   - Cookie schema diffs
 *   - Risk flag deltas
 *   - WS channel changes
 *   - Severity score (0-100)
 *
 * Uses jsondiffpatch for structural diffs where applicable.
 */

const fs = require('fs');
const path = require('path');
const jsondiffpatch = require('jsondiffpatch');

const DIFFS_DIR = path.join(__dirname, 'output', 'diffs');

class SessionDiffer {
  constructor() {
    fs.mkdirSync(DIFFS_DIR, { recursive: true });
    this.differ = jsondiffpatch.create({
      arrays: { detectMove: true },
      objectHash: (obj) => obj.name || obj.key || JSON.stringify(obj),
    });
  }

  /**
   * Compare a session against a baseline
   * @param {object} session - completed session export
   * @param {object} report - auth report from current session
   * @param {object} baseline - baseline to compare against
   * @returns {object} diff result
   */
  compare(session, report, baseline) {
    const currentFingerprint = this._extractCurrentFingerprint(session, report);
    const currentMetrics = this._extractCurrentMetrics(session);

    const baselineFp = baseline.fingerprint || {};
    const baselineMetrics = baseline.metrics || {};

    // Endpoint diff
    const currentEndpoints = new Set(currentFingerprint.endpoints || []);
    const baselineEndpoints = new Set(baselineFp.endpoints || []);
    const addedEndpoints = [...currentEndpoints].filter(e => !baselineEndpoints.has(e));
    const removedEndpoints = [...baselineEndpoints].filter(e => !currentEndpoints.has(e));

    // Auth model change
    const authChanges = [];
    if (currentFingerprint.auth_model !== baselineFp.auth_model) {
      authChanges.push({
        type: 'auth_model_change',
        from: baselineFp.auth_model,
        to: currentFingerprint.auth_model,
        severity: 'high',
      });
    }

    // Cookie schema diff
    const cookieDiff = this._diffCookieSchema(
      currentFingerprint.cookie_schema || [],
      baselineFp.cookie_schema || []
    );

    // Risk flag delta
    const currentRisks = new Set(currentFingerprint.risk_flags || []);
    const baselineRisks = new Set(baselineFp.risk_flags || []);
    const addedRisks = [...currentRisks].filter(r => !baselineRisks.has(r));
    const removedRisks = [...baselineRisks].filter(r => !currentRisks.has(r));

    // WS channel changes
    const currentWs = new Set(currentFingerprint.ws_channels || []);
    const baselineWs = new Set(baselineFp.ws_channels || []);
    const addedWs = [...currentWs].filter(c => !baselineWs.has(c));
    const removedWs = [...baselineWs].filter(c => !currentWs.has(c));

    // Metrics delta
    const metricsDelta = this._diffMetrics(currentMetrics, baselineMetrics);

    // Compute severity score (0-100)
    const severityScore = this._computeSeverity({
      addedEndpoints, removedEndpoints, authChanges, cookieDiff,
      addedRisks, removedRisks, addedWs, removedWs, metricsDelta,
    });

    const diff = {
      id: `diff-${Date.now()}`,
      baseline_id: baseline.id,
      session_start: session.sessionStart,
      compared_at: Date.now(),
      added_endpoints: addedEndpoints,
      removed_endpoints: removedEndpoints,
      auth_changes: authChanges,
      cookie_diff: cookieDiff,
      risk_delta: { added: addedRisks, removed: removedRisks },
      ws_changes: { added: addedWs, removed: removedWs },
      metrics_delta: metricsDelta,
      severity_score: severityScore,
      verdict: severityScore >= 70 ? 'critical' : severityScore >= 40 ? 'warning' : 'clean',
    };

    return diff;
  }

  /**
   * Diff cookie schemas (detect downgrades)
   */
  _diffCookieSchema(current, baseline) {
    const changes = [];
    const baselineMap = new Map(baseline.map(c => [c.name, c]));
    const currentMap = new Map(current.map(c => [c.name, c]));

    // Check for new cookies
    for (const c of current) {
      if (!baselineMap.has(c.name)) {
        changes.push({ type: 'cookie_added', name: c.name, severity: 'info' });
      }
    }

    // Check for removed cookies and attribute changes
    for (const b of baseline) {
      const c = currentMap.get(b.name);
      if (!c) {
        changes.push({ type: 'cookie_removed', name: b.name, severity: 'medium' });
        continue;
      }

      // httpOnly downgrade
      if (b.httpOnly && !c.httpOnly) {
        changes.push({ type: 'cookie_httpOnly_downgrade', name: b.name, severity: 'high', from: true, to: false });
      }
      // secure downgrade
      if (b.secure && !c.secure) {
        changes.push({ type: 'cookie_secure_downgrade', name: b.name, severity: 'high', from: true, to: false });
      }
      // sameSite downgrade
      if (b.sameSite === 'Strict' && c.sameSite !== 'Strict') {
        changes.push({ type: 'cookie_sameSite_downgrade', name: b.name, severity: 'medium', from: b.sameSite, to: c.sameSite });
      }
      // domain change
      if (b.domain !== c.domain) {
        changes.push({ type: 'cookie_domain_change', name: b.name, severity: 'low', from: b.domain, to: c.domain });
      }
    }

    return changes;
  }

  /**
   * Diff metrics
   */
  _diffMetrics(current, baseline) {
    const delta = {};
    for (const key of ['request_count', 'error_count', 'ws_message_count', 'auth_events', 'error_rate']) {
      if (current[key] !== undefined || baseline[key] !== undefined) {
        delta[key] = {
          current: current[key] || 0,
          baseline: baseline[key] || 0,
          change: (current[key] || 0) - (baseline[key] || 0),
          pct_change: baseline[key] ? Math.round(((current[key] || 0) - baseline[key]) / baseline[key] * 100) : null,
        };
      }
    }
    return delta;
  }

  /**
   * Compute severity score from diff components
   */
  _computeSeverity(diff) {
    let score = 0;

    // Auth model changes are critical
    for (const ac of diff.authChanges) {
      score += ac.severity === 'high' ? 25 : 10;
    }

    // Cookie downgrades
    for (const cd of diff.cookieDiff) {
      score += cd.severity === 'high' ? 15 : cd.severity === 'medium' ? 8 : 2;
    }

    // New risk flags
    score += diff.addedRisks.length * 10;

    // Unexpected endpoints
    score += Math.min(diff.addedEndpoints.length * 3, 20);

    // Removed endpoints (API regression)
    score += Math.min(diff.removedEndpoints.length * 5, 20);

    // Unexpected WS channels
    score += diff.addedWs.length * 8;

    // Error rate spike
    if (diff.metricsDelta?.error_rate?.pct_change > 50) {
      score += 15;
    }

    return Math.min(score, 100);
  }

  /**
   * Extract fingerprint from current session + report
   */
  _extractCurrentFingerprint(session, report) {
    const events = session.events || [];
    const endpoints = new Set();
    const wsChannels = new Set();
    const cookieSchema = [];

    for (const event of events) {
      if ((event.type === 'network_request' || event.type === 'network_response') && event.url) {
        try { endpoints.add(`${event.method || 'GET'} ${new URL(event.url).pathname}`); } catch (_) {}
      }
      if (event.type === 'websocket_open' && event.url) {
        try { wsChannels.add(new URL(event.url).origin + new URL(event.url).pathname); } catch (_) {}
      }
    }

    if (report && report.cookies) {
      for (const c of report.cookies) {
        cookieSchema.push({ name: c.name, domain: c.domain || null, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite || null });
      }
    }

    return {
      endpoints: [...endpoints].sort(),
      auth_model: report ? report.auth_model : 'unknown',
      ws_channels: [...wsChannels].sort(),
      cookie_schema: cookieSchema,
      risk_flags: report ? report.risk_flags.map(f => f.flag) : [],
    };
  }

  _extractCurrentMetrics(session) {
    const events = session.events || [];
    let requestCount = 0, errorCount = 0, wsMessageCount = 0, authEvents = 0;
    for (const e of events) {
      if (e.type === 'network_request') requestCount++;
      if (e.type === 'console_error' || e.type === 'network_failure') errorCount++;
      if (e.type === 'websocket_message_in' || e.type === 'websocket_message_out') wsMessageCount++;
      if (e.type === 'auth_signal') authEvents++;
    }
    return {
      request_count: requestCount,
      error_count: errorCount,
      ws_message_count: wsMessageCount,
      auth_events: authEvents,
      error_rate: requestCount > 0 ? errorCount / requestCount : 0,
    };
  }

  /**
   * Save diff to disk
   */
  save(diff, filename) {
    const filePath = path.join(DIFFS_DIR, filename || `${diff.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(diff, null, 2));
    return filePath;
  }

  /**
   * Load diff from disk
   */
  load(diffId) {
    const filePath = path.join(DIFFS_DIR, `${diffId}.json`);
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }
}

module.exports = { SessionDiffer, DIFFS_DIR };


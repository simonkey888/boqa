/**
 * BOQA state-diff.js — State Diff Engine
 *
 * Compares application state before and after verification actions.
 * Tracks cookies, localStorage, auth signals, page state, and
 * response patterns to detect unexpected state changes during
 * the verification process.
 *
 * This engine enables the VerificationEngine to:
 *   1. Capture a "before" snapshot before executing a verification step
 *   2. Execute the step
 *   3. Capture an "after" snapshot
 *   4. Compute the diff and flag unexpected changes
 *
 * Safe mode: no destructive mutations, only passive observation.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'output', 'state-diffs');
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ─── State Snapshot Schema ────────────────────────────────────────

// {
//   id: string,
//   ts: number,
//   cookies: [{ name, value_hash, domain, path, httpOnly, secure, sameSite }],
//   localStorage_keys: [string],
//   auth_signals: [{ signalType, ts, url }],
//   page_url: string | null,
//   page_title: string | null,
//   active_ws_connections: number,
//   request_count: number,
//   error_count: number,
//   session_cookies_hash: string,
// }

// ─── State Diff Schema ────────────────────────────────────────────

// {
//   id: string,
//   before_snapshot_id: string,
//   after_snapshot_id: string,
//   diff_type: 'expected' | 'unexpected' | 'critical',
//   cookie_diffs: [],
//   localStorage_diffs: [],
//   auth_state_diff: {},
//   page_state_diff: {},
//   ws_state_diff: {},
//   metrics_diff: {},
//   severity: 'info' | 'low' | 'medium' | 'high' | 'critical',
//   summary: string,
// }

class StateDiffEngine {
  constructor(options = {}) {
    this.snapshots = new Map();   // snapshotId → snapshot
    this.diffs = new Map();       // diffId → diff
    this.snapshotCounter = 0;
    this.diffCounter = 0;
    this.options = {
      maxCookieHashLength: 16,
      safeMode: true,
      ...options,
    };
  }

  // ─── Snapshot Capture ─────────────────────────────────────────

  /**
   * Capture an application state snapshot from the event stream
   * @param {object} observations - { events, report }
   * @param {string} label - descriptive label (e.g., "before_verification_step_3")
   * @returns {object} state snapshot
   */
  captureSnapshot(observations = {}, label = 'unnamed') {
    const { events = [], report = {} } = observations;
    this.snapshotCounter++;
    const snapshotId = `snap-${Date.now().toString(36)}-${this.snapshotCounter}`;

    // Extract cookie state
    const cookies = this._extractCookieState(events, report);

    // Extract localStorage state
    const localStorageKeys = this._extractLocalStorageState(events);

    // Extract auth signals
    const authSignals = this._extractAuthSignals(events);

    // Extract page state
    const pageState = this._extractPageState(events);

    // Extract WS state
    const wsState = this._extractWsState(events);

    // Extract metrics
    const metrics = this._extractMetrics(events);

    // Compute session hash for quick comparison
    const sessionCookiesHash = this._computeSessionHash(cookies);

    const snapshot = {
      id: snapshotId,
      label,
      ts: Date.now(),
      cookies,
      localStorage_keys: localStorageKeys,
      auth_signals: authSignals,
      page_url: pageState.url,
      page_title: pageState.title,
      active_ws_connections: wsState.active,
      request_count: metrics.request_count,
      error_count: metrics.error_count,
      session_cookies_hash: sessionCookiesHash,
      event_count_at: events.length,
    };

    this.snapshots.set(snapshotId, snapshot);
    return snapshot;
  }

  /**
   * Capture a minimal snapshot from the tail of the event stream
   * (only considers events after a given timestamp)
   */
  captureDeltaSnapshot(observations = {}, sinceTs = 0, label = 'delta') {
    const { events = [], report = {} } = observations;
    const recentEvents = events.filter(e => e.ts > sinceTs);
    return this.captureSnapshot({ events: recentEvents, report }, label);
  }

  // ─── Diff Computation ─────────────────────────────────────────

  /**
   * Compare two snapshots and compute the state diff
   * @param {object} before - before snapshot
   * @param {object} after - after snapshot
   * @returns {object} state diff
   */
  compare(before, after) {
    this.diffCounter++;
    const diffId = `diff-${Date.now().toString(36)}-${this.diffCounter}`;

    // Cookie diffs
    const cookieDiffs = this._diffCookies(before.cookies, after.cookies);

    // localStorage diffs
    const localStorageDiffs = this._diffLocalStorage(before.localStorage_keys, after.localStorage_keys);

    // Auth state diff
    const authStateDiff = this._diffAuthState(before.auth_signals, after.auth_signals);

    // Page state diff
    const pageStateDiff = this._diffPageState(before, after);

    // WS state diff
    const wsStateDiff = this._diffWsState(before, after);

    // Metrics diff
    const metricsDiff = this._diffMetrics(before, after);

    // Determine diff type and severity
    const { diffType, severity } = this._classifyDiff(cookieDiffs, authStateDiff, pageStateDiff);

    // Build summary
    const summary = this._buildSummary(cookieDiffs, authStateDiff, pageStateDiff, diffType);

    const diff = {
      id: diffId,
      before_snapshot_id: before.id,
      after_snapshot_id: after.id,
      diff_type: diffType,
      cookie_diffs: cookieDiffs,
      localStorage_diffs: localStorageDiffs,
      auth_state_diff: authStateDiff,
      page_state_diff: pageStateDiff,
      ws_state_diff: wsStateDiff,
      metrics_diff: metricsDiff,
      severity,
      summary,
      computed_at: Date.now(),
    };

    this.diffs.set(diffId, diff);
    return diff;
  }

  /**
   * Convenience: capture before → execute action → capture after → compare
   * Used by VerificationEngine to wrap each step execution
   */
  async captureAndCompare(observations, actionFn, label = 'verification-step') {
    const before = this.captureSnapshot(observations, `${label}-before`);

    // Execute the action (if provided)
    if (actionFn) {
      await actionFn();
    }

    const after = this.captureSnapshot(observations, `${label}-after`);
    return this.compare(before, after);
  }

  // ─── Cookie State Extraction ──────────────────────────────────

  _extractCookieState(events, report) {
    const cookies = [];

    // Start from report cookies (most authoritative)
    if (report.cookies) {
      for (const c of report.cookies) {
        cookies.push({
          name: c.name,
          value_hash: this._hashValue(c.valuePreview || c.value || ''),
          domain: c.domain || null,
          path: c.path || '/',
          httpOnly: c.httpOnly || false,
          secure: c.secure || false,
          sameSite: c.sameSite || null,
          source: 'report',
        });
      }
    }

    // Supplement with cookie snapshot events
    const cookieEvents = events.filter(e => e.type === 'cookie_snapshot' && e.meta?.authCookies);
    for (const ce of cookieEvents) {
      for (const c of ce.meta.authCookies) {
        const existing = cookies.find(ec => ec.name === c.name);
        if (!existing) {
          cookies.push({
            name: c.name,
            value_hash: this._hashValue(c.valuePreview || c.value || ''),
            domain: c.domain || null,
            path: c.path || '/',
            httpOnly: c.httpOnly || false,
            secure: c.secure || false,
            sameSite: c.sameSite || null,
            source: 'snapshot',
          });
        } else {
          // Update hash if different
          const newHash = this._hashValue(c.valuePreview || c.value || '');
          if (existing.value_hash !== newHash) {
            existing.value_hash = newHash;
            existing.source = 'updated';
          }
        }
      }
    }

    return cookies;
  }

  _extractLocalStorageState(events) {
    const keys = new Set();
    for (const e of events) {
      if (e.type === 'console_log' && e.payload && typeof e.payload === 'string') {
        // Look for localStorage key patterns in instrumentation output
        const match = e.payload.match(/__BOQA__storage_key[:=]\s*(\S+)/);
        if (match) keys.add(match[1]);
      }
    }
    return [...keys].sort();
  }

  _extractAuthSignals(events) {
    const signals = [];
    for (const e of events) {
      if (e.type === 'auth_signal') {
        signals.push({
          signalType: e.meta?.signalType || 'unknown',
          ts: e.ts,
          url: e.url || null,
        });
      }
    }
    return signals.slice(-20); // Last 20 auth signals
  }

  _extractPageState(events) {
    let url = null;
    let title = null;

    // Get latest navigation
    const navEvents = events.filter(e => e.type === 'page_navigation');
    if (navEvents.length > 0) {
      const lastNav = navEvents[navEvents.length - 1];
      url = lastNav.url || null;
      title = lastNav.meta?.title || null;
    }

    return { url, title };
  }

  _extractWsState(events) {
    const openEvents = events.filter(e => e.type === 'websocket_open');
    const closeEvents = events.filter(e => e.type === 'websocket_close');

    return {
      active: Math.max(0, openEvents.length - closeEvents.length),
      total_opened: openEvents.length,
      total_closed: closeEvents.length,
    };
  }

  _extractMetrics(events) {
    let requestCount = 0;
    let errorCount = 0;

    for (const e of events) {
      if (e.type === 'network_request') requestCount++;
      if (e.type === 'console_error' || e.type === 'network_failure') errorCount++;
    }

    return { request_count: requestCount, error_count: errorCount };
  }

  // ─── Diff Computation Methods ─────────────────────────────────

  _diffCookies(beforeCookies, afterCookies) {
    const diffs = [];
    const beforeMap = new Map(beforeCookies.map(c => [c.name, c]));
    const afterMap = new Map(afterCookies.map(c => [c.name, c]));

    // Check for new cookies
    for (const [name, after] of afterMap) {
      const before = beforeMap.get(name);
      if (!before) {
        diffs.push({
          type: 'cookie_added',
          name,
          severity: this._cookieChangeSeverity(name, 'added'),
          details: { httpOnly: after.httpOnly, secure: after.secure, sameSite: after.sameSite, domain: after.domain },
        });
        continue;
      }

      // Check for attribute changes
      if (before.httpOnly !== after.httpOnly) {
        diffs.push({
          type: before.httpOnly ? 'httpOnly_removed' : 'httpOnly_added',
          name,
          severity: before.httpOnly ? 'high' : 'info',
          details: { from: before.httpOnly, to: after.httpOnly },
        });
      }

      if (before.secure !== after.secure) {
        diffs.push({
          type: before.secure ? 'secure_removed' : 'secure_added',
          name,
          severity: before.secure ? 'high' : 'info',
          details: { from: before.secure, to: after.secure },
        });
      }

      if (before.sameSite !== after.sameSite) {
        const downgraded = this._isSameSiteDowngrade(before.sameSite, after.sameSite);
        diffs.push({
          type: downgraded ? 'sameSite_downgrade' : 'sameSite_upgrade',
          name,
          severity: downgraded ? 'medium' : 'info',
          details: { from: before.sameSite, to: after.sameSite },
        });
      }

      if (before.domain !== after.domain) {
        diffs.push({
          type: 'domain_changed',
          name,
          severity: 'medium',
          details: { from: before.domain, to: after.domain },
        });
      }

      // Value hash change (rotation)
      if (before.value_hash !== after.value_hash) {
        diffs.push({
          type: 'value_rotated',
          name,
          severity: this._cookieChangeSeverity(name, 'rotated'),
          details: { hint: 'Cookie value changed (hash differs)' },
        });
      }
    }

    // Check for removed cookies
    for (const [name, before] of beforeMap) {
      if (!afterMap.has(name)) {
        diffs.push({
          type: 'cookie_removed',
          name,
          severity: this._cookieChangeSeverity(name, 'removed'),
          details: { was_httpOnly: before.httpOnly, was_secure: before.secure },
        });
      }
    }

    return diffs;
  }

  _diffLocalStorage(beforeKeys, afterKeys) {
    const diffs = [];
    const beforeSet = new Set(beforeKeys);
    const afterSet = new Set(afterKeys);

    for (const key of afterSet) {
      if (!beforeSet.has(key)) {
        diffs.push({ type: 'key_added', key });
      }
    }

    for (const key of beforeSet) {
      if (!afterSet.has(key)) {
        diffs.push({ type: 'key_removed', key });
      }
    }

    return diffs;
  }

  _diffAuthState(beforeSignals, afterSignals) {
    const beforeTypes = new Set(beforeSignals.map(s => s.signalType));
    const afterTypes = new Set(afterSignals.map(s => s.signalType));

    const newSignals = [...afterTypes].filter(s => !beforeTypes.has(s));
    const lostSignals = [...beforeTypes].filter(s => !afterTypes.has(s));

    return {
      new_signal_types: newSignals,
      lost_signal_types: lostSignals,
      before_count: beforeSignals.length,
      after_count: afterSignals.length,
      change: afterSignals.length - beforeSignals.length,
    };
  }

  _diffPageState(before, after) {
    const diff = { url_changed: false, title_changed: false };

    if (before.page_url !== after.page_url) {
      diff.url_changed = true;
      diff.url_from = before.page_url;
      diff.url_to = after.page_url;
    }

    if (before.page_title !== after.page_title) {
      diff.title_changed = true;
      diff.title_from = before.page_title;
      diff.title_to = after.page_title;
    }

    return diff;
  }

  _diffWsState(before, after) {
    return {
      active_change: after.active_ws_connections - before.active_ws_connections,
      opened_change: (after.request_count || 0) - (before.request_count || 0),
    };
  }

  _diffMetrics(before, after) {
    return {
      request_count_change: after.request_count - before.request_count,
      error_count_change: after.error_count - before.error_count,
    };
  }

  // ─── Classification ───────────────────────────────────────────

  _classifyDiff(cookieDiffs, authStateDiff, pageStateDiff) {
    let diffType = 'expected';
    let severity = 'info';

    // Check for critical cookie changes
    const criticalCookieDiffs = cookieDiffs.filter(cd =>
      cd.severity === 'high' || cd.type === 'httpOnly_removed' || cd.type === 'secure_removed'
    );
    if (criticalCookieDiffs.length > 0) {
      diffType = 'critical';
      severity = 'high';
    }

    // Check for unexpected auth state changes
    if (authStateDiff.new_signal_types.includes('unauthorized') || authStateDiff.new_signal_types.includes('forbidden')) {
      diffType = 'unexpected';
      severity = severity === 'info' ? 'medium' : severity;
    }

    // Check for unexpected cookie additions
    const authCookieAdded = cookieDiffs.find(cd =>
      cd.type === 'cookie_added' && ['sessionid', 'ripio_access', 'access_token'].includes(cd.name)
    );
    if (authCookieAdded) {
      if (diffType === 'expected') diffType = 'unexpected';
      severity = severity === 'info' ? 'medium' : severity;
    }

    return { diffType, severity };
  }

  _buildSummary(cookieDiffs, authStateDiff, pageStateDiff, diffType) {
    const parts = [];

    if (cookieDiffs.length > 0) {
      const critical = cookieDiffs.filter(cd => cd.severity === 'high').length;
      const medium = cookieDiffs.filter(cd => cd.severity === 'medium').length;
      parts.push(`${cookieDiffs.length} cookie change(s) (${critical} critical, ${medium} medium)`);
    }

    if (authStateDiff.new_signal_types.length > 0) {
      parts.push(`new auth signals: ${authStateDiff.new_signal_types.join(', ')}`);
    }

    if (pageStateDiff.url_changed) {
      parts.push('page URL changed');
    }

    if (parts.length === 0) {
      return `No significant state changes detected (diff_type: ${diffType})`;
    }

    return `[${diffType.toUpperCase()}] ${parts.join('; ')}`;
  }

  // ─── Utility Methods ─────────────────────────────────────────

  _hashValue(value) {
    if (!value) return 'null';
    return crypto.createHash('sha256').update(String(value)).digest('hex').substring(0, this.options.maxCookieHashLength);
  }

  _computeSessionHash(cookies) {
    const sessionCookies = cookies.filter(c =>
      ['ripio_access', 'sessionid', 'access_token', 'auth_token', '_jwt', 'csrftoken'].includes(c.name)
    ).sort((a, b) => a.name.localeCompare(b.name));

    const hashInput = sessionCookies.map(c => `${c.name}:${c.value_hash}`).join('|');
    return crypto.createHash('sha256').update(hashInput).digest('hex').substring(0, 12);
  }

  _cookieChangeSeverity(name, changeType) {
    const authCookies = new Set(['ripio_access', 'sessionid', 'access_token', 'auth_token', '_jwt']);
    const isAuth = authCookies.has(name);

    if (changeType === 'removed' && isAuth) return 'high';
    if (changeType === 'added' && isAuth) return 'medium';
    if (changeType === 'rotated' && isAuth) return 'low';
    if (name === 'csrftoken') return 'low';
    return 'info';
  }

  _isSameSiteDowngrade(before, after) {
    const levels = { Strict: 3, Lax: 2, None: 1, none: 1, '': 0, null: 0, undefined: 0 };
    return (levels[before] || 0) > (levels[after] || 0);
  }

  // ─── Persistence ──────────────────────────────────────────────

  saveDiff(diffId) {
    const diff = this.diffs.get(diffId);
    if (!diff) return null;

    const filePath = path.join(OUTPUT_DIR, `${diff.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(diff, null, 2));
    return filePath;
  }

  // ─── Accessors ────────────────────────────────────────────────

  getSnapshot(id) {
    return this.snapshots.get(id);
  }

  getDiff(id) {
    return this.diffs.get(id);
  }

  getAllDiffs() {
    return [...this.diffs.values()];
  }

  getAllSnapshots() {
    return [...this.snapshots.values()];
  }

  getSummary() {
    const diffs = [...this.diffs.values()];
    return {
      total_snapshots: this.snapshots.size,
      total_diffs: diffs.length,
      by_type: {
        expected: diffs.filter(d => d.diff_type === 'expected').length,
        unexpected: diffs.filter(d => d.diff_type === 'unexpected').length,
        critical: diffs.filter(d => d.diff_type === 'critical').length,
      },
      by_severity: {
        critical: diffs.filter(d => d.severity === 'critical').length,
        high: diffs.filter(d => d.severity === 'high').length,
        medium: diffs.filter(d => d.severity === 'medium').length,
        low: diffs.filter(d => d.severity === 'low').length,
        info: diffs.filter(d => d.severity === 'info').length,
      },
    };
  }
}

module.exports = { StateDiffEngine, OUTPUT_DIR };


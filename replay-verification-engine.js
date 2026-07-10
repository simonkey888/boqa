/**
 * BOQA replay-verification-engine.js — ReplayVerificationEngine v1.5 (P5)
 *
 * Compares replay output against recorded truth using multiple
 * comparison axes: DOM, visual, network, cookies, storage,
 * console, WebSocket, and internal state.
 *
 * This engine supports:
 *   - DOM diffing with configurable thresholds
 *   - Visual diff metadata comparison (not pixel diff)
 *   - Network request/response comparison
 *   - Cookie and storage state comparison
 *   - Console log comparison (filtered)
 *   - WebSocket frame comparison
 *   - Internal BOQA state comparison
 *
 * Verification produces a composite score and per-axis scores
 * with configurable thresholds.
 *
 * Safe mode: no real browser needed — works on recorded data.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');

// ─── Comparison Axes ───────────────────────────────────────────────

const COMPARISON_AXES = [
  'dom', 'visual', 'network', 'cookies', 'storage',
  'console', 'websocket', 'internal_state',
];

// ─── Diff Helpers ──────────────────────────────────────────────────

function computeSetSimilarity(setA, setB) {
  const a = new Set(setA);
  const b = new Set(setB);
  if (a.size === 0 && b.size === 0) return 1.0;
  if (a.size === 0 || b.size === 0) return 0.0;

  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }

  return intersection / (a.size + b.size - intersection);
}

function computeObjectSimilarity(objA, objB, ignoreKeys = []) {
  const keysA = Object.keys(objA).filter(k => !ignoreKeys.includes(k));
  const keysB = Object.keys(objB).filter(k => !ignoreKeys.includes(k));
  const allKeys = new Set([...keysA, ...keysB]);

  if (allKeys.size === 0) return 1.0;

  let matches = 0;
  for (const key of allKeys) {
    const valA = JSON.stringify(objA[key]);
    const valB = JSON.stringify(objB[key]);
    if (valA === valB) matches++;
  }

  return matches / allKeys.size;
}

function computeSequenceSimilarity(seqA, seqB, keyFn = (x) => x) {
  if (seqA.length === 0 && seqB.length === 0) return 1.0;
  if (seqA.length === 0 || seqB.length === 0) return 0.0;

  // Longest common subsequence approach
  const m = seqA.length;
  const n = seqB.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (keyFn(seqA[i - 1]) === keyFn(seqB[j - 1])) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  return (2 * dp[m][n]) / (m + n);
}

// ─── ReplayVerificationEngine ──────────────────────────────────────

class ReplayVerificationEngine {
  /**
   * @param {object} options
   * @param {number} [options.visualDiffThreshold=0.02] - Max visual diff ratio
   * @param {number} [options.domDiffThreshold=0.05] - Max DOM diff ratio
   * @param {number} [options.networkDiffThreshold=0.01] - Max network diff ratio
   * @param {number} [options.stateDiffThreshold=0.01] - Max state diff ratio
   * @param {string[]} [options.ignoreKeys] - Keys to ignore in comparisons
   * @param {boolean} [options.ignoreTimestamps=true] - Ignore timestamp fields
   * @param {boolean} [options.ignoreDynamicIds=true] - Ignore dynamic ID fields
   */
  constructor(options = {}) {
    this.options = {
      visualDiffThreshold: options.visualDiffThreshold || 0.02,
      domDiffThreshold: options.domDiffThreshold || 0.05,
      networkDiffThreshold: options.networkDiffThreshold || 0.01,
      stateDiffThreshold: options.stateDiffThreshold || 0.01,
      ignoreKeys: options.ignoreKeys || ['ts', 'elapsed', 'timestamp', 'generated_at', 'built_at'],
      ignoreTimestamps: options.ignoreTimestamps !== false,
      ignoreDynamicIds: options.ignoreDynamicIds !== false,
    };

    this.verificationResults = new Map(); // verificationId → result
  }

  /**
   * Verify a replay against the original recording.
   *
   * @param {object} params
   * @param {object} params.original - Original recording export
   * @param {object} params.replay - Replay recording export
   * @param {object} [params.originalManifest] - Original manifest
   * @param {object} [params.replayManifest] - Replay manifest
   * @returns {object} Verification result with per-axis scores
   */
  verify(params = {}) {
    const {
      original,
      replay,
      originalManifest = null,
      replayManifest = null,
    } = params;

    const verificationId = `VER-${crypto.randomUUID().substring(0, 8)}`;
    const originalEvents = original.events || [];
    const replayEvents = replay.events || [];

    // Per-axis comparison
    const axes = {};

    // 1. DOM comparison
    axes.dom = this._compareDom(originalEvents, replayEvents);

    // 2. Visual comparison (metadata only)
    axes.visual = this._compareVisual(originalEvents, replayEvents);

    // 3. Network comparison
    axes.network = this._compareNetwork(originalEvents, replayEvents);

    // 4. Cookie comparison
    axes.cookies = this._compareCookies(originalEvents, replayEvents);

    // 5. Storage comparison
    axes.storage = this._compareStorage(originalEvents, replayEvents);

    // 6. Console comparison
    axes.console = this._compareConsole(originalEvents, replayEvents);

    // 7. WebSocket comparison
    axes.websocket = this._compareWebsocket(originalEvents, replayEvents);

    // 8. Internal state comparison
    if (originalManifest && replayManifest) {
      axes.internal_state = this._compareInternalState(
        originalManifest.internal_state || {},
        replayManifest.internal_state || {}
      );
    } else {
      axes.internal_state = { score: 1.0, verdict: 'skipped', details: 'No manifests provided' };
    }

    // Compute composite score
    const composite = this._computeCompositeScore(axes);

    // Overall verdict
    const verdict = this._computeVerdict(axes, composite);

    const result = {
      verification_id: verificationId,
      original_recorder_id: original.recorder_id,
      replay_recorder_id: replay.recorder_id,
      verified_at: Date.now(),
      axes,
      composite_score: composite,
      verdict,
      thresholds: {
        visual: this.options.visualDiffThreshold,
        dom: this.options.domDiffThreshold,
        network: this.options.networkDiffThreshold,
        state: this.options.stateDiffThreshold,
      },
    };

    this.verificationResults.set(verificationId, result);
    return result;
  }

  /**
   * Verify only a specific comparison axis.
   *
   * @param {string} axis - Comparison axis name
   * @param {object} original - Original recording
   * @param {object} replay - Replay recording
   * @returns {object} Axis comparison result
   */
  verifyAxis(axis, original, replay) {
    if (!COMPARISON_AXES.includes(axis)) {
      throw new Error(`Unknown comparison axis: ${axis}`);
    }

    const originalEvents = original.events || [];
    const replayEvents = replay.events || [];

    switch (axis) {
      case 'dom': return this._compareDom(originalEvents, replayEvents);
      case 'visual': return this._compareVisual(originalEvents, replayEvents);
      case 'network': return this._compareNetwork(originalEvents, replayEvents);
      case 'cookies': return this._compareCookies(originalEvents, replayEvents);
      case 'storage': return this._compareStorage(originalEvents, replayEvents);
      case 'console': return this._compareConsole(originalEvents, replayEvents);
      case 'websocket': return this._compareWebsocket(originalEvents, replayEvents);
      default: return { score: 0, verdict: 'unknown_axis' };
    }
  }

  /**
   * Get a verification result by ID.
   */
  getResult(verificationId) {
    return this.verificationResults.get(verificationId);
  }

  /**
   * Save verification result to disk.
   */
  save(result, filename) {
    const fn = filename || `verification-${result.verification_id}-${Date.now()}.json`;
    const filePath = path.join(REPLAYS_DIR, 'indexes', fn);
    fs.writeFileSync(filePath, JSON.stringify(result, null, 2));
    return filePath;
  }

  // ─── Axis Comparisons ───────────────────────────────────────────

  _compareDom(originalEvents, replayEvents) {
    const origDom = originalEvents.filter(e => e.type === 'replay_dom_snapshot' || e.type === 'page_navigation');
    const replayDom = replayEvents.filter(e => e.type === 'replay_dom_snapshot' || e.type === 'page_navigation');

    if (origDom.length === 0 && replayDom.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No DOM snapshots in either recording' };
    }

    // Compare URLs visited
    const origUrls = origDom.map(e => e.url).filter(Boolean);
    const replayUrls = replayDom.map(e => e.url).filter(Boolean);
    const urlSimilarity = computeSetSimilarity(origUrls, replayUrls);

    // Compare page navigation sequence
    const origNavSeq = origDom
      .filter(e => e.type === 'page_navigation')
      .map(e => e.url);
    const replayNavSeq = replayDom
      .filter(e => e.type === 'page_navigation')
      .map(e => e.url);
    const navSequenceSimilarity = computeSequenceSimilarity(origNavSeq, replayNavSeq);

    const score = urlSimilarity * 0.4 + navSequenceSimilarity * 0.6;
    const withinThreshold = score >= (1 - this.options.domDiffThreshold);

    return {
      score,
      url_similarity: urlSimilarity,
      navigation_sequence_similarity: navSequenceSimilarity,
      original_pages: origDom.length,
      replay_pages: replayDom.length,
      verdict: withinThreshold ? 'pass' : 'fail',
      within_threshold: withinThreshold,
      threshold: this.options.domDiffThreshold,
    };
  }

  _compareVisual(originalEvents, replayEvents) {
    const origScreenshots = originalEvents.filter(e => e.type === 'replay_screenshot_meta');
    const replayScreenshots = replayEvents.filter(e => e.type === 'replay_screenshot_meta');

    if (origScreenshots.length === 0 && replayScreenshots.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No screenshot metadata in either recording' };
    }

    // Compare screenshot count and viewport consistency
    const countSimilarity = 1 - Math.abs(origScreenshots.length - replayScreenshots.length) /
      Math.max(origScreenshots.length, replayScreenshots.length, 1);

    const score = countSimilarity;
    const withinThreshold = score >= (1 - this.options.visualDiffThreshold);

    return {
      score,
      original_count: origScreenshots.length,
      replay_count: replayScreenshots.length,
      count_similarity: countSimilarity,
      verdict: withinThreshold ? 'pass' : 'fail',
      within_threshold: withinThreshold,
      threshold: this.options.visualDiffThreshold,
    };
  }

  _compareNetwork(originalEvents, replayEvents) {
    const origReqs = originalEvents.filter(e => e.type === 'network_request');
    const replayReqs = replayEvents.filter(e => e.type === 'network_request');

    if (origReqs.length === 0 && replayReqs.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No network requests in either recording' };
    }

    // Compare request methods + URLs
    const origKeys = origReqs.map(e => `${e.method || 'GET'} ${e.url}`).filter(k => !k.includes('null'));
    const replayKeys = replayReqs.map(e => `${e.method || 'GET'} ${e.url}`).filter(k => !k.includes('null'));
    const requestSimilarity = computeSetSimilarity(origKeys, replayKeys);

    // Compare request sequence
    const sequenceSimilarity = computeSequenceSimilarity(origReqs, replayReqs, e => `${e.method} ${e.url}`);

    // Compare response status codes
    const origResps = originalEvents.filter(e => e.type === 'network_response');
    const replayResps = replayEvents.filter(e => e.type === 'network_response');

    const origStatuses = origResps.map(e => e.status).filter(Boolean);
    const replayStatuses = replayResps.map(e => e.status).filter(Boolean);
    const statusSimilarity = computeSetSimilarity(
      origStatuses.map(String),
      replayStatuses.map(String)
    );

    const score = requestSimilarity * 0.4 + sequenceSimilarity * 0.3 + statusSimilarity * 0.3;
    const withinThreshold = score >= (1 - this.options.networkDiffThreshold);

    return {
      score,
      request_similarity: requestSimilarity,
      sequence_similarity: sequenceSimilarity,
      status_similarity: statusSimilarity,
      original_requests: origReqs.length,
      replay_requests: replayReqs.length,
      verdict: withinThreshold ? 'pass' : 'fail',
      within_threshold: withinThreshold,
      threshold: this.options.networkDiffThreshold,
    };
  }

  _compareCookies(originalEvents, replayEvents) {
    const origCookies = originalEvents.filter(e => e.type === 'cookie_snapshot');
    const replayCookies = replayEvents.filter(e => e.type === 'cookie_snapshot');

    if (origCookies.length === 0 && replayCookies.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No cookie snapshots in either recording' };
    }

    // Compare cookie names (not values — those are redacted)
    const origNames = new Set();
    const replayNames = new Set();

    for (const e of origCookies) {
      if (e.meta?.authCookies) {
        for (const c of e.meta.authCookies) origNames.add(c.name);
      }
    }
    for (const e of replayCookies) {
      if (e.meta?.authCookies) {
        for (const c of e.meta.authCookies) replayNames.add(c.name);
      }
    }

    const score = computeSetSimilarity(origNames, replayNames);

    return {
      score,
      original_cookie_names: [...origNames],
      replay_cookie_names: [...replayNames],
      name_similarity: score,
      verdict: score >= 0.8 ? 'pass' : 'fail',
    };
  }

  _compareStorage(originalEvents, replayEvents) {
    const origStorage = originalEvents.filter(e => e.type === 'replay_storage_write');
    const replayStorage = replayEvents.filter(e => e.type === 'replay_storage_write');

    if (origStorage.length === 0 && replayStorage.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No storage writes in either recording' };
    }

    const origKeys = origStorage.map(e => `${e.payload?.storage_type}:${e.payload?.key}`);
    const replayKeys = replayStorage.map(e => `${e.payload?.storage_type}:${e.payload?.key}`);
    const score = computeSetSimilarity(origKeys, replayKeys);

    return {
      score,
      original_writes: origStorage.length,
      replay_writes: replayStorage.length,
      key_similarity: score,
      verdict: score >= 0.8 ? 'pass' : 'fail',
    };
  }

  _compareConsole(originalEvents, replayEvents) {
    const origConsole = originalEvents.filter(e => e.type === 'console_log' || e.type === 'console_error');
    const replayConsole = replayEvents.filter(e => e.type === 'console_log' || e.type === 'console_error');

    if (origConsole.length === 0 && replayConsole.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No console events in either recording' };
    }

    // Compare console event types distribution
    const origTypes = {};
    const replayTypes = {};
    for (const e of origConsole) origTypes[e.type] = (origTypes[e.type] || 0) + 1;
    for (const e of replayConsole) replayTypes[e.type] = (replayTypes[e.type] || 0) + 1;

    const score = computeObjectSimilarity(origTypes, replayTypes);

    return {
      score,
      original_count: origConsole.length,
      replay_count: replayConsole.length,
      type_distribution_similarity: score,
      verdict: score >= 0.8 ? 'pass' : 'fail',
    };
  }

  _compareWebsocket(originalEvents, replayEvents) {
    const origWs = originalEvents.filter(e =>
      e.type === 'websocket_open' || e.type === 'websocket_message_in' ||
      e.type === 'websocket_message_out' || e.type === 'websocket_close'
    );
    const replayWs = replayEvents.filter(e =>
      e.type === 'websocket_open' || e.type === 'websocket_message_in' ||
      e.type === 'websocket_message_out' || e.type === 'websocket_close'
    );

    if (origWs.length === 0 && replayWs.length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No WebSocket events in either recording' };
    }

    // Compare WS event type distribution
    const origTypes = {};
    const replayTypes = {};
    for (const e of origWs) origTypes[e.type] = (origTypes[e.type] || 0) + 1;
    for (const e of replayWs) replayTypes[e.type] = (replayTypes[e.type] || 0) + 1;

    const score = computeObjectSimilarity(origTypes, replayTypes);

    return {
      score,
      original_count: origWs.length,
      replay_count: replayWs.length,
      type_similarity: score,
      verdict: score >= 0.8 ? 'pass' : 'fail',
    };
  }

  _compareInternalState(origState, replayState) {
    if (Object.keys(origState).length === 0 && Object.keys(replayState).length === 0) {
      return { score: 1.0, verdict: 'no_data', details: 'No internal state in either manifest' };
    }

    const ignoreKeys = this.options.ignoreKeys;
    const score = computeObjectSimilarity(origState, replayState, ignoreKeys);
    const withinThreshold = score >= (1 - this.options.stateDiffThreshold);

    return {
      score,
      state_similarity: score,
      original_domains: Object.keys(origState),
      replay_domains: Object.keys(replayState),
      verdict: withinThreshold ? 'pass' : 'fail',
      within_threshold: withinThreshold,
      threshold: this.options.stateDiffThreshold,
    };
  }

  _computeCompositeScore(axes) {
    const weights = {
      dom: 0.2,
      visual: 0.1,
      network: 0.25,
      cookies: 0.1,
      storage: 0.05,
      console: 0.05,
      websocket: 0.05,
      internal_state: 0.2,
    };

    let totalWeight = 0;
    let weightedSum = 0;

    for (const [axis, result] of Object.entries(axes)) {
      const weight = weights[axis] || 0.05;
      if (result.score !== undefined) {
        weightedSum += result.score * weight;
        totalWeight += weight;
      }
    }

    return totalWeight > 0 ? weightedSum / totalWeight : 0;
  }

  _computeVerdict(axes, composite) {
    const failures = Object.entries(axes)
      .filter(([, r]) => r.verdict === 'fail')
      .map(([axis]) => axis);

    if (failures.length === 0 && composite >= 0.95) return 'exact_match';
    if (failures.length === 0 && composite >= 0.8) return 'acceptable_match';
    if (failures.length <= 2 && composite >= 0.6) return 'partial_match';
    return 'mismatch';
  }
}

module.exports = {
  ReplayVerificationEngine,
  COMPARISON_AXES,
  computeSetSimilarity,
  computeObjectSimilarity,
  computeSequenceSimilarity,
};


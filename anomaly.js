/**
 * BOQA anomaly.js — Hybrid anomaly detection engine
 *
 * Rule-based detectors:
 *   - auth_model_change
 *   - new_bearer_usage_detected
 *   - cookie_httpOnly_downgrade
 *   - unexpected_ws_channel
 *   - endpoint_entropy_spike
 *   - error_rate_spike
 *
 * Statistical detectors:
 *   - z_score_request_volume
 *   - entropy_endpoint_distribution
 *   - timing_deviation_detection
 *
 * Operates on a sliding window of events for real-time detection,
 * and on completed sessions for post-hoc analysis.
 */

class AnomalyEngine {
  constructor(baseline = null) {
    this.baseline = baseline;
    this.anomalies = [];

    // Sliding window state for real-time detection
    this._windowSize = 200;
    this._requestTimestamps = [];
    this._endpointCounts = {};
    this._errorCount = 0;
    this._totalRequests = 0;
    this._wsChannels = new Set();
    this._prevAuthModel = null;
    this._prevCookieAttrs = new Map(); // name → { httpOnly, secure, sameSite }

    // Seed from baseline if available
    if (baseline) {
      this._seedFromBaseline(baseline);
    }
  }

  /**
   * Seed detectors from a known baseline
   */
  _seedFromBaseline(baseline) {
    const fp = baseline.fingerprint || {};
    const metrics = baseline.metrics || {};

    this._prevAuthModel = fp.auth_model || null;

    // Seed endpoint counts
    if (metrics.endpoint_frequency) {
      this._endpointCounts = { ...metrics.endpoint_frequency };
    }

    // Seed WS channels
    if (fp.ws_channels) {
      for (const ch of fp.ws_channels) this._wsChannels.add(ch);
    }

    // Seed cookie attributes
    if (fp.cookie_schema) {
      for (const c of fp.cookie_schema) {
        this._prevCookieAttrs.set(c.name, { httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite });
      }
    }
  }

  /**
   * Ingest an event in real-time (called per event)
   * Returns an array of newly detected anomalies
   */
  ingest(event) {
    const detected = [];

    switch (event.type) {
      case 'network_request':
        this._totalRequests++;
        this._requestTimestamps.push(event.ts);
        if (this._requestTimestamps.length > this._windowSize) {
          this._requestTimestamps.shift();
        }
        // Track endpoint
        if (event.url) {
          try {
            const key = new URL(event.url).pathname;
            this._endpointCounts[key] = (this._endpointCounts[key] || 0) + 1;
          } catch (_) {}
        }
        // Rule: detect new Authorization header
        if (event.headers) {
          const lower = {};
          for (const [k, v] of Object.entries(event.headers)) lower[k.toLowerCase()] = v;
          if (lower['authorization'] && this.baseline) {
            const blFp = this.baseline.fingerprint || {};
            if (!blFp.risk_flags?.includes('bearer_usage') && !blFp.risk_flags?.includes('jwt_in_js_memory')) {
              detected.push(this._makeAnomaly('new_bearer_usage_detected', 'high',
                `Authorization header detected — not present in baseline`, event.url));
            }
          }
        }
        break;

      case 'network_response':
        // No specific anomaly rules for responses yet
        break;

      case 'console_error':
      case 'network_failure':
        this._errorCount++;
        // Rule: error rate spike (check every 50 events)
        if (this._totalRequests > 0 && this._totalRequests % 50 === 0) {
          const rate = this._errorCount / this._totalRequests;
          const baselineRate = this.baseline?.metrics?.error_rate || 0;
          if (baselineRate > 0 && rate > baselineRate * 2) {
            detected.push(this._makeAnomaly('error_rate_spike', 'medium',
              `Error rate ${(rate * 100).toFixed(1)}% vs baseline ${(baselineRate * 100).toFixed(1)}%`));
          }
        }
        break;

      case 'auth_signal':
        detected.push(...this._checkAuthAnomalies(event));
        break;

      case 'websocket_open':
        if (event.url && this.baseline) {
          try {
            const key = new URL(event.url).origin + new URL(event.url).pathname;
            if (!this._wsChannels.has(key)) {
              detected.push(this._makeAnomaly('unexpected_ws_channel', 'medium',
                `New WebSocket channel not in baseline: ${key}`, key));
            }
          } catch (_) {}
        }
        break;

      case 'cookie_snapshot':
        if (event.meta?.authCookies) {
          detected.push(...this._checkCookieAnomalies(event.meta.authCookies));
        }
        break;
    }

    // Statistical checks every 100 requests
    if (event.type === 'network_request' && this._totalRequests % 100 === 0) {
      detected.push(...this._statisticalChecks());
    }

    this.anomalies.push(...detected);
    return detected;
  }

  /**
   * Auth-related anomaly rules
   */
  _checkAuthAnomalies(event) {
    const detected = [];
    const meta = event.meta || {};

    switch (meta.signalType) {
      case 'auth_cookie_set':
      case 'auth_cookies_present':
        if (meta.cookies && this._prevAuthModel && this._prevAuthModel !== 'unknown') {
          // If we had bearer-only and now see cookies → model changed
          if (this._prevAuthModel === 'bearer') {
            detected.push(this._makeAnomaly('auth_model_change', 'high',
              `Auth model shift: ${this._prevAuthModel} → hybrid (cookies now present)`));
          }
        }
        break;
    }

    return detected;
  }

  /**
   * Cookie attribute anomaly rules (downgrade detection)
   */
  _checkCookieAnomalies(cookies) {
    const detected = [];
    for (const c of cookies) {
      const prev = this._prevCookieAttrs.get(c.name);
      if (prev) {
        if (prev.httpOnly && !c.httpOnly) {
          detected.push(this._makeAnomaly('cookie_httpOnly_downgrade', 'high',
            `Cookie "${c.name}" HttpOnly removed: ${prev.httpOnly} → ${c.httpOnly}`));
        }
        if (prev.secure && !c.secure) {
          detected.push(this._makeAnomaly('cookie_secure_downgrade', 'high',
            `Cookie "${c.name}" Secure removed: ${prev.secure} → ${c.secure}`));
        }
      }
      // Update state
      this._prevCookieAttrs.set(c.name, { httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite });
    }
    return detected;
  }

  /**
   * Statistical anomaly checks
   */
  _statisticalChecks() {
    const detected = [];

    // Z-score on request volume (requests per second in window)
    if (this._requestTimestamps.length >= 50) {
      const volumes = this._computeRequestVolumes();
      const zScore = this._zScore(volumes);
      if (Math.abs(zScore) > 2.5) {
        detected.push(this._makeAnomaly('z_score_request_volume', 'low',
          `Request volume z-score: ${zScore.toFixed(2)} (threshold: 2.5)`));
      }
    }

    // Endpoint entropy spike
    const entropy = this._computeEntropy();
    const baselineEntropy = this.baseline?.metrics?.endpoint_entropy;
    if (baselineEntropy && entropy > baselineEntropy * 1.5) {
      detected.push(this._makeAnomaly('endpoint_entropy_spike', 'medium',
        `Endpoint entropy ${entropy.toFixed(2)} vs baseline ${baselineEntropy.toFixed(2)}`));
    }

    // Timing deviation detection (requests becoming bursty)
    if (this._requestTimestamps.length >= 100) {
      const intervals = this._computeIntervals();
      const mean = intervals.reduce((s, v) => s + v, 0) / intervals.length;
      const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
      const cv = Math.sqrt(variance) / (mean || 1); // coefficient of variation
      if (cv > 2.0) {
        detected.push(this._makeAnomaly('timing_deviation_detected', 'low',
          `Request timing CV: ${cv.toFixed(2)} (bursty traffic pattern)`));
      }
    }

    return detected;
  }

  /**
   * Compute request volumes (requests per second in buckets)
   */
  _computeRequestVolumes() {
    if (this._requestTimestamps.length < 2) return [1];
    const buckets = {};
    for (const ts of this._requestTimestamps) {
      const bucket = Math.floor(ts / 1000); // 1-second buckets
      buckets[bucket] = (buckets[bucket] || 0) + 1;
    }
    return Object.values(buckets);
  }

  /**
   * Compute Z-score of the latest value in a series
   */
  _zScore(values) {
    if (values.length < 2) return 0;
    const mean = values.reduce((s, v) => s + v, 0) / values.length;
    const stdDev = Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length);
    return stdDev > 0 ? (values[values.length - 1] - mean) / stdDev : 0;
  }

  /**
   * Compute Shannon entropy of endpoint distribution
   */
  _computeEntropy() {
    const counts = Object.values(this._endpointCounts);
    const total = counts.reduce((s, c) => s + c, 0);
    if (total === 0) return 0;
    let entropy = 0;
    for (const c of counts) {
      const p = c / total;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Compute intervals between consecutive requests
   */
  _computeIntervals() {
    const intervals = [];
    for (let i = 1; i < this._requestTimestamps.length; i++) {
      intervals.push(this._requestTimestamps[i] - this._requestTimestamps[i - 1]);
    }
    return intervals;
  }

  /**
   * Create an anomaly record
   */
  _makeAnomaly(rule, severity, detail, context = null) {
    return {
      ts: Date.now(),
      rule,
      severity,
      detail,
      context,
    };
  }

  /**
   * Get all anomalies detected so far
   */
  getAnomalies() {
    return this.anomalies;
  }

  /**
   * Get anomaly summary
   */
  getSummary() {
    const byRule = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const a of this.anomalies) {
      byRule[a.rule] = (byRule[a.rule] || 0) + 1;
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
    }
    return {
      total: this.anomalies.length,
      byRule,
      bySeverity,
      hasHigh: bySeverity.high > 0,
    };
  }

  /**
   * Post-hoc analysis on a completed session
   */
  analyzeSession(session, report, baseline) {
    const anomalies = [];
    const bl = baseline || this.baseline;

    if (bl) {
      const blFp = bl.fingerprint || {};

      // Auth model change
      if (report.auth_model !== blFp.auth_model && blFp.auth_model !== 'unknown') {
        anomalies.push(this._makeAnomaly('auth_model_change', 'high',
          `Auth model changed: ${blFp.auth_model} → ${report.auth_model}`));
      }

      // Bearer appeared for first time
      if (report.bearer_detected && !blFp.risk_flags?.includes('bearer_usage')) {
        anomalies.push(this._makeAnomaly('new_bearer_usage_detected', 'high',
          `Bearer token usage detected — not in baseline`));
      }

      // Cookie downgrades
      if (blFp.cookie_schema && report.cookies) {
        const blMap = new Map(blFp.cookie_schema.map(c => [c.name, c]));
        for (const c of report.cookies) {
          const prev = blMap.get(c.name);
          if (prev) {
            if (prev.httpOnly && !c.httpOnly) {
              anomalies.push(this._makeAnomaly('cookie_httpOnly_downgrade', 'high',
                `Cookie "${c.name}" HttpOnly removed`));
            }
            if (prev.secure && !c.secure) {
              anomalies.push(this._makeAnomaly('cookie_secure_downgrade', 'high',
                `Cookie "${c.name}" Secure removed`));
            }
          }
        }
      }

      // Unexpected WS channels
      if (blFp.ws_channels && report.ws_channels) {
        const blSet = new Set(blFp.ws_channels);
        for (const ch of report.ws_channels) {
          if (!blSet.has(ch.url)) {
            anomalies.push(this._makeAnomaly('unexpected_ws_channel', 'medium',
              `New WebSocket: ${ch.url}`));
          }
        }
      }
    }

    // Error rate spike
    const events = session.events || [];
    let reqCount = 0, errCount = 0;
    for (const e of events) {
      if (e.type === 'network_request') reqCount++;
      if (e.type === 'console_error' || e.type === 'network_failure') errCount++;
    }
    const errorRate = reqCount > 0 ? errCount / reqCount : 0;
    const blErrorRate = bl?.metrics?.error_rate || 0;
    if (blErrorRate > 0 && errorRate > blErrorRate * 2) {
      anomalies.push(this._makeAnomaly('error_rate_spike', 'medium',
        `Error rate ${(errorRate * 100).toFixed(1)}% vs baseline ${(blErrorRate * 100).toFixed(1)}%`));
    }

    return anomalies;
  }
}

module.exports = { AnomalyEngine };


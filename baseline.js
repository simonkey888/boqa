/**
 * BOQA baseline.js — Baseline builder + fingerprint extraction
 *
 * Generates a deterministic fingerprint from a completed session:
 *   - Endpoints (sorted, deduplicated)
 *   - Auth model + cookie schema
 *   - WebSocket channels
 *   - Request volume metrics
 *   - Error rate baseline
 *
 * Baselines are stored as JSON files in output/baselines/
 * and used by compare.js for regression detection.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASELINES_DIR = path.join(__dirname, 'output', 'baselines');

class BaselineBuilder {
  constructor() {
    fs.mkdirSync(BASELINES_DIR, { recursive: true });
  }

  /**
   * Build a baseline from a completed session
   * @param {object} session - session export from EventBus
   * @param {object} report - auth report from Agent
   * @returns {object} baseline
   */
  build(session, report) {
    const events = session.events || [];
    const fingerprint = this._extractFingerprint(events, report);
    const metrics = this._extractMetrics(events);

    const baseline = {
      id: this._generateId(session.target),
      version: '0.2.0',
      source_session: session.sessionStart,
      target: session.target || null,
      created_at: Date.now(),
      fingerprint,
      metrics,
      event_count: session.totalEvents || events.length,
      session_duration: (session.sessionEnd || Date.now()) - (session.sessionStart || Date.now()),
    };

    return baseline;
  }

  /**
   * Extract fingerprint from session events + auth report
   */
  _extractFingerprint(events, report) {
    const endpoints = new Set();
    const wsChannels = new Set();
    const cookieSchema = [];

    for (const event of events) {
      // Collect unique endpoints (method + pathname)
      if ((event.type === 'network_request' || event.type === 'network_response') && event.url) {
        try {
          const u = new URL(event.url);
          const key = `${event.method || 'GET'} ${u.pathname}`;
          endpoints.add(key);
        } catch (_) {}
      }

      // Collect WebSocket channels
      if (event.type === 'websocket_open' && event.url) {
        try {
          const u = new URL(event.url);
          wsChannels.add(u.origin + u.pathname);
        } catch (_) {}
      }
    }

    // Cookie schema from report
    if (report && report.cookies) {
      for (const c of report.cookies) {
        cookieSchema.push({
          name: c.name,
          domain: c.domain || null,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite || null,
        });
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

  /**
   * Extract metrics from session events
   */
  _extractMetrics(events) {
    let requestCount = 0;
    let errorCount = 0;
    let wsMessageCount = 0;
    let authEvents = 0;
    const statusCodes = {};
    const endpointCounts = {};

    for (const event of events) {
      switch (event.type) {
        case 'network_request':
          requestCount++;
          if (event.url) {
            try {
              const key = new URL(event.url).pathname;
              endpointCounts[key] = (endpointCounts[key] || 0) + 1;
            } catch (_) {}
          }
          break;
        case 'network_response':
          if (event.status) {
            statusCodes[event.status] = (statusCodes[event.status] || 0) + 1;
          }
          break;
        case 'console_error':
        case 'network_failure':
          errorCount++;
          break;
        case 'websocket_message_in':
        case 'websocket_message_out':
          wsMessageCount++;
          break;
        case 'auth_signal':
          authEvents++;
          break;
      }
    }

    return {
      request_count: requestCount,
      error_count: errorCount,
      ws_message_count: wsMessageCount,
      auth_events: authEvents,
      error_rate: requestCount > 0 ? errorCount / requestCount : 0,
      status_code_distribution: statusCodes,
      endpoint_frequency: endpointCounts,
      unique_endpoints: Object.keys(endpointCounts).length,
    };
  }

  /**
   * Generate a deterministic baseline ID
   */
  _generateId(target) {
    const hash = crypto.createHash('sha256');
    hash.update(target || 'unknown');
    hash.update(Date.now().toString());
    return `bl-${hash.digest('hex').substring(0, 12)}`;
  }

  /**
   * Save baseline to disk
   */
  save(baseline, filename) {
    const filePath = path.join(BASELINES_DIR, filename || `${baseline.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2));
    return filePath;
  }

  /**
   * Load baseline from disk
   */
  load(baselineId) {
    const filePath = path.join(BASELINES_DIR, `${baselineId}.json`);
    if (!fs.existsSync(filePath)) {
      // Try as filename
      const alt = path.join(BASELINES_DIR, baselineId);
      if (fs.existsSync(alt)) return JSON.parse(fs.readFileSync(alt, 'utf8'));
      throw new Error(`Baseline not found: ${baselineId}`);
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }

  /**
   * List all available baselines
   */
  list() {
    if (!fs.existsSync(BASELINES_DIR)) return [];
    return fs.readdirSync(BASELINES_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        try {
          const bl = JSON.parse(fs.readFileSync(path.join(BASELINES_DIR, f), 'utf8'));
          return { id: bl.id, target: bl.target, created_at: bl.created_at, auth_model: bl.fingerprint?.auth_model };
        } catch (_) { return null; }
      })
      .filter(Boolean);
  }

  /**
   * Find the latest baseline for a target
   */
  findLatest(target) {
    const all = this.list()
      .filter(bl => bl.target === target)
      .sort((a, b) => b.created_at - a.created_at);
    return all.length > 0 ? this.load(all[0].id) : null;
  }
}

module.exports = { BaselineBuilder, BASELINES_DIR };


/**
 * BOQA evidence-package-generator.js — Evidence Package Generator (S6-4)
 *
 * Generates a complete forensic package automatically for each confirmed bug.
 * Artifacts produced:
 *   - manifest.json       — Package metadata and artifact index
 *   - timeline.json       — Ordered event timeline
 *   - dom_before.html     — DOM state before the bug triggered
 *   - dom_after.html      — DOM state after the bug triggered
 *   - dom_diff.json       — Structured DOM diff
 *   - network.har         — HTTP archive of network traffic
 *   - cookies.json        — Cookie state at bug time
 *   - storage.json        — localStorage/sessionStorage state
 *   - console.json        — Console output log
 *   - screenshots/        — Screenshot metadata (paths, timestamps)
 *   - replay.json         — Replay recording data
 *   - verification.json   — Verification result
 *   - environment.json    — Browser/OS/runtime environment
 *   - runtime_metrics.json — Performance and resource metrics
 *   - summary.md          — Human-readable summary
 *
 * Leverages existing P5 infrastructure for manifest, recording, and verification.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jsondiffpatch = require('jsondiffpatch');

class EvidencePackageGenerator {
  /**
   * @param {object} opts
   * @param {object} opts.manifestBuilder    - ReplayManifestBuilder
   * @param {object} opts.recorder           - UniversalSessionRecorder
   * @param {object} opts.verificationEngine - ReplayVerificationEngine
   * @param {object} opts.securityGuard      - ReplaySecurityGuard
   * @param {string} opts.outputDir          - Directory for evidence packages
   */
  constructor(opts = {}) {
    this.manifestBuilder = opts.manifestBuilder || null;
    this.recorder = opts.recorder || null;
    this.verificationEngine = opts.verificationEngine || null;
    this.securityGuard = opts.securityGuard || null;
    this.outputDir = opts.outputDir || path.join(__dirname, 'output', 'evidence');

    this._packages = new Map();
    this._stats = {
      total_generated: 0,
      total_artifacts: 0,
      avg_artifact_count: 0,
      total_size_bytes: 0,
    };
  }

  /**
   * Generate a complete evidence package for a confirmed bug.
   *
   * @param {object} bug       - Confirmed bug object
   * @param {object} agent     - Agent instance
   * @param {object} ctx       - BOQA context
   * @returns {object} Evidence package with all artifacts
   */
  generate(bug, agent, ctx) {
    const evidenceId = `ev-${crypto.randomUUID().substring(0, 12)}`;
    const timestamp = Date.now();

    // Collect raw data
    const events = ctx.bus ? ctx.bus.eventLog : [];
    const report = agent && typeof agent.getReport === 'function' ? agent.getReport() : {};
    const anomalies = agent && agent.anomaly ? agent.anomaly.getAnomalies() : [];

    // Build each artifact
    const manifest = this._buildManifest(evidenceId, bug, timestamp, ctx);
    const timeline = this._buildTimeline(events, bug);
    const domBefore = this._extractDOMSnapshot(events, bug, 'before');
    const domAfter = this._extractDOMSnapshot(events, bug, 'after');
    const domDiff = this._computeDOMDiff(domBefore, domAfter);
    const networkHAR = this._buildHAR(events, bug);
    const cookiesState = this._extractCookies(events, report, bug);
    const storageState = this._extractStorage(events, bug);
    const consoleLog = this._extractConsole(events, bug);
    const screenshots = this._extractScreenshots(events, bug);
    const replayData = this._extractReplayData(bug, ctx);
    const verificationData = this._extractVerification(bug);
    const environment = this._extractEnvironment(agent, ctx);
    const runtimeMetrics = this._extractRuntimeMetrics(events, bug);
    const summary = this._buildSummary(bug, manifest, timeline, networkHAR, consoleLog, verificationData, environment);

    // Redact secrets if security guard available
    const redactedCookies = this.securityGuard
      ? this.securityGuard.redact(cookiesState).redacted
      : cookiesState;
    const redactedStorage = this.securityGuard
      ? this.securityGuard.redact(storageState).redacted
      : storageState;

    const pkg = {
      evidence_id: evidenceId,
      bug_id: bug.id,
      generated_at: timestamp,
      generator_version: '1.0.0-s6',
      manifest,
      artifacts: {
        timeline,
        dom_before: domBefore,
        dom_after: domAfter,
        dom_diff: domDiff,
        network_har: networkHAR,
        cookies: redactedCookies,
        storage: redactedStorage,
        console: consoleLog,
        screenshots,
        replay: replayData,
        verification: verificationData,
        environment,
        runtime_metrics: runtimeMetrics,
        summary,
      },
      artifact_count: 15,
      integrity: {
        hash: crypto.createHash('sha256').update(
          JSON.stringify({ timeline, domDiff, networkHAR, consoleLog, verificationData })
        ).digest('hex'),
        algorithm: 'sha256',
      },
    };

    // Sign if security guard available
    if (this.securityGuard) {
      try {
        const signature = this.securityGuard.sign(pkg);
        pkg.integrity.signature = signature.signature;
        pkg.integrity.signed_at = Date.now();
      } catch (_) {}
    }

    this._packages.set(evidenceId, pkg);
    this._stats.total_generated++;
    this._stats.total_artifacts += pkg.artifact_count;
    this._stats.avg_artifact_count = this._stats.total_artifacts / this._stats.total_generated;

    // Persist to disk
    this._savePackage(pkg);

    return pkg;
  }

  // ─── Artifact Builders ────────────────────────────────────────────

  _buildManifest(evidenceId, bug, timestamp, ctx) {
    return {
      evidence_id: evidenceId,
      bug_id: bug.id,
      bug_category: bug.category,
      bug_confidence: bug.confidence_score || bug.initial_confidence || 0,
      target: bug.target || (ctx.CONFIG ? ctx.CONFIG.target : 'unknown'),
      generated_at: timestamp,
      boqa_version: ctx.CONFIG ? '1.4.0' : 'unknown',
      artifact_index: [
        'timeline.json', 'dom_before.html', 'dom_after.html', 'dom_diff.json',
        'network.har', 'cookies.json', 'storage.json', 'console.json',
        'screenshots/', 'replay.json', 'verification.json',
        'environment.json', 'runtime_metrics.json', 'summary.md',
      ],
      artifact_hash: crypto.createHash('sha256').update(
        evidenceId + bug.id + timestamp
      ).digest('hex').substring(0, 16),
    };
  }

  _buildTimeline(events, bug) {
    const bugTime = bug.detected_at || Date.now();
    const windowMs = 60000; // 60s window around bug
    const relevant = events
      .filter(e => e.ts >= bugTime - windowMs && e.ts <= bugTime + 10000)
      .map(e => ({
        ts: e.ts,
        elapsed_ms: e.ts - bugTime,
        type: e.type,
        url: e.url || null,
        method: e.method || null,
        status: e.status || null,
        summary: this._summarizeEvent(e),
      }))
      .sort((a, b) => a.ts - b.ts);

    return {
      entries: relevant,
      total: relevant.length,
      window_start: bugTime - windowMs,
      window_end: bugTime + 10000,
      bug_timestamp: bugTime,
    };
  }

  _extractDOMSnapshot(events, bug, phase) {
    const bugTime = bug.detected_at || Date.now();
    const delta = phase === 'before' ? -5000 : 5000;

    const domEvents = events.filter(e =>
      e.type === 'dom_snapshot' && Math.abs(e.ts - (bugTime + delta)) < 10000
    );

    if (domEvents.length > 0) {
      const closest = phase === 'before'
        ? domEvents.reduce((best, e) => e.ts < bugTime && e.ts > (best?.ts || 0) ? e : best, null)
        : domEvents.reduce((best, e) => e.ts > bugTime && e.ts < (best?.ts || Infinity) ? e : best, null);

      if (closest) {
        return closest.meta?.html || closest.data?.html || '<!-- DOM snapshot captured -->';
      }
    }

    return `<!-- No DOM snapshot available for ${phase} phase -->`;
  }

  _computeDOMDiff(before, after) {
    if (!before || !after || before.startsWith('<!--') || after.startsWith('<!--')) {
      return { available: false, reason: 'DOM snapshots not available for diff' };
    }

    try {
      const differ = jsondiffpatch.create({
        textDiff: { minLength: 20 },
      });
      const delta = differ.diff(
        { html: before.substring(0, 50000) },
        { html: after.substring(0, 50000) }
      );
      return {
        available: true,
        delta: delta || null,
        has_changes: delta !== null && delta !== undefined,
      };
    } catch (_) {
      return { available: false, reason: 'DOM diff computation failed' };
    }
  }

  _buildHAR(events, bug) {
    const bugTime = bug.detected_at || Date.now();
    const windowMs = 30000;
    const networkEvents = events.filter(e =>
      (e.type === 'network_request' || e.type === 'network_response') &&
      e.ts >= bugTime - windowMs && e.ts <= bugTime + 5000
    );

    const entries = [];
    for (const req of networkEvents.filter(e => e.type === 'network_request')) {
      const resp = networkEvents.find(e =>
        e.type === 'network_response' && e.url === req.url && e.ts > req.ts
      );

      entries.push({
        startedDateTime: new Date(req.ts).toISOString(),
        time: resp ? resp.ts - req.ts : 0,
        request: {
          method: req.method || 'GET',
          url: req.url,
          httpVersion: 'HTTP/1.1',
          headers: this._redactHeaders(req.headers || {}),
          queryString: [],
          headersSize: -1,
          bodySize: -1,
        },
        response: resp ? {
          status: resp.status || 0,
          statusText: resp.statusText || '',
          httpVersion: 'HTTP/1.1',
          headers: this._redactHeaders(resp.headers || {}),
          content: { size: 0, mimeType: resp.contentType || 'application/octet-stream' },
          redirectURL: '',
          headersSize: -1,
          bodySize: -1,
        } : { status: 0, statusText: 'No response' },
        timings: { send: 0, wait: resp ? resp.ts - req.ts : 0, receive: 0 },
      });
    }

    return {
      log: {
        version: '1.2',
        creator: { name: 'BOQA Evidence Generator', version: '1.0.0' },
        entries,
      },
      total_entries: entries.length,
    };
  }

  _extractCookies(events, report, bug) {
    const cookies = [];

    // From report
    if (report && report.cookies) {
      cookies.push(...report.cookies.map(c => ({
        name: c.name,
        value: '[REDACTED]', // Always redact values in evidence
        domain: c.domain,
        path: c.path,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
        expires: c.expires || null,
      })));
    }

    // From cookie snapshot events
    const cookieEvents = events.filter(e => e.type === 'cookie_snapshot');
    for (const ce of cookieEvents) {
      const eventCookies = ce.meta?.cookies || ce.meta?.authCookies || [];
      for (const c of eventCookies) {
        if (!cookies.find(ec => ec.name === c.name)) {
          cookies.push({
            name: c.name,
            value: '[REDACTED]',
            domain: c.domain || '',
            path: c.path || '/',
            httpOnly: c.httpOnly,
            secure: c.secure,
            sameSite: c.sameSite,
            expires: c.expires || null,
          });
        }
      }
    }

    return { cookies, total: cookies.length, captured_at: Date.now() };
  }

  _extractStorage(events, bug) {
    const localStorage = {};
    const sessionStorage = {};

    const storageEvents = events.filter(e =>
      e.type === 'storage_write' || e.type === 'interaction' && e.meta?.storageType
    );

    for (const se of storageEvents) {
      const type = se.meta?.storageType || 'localStorage';
      const key = se.meta?.key || se.key || 'unknown';
      const target = type === 'sessionStorage' ? sessionStorage : localStorage;
      target[key] = '[REDACTED]';
    }

    return {
      localStorage,
      sessionStorage,
      total_keys: Object.keys(localStorage).length + Object.keys(sessionStorage).length,
      captured_at: Date.now(),
    };
  }

  _extractConsole(events, bug) {
    const bugTime = bug.detected_at || Date.now();
    const windowMs = 30000;

    const consoleEvents = events.filter(e =>
      (e.type === 'console_error' || e.type === 'console_warning' || e.type === 'console_log') &&
      e.ts >= bugTime - windowMs && e.ts <= bugTime + 5000
    );

    return {
      entries: consoleEvents.map(e => ({
        level: e.type.replace('console_', ''),
        text: (e.text || '').substring(0, 500),
        url: e.url || null,
        line: e.line || null,
        timestamp: e.ts,
      })),
      total: consoleEvents.length,
      errors: consoleEvents.filter(e => e.type === 'console_error').length,
      warnings: consoleEvents.filter(e => e.type === 'console_warning').length,
    };
  }

  _extractScreenshots(events, bug) {
    const screenshotEvents = events.filter(e =>
      e.type === 'screenshot' || (e.type === 'interaction' && e.meta?.screenshot)
    );

    return {
      available: screenshotEvents.length > 0,
      count: screenshotEvents.length,
      entries: screenshotEvents.map(e => ({
        timestamp: e.ts,
        url: e.url || null,
        path: e.meta?.path || null,
        meta: { captured_at: e.ts },
      })),
    };
  }

  _extractReplayData(bug, ctx) {
    if (ctx.lastRecordingResult) {
      return {
        available: true,
        recorder_id: ctx.lastRecordingResult.recorder_id,
        events_count: ctx.lastRecordingResult.events_count || 0,
        step_boundaries: ctx.lastRecordingResult.step_boundaries || 0,
      };
    }
    return {
      available: false,
      reason: 'No recording available for this bug',
    };
  }

  _extractVerification(bug) {
    if (bug._confirmation) {
      return {
        available: true,
        score: bug._confirmation.final_score,
        verdict: bug._confirmation.final_verdict,
        attempts: bug._confirmation.attempts,
        nondeterministic: bug._confirmation.nondeterministic,
      };
    }
    return {
      available: false,
      confidence: bug.confidence_score || bug.initial_confidence || 0,
      level: bug.confidence_level || 'UNKNOWN',
    };
  }

  _extractEnvironment(agent, ctx) {
    const config = ctx.CONFIG || {};
    return {
      boqa_version: '1.4.0',
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      target: config.target || 'unknown',
      mode: config.mode || 'unknown',
      headless: config.headless || false,
      agent_available: !!agent,
      agent_running: agent ? (!('page' in agent) || !!agent.page) : false,
      pid: process.pid,
      memory_usage: process.memoryUsage(),
      captured_at: Date.now(),
    };
  }

  _extractRuntimeMetrics(events, bug) {
    const bugTime = bug.detected_at || Date.now();
    const windowMs = 30000;
    const windowEvents = events.filter(e => e.ts >= bugTime - windowMs && e.ts <= bugTime + 5000);

    const byType = {};
    for (const e of windowEvents) {
      byType[e.type] = (byType[e.type] || 0) + 1;
    }

    return {
      events_in_window: windowEvents.length,
      events_by_type: byType,
      window_ms: windowMs + 5000,
      memory_rss: process.memoryUsage().rss,
      memory_heap_used: process.memoryUsage().heapUsed,
      event_rate_per_sec: windowEvents.length / ((windowMs + 5000) / 1000),
      captured_at: Date.now(),
    };
  }

  _buildSummary(bug, manifest, timeline, networkHAR, consoleLog, verification, environment) {
    const lines = [
      `# Bug Evidence Package: ${bug.id}`,
      ``,
      `**Category:** ${bug.category}`,
      `**Confidence:** ${bug.confidence_score || bug.initial_confidence || 0}%`,
      `**Target:** ${manifest.target}`,
      `**Generated:** ${new Date(manifest.generated_at).toISOString()}`,
      ``,
      `## Summary`,
      ``,
      `${bug.reasoning || 'No reasoning provided.'}`,
      ``,
      `## Timeline`,
      ``,
      `- **Total events in window:** ${timeline.total}`,
      `- **Bug timestamp:** ${new Date(timeline.bug_timestamp).toISOString()}`,
      ``,
      `## Network Activity`,
      ``,
      `- **HTTP entries captured:** ${networkHAR.total_entries}`,
      ``,
      `## Console Output`,
      ``,
      `- **Errors:** ${consoleLog.errors}`,
      `- **Warnings:** ${consoleLog.warnings}`,
      ``,
      `## Verification`,
      ``,
      verification.available
        ? `- **Score:** ${(verification.score * 100).toFixed(1)}%`
        : `- **Confidence:** ${verification.confidence}%`,
      verification.available
        ? `- **Verdict:** ${verification.verdict}`
        : `- **Level:** ${verification.level}`,
      verification.available
        ? `- **Attempts:** ${verification.attempts}`
        : '',
      ``,
      `## Environment`,
      ``,
      `- **BOQA Version:** ${environment.boqa_version}`,
      `- **Node:** ${environment.node_version}`,
      `- **Agent Running:** ${environment.agent_running}`,
      ``,
      `---`,
      `*Auto-generated by BOQA Evidence Package Generator v1.0.0-s6*`,
    ];

    return lines.join('\n');
  }

  // ─── Helpers ──────────────────────────────────────────────────────

  _summarizeEvent(e) {
    switch (e.type) {
      case 'network_request': return `${e.method || 'GET'} ${e.url || '?'}`;
      case 'network_response': return `${e.status} ${e.url || '?'}`;
      case 'navigation': return `Navigate → ${e.url || '?'}`;
      case 'console_error': return `Error: ${(e.text || '').substring(0, 60)}`;
      case 'auth_signal': return `Auth: ${e.meta?.signalType || 'unknown'}`;
      case 'cookie_snapshot': return `Cookies: ${(e.meta?.cookies || []).length} captured`;
      default: return e.type;
    }
  }

  _redactHeaders(headers) {
    const redacted = { ...headers };
    const sensitiveKeys = ['authorization', 'cookie', 'set-cookie', 'x-csrftoken', 'x-auth-token'];
    for (const key of Object.keys(redacted)) {
      if (sensitiveKeys.includes(key.toLowerCase())) {
        redacted[key] = '[REDACTED]';
      }
    }
    return redacted;
  }

  _savePackage(pkg) {
    try {
      const dir = path.join(this.outputDir, pkg.evidence_id);
      fs.mkdirSync(dir, { recursive: true });

      // Save full package as JSON
      fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify(pkg, null, 2)
      );

      // Save summary as markdown
      fs.writeFileSync(
        path.join(dir, 'summary.md'),
        pkg.artifacts.summary
      );

      // Update size stats
      const size = JSON.stringify(pkg).length;
      this._stats.total_size_bytes += size;
    } catch (_) {
      // Silently continue if save fails
    }
  }

  /**
   * Get a stored package by evidence ID.
   */
  getPackage(evidenceId) {
    return this._packages.get(evidenceId) || null;
  }

  /**
   * List all stored packages.
   */
  listPackages() {
    return [...this._packages.values()].map(p => ({
      evidence_id: p.evidence_id,
      bug_id: p.bug_id,
      generated_at: p.generated_at,
      artifact_count: p.artifact_count,
    }));
  }

  /**
   * Get generator statistics.
   */
  getStats() {
    return { ...this._stats };
  }

  /**
   * Reset all state.
   */
  reset() {
    this._packages.clear();
    this._stats = {
      total_generated: 0,
      total_artifacts: 0,
      avg_artifact_count: 0,
      total_size_bytes: 0,
    };
  }
}

module.exports = { EvidencePackageGenerator };


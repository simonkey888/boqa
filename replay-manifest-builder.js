/**
 * BOQA replay-manifest-builder.js — ReplayManifestBuilder v1.5 (P5)
 *
 * Builds immutable replay manifests containing full execution context
 * and BOQA internal state. Each manifest captures the complete environment
 * fingerprint, configuration, internal engine state, and artifact index
 * so that any recorded session can be deterministically reproduced.
 *
 * Design principles (P5):
 *   - Determinism first: every field is either a literal, a hash, or
 *     a frozen snapshot — never a live reference.
 *   - Context matters: the manifest includes not just browser events
 *     but the full BOQA engine state at recording time.
 *   - Immutable artifacts: once built, manifests are frozen and hashed.
 *   - Safe mode: secrets are redacted before storage; never plaintext.
 *
 * Manifest schema: replay_manifest_v1
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');
const MANIFESTS_DIR = path.join(REPLAYS_DIR, 'manifests');
const SNAPSHOTS_DIR = path.join(REPLAYS_DIR, 'snapshots');

fs.mkdirSync(MANIFESTS_DIR, { recursive: true });
fs.mkdirSync(SNAPSHOTS_DIR, { recursive: true });

// ─── Version Detection Helpers ─────────────────────────────────────

function getBoqaVersion() {
  try {
    const pkg = require('./package.json');
    return pkg.version || '1.5.0';
  } catch (_) {
    return '1.5.0';
  }
}

function getNodeVersion() {
  return process.version;
}

function getPlaywrightVersion() {
  try {
    const pwPkg = require('playwright/package.json');
    return pwPkg.version || 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

function getOsVersion() {
  return `${process.platform} ${process.arch} ${require('os').release()}`;
}

// ─── Fingerprint Builder ───────────────────────────────────────────

function buildFingerprint(config = {}) {
  return Object.freeze({
    boqa_version: getBoqaVersion(),
    node_version: getNodeVersion(),
    playwright_version: getPlaywrightVersion(),
    chromium_version: config.chromiumVersion || 'bundled',
    os_version: getOsVersion(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    locale: Intl.DateTimeFormat().resolvedOptions().locale,
    viewport: config.viewport || null,
    browser_fingerprint: config.browserFingerprint || null,
  });
}

// ─── Environment Capture ───────────────────────────────────────────

function buildEnvironment(config = {}) {
  // Capture non-sensitive config flags only
  const envVars = {};
  const SAFE_ENV_PREFIXES = ['BOQA_MODE', 'BOQA_TARGET', 'BOQA_PORT', 'NODE_ENV'];
  for (const key of SAFE_ENV_PREFIXES) {
    if (process.env[key]) envVars[key] = process.env[key];
  }

  return Object.freeze({
    config_flags: {
      mode: config.mode || null,
      headless: config.headless ?? true,
      port: config.port || 7070,
      autoAnalyze: config.autoAnalyze ?? false,
      analyzeInterval: config.analyzeInterval || 60,
      duration: config.duration || 0,
      har: config.har ?? false,
      cdp: config.cdp || null,
    },
    environment_variables: envVars,
    target_url: config.target || null,
    target_domain: config.target ? extractDomain(config.target) : null,
  });
}

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return null;
  }
}

// ─── State Snapshot Builder ────────────────────────────────────────

/**
 * Capture BOQA internal state for deterministic replay context.
 * Each engine's key state is serialized into a frozen snapshot.
 */
function buildStateSnapshot(ctx = {}) {
  const snapshot = {};

  // Memory graph state
  if (ctx.memoryGraph) {
    snapshot.memory_graph_snapshot = safeSnapshot(() => ({
      node_count: ctx.memoryGraph.nodes?.size || 0,
      edge_count: ctx.memoryGraph.edges?.size || 0,
      version: ctx.memoryGraph.version || '1.1',
    }));
  }

  // Economic value engine (CEVI) state
  if (ctx.economicValueEngine) {
    snapshot.cevi_state = safeSnapshot(() => ({
      score: ctx.economicValueEngine.lastScore || null,
      class: ctx.economicValueEngine.lastClass || null,
      version: ctx.economicValueEngine.version || '1.2',
    }));
  }

  // Autonomy governor state
  if (ctx.autonomyGovernor) {
    snapshot.autonomy_governor_state = safeSnapshot(() => ({
      current_level: ctx.autonomyGovernor.currentLevel || 'L0',
      behavioral_mode: ctx.autonomyGovernor.behavioralMode || 'OBSERVE_ONLY',
      budget_remaining: ctx.autonomyGovernor.budgetRemaining ?? null,
      total_decisions: ctx.autonomyGovernor.totalDecisions || 0,
      version: ctx.autonomyGovernor.version || '1.4',
    }));
  }

  // Decision policy state
  if (ctx.decisionPolicyEngine) {
    snapshot.decision_policy_state = safeSnapshot(() => ({
      mode: ctx.decisionPolicyEngine.mode || 'BALANCED',
      total_decisions: ctx.decisionPolicyEngine.totalDecisions || 0,
      version: ctx.decisionPolicyEngine.version || '1.2',
    }));
  }

  // Confidence calibrator state
  if (ctx.confidenceCalibrator) {
    snapshot.confidence_calibrator_state = safeSnapshot(() => ({
      calibration_curve: ctx.confidenceCalibrator.calibrationCurve || [],
      total_predictions: ctx.confidenceCalibrator.totalPredictions || 0,
      version: ctx.confidenceCalibrator.version || '1.1',
    }));
  }

  // Knowledge graph state
  if (ctx.knowledgeBase) {
    snapshot.knowledge_graph_state = safeSnapshot(() => ({
      observations: ctx.knowledgeBase.observations?.size || 0,
      findings: ctx.knowledgeBase.findings?.size || 0,
      assets: ctx.knowledgeBase.assets?.size || 0,
      validations: ctx.knowledgeBase.validations?.size || 0,
      hypotheses: ctx.knowledgeBase.hypotheses?.size || 0,
      sessions: ctx.knowledgeBase.sessions?.size || 0,
      coverage_maps: ctx.knowledgeBase.coverage?.size || 0,
      metrics: ctx.knowledgeBase.getMetrics ? ctx.knowledgeBase.getMetrics() : {},
    }));
  }

  // Verification summary
  if (ctx.verificationEngine) {
    snapshot.verification_summary = safeSnapshot(() => ({
      total_plans: ctx.verificationEngine.plans?.size || 0,
      version: ctx.verificationEngine.version || '0.4',
    }));
  }

  // Risk summary
  if (ctx.riskEngine) {
    snapshot.risk_summary = safeSnapshot(() => ({
      total_findings: ctx.riskEngine.findings?.size || 0,
      version: ctx.riskEngine.version || '0.3',
    }));
  }

  return Object.freeze(snapshot);
}

function safeSnapshot(fn) {
  try {
    return fn();
  } catch (_) {
    return { error: 'snapshot_failed' };
  }
}

// ─── ReplayManifestBuilder ─────────────────────────────────────────

class ReplayManifestBuilder {
  /**
   * @param {object} options
   * @param {boolean} [options.includeStateSnapshots=true]
   * @param {boolean} [options.redactSecrets=true]
   */
  constructor(options = {}) {
    this.options = {
      includeStateSnapshots: options.includeStateSnapshots !== false,
      redactSecrets: options.redactSecrets !== false,
    };
    this.manifests = new Map(); // replayId → manifest
  }

  /**
   * Build an immutable replay manifest.
   *
   * @param {object} params
   * @param {object} params.config - BOQA config
   * @param {object} params.ctx - Engine context (for state snapshots)
   * @param {object[]} params.events - Captured session events
   * @param {object} [params.sessionMeta] - Session metadata
   * @param {string} [params.scenarioName] - Scenario that was recorded
   * @param {string[]} [params.scenarioTags] - Tags for categorization
   * @returns {object} The built manifest (frozen)
   */
  build(params = {}) {
    const {
      config = {},
      ctx = {},
      events = [],
      sessionMeta = {},
      scenarioName = 'unnamed',
      scenarioTags = [],
    } = params;

    const replayId = `RPL-${crypto.randomUUID().substring(0, 12)}`;
    const timestampUtc = new Date().toISOString();
    const fingerprint = buildFingerprint(config);
    const environment = buildEnvironment(config);

    // State snapshot (optional, controlled by options)
    let internalState = {};
    let stateHash = null;
    if (this.options.includeStateSnapshots) {
      internalState = buildStateSnapshot(ctx);
      stateHash = this._hashObject(internalState);
    }

    // Session timestamps
    const sessionTimestamps = {
      session_start: sessionMeta.sessionStart || null,
      session_end: sessionMeta.sessionEnd || Date.now(),
      manifest_built_at: Date.now(),
    };

    // Cookie/storage metadata (redacted)
    const storageMeta = this._buildStorageMeta(events);

    // Network summary
    const networkSummary = this._buildNetworkSummary(events);

    // Build artifact index
    const artifactIndex = this._buildArtifactIndex(events, internalState);

    // Compute artifact hash
    const artifactHash = this._hashObject({
      events_count: events.length,
      fingerprint,
      sessionTimestamps,
      stateHash,
    });

    const manifest = {
      schema_name: 'replay_manifest_v1',
      replay_id: replayId,
      boqa_version: fingerprint.boqa_version,
      node_version: fingerprint.node_version,
      playwright_version: fingerprint.playwright_version,
      chromium_version: fingerprint.chromium_version,
      os_version: fingerprint.os_version,
      timestamp_utc: timestampUtc,
      target_domain: environment.target_domain,
      scenario_name: scenarioName,
      scenario_tags: scenarioTags,
      config: environment.config_flags,
      environment: environment.environment_variables,
      fingerprint,
      session_timestamps: sessionTimestamps,
      storage_meta: storageMeta,
      network_summary: networkSummary,
      internal_state: internalState,
      state_hash: stateHash,
      artifact_index: artifactIndex,
      artifact_hash: artifactHash,
      events_count: events.length,
      signature: null, // to be set by ReplaySecurityGuard
      redaction_summary: {
        cookie_values_redacted: this.options.redactSecrets,
        token_values_redacted: this.options.redactSecrets,
        secrets_in_plaintext: false,
      },
    };

    // Freeze the manifest — immutable after build
    const frozen = deepFreeze(manifest);
    this.manifests.set(replayId, frozen);
    return frozen;
  }

  /**
   * Build manifest from an existing session export.
   *
   * @param {object} sessionExport - Output from bus.exportSession()
   * @param {object} config - BOQA config
   * @param {object} ctx - Engine context
   * @returns {object} Manifest
   */
  buildFromSession(sessionExport, config = {}, ctx = {}) {
    return this.build({
      config,
      ctx,
      events: sessionExport.events || [],
      sessionMeta: {
        sessionStart: sessionExport.sessionStart,
        sessionEnd: sessionExport.sessionEnd,
      },
      scenarioName: `session-${sessionExport.id?.substring(0, 8) || 'unknown'}`,
    });
  }

  /**
   * Persist manifest to disk.
   *
   * @param {object} manifest - The manifest to save
   * @param {string} [filename] - Optional custom filename
   * @returns {string} Path to saved file
   */
  save(manifest, filename) {
    const fn = filename || `manifest-${manifest.replay_id}-${Date.now()}.json`;
    const filePath = path.join(MANIFESTS_DIR, fn);
    fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2));
    return filePath;
  }

  /**
   * Save state snapshot separately.
   *
   * @param {object} manifest - The manifest whose state to save
   * @returns {string} Path to saved snapshot
   */
  saveStateSnapshot(manifest) {
    const fn = `snapshot-${manifest.replay_id}-${Date.now()}.json`;
    const filePath = path.join(SNAPSHOTS_DIR, fn);
    fs.writeFileSync(filePath, JSON.stringify(manifest.internal_state, null, 2));
    return filePath;
  }

  /**
   * Load a manifest from disk.
   *
   * @param {string} filePath - Path to manifest JSON
   * @returns {object} Manifest
   */
  load(filePath) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (data.schema_name !== 'replay_manifest_v1') {
      throw new Error(`Invalid manifest schema: ${data.schema_name}`);
    }
    return data;
  }

  /**
   * Get a previously built manifest by replay ID.
   */
  getManifest(replayId) {
    return this.manifests.get(replayId);
  }

  /**
   * List all in-memory manifests.
   */
  listManifests() {
    return [...this.manifests.values()].map(m => ({
      replay_id: m.replay_id,
      scenario_name: m.scenario_name,
      timestamp_utc: m.timestamp_utc,
      events_count: m.events_count,
      target_domain: m.target_domain,
      state_hash: m.state_hash,
    }));
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  _buildStorageMeta(events) {
    const meta = {
      cookies_count: 0,
      localStorage_keys: [],
      sessionStorage_keys: [],
      indexeddb_databases: [],
    };

    for (const e of events) {
      if (e.type === 'cookie_snapshot' && e.meta?.authCookies) {
        meta.cookies_count += e.meta.authCookies.length;
      }
      if (e.type === 'console_log' && e.payload) {
        const payloadStr = typeof e.payload === 'string' ? e.payload : JSON.stringify(e.payload);
        if (payloadStr.includes('localStorage')) {
          meta.localStorage_keys.push('(redacted)');
        }
        if (payloadStr.includes('sessionStorage')) {
          meta.sessionStorage_keys.push('(redacted)');
        }
      }
    }

    // Deduplicate and cap
    meta.localStorage_keys = [...new Set(meta.localStorage_keys)].slice(0, 50);
    meta.sessionStorage_keys = [...new Set(meta.sessionStorage_keys)].slice(0, 50);

    return meta;
  }

  _buildNetworkSummary(events) {
    const summary = {
      total_requests: 0,
      total_responses: 0,
      total_websocket_frames: 0,
      total_redirects: 0,
      status_codes: {},
      auth_requests: 0,
    };

    for (const e of events) {
      if (e.type === 'network_request') {
        summary.total_requests++;
        if (this._isAuthEvent(e)) summary.auth_requests++;
      }
      if (e.type === 'network_response') {
        summary.total_responses++;
        if (e.status) {
          summary.status_codes[e.status] = (summary.status_codes[e.status] || 0) + 1;
        }
        if (e.status && e.status >= 300 && e.status < 400) {
          summary.total_redirects++;
        }
      }
      if (e.type === 'websocket_message_in' || e.type === 'websocket_message_out') {
        summary.total_websocket_frames++;
      }
    }

    return summary;
  }

  _isAuthEvent(event) {
    const url = event.url || '';
    return /\/auth\/|\/login|\/logout|\/token|\/session|\/2fa|\/verify|\/api\/users\/me/.test(url) ||
      (event.headers && event.headers['authorization']) ||
      (event.headers && event.headers['x-csrftoken']);
  }

  _buildArtifactIndex(events, internalState) {
    return {
      events_file: null, // set by recorder when saved
      snapshot_file: null, // set when snapshot is saved
      screenshot_count: events.filter(e => e.type === 'page_navigation').length,
      dom_snapshot_count: events.filter(e => e.type === 'page_navigation').length,
      network_trace_entries: events.filter(e =>
        e.type === 'network_request' || e.type === 'network_response'
      ).length,
      state_snapshot_included: Object.keys(internalState).length > 0,
    };
  }

  _hashObject(obj) {
    if (!obj || typeof obj !== 'object') return null;
    const content = JSON.stringify(obj, Object.keys(obj).sort());
    return crypto.createHash('sha256').update(content).digest('hex');
  }
}

// ─── Utility ───────────────────────────────────────────────────────

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === 'object' && val !== null && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

module.exports = {
  ReplayManifestBuilder,
  MANIFESTS_DIR,
  SNAPSHOTS_DIR,
  buildFingerprint,
  buildEnvironment,
  buildStateSnapshot,
};


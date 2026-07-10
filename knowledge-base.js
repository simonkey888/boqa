/**
 * BOQA knowledge-base.js — Persistent Memory v0.6
 *
 * Central knowledge store for all observations, findings, assets,
 * historical validations, session metadata, and cross-session
 * intelligence. Every engine in the Autonomous Discovery pipeline
 * reads from and writes to this store.
 *
 * Storage tiers:
 *   - In-memory hot cache (current session observations)
 *   - On-disk SQLite-style JSON files (persistent history)
 *
 * Data domains:
 *   - observations: raw event-derived observations
 *   - findings: deduplicated, ranked findings
 *   - assets: endpoint, cookie, auth, websocket inventories
 *   - validations: historical verification results
 *   - hypotheses: generated and tested hypotheses
 *   - sessions: session metadata and coverage snapshots
 *   - coverage: per-target coverage maps
 *
 * Safe mode: all data is read-only observability data; no PII
 * is persisted beyond what the authorized instrumentation captures.
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Persistence Directory ──────────────────────────────────────────

const KB_DIR = path.join(__dirname, 'output', 'knowledge');
const OBS_DIR = path.join(KB_DIR, 'observations');
const FINDINGS_FILE = path.join(KB_DIR, 'findings.json');
const ASSETS_FILE = path.join(KB_DIR, 'assets.json');
const VALIDATIONS_FILE = path.join(KB_DIR, 'validations.json');
const HYPOTHESES_FILE = path.join(KB_DIR, 'hypotheses.json');
const SESSIONS_FILE = path.join(KB_DIR, 'sessions.json');
const COVERAGE_FILE = path.join(KB_DIR, 'coverage.json');
const METRICS_FILE = path.join(KB_DIR, 'metrics.json');

// ─── Defaults ───────────────────────────────────────────────────────

const MAX_OBSERVATIONS_PER_TARGET = 50000;
const MAX_FINDINGS = 10000;
const MAX_HYPOTHESES = 5000;
const MAX_SESSIONS = 1000;
const MAX_VALIDATIONS = 10000;

// =====================================================================
//  KnowledgeBase
// =====================================================================

class KnowledgeBase {
  /**
   * @param {object} options
   * @param {number} [options.maxObservations] - max observations per target
   * @param {number} [options.maxFindings]     - max findings stored
   * @param {number} [options.maxHypotheses]   - max hypotheses stored
   */
  constructor(options = {}) {
    this.maxObservations = options.maxObservations || MAX_OBSERVATIONS_PER_TARGET;
    this.maxFindings = options.maxFindings || MAX_FINDINGS;
    this.maxHypotheses = options.maxHypotheses || MAX_HYPOTHESES;

    // ── In-memory stores ──────────────────────────────────────────
    /** @type {Map<string, object[]>} target_id → observations */
    this.observations = new Map();

    /** @type {Map<string, object>} finding_id → finding */
    this.findings = new Map();

    /** @type {Map<string, object>} target_id → asset inventory */
    this.assets = new Map();

    /** @type {Map<string, object>} validation_id → result */
    this.validations = new Map();

    /** @type {Map<string, object>} hypothesis_id → hypothesis */
    this.hypotheses = new Map();

    /** @type {Map<string, object>} session_id → metadata */
    this.sessions = new Map();

    /** @type {Map<string, object>} target_id → coverage map */
    this.coverage = new Map();

    /** @type {object} aggregate metrics */
    this.metrics = {
      total_observations: 0,
      total_findings: 0,
      total_validations: 0,
      total_hypotheses: 0,
      validated_bugs_per_hour: 0,
      false_positive_rate: 0,
      coverage_score: 0,
      evidence_completeness: 0,
      mean_time_to_confirmation_ms: 0,
      discovery_start: null,
    };

    // Ensure directories exist
    for (const dir of [KB_DIR, OBS_DIR]) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Auto-load from disk
    this.load();
  }

  // ─── Observations ────────────────────────────────────────────────

  /**
   * Record a new observation from the event stream.
   * Observations are keyed by target_id and capped at maxObservations.
   *
   * @param {string} targetId
   * @param {object} observation - { type, url, method, status, headers, payload, meta, ts }
   * @returns {object} the stored observation (with generated id)
   */
  addObservation(targetId, observation) {
    if (!this.observations.has(targetId)) {
      this.observations.set(targetId, []);
    }

    const obs = {
      id: `OBS-${crypto.randomUUID().substring(0, 8)}`,
      target_id: targetId,
      ts: observation.ts || Date.now(),
      type: observation.type || 'unknown',
      url: observation.url || null,
      method: observation.method || null,
      status: observation.status || null,
      headers: observation.headers || null,
      payload: observation.payload || null,
      meta: observation.meta || {},
    };

    const list = this.observations.get(targetId);
    list.push(obs);
    this.metrics.total_observations++;

    // Cap the list
    if (list.length > this.maxObservations) {
      list.splice(0, list.length - this.maxObservations);
    }

    return obs;
  }

  /**
   * Get observations for a target, optionally filtered.
   *
   * @param {string} targetId
   * @param {object} [filter] - { type, since, limit, offset }
   * @returns {object[]}
   */
  getObservations(targetId, filter = {}) {
    let list = this.observations.get(targetId) || [];

    if (filter.type) {
      list = list.filter(o => o.type === filter.type);
    }
    if (filter.since) {
      list = list.filter(o => o.ts >= filter.since);
    }

    const offset = filter.offset || 0;
    const limit = filter.limit || list.length;

    return list.slice(offset, offset + limit);
  }

  // ─── Findings ────────────────────────────────────────────────────

  /**
   * Store or update a finding.
   *
   * @param {object} finding
   * @returns {object} the stored finding
   */
  upsertFinding(finding) {
    const id = finding.finding_id || finding.id || `FND-${Date.now().toString(36)}`;
    const existing = this.findings.get(id);

    const stored = {
      ...finding,
      finding_id: id,
      updated_at: Date.now(),
      created_at: existing?.created_at || finding.created_at || Date.now(),
    };

    this.findings.set(id, stored);
    this.metrics.total_findings = this.findings.size;

    return stored;
  }

  /**
   * Get a finding by ID.
   * @param {string} findingId
   * @returns {object|null}
   */
  getFinding(findingId) {
    return this.findings.get(findingId) || null;
  }

  /**
   * Query findings with filters.
   *
   * @param {object} [filter] - { severity, category, lifecycle_state, target_id, limit }
   * @returns {object[]}
   */
  queryFindings(filter = {}) {
    let results = [...this.findings.values()];

    if (filter.severity) {
      results = results.filter(f => f.severity === filter.severity);
    }
    if (filter.category) {
      results = results.filter(f => f.category === filter.category);
    }
    if (filter.lifecycle_state) {
      results = results.filter(f => f.lifecycle_state === filter.lifecycle_state);
    }
    if (filter.target_id) {
      results = results.filter(f => f.target_id === filter.target_id);
    }

    // Sort by risk_score descending
    results.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

    return results.slice(0, filter.limit || results.length);
  }

  // ─── Assets ──────────────────────────────────────────────────────

  /**
   * Store or update the asset inventory for a target.
   *
   * @param {string} targetId
   * @param {object} assetInventory - { endpoints, cookies, auth_flows, websockets, forms, state_transitions }
   * @returns {object}
   */
  upsertAssets(targetId, assetInventory) {
    const existing = this.assets.get(targetId) || {};

    const stored = {
      target_id: targetId,
      endpoints: assetInventory.endpoints || existing.endpoints || [],
      cookies: assetInventory.cookies || existing.cookies || [],
      auth_flows: assetInventory.auth_flows || existing.auth_flows || [],
      websockets: assetInventory.websockets || existing.websockets || [],
      forms: assetInventory.forms || existing.forms || [],
      state_transitions: assetInventory.state_transitions || existing.state_transitions || [],
      updated_at: Date.now(),
      created_at: existing.created_at || Date.now(),
    };

    this.assets.set(targetId, stored);
    return stored;
  }

  /**
   * Get the asset inventory for a target.
   * @param {string} targetId
   * @returns {object|null}
   */
  getAssets(targetId) {
    return this.assets.get(targetId) || null;
  }

  // ─── Validations ─────────────────────────────────────────────────

  /**
   * Store a validation result.
   *
   * @param {object} validation - { finding_id, verdict, evidence, duration_ms, worker_id }
   * @returns {object}
   */
  addValidation(validation) {
    const id = validation.id || `VAL-${crypto.randomUUID().substring(0, 8)}`;
    const stored = {
      id,
      finding_id: validation.finding_id,
      verdict: validation.verdict || 'unknown', // confirmed, rejected, inconclusive
      evidence: validation.evidence || [],
      duration_ms: validation.duration_ms || 0,
      worker_id: validation.worker_id || null,
      ts: Date.now(),
      meta: validation.meta || {},
    };

    this.validations.set(id, stored);
    this.metrics.total_validations = this.validations.size;

    // Update false positive rate
    this._recomputeMetrics();

    return stored;
  }

  /**
   * Get validation results for a finding.
   * @param {string} findingId
   * @returns {object[]}
   */
  getValidationsForFinding(findingId) {
    const results = [];
    for (const v of this.validations.values()) {
      if (v.finding_id === findingId) results.push(v);
    }
    return results.sort((a, b) => b.ts - a.ts);
  }

  // ─── Hypotheses ──────────────────────────────────────────────────

  /**
   * Store or update a hypothesis.
   *
   * @param {object} hypothesis
   * @returns {object}
   */
  upsertHypothesis(hypothesis) {
    const id = hypothesis.id || `HYP-${Date.now().toString(36)}`;
    const existing = this.hypotheses.get(id);

    const stored = {
      ...hypothesis,
      id,
      updated_at: Date.now(),
      created_at: existing?.created_at || hypothesis.created_at || Date.now(),
    };

    this.hypotheses.set(id, stored);
    this.metrics.total_hypotheses = this.hypotheses.size;

    return stored;
  }

  /**
   * Get a hypothesis by ID.
   * @param {string} id
   * @returns {object|null}
   */
  getHypothesis(id) {
    return this.hypotheses.get(id) || null;
  }

  /**
   * Query hypotheses.
   * @param {object} [filter] - { status, target_id, min_score, limit }
   * @returns {object[]}
   */
  queryHypotheses(filter = {}) {
    let results = [...this.hypotheses.values()];

    if (filter.status) {
      results = results.filter(h => h.status === filter.status);
    }
    if (filter.target_id) {
      results = results.filter(h => h.target_id === filter.target_id);
    }
    if (filter.min_score) {
      results = results.filter(h => (h.expected_value || 0) >= filter.min_score);
    }

    results.sort((a, b) => (b.expected_value || 0) - (a.expected_value || 0));
    return results.slice(0, filter.limit || results.length);
  }

  // ─── Sessions ────────────────────────────────────────────────────

  /**
   * Store session metadata.
   *
   * @param {object} session - { session_id, target_id, mode, start, end, coverage_score }
   * @returns {object}
   */
  addSession(session) {
    const id = session.session_id || `SES-${Date.now().toString(36)}`;
    const stored = {
      ...session,
      session_id: id,
      stored_at: Date.now(),
    };

    this.sessions.set(id, stored);

    // Cap sessions
    if (this.sessions.size > MAX_SESSIONS) {
      const oldest = [...this.sessions.entries()]
        .sort((a, b) => (a[1].stored_at || 0) - (b[1].stored_at || 0));
      for (let i = 0; i < oldest.length - MAX_SESSIONS; i++) {
        this.sessions.delete(oldest[i][0]);
      }
    }

    return stored;
  }

  /**
   * Get sessions, optionally filtered by target.
   * @param {string} [targetId]
   * @returns {object[]}
   */
  getSessions(targetId) {
    let results = [...this.sessions.values()];
    if (targetId) {
      results = results.filter(s => s.target_id === targetId);
    }
    return results.sort((a, b) => (b.start || 0) - (a.start || 0));
  }

  // ─── Coverage ────────────────────────────────────────────────────

  /**
   * Store or update the coverage map for a target.
   *
   * @param {string} targetId
   * @param {object} coverageMap - { routes, api_endpoints, auth_flows, websockets, forms, state_transitions, score }
   * @returns {object}
   */
  upsertCoverage(targetId, coverageMap) {
    const existing = this.coverage.get(targetId) || {};

    const stored = {
      target_id: targetId,
      routes: coverageMap.routes || existing.routes || [],
      api_endpoints: coverageMap.api_endpoints || existing.api_endpoints || [],
      auth_flows: coverageMap.auth_flows || existing.auth_flows || [],
      websockets: coverageMap.websockets || existing.websockets || [],
      forms: coverageMap.forms || existing.forms || [],
      state_transitions: coverageMap.state_transitions || existing.state_transitions || [],
      score: coverageMap.score ?? existing.score ?? 0,
      discovered_at: coverageMap.discovered_at || existing.discovered_at || Date.now(),
      updated_at: Date.now(),
    };

    this.coverage.set(targetId, stored);
    this.metrics.coverage_score = stored.score;
    return stored;
  }

  /**
   * Get the coverage map for a target.
   * @param {string} targetId
   * @returns {object|null}
   */
  getCoverage(targetId) {
    return this.coverage.get(targetId) || null;
  }

  // ─── Historical Queries ──────────────────────────────────────────

  /**
   * Find findings similar to the given observation across all targets.
   * Uses category + affected_cookies/endpoint overlap for matching.
   *
   * @param {object} observation
   * @param {number} [limit=10]
   * @returns {object[]} matching findings with similarity score
   */
  findSimilarHistorical(observation, limit = 10) {
    const scored = [];
    const obsCookies = new Set(observation.affected_cookies || observation.cookies || []);
    const obsEndpoints = new Set((observation.affected_endpoints || observation.endpoints || [])
      .map(e => {
        try { return new URL(e).pathname; } catch { return e; }
      }));

    for (const [, finding] of this.findings) {
      // Category match
      const categoryMatch = (finding.category || '').toLowerCase() ===
        (observation.category || '').toLowerCase() ? 1 : 0;

      // Cookie overlap
      const fCookies = new Set(finding.affected_cookies || []);
      let cookieOverlap = 0;
      if (obsCookies.size > 0 && fCookies.size > 0) {
        let intersection = 0;
        for (const c of obsCookies) { if (fCookies.has(c)) intersection++; }
        cookieOverlap = intersection / (obsCookies.size + fCookies.size - intersection);
      }

      // Endpoint overlap
      const fEndpoints = new Set((finding.affected_endpoints || [])
        .map(e => {
          try { return new URL(e).pathname; } catch { return e; }
        }));
      let endpointOverlap = 0;
      if (obsEndpoints.size > 0 && fEndpoints.size > 0) {
        let intersection = 0;
        for (const e of obsEndpoints) { if (fEndpoints.has(e)) intersection++; }
        endpointOverlap = intersection / (obsEndpoints.size + fEndpoints.size - intersection);
      }

      const similarity = categoryMatch * 0.4 + cookieOverlap * 0.3 + endpointOverlap * 0.3;
      if (similarity > 0.2) {
        scored.push({ finding: { ...finding }, similarity });
      }
    }

    scored.sort((a, b) => b.similarity - a.similarity);
    return scored.slice(0, limit);
  }

  /**
   * Get validation success rate for a category.
   * @param {string} category
   * @returns {number} 0-1 success rate
   */
  getHistoricalValidationRate(category) {
    let total = 0;
    let confirmed = 0;

    for (const v of this.validations.values()) {
      const finding = this.findings.get(v.finding_id);
      if (finding && (finding.category || '').toLowerCase() === (category || '').toLowerCase()) {
        total++;
        if (v.verdict === 'confirmed') confirmed++;
      }
    }

    return total > 0 ? confirmed / total : 0;
  }

  // ─── Metrics ─────────────────────────────────────────────────────

  /**
   * Compute and return aggregate metrics.
   * @returns {object}
   */
  getMetrics() {
    this._recomputeMetrics();
    return { ...this.metrics };
  }

  /**
   * Recompute derived metrics from current data.
   * @private
   */
  _recomputeMetrics() {
    // False positive rate
    const totalValidations = this.validations.size;
    if (totalValidations > 0) {
      let rejected = 0;
      for (const v of this.validations.values()) {
        if (v.verdict === 'rejected') rejected++;
      }
      this.metrics.false_positive_rate = Math.round((rejected / totalValidations) * 10000) / 10000;
    }

    // Evidence completeness (average across findings)
    if (this.findings.size > 0) {
      let totalEvidence = 0;
      for (const f of this.findings.values()) {
        const evCount = f.evidence_count || f.evidence?.length || 0;
        totalEvidence += Math.min(evCount / 5, 1.0); // 5 evidence items = 100%
      }
      this.metrics.evidence_completeness = Math.round((totalEvidence / this.findings.size) * 100);
    }

    // Mean time to confirmation
    let totalConfirmationTime = 0;
    let confirmedCount = 0;
    for (const f of this.findings.values()) {
      if (f.confirmed_at && f.created_at) {
        totalConfirmationTime += (f.confirmed_at - f.created_at);
        confirmedCount++;
      }
    }
    if (confirmedCount > 0) {
      this.metrics.mean_time_to_confirmation_ms = Math.round(totalConfirmationTime / confirmedCount);
    }

    // Validated bugs per hour
    if (this.metrics.discovery_start) {
      const hoursElapsed = (Date.now() - this.metrics.discovery_start) / (1000 * 60 * 60);
      if (hoursElapsed > 0) {
        const confirmedBugs = [...this.findings.values()]
          .filter(f => f.lifecycle_state === 'confirmed' || f.lifecycle_state === 'ranked').length;
        this.metrics.validated_bugs_per_hour = Math.round(confirmedBugs / hoursElapsed * 100) / 100;
      }
    }
  }

  // ─── Persistence ─────────────────────────────────────────────────

  /**
   * Save all knowledge to disk.
   * @returns {object} paths written
   */
  save() {
    const paths = {};

    // Findings
    const findingsData = {
      version: '0.6',
      saved_at: Date.now(),
      findings: [...this.findings.values()],
    };
    fs.writeFileSync(FINDINGS_FILE, JSON.stringify(findingsData, null, 2));
    paths.findings = FINDINGS_FILE;

    // Assets
    const assetsData = {
      version: '0.6',
      saved_at: Date.now(),
      assets: [...this.assets.values()],
    };
    fs.writeFileSync(ASSETS_FILE, JSON.stringify(assetsData, null, 2));
    paths.assets = ASSETS_FILE;

    // Validations
    const validationsData = {
      version: '0.6',
      saved_at: Date.now(),
      validations: [...this.validations.values()],
    };
    fs.writeFileSync(VALIDATIONS_FILE, JSON.stringify(validationsData, null, 2));
    paths.validations = VALIDATIONS_FILE;

    // Hypotheses
    const hypothesesData = {
      version: '0.6',
      saved_at: Date.now(),
      hypotheses: [...this.hypotheses.values()],
    };
    fs.writeFileSync(HYPOTHESES_FILE, JSON.stringify(hypothesesData, null, 2));
    paths.hypotheses = HYPOTHESES_FILE;

    // Sessions
    const sessionsData = {
      version: '0.6',
      saved_at: Date.now(),
      sessions: [...this.sessions.values()],
    };
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessionsData, null, 2));
    paths.sessions = SESSIONS_FILE;

    // Coverage
    const coverageData = {
      version: '0.6',
      saved_at: Date.now(),
      coverage: [...this.coverage.values()],
    };
    fs.writeFileSync(COVERAGE_FILE, JSON.stringify(coverageData, null, 2));
    paths.coverage = COVERAGE_FILE;

    // Metrics
    fs.writeFileSync(METRICS_FILE, JSON.stringify(this.getMetrics(), null, 2));
    paths.metrics = METRICS_FILE;

    return paths;
  }

  /**
   * Load all knowledge from disk.
   * @returns {boolean}
   */
  load() {
    let loaded = false;

    // Findings
    if (fs.existsSync(FINDINGS_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(FINDINGS_FILE, 'utf8'));
        for (const f of (data.findings || [])) {
          this.findings.set(f.finding_id, f);
        }
        this.metrics.total_findings = this.findings.size;
        loaded = true;
      } catch (_) {}
    }

    // Assets
    if (fs.existsSync(ASSETS_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(ASSETS_FILE, 'utf8'));
        for (const a of (data.assets || [])) {
          this.assets.set(a.target_id, a);
        }
        loaded = true;
      } catch (_) {}
    }

    // Validations
    if (fs.existsSync(VALIDATIONS_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(VALIDATIONS_FILE, 'utf8'));
        for (const v of (data.validations || [])) {
          this.validations.set(v.id, v);
        }
        this.metrics.total_validations = this.validations.size;
        loaded = true;
      } catch (_) {}
    }

    // Hypotheses
    if (fs.existsSync(HYPOTHESES_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(HYPOTHESES_FILE, 'utf8'));
        for (const h of (data.hypotheses || [])) {
          this.hypotheses.set(h.id, h);
        }
        this.metrics.total_hypotheses = this.hypotheses.size;
        loaded = true;
      } catch (_) {}
    }

    // Sessions
    if (fs.existsSync(SESSIONS_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
        for (const s of (data.sessions || [])) {
          this.sessions.set(s.session_id, s);
        }
        loaded = true;
      } catch (_) {}
    }

    // Coverage
    if (fs.existsSync(COVERAGE_FILE)) {
      try {
        const data = JSON.parse(fs.readFileSync(COVERAGE_FILE, 'utf8'));
        for (const c of (data.coverage || [])) {
          this.coverage.set(c.target_id, c);
        }
        loaded = true;
      } catch (_) {}
    }

    if (loaded) {
      this._recomputeMetrics();
    }

    return loaded;
  }

  // ─── P5: Replay Metadata as First-Class Nodes ────────────────────

  /**
   * Store replay metadata as a first-class knowledge node.
   * Enables searching by version, context, and state hash.
   *
   * @param {object} manifest - Replay manifest
   * @returns {object} Stored replay node
   */
  addReplayNode(manifest) {
    const id = manifest.replay_id || `RPL-${Date.now().toString(36)}`;
    const node = {
      id,
      type: 'replay_node',
      boqa_version: manifest.boqa_version || 'unknown',
      target_domain: manifest.target_domain || 'unknown',
      scenario_name: manifest.scenario_name || 'unnamed',
      scenario_tags: manifest.scenario_tags || [],
      timestamp_utc: manifest.timestamp_utc || new Date().toISOString(),
      events_count: manifest.events_count || 0,
      state_hash: manifest.state_hash || null,
      artifact_hash: manifest.artifact_hash || null,
      cevi_band: manifest.internal_state?.cevi_state?.class || null,
      autonomy_level: manifest.internal_state?.autonomy_governor_state?.current_level || null,
      stored_at: Date.now(),
    };

    // Store as a session with replay metadata
    this.sessions.set(id, {
      session_id: id,
      target_id: manifest.target_domain,
      mode: 'replay',
      start: new Date(manifest.timestamp_utc || Date.now()).getTime(),
      coverage_score: 0,
      replay_metadata: node,
    });

    return node;
  }

  /**
   * Search for replay nodes by version and context.
   *
   * @param {object} filter - { boqa_version, target_domain, scenario_name, state_hash }
   * @returns {object[]} Matching replay nodes
   */
  queryReplayNodes(filter = {}) {
    const results = [];

    for (const [, session] of this.sessions) {
      if (!session.replay_metadata) continue;

      const meta = session.replay_metadata;
      let match = true;

      if (filter.boqa_version && meta.boqa_version !== filter.boqa_version) match = false;
      if (filter.target_domain && meta.target_domain !== filter.target_domain) match = false;
      if (filter.scenario_name && meta.scenario_name !== filter.scenario_name) match = false;
      if (filter.state_hash && meta.state_hash !== filter.state_hash) match = false;

      if (match) results.push(meta);
    }

    return results.sort((a, b) => (b.stored_at || 0) - (a.stored_at || 0));
  }

  /**
   * Clear all in-memory state.
   */
  reset() {
    this.observations.clear();
    this.findings.clear();
    this.assets.clear();
    this.validations.clear();
    this.hypotheses.clear();
    this.sessions.clear();
    this.coverage.clear();
    this.metrics = {
      total_observations: 0,
      total_findings: 0,
      total_validations: 0,
      total_hypotheses: 0,
      validated_bugs_per_hour: 0,
      false_positive_rate: 0,
      coverage_score: 0,
      evidence_completeness: 0,
      mean_time_to_confirmation_ms: 0,
      discovery_start: null,
    };
  }

  /**
   * Get a summary of all knowledge domains.
   * @returns {object}
   */
  getSummary() {
    return {
      observations: [...this.observations.values()].reduce((sum, list) => sum + list.length, 0),
      findings: this.findings.size,
      assets: this.assets.size,
      validations: this.validations.size,
      hypotheses: this.hypotheses.size,
      sessions: this.sessions.size,
      coverage_maps: this.coverage.size,
      metrics: this.getMetrics(),
    };
  }
}

module.exports = { KnowledgeBase };


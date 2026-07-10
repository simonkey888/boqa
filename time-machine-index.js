/**
 * BOQA time-machine-index.js — TimeMachineIndex v1.5 (P5)
 *
 * Indexes replay artifacts by version, target, scenario, state hash,
 * and timestamp for forensic search across time. Enables:
 *
 *   - Find all replays for a given target domain
 *   - Compare replays across BOQA versions
 *   - Find replays where a specific engine's state changed
 *   - Track scenario execution over time
 *   - Detect environment drift across replays
 *   - Forensic comparison: "what changed between these two timestamps?"
 *
 * Search dimensions:
 *   boqa_version, playwright_version, chromium_version,
 *   target_domain, scenario_tag, decision_id, cevi_band
 *
 * Safe mode: read-only index, no live execution.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');
const INDEX_DIR = path.join(REPLAYS_DIR, 'indexes');

fs.mkdirSync(INDEX_DIR, { recursive: true });

// ─── Index Entry ───────────────────────────────────────────────────

// {
//   replay_id: string,
//   boqa_version: string,
//   node_version: string,
//   playwright_version: string,
//   chromium_version: string,
//   os_version: string,
//   target_domain: string,
//   scenario_name: string,
//   scenario_tags: string[],
//   timestamp_utc: string,
//   timestamp_epoch: number,
//   events_count: number,
//   state_hash: string,
//   artifact_hash: string,
//   manifest_path: string,
//   recording_path: string,
//   cevi_band: string | null,
//   autonomy_level: string | null,
//   decision_count: number,
//   verified: boolean,
//   verification_score: number | null,
// }

// ─── TimeMachineIndex ──────────────────────────────────────────────

class TimeMachineIndex {
  /**
   * @param {object} options
   * @param {string} [options.indexDir] - Directory for index persistence
   */
  constructor(options = {}) {
    this.indexDir = options.indexDir || INDEX_DIR;
    this.index = []; // array of index entries
    this.byReplayId = new Map(); // replayId → index entry
    this.byDomain = new Map(); // domain → Set<replayId>
    this.byVersion = new Map(); // boqaVersion → Set<replayId>
    this.byScenario = new Map(); // scenarioName → Set<replayId>
    this.byTag = new Map(); // tag → Set<replayId>
    this.byStateHash = new Map(); // stateHash → Set<replayId>

    // Load from disk
    this._load();
  }

  /**
   * Index a replay artifact.
   *
   * @param {object} manifest - Replay manifest
   * @param {string} [manifestPath] - Path to manifest file
   * @param {string} [recordingPath] - Path to recording file
   * @param {object} [verificationResult] - Verification result if available
   * @returns {object} Index entry
   */
  indexReplay(manifest, manifestPath, recordingPath, verificationResult = null) {
    const entry = {
      replay_id: manifest.replay_id,
      boqa_version: manifest.boqa_version || 'unknown',
      node_version: manifest.node_version || 'unknown',
      playwright_version: manifest.playwright_version || 'unknown',
      chromium_version: manifest.chromium_version || 'unknown',
      os_version: manifest.os_version || 'unknown',
      target_domain: manifest.target_domain || 'unknown',
      scenario_name: manifest.scenario_name || 'unnamed',
      scenario_tags: manifest.scenario_tags || [],
      timestamp_utc: manifest.timestamp_utc || new Date().toISOString(),
      timestamp_epoch: new Date(manifest.timestamp_utc || Date.now()).getTime(),
      events_count: manifest.events_count || 0,
      state_hash: manifest.state_hash || null,
      artifact_hash: manifest.artifact_hash || null,
      manifest_path: manifestPath || null,
      recording_path: recordingPath || null,
      cevi_band: manifest.internal_state?.cevi_state?.class || null,
      autonomy_level: manifest.internal_state?.autonomy_governor_state?.current_level || null,
      decision_count: manifest.internal_state?.autonomy_governor_state?.total_decisions || 0,
      verified: verificationResult !== null,
      verification_score: verificationResult?.composite_score || null,
      indexed_at: Date.now(),
    };

    // Add to main index
    this.index.push(entry);
    this.byReplayId.set(entry.replay_id, entry);

    // Update secondary indexes
    this._addToIndex(this.byDomain, entry.target_domain, entry.replay_id);
    this._addToIndex(this.byVersion, entry.boqa_version, entry.replay_id);
    this._addToIndex(this.byScenario, entry.scenario_name, entry.replay_id);
    for (const tag of entry.scenario_tags) {
      this._addToIndex(this.byTag, tag, entry.replay_id);
    }
    if (entry.state_hash) {
      this._addToIndex(this.byStateHash, entry.state_hash, entry.replay_id);
    }

    return entry;
  }

  /**
   * Search the index.
   *
   * @param {object} query
   * @param {string} [query.target_domain] - Filter by target domain
   * @param {string} [query.boqa_version] - Filter by BOQA version
   * @param {string} [query.scenario_name] - Filter by scenario name
   * @param {string} [query.scenario_tag] - Filter by scenario tag
   * @param {string} [query.state_hash] - Filter by state hash
   * @param {string} [query.cevi_band] - Filter by CEVI band
   * @param {string} [query.autonomy_level] - Filter by autonomy level
   * @param {number} [query.from_epoch] - Start timestamp
   * @param {number} [query.to_epoch] - End timestamp
   * @param {number} [query.limit=50] - Maximum results
   * @param {string} [query.sort='timestamp_desc'] - Sort order
   * @returns {object[]} Matching index entries
   */
  search(query = {}) {
    let results = [...this.index];

    if (query.target_domain) {
      results = results.filter(e => e.target_domain === query.target_domain);
    }
    if (query.boqa_version) {
      results = results.filter(e => e.boqa_version === query.boqa_version);
    }
    if (query.scenario_name) {
      results = results.filter(e => e.scenario_name === query.scenario_name);
    }
    if (query.scenario_tag) {
      results = results.filter(e => e.scenario_tags.includes(query.scenario_tag));
    }
    if (query.state_hash) {
      results = results.filter(e => e.state_hash === query.state_hash);
    }
    if (query.cevi_band) {
      results = results.filter(e => e.cevi_band === query.cevi_band);
    }
    if (query.autonomy_level) {
      results = results.filter(e => e.autonomy_level === query.autonomy_level);
    }
    if (query.from_epoch) {
      results = results.filter(e => e.timestamp_epoch >= query.from_epoch);
    }
    if (query.to_epoch) {
      results = results.filter(e => e.timestamp_epoch <= query.to_epoch);
    }

    // Sort
    const sortOrder = query.sort || 'timestamp_desc';
    switch (sortOrder) {
      case 'timestamp_desc':
        results.sort((a, b) => b.timestamp_epoch - a.timestamp_epoch);
        break;
      case 'timestamp_asc':
        results.sort((a, b) => a.timestamp_epoch - b.timestamp_epoch);
        break;
      case 'events_desc':
        results.sort((a, b) => b.events_count - a.events_count);
        break;
      case 'verification_desc':
        results.sort((a, b) => (b.verification_score || 0) - (a.verification_score || 0));
        break;
    }

    return results.slice(0, query.limit || 50);
  }

  /**
   * Find replays that represent environment drift from a reference.
   *
   * @param {string} referenceReplayId - The reference replay ID
   * @param {object} [options] - { checkVersion, checkOs, checkFingerprint }
   * @returns {object[]} Drift entries
   */
  findDrift(referenceReplayId, options = {}) {
    const reference = this.byReplayId.get(referenceReplayId);
    if (!reference) return [];

    const driftEntries = [];

    for (const entry of this.index) {
      if (entry.replay_id === referenceReplayId) continue;
      if (entry.target_domain !== reference.target_domain) continue;

      const drifts = [];

      if (options.checkVersion !== false && entry.boqa_version !== reference.boqa_version) {
        drifts.push({ dimension: 'boqa_version', from: reference.boqa_version, to: entry.boqa_version });
      }
      if (options.checkOs !== false && entry.os_version !== reference.os_version) {
        drifts.push({ dimension: 'os_version', from: reference.os_version, to: entry.os_version });
      }
      if (options.checkFingerprint !== false && entry.playwright_version !== reference.playwright_version) {
        drifts.push({ dimension: 'playwright_version', from: reference.playwright_version, to: entry.playwright_version });
      }
      if (entry.state_hash !== reference.state_hash) {
        drifts.push({ dimension: 'state_hash', from: reference.state_hash, to: entry.state_hash });
      }

      if (drifts.length > 0) {
        driftEntries.push({ entry, drifts });
      }
    }

    return driftEntries;
  }

  /**
   * Compare two replays forensically.
   *
   * @param {string} replayIdA
   * @param {string} replayIdB
   * @returns {object} Forensic comparison
   */
  compare(replayIdA, replayIdB) {
    const a = this.byReplayId.get(replayIdA);
    const b = this.byReplayId.get(replayIdB);
    if (!a || !b) return null;

    const diffs = [];

    const fields = ['boqa_version', 'node_version', 'playwright_version', 'chromium_version',
      'os_version', 'target_domain', 'scenario_name', 'cevi_band', 'autonomy_level'];

    for (const field of fields) {
      if (a[field] !== b[field]) {
        diffs.push({ field, from: a[field], to: b[field] });
      }
    }

    // Time difference
    const timeDiffMs = Math.abs(a.timestamp_epoch - b.timestamp_epoch);

    return {
      replay_a: replayIdA,
      replay_b: replayIdB,
      time_diff_ms: timeDiffMs,
      time_diff_human: formatDuration(timeDiffMs),
      events_diff: a.events_count - b.events_count,
      decisions_diff: a.decision_count - b.decision_count,
      same_state: a.state_hash === b.state_hash,
      same_artifact: a.artifact_hash === b.artifact_hash,
      diffs,
    };
  }

  /**
   * Get timeline of replays for a domain.
   *
   * @param {string} domain
   * @returns {object[]} Time-ordered entries
   */
  getTimeline(domain) {
    const ids = this.byDomain.get(domain);
    if (!ids) return [];

    return [...ids]
      .map(id => this.byReplayId.get(id))
      .filter(Boolean)
      .sort((a, b) => a.timestamp_epoch - b.timestamp_epoch);
  }

  /**
   * Persist index to disk.
   */
  save() {
    const data = {
      version: '1.5',
      saved_at: Date.now(),
      entries: this.index,
    };
    const filePath = path.join(this.indexDir, 'time-machine-index.json');
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Get index statistics.
   */
  getStats() {
    return {
      total_entries: this.index.length,
      unique_domains: this.byDomain.size,
      unique_versions: this.byVersion.size,
      unique_scenarios: this.byScenario.size,
      unique_state_hashes: this.byStateHash.size,
      verified_count: this.index.filter(e => e.verified).length,
    };
  }

  /**
   * Reset all index data.
   */
  reset() {
    this.index = [];
    this.byReplayId.clear();
    this.byDomain.clear();
    this.byVersion.clear();
    this.byScenario.clear();
    this.byTag.clear();
    this.byStateHash.clear();
  }

  // ─── Internal ────────────────────────────────────────────────────

  _addToIndex(indexMap, key, value) {
    if (!indexMap.has(key)) {
      indexMap.set(key, new Set());
    }
    indexMap.get(key).add(value);
  }

  _load() {
    const filePath = path.join(this.indexDir, 'time-machine-index.json');
    if (!fs.existsSync(filePath)) return;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      for (const entry of (data.entries || [])) {
        this.index.push(entry);
        this.byReplayId.set(entry.replay_id, entry);
        this._addToIndex(this.byDomain, entry.target_domain, entry.replay_id);
        this._addToIndex(this.byVersion, entry.boqa_version, entry.replay_id);
        this._addToIndex(this.byScenario, entry.scenario_name, entry.replay_id);
        for (const tag of (entry.scenario_tags || [])) {
          this._addToIndex(this.byTag, tag, entry.replay_id);
        }
        if (entry.state_hash) {
          this._addToIndex(this.byStateHash, entry.state_hash, entry.replay_id);
        }
      }
    } catch (_) {
      // Ignore load errors
    }
  }
}

// ─── Utility ───────────────────────────────────────────────────────

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

module.exports = {
  TimeMachineIndex,
  INDEX_DIR,
  formatDuration,
};


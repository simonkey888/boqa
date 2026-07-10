/**
 * BOQA dedup.js — Deduplication Engine v0.5
 *
 * Merges duplicate findings across sessions and targets. Findings from
 * different scans (different target_id / session_id) that represent the
 * same underlying issue are collapsed into a single canonical finding.
 *
 * Similarity is a weighted composite of:
 *   - Category exact match           (0.3)
 *   - Severity match / adjacency     (0.1)
 *   - Cookie overlap (Jaccard)       (0.3)
 *   - Endpoint overlap (Jaccard)     (0.2)
 *   - Title similarity (Levenshtein) (0.1)
 *
 * Canonical findings track every source observation so the original
 * target and session provenance is always recoverable.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, 'output', 'dedup');
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ─── Severity adjacency map ─────────────────────────────────────────

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

// ─── Levenshtein Distance ───────────────────────────────────────────

/**
 * Compute Levenshtein edit distance between two strings.
 * Simple DP implementation — O(m*n) time, O(min(m,n)) space.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Ensure a is the shorter string for space optimisation
  if (a.length > b.length) {
    const tmp = a;
    a = b;
    b = tmp;
  }

  const aLen = a.length;
  const bLen = b.length;
  let prev = new Array(aLen + 1);
  let curr = new Array(aLen + 1);

  for (let i = 0; i <= aLen; i++) {
    prev[i] = i;
  }

  for (let j = 1; j <= bLen; j++) {
    curr[0] = j;
    for (let i = 1; i <= aLen; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[i] = Math.min(
        prev[i] + 1,       // deletion
        curr[i - 1] + 1,   // insertion
        prev[i - 1] + cost // substitution
      );
    }
    const swap = prev;
    prev = curr;
    curr = swap;
  }

  return prev[aLen];
}

// ─── Jaccard Index ──────────────────────────────────────────────────

/**
 * Compute Jaccard index between two arrays.
 * |intersection| / |union|. Both empty → 1.0. One empty → 0.0.
 *
 * @param {Array} a
 * @param {Array} b
 * @returns {number} 0-1
 */
function jaccardIndex(a, b) {
  const setA = new Set(a);
  const setB = new Set(b);

  if (setA.size === 0 && setB.size === 0) return 1.0;
  if (setA.size === 0 || setB.size === 0) return 0.0;

  let intersection = 0;
  for (const item of setA) {
    if (setB.has(item)) intersection++;
  }

  const union = setA.size + setB.size - intersection;
  if (union === 0) return 1.0;

  return intersection / union;
}

// ─── Path-only extraction ───────────────────────────────────────────

/**
 * Strip query parameters and fragment from a URL path.
 * "https://x.com/api/v1/users?limit=10" → "/api/v1/users"
 * "/api/v1/users?limit=10"               → "/api/v1/users"
 *
 * @param {string} endpoint
 * @returns {string}
 */
function pathOnly(endpoint) {
  if (!endpoint || typeof endpoint !== 'string') return '';
  try {
    // If it looks like a full URL, parse with URL
    if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
      const url = new URL(endpoint);
      return url.pathname;
    }
    // Strip query and fragment from a bare path
    const qIdx = endpoint.indexOf('?');
    const hIdx = endpoint.indexOf('#');
    let end = endpoint.length;
    if (qIdx !== -1) end = Math.min(end, qIdx);
    if (hIdx !== -1) end = Math.min(end, hIdx);
    return endpoint.substring(0, end);
  } catch {
    // Fallback: strip after first ? or #
    const qIdx = endpoint.indexOf('?');
    const hIdx = endpoint.indexOf('#');
    let end = endpoint.length;
    if (qIdx !== -1) end = Math.min(end, qIdx);
    if (hIdx !== -1) end = Math.min(end, hIdx);
    return endpoint.substring(0, end);
  }
}

// ─── DedupEngine ────────────────────────────────────────────────────

class DedupEngine {
  /**
   * @param {object} options
   * @param {number} options.similarityThreshold  - Minimum similarity to merge (default 0.75)
   * @param {string[]} options.fingerprintFields  - Fields used for fingerprint (default ['category','severity','affected_cookies','affected_endpoints'])
   */
  constructor(options = {}) {
    this.similarityThreshold = options.similarityThreshold ?? 0.75;
    this.fingerprintFields = options.fingerprintFields ?? [
      'category', 'severity', 'affected_cookies', 'affected_endpoints',
    ];

    /** @type {Map<string, object>} canonical_id → canonical finding */
    this._canonicals = new Map();

    /** @type {Map<string, object[]>} canonical_id → array of merged member records */
    this._groups = new Map();

    /** @type {Map<string, string>} fingerprint → canonical_id (index for fast lookup) */
    this._fingerprintIndex = new Map();

    /** @type {number} Running counter for CAN-XXXX ids */
    this._nextId = 1;

    /** @type {number} Total raw findings ingested */
    this._totalInput = 0;
  }

  // ─── Core API ──────────────────────────────────────────────────────

  /**
   * Ingest a finding. If it matches an existing canonical finding
   * (similarity ≥ threshold), merge. Otherwise create a new canonical.
   *
   * @param {object} finding      - A finding or bug object
   * @param {object} sourceInfo   - { target_id, session_id, observed_at }
   * @returns {object} The canonical finding (merged or new)
   */
  ingest(finding, sourceInfo = {}) {
    this._totalInput++;

    const fingerprint = this.computeFingerprint(finding);

    // Fast path: exact fingerprint match — still verify similarity
    // (fingerprint matches category + sorted cookies + sorted endpoints,
    //  but severity or title could differ enough to warrant a separate finding)
    const existingId = this._fingerprintIndex.get(fingerprint);
    if (existingId && this._canonicals.has(existingId)) {
      const existing = this._canonicals.get(existingId);
      const similarity = this.computeSimilarity(finding, existing);
      if (similarity >= this.similarityThreshold) {
        this.merge(finding, existing);
        // Record membership
        this._addGroupMember(existing.id, finding, sourceInfo, similarity);
        existing.updated_at = Date.now();
        return existing;
      }
    }

    // Slow path: compare against all canonicals, pick best match
    let bestMatch = null;
    let bestSimilarity = 0;

    for (const [, canonical] of this._canonicals) {
      const sim = this.computeSimilarity(finding, canonical);
      if (sim > bestSimilarity) {
        bestSimilarity = sim;
        bestMatch = canonical;
      }
    }

    if (bestMatch && bestSimilarity >= this.similarityThreshold) {
      this.merge(finding, bestMatch);
      this._addGroupMember(bestMatch.id, finding, sourceInfo, bestSimilarity);
      // Update fingerprint index if fingerprint changed after merge
      const newFp = this.computeFingerprint(bestMatch);
      if (newFp !== fingerprint) {
        this._fingerprintIndex.delete(fingerprint);
        this._fingerprintIndex.set(newFp, bestMatch.id);
        bestMatch.fingerprint = newFp;
      }
      bestMatch.updated_at = Date.now();
      return bestMatch;
    }

    // No match → create new canonical finding
    const canonical = this._createCanonical(finding, fingerprint, sourceInfo);
    this._canonicals.set(canonical.id, canonical);
    this._fingerprintIndex.set(fingerprint, canonical.id);
    // Seed the group with the original observation
    this._groups.set(canonical.id, [{
      finding_id: finding.id || null,
      target_id: sourceInfo.target_id || null,
      session_id: sourceInfo.session_id || null,
      observed_at: sourceInfo.observed_at || canonical.created_at,
      similarity: 1.0,
    }]);
    return canonical;
  }

  /**
   * Generate a dedup fingerprint based on category + sorted
   * affected_cookies + sorted affected_endpoints.
   *
   * @param {object} finding
   * @returns {string} hex hash
   */
  computeFingerprint(finding) {
    const category = (finding.category || '').toString().toLowerCase();
    const cookies = [...(finding.affected_cookies || [])].sort();
    const endpoints = [...(finding.affected_endpoints || [])]
      .map(e => pathOnly(e))
      .filter(Boolean)
      .sort();

    const raw = JSON.stringify({ category, cookies, endpoints });
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
  }

  /**
   * Compute weighted similarity between two findings.
   *
   * Weights:
   *   category match           0.3  (exact = 1.0, else 0.0)
   *   severity match           0.1  (exact = 1.0, adjacent = 0.5, else 0.0)
   *   cookie overlap (Jaccard) 0.3
   *   endpoint overlap (Jaccard)0.2  (path-only)
   *   title similarity         0.1  (1 - levenshtein / max_len)
   *
   * Title similarity is only computed when category matches and
   * cookie/endpoint similarity is above 0.3 (efficiency guard).
   *
   * @param {object} f1
   * @param {object} f2
   * @returns {number} 0-1
   */
  computeSimilarity(f1, f2) {
    // Category match (weight 0.3)
    const categoryScore = (f1.category || '').toLowerCase() === (f2.category || '').toLowerCase() ? 1.0 : 0.0;

    // Severity match (weight 0.1)
    const severityScore = this._severitySimilarity(f1.severity, f2.severity);

    // Cookie overlap (weight 0.3)
    const cookieScore = jaccardIndex(f1.affected_cookies || [], f2.affected_cookies || []);

    // Endpoint overlap — path-only (weight 0.2)
    const endpoints1 = (f1.affected_endpoints || []).map(pathOnly).filter(Boolean);
    const endpoints2 = (f2.affected_endpoints || []).map(pathOnly).filter(Boolean);
    const endpointScore = jaccardIndex(endpoints1, endpoints2);

    // Title similarity (weight 0.1)
    // Only compute Levenshtein when category matches and
    // cookie/endpoint similarity is above 0.3
    let titleScore = 0.0;
    const cookieEndpointSim = (cookieScore + endpointScore) / 2;
    if (categoryScore === 1.0 && cookieEndpointSim > 0.3) {
      const t1 = (f1.title || '').toString();
      const t2 = (f2.title || '').toString();
      const maxLen = Math.max(t1.length, t2.length);
      if (maxLen === 0) {
        titleScore = 1.0;
      } else {
        const dist = levenshteinDistance(t1, t2);
        titleScore = 1 - (dist / maxLen);
      }
    }

    return (
      categoryScore * 0.3 +
      severityScore * 0.1 +
      cookieScore * 0.3 +
      endpointScore * 0.2 +
      titleScore * 0.1
    );
  }

  /**
   * Merge a new finding into an existing canonical finding.
   * The canonical gets:
   *   - union of affected_endpoints
   *   - union of affected_cookies
   *   - max confidence
   *   - max risk_score
   *   - min created_at
   *   - latest source appended to sources array
   *   - evidence_count incremented
   *
   * @param {object} finding   - The incoming finding
   * @param {object} existing  - The canonical finding to merge into
   * @returns {object} The updated canonical finding
   */
  merge(finding, existing) {
    // Union of affected_endpoints
    const epSet = new Set(existing.affected_endpoints || []);
    for (const ep of (finding.affected_endpoints || [])) {
      epSet.add(ep);
    }
    existing.affected_endpoints = [...epSet];

    // Union of affected_cookies
    const cookieSet = new Set(existing.affected_cookies || []);
    for (const c of (finding.affected_cookies || [])) {
      cookieSet.add(c);
    }
    existing.affected_cookies = [...cookieSet];

    // Max confidence
    existing.confidence = Math.max(
      existing.confidence || 0,
      finding.confidence || 0
    );

    // Max risk_score
    existing.risk_score = Math.max(
      existing.risk_score || 0,
      finding.risk_score || 0
    );

    // Min created_at (keep the earliest)
    const findingCreatedAt = finding.created_at || Infinity;
    if (findingCreatedAt < (existing.created_at || Infinity)) {
      existing.created_at = findingCreatedAt;
    }

    // Evidence count incremented
    existing.evidence_count = (existing.evidence_count || 1) + 1;

    // Update timestamp
    existing.updated_at = Date.now();

    return existing;
  }

  /**
   * Return all canonical (deduplicated) findings as an array.
   * @returns {object[]}
   */
  getCanonicalFindings() {
    return [...this._canonicals.values()];
  }

  /**
   * Return groups of findings that were merged together.
   * Each group: { canonical_id, members: [{ finding_id, target_id, session_id, similarity }] }
   *
   * @returns {object[]}
   */
  getDuplicateGroups() {
    const groups = [];
    for (const [canonicalId, members] of this._groups) {
      groups.push({
        canonical_id: canonicalId,
        members: members.map(m => ({
          finding_id: m.finding_id,
          target_id: m.target_id,
          session_id: m.session_id,
          similarity: m.similarity,
        })),
      });
    }
    return groups;
  }

  /**
   * Return dedup statistics.
   * @returns {object}
   */
  getStats() {
    const totalInput = this._totalInput;
    const canonicalCount = this._canonicals.size;
    const duplicatesRemoved = totalInput - canonicalCount;
    const reductionPct = totalInput > 0
      ? Math.round((duplicatesRemoved / totalInput) * 10000) / 100
      : 0;
    const avgGroupSize = this._groups.size > 0
      ? Math.round(([...this._groups.values()].reduce((sum, g) => sum + g.length, 0) / this._groups.size) * 100) / 100
      : 0;

    return {
      total_input_findings: totalInput,
      canonical_findings: canonicalCount,
      duplicates_removed: duplicatesRemoved,
      duplicate_reduction_pct: reductionPct,
      avg_group_size: avgGroupSize,
    };
  }

  /**
   * Find the N most similar canonical findings to the given finding.
   *
   * @param {object} finding
   * @param {number} limit - Max results (default 5)
   * @returns {object[]} [{ finding, similarity }]
   */
  findSimilar(finding, limit = 5) {
    const scored = [];
    for (const [, canonical] of this._canonicals) {
      const similarity = this.computeSimilarity(finding, canonical);
      scored.push({ finding: canonical, similarity });
    }
    scored.sort((a, b) => b.similarity - a.similarity);
    return scored.slice(0, limit);
  }

  /**
   * Persist all canonical findings to disk.
   * Path: <output>/dedup/canonical-findings.json
   *
   * @returns {string} The file path written
   */
  save() {
    const payload = {
      version: '0.5',
      saved_at: Date.now(),
      stats: this.getStats(),
      canonical_findings: this.getCanonicalFindings(),
      duplicate_groups: this.getDuplicateGroups(),
    };

    const filePath = path.join(OUTPUT_DIR, 'canonical-findings.json');
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf-8');
    return filePath;
  }

  /**
   * Load canonical findings and groups from disk.
   * Replaces all in-memory state.
   *
   * @returns {boolean} true if loaded, false if no file found
   */
  load() {
    const filePath = path.join(OUTPUT_DIR, 'canonical-findings.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      const payload = JSON.parse(raw);

      this.reset();

      const findings = payload.canonical_findings || [];
      const groups = payload.duplicate_groups || [];

      for (const f of findings) {
        this._canonicals.set(f.id, f);
        if (f.fingerprint) {
          this._fingerprintIndex.set(f.fingerprint, f.id);
        }
        // Track next ID counter
        const numPart = f.id.replace('CAN-', '');
        const num = parseInt(numPart, 10);
        if (!isNaN(num) && num >= this._nextId) {
          this._nextId = num + 1;
        }
      }

      for (const group of groups) {
        this._groups.set(group.canonical_id, (group.members || []).map(m => ({
          finding_id: m.finding_id,
          target_id: m.target_id,
          session_id: m.session_id,
          observed_at: m.observed_at,
          similarity: m.similarity,
        })));
      }

      // Restore total input count from stats if available
      if (payload.stats) {
        this._totalInput = payload.stats.total_input_findings || this._canonicals.size;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Clear all engine state.
   */
  reset() {
    this._canonicals.clear();
    this._groups.clear();
    this._fingerprintIndex.clear();
    this._nextId = 1;
    this._totalInput = 0;
  }

  // ─── Internal helpers ──────────────────────────────────────────────

  /**
   * Create a new canonical finding from an incoming finding.
   *
   * @param {object} finding
   * @param {string} fingerprint
   * @param {object} sourceInfo - { target_id, session_id, observed_at }
   * @returns {object} canonical finding
   */
  _createCanonical(finding, fingerprint, sourceInfo = {}) {
    const id = `CAN-${String(this._nextId++).padStart(4, '0')}`;
    const now = Date.now();
    const observedAt = sourceInfo.observed_at || now;

    return {
      id,
      title: finding.title || '',
      category: finding.category || '',
      severity: finding.severity || 'low',
      confidence: finding.confidence || 0,
      risk_score: finding.risk_score || 0,
      affected_endpoints: [...(finding.affected_endpoints || [])],
      affected_cookies: [...(finding.affected_cookies || [])],
      sources: [{
        finding_id: finding.id || null,
        target_id: sourceInfo.target_id || null,
        session_id: sourceInfo.session_id || null,
        observed_at: observedAt,
        similarity: 1.0,
      }],
      evidence_count: 1,
      fingerprint,
      created_at: finding.created_at || observedAt,
      updated_at: now,
    };
  }

  /**
   * Add a member record to a duplicate group.
   *
   * @param {string} canonicalId
   * @param {object} finding
   * @param {object} sourceInfo
   * @param {number} similarity
   */
  _addGroupMember(canonicalId, finding, sourceInfo, similarity) {
    if (!this._groups.has(canonicalId)) {
      this._groups.set(canonicalId, []);
    }
    this._groups.get(canonicalId).push({
      finding_id: finding.id || null,
      target_id: sourceInfo.target_id || null,
      session_id: sourceInfo.session_id || null,
      observed_at: sourceInfo.observed_at || Date.now(),
      similarity: Math.round(similarity * 10000) / 10000,
    });

    // Also append source to the canonical finding's sources array
    const canonical = this._canonicals.get(canonicalId);
    if (canonical) {
      canonical.sources.push({
        finding_id: finding.id || null,
        target_id: sourceInfo.target_id || null,
        session_id: sourceInfo.session_id || null,
        observed_at: sourceInfo.observed_at || Date.now(),
        similarity: Math.round(similarity * 10000) / 10000,
      });
    }
  }

  /**
   * Compute severity similarity score.
   * exact = 1.0, adjacent = 0.5, else = 0.0
   *
   * @param {string} s1
   * @param {string} s2
   * @returns {number}
   */
  _severitySimilarity(s1, s2) {
    const a = (s1 || '').toLowerCase();
    const b = (s2 || '').toLowerCase();

    if (a === b) return 1.0;

    const idxA = SEVERITY_ORDER.indexOf(a);
    const idxB = SEVERITY_ORDER.indexOf(b);

    if (idxA === -1 || idxB === -1) return 0.0;
    if (Math.abs(idxA - idxB) === 1) return 0.5;

    return 0.0;
  }
}

module.exports = { DedupEngine };


'use strict';

/**
 * canonical-bug-store.js
 *
 * Fase 1-2: Single lifecycle model + deduplication.
 *
 * Pipeline:
 *   raw_observation → candidate → canonical → validating → confirmed
 *                   → reportable | needs_review | rejected → disclosed
 *
 * Key invariants:
 *   - Identity is a 24-char hex fingerprint derived from
 *     (target_id, origin, category, method, path, component, cookie_name,
 *      evidence_signature).
 *   - Two bugs with the same fingerprint on DIFFERENT targets are two bugs.
 *   - The same bug confirmed in four cycles yields ONE canonical bug with
 *     observation_count=4.
 *   - Sequential IDs are NEVER used as functional identity — only for
 *     human display.
 *
 * NEVER use "confirmed" as a synonym for "reportable".
 */

const crypto = require('crypto');

// ─── Status lifecycle (Fase 1) ──────────────────────────────────────────
const LIFECYCLE_STATUS = Object.freeze({
  RAW_OBSERVATION: 'raw_observation',
  CANDIDATE:       'candidate',
  CANONICAL:       'canonical',
  VALIDATING:      'validating',
  CONFIRMED:       'confirmed',
  REPORTABLE:      'reportable',
  NEEDS_REVIEW:    'needs_review',
  REJECTED:        'rejected',
  DISCLOSED:       'disclosed',
});

// Statuses that are considered "terminal" for the quality pipeline
const TERMINAL_STATUSES = Object.freeze(new Set([
  LIFECYCLE_STATUS.REPORTABLE,
  LIFECYCLE_STATUS.NEEDS_REVIEW,
  LIFECYCLE_STATUS.REJECTED,
  LIFECYCLE_STATUS.DISCLOSED,
]));

// ─── FASE 2 (revised): Technical vs Reportability axes ──────────────────
//
// technical_status: tracks whether the bug is technically real
//   candidate    → just observed, unverified
//   validating   → in verification rounds
//   confirmed    → reproduced with sufficient evidence
//   needs_review → inconclusive (e.g., 1/3 reproductions, missing detector)
//   rejected     → DEMONSTRATED false positive / benign / non-reproducible
//
// reportability_status: tracks whether the bug can be reported to a program
//   reportable         → passes ALL 8 gates (incl. scope + confidence >= 90)
//   blocked_scope      → target not authorized (technical_status preserved)
//   blocked_evidence   → insufficient evidence (≠ false positive)
//   blocked_program_rules → category/method out of program scope
//   blocked_duplicate_risk → likely duplicate of known issue
//   not_reportable     → catch-all for other blockers
//
// IMPORTANT: blocked_scope NEVER implies technical rejected. A bug can be
// technically confirmed but un-reportable because the target lacks a
// verified bug bounty program. Conversely, a bug can be rejected as a
// false positive even on an authorized target.
const TECHNICAL_STATUS = Object.freeze({
  CANDIDATE:    'candidate',
  VALIDATING:   'validating',
  CONFIRMED:    'confirmed',
  NEEDS_REVIEW: 'needs_review',
  REJECTED:     'rejected',
});

const REPORTABILITY_STATUS = Object.freeze({
  REPORTABLE:             'reportable',
  BLOCKED_SCOPE:          'blocked_scope',
  BLOCKED_EVIDENCE:       'blocked_evidence',
  BLOCKED_PROGRAM_RULES:  'blocked_program_rules',
  BLOCKED_DUPLICATE_RISK: 'blocked_duplicate_risk',
  NOT_REPORTABLE:         'not_reportable',
});

// ─── Normalizers (PURE functions) ───────────────────────────────────────

function normalizeOrigin(url) {
  if (!url || typeof url !== 'string') return '';
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return String(url).toLowerCase().replace(/\/+$/, '');
  }
}

function normalizePath(p) {
  if (!p || typeof p !== 'string') return '/';
  let path = p.split(/[?#]/)[0];
  try {
    if (/^https?:\/\//i.test(path)) {
      path = new URL(path).pathname;
    }
  } catch { /* keep as-is */ }
  path = path.replace(/\/+/g, '/');
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  if (!path.startsWith('/')) path = '/' + path;
  return path.toLowerCase();
}

function normalizeCategory(category) {
  if (!category) return 'unknown';
  const c = String(category).toLowerCase().trim();
  const EQUIV = {
    'csrf': 'csrf',
    'cross_site_request_forgery': 'csrf',
    'cross-site request forgery': 'csrf',
    'cors': 'cors',
    'cross_origin_resource_sharing': 'cors',
    'cross-origin resource sharing': 'cors',
    'cookie_security': 'cookie_security',
    'cookie security': 'cookie_security',
    'cookie-security': 'cookie_security',
    'missing_cache_control': 'cache_control',
    'cache-control': 'cache_control',
    'cache_control': 'cache_control',
    'sensitive_data_in_url': 'sensitive_data_query',
    'sensitive data in url': 'sensitive_data_query',
    'sensitive_data_query': 'sensitive_data_query',
    'xss': 'xss',
    'cross_site_scripting': 'xss',
    'open_redirect': 'open_redirect',
    'auth_bypass': 'auth_bypass',
    'authentication_bypass': 'auth_bypass',
  };
  return EQUIV[c] || c.replace(/[^a-z0-9_]/g, '_');
}

function normalizeMethod(method) {
  if (!method) return 'GET';
  return String(method).toUpperCase().trim();
}

function normalizeComponent(component) {
  if (!component) return 'unknown';
  return String(component).toLowerCase().trim();
}

function normalizeCookieName(name) {
  if (!name) return '';
  return String(name).toLowerCase().trim();
}

/**
 * Build a stable signature of the evidence collected for a bug.
 * Used as part of the fingerprint so that bugs with same category but
 * different evidence are not deduplicated.
 */
function buildEvidenceSignature(bug) {
  if (!bug) return '0000000000000000';
  const evidence = Array.isArray(bug.evidence) ? bug.evidence :
                   (bug.evidence ? [bug.evidence] : []);
  if (evidence.length === 0) return '0000000000000000';

  const pieces = evidence.map(e => {
    if (!e || typeof e !== 'object') return String(e || '');
    return [
      e.type || '',
      e.method || '',
      typeof e.status === 'number' ? String(e.status) : '',
      e.header_name || '',
      e.cookie_name || '',
      e.param_name || '',
    ].filter(Boolean).join('|');
  }).sort();

  return crypto.createHash('sha256')
    .update(pieces.join('||'))
    .digest('hex')
    .slice(0, 16);
}

/**
 * Build the stable fingerprint for a bug observation.
 *
 * Fingerprint inputs (all normalized):
 *   target_id, origin, category, method, path, component, cookie_name,
 *   evidence_signature
 *
 * Things EXCLUDED from fingerprint (must NOT affect identity):
 *   - timestamps, session IDs, random values
 *   - query VALUES (param NAMES are kept via path)
 *   - bugCounter / sequential IDs
 */
function buildBugFingerprint(bug, target) {
  if (!bug) throw new Error('buildBugFingerprint: bug is required');
  if (!target) throw new Error('buildBugFingerprint: target is required');

  const targetId = target.id || normalizeOrigin(target.url) || 'unknown-target';
  const origin = normalizeOrigin(target.url || target.origin || bug.target);

  const payload = {
    target_id: targetId,
    origin: origin,
    category: normalizeCategory(bug.category),
    method: normalizeMethod(bug.method || bug.http_method),
    path: normalizePath(bug.endpoint || bug.path || bug.url),
    component: normalizeComponent(bug.component),
    cookie_name: normalizeCookieName(bug.cookie_name),
    evidence_signature: buildEvidenceSignature(bug),
  };

  const hash = crypto.createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');

  return {
    fingerprint: hash.slice(0, 24),
    bug_id: `BUG-${hash.slice(0, 24)}`,
    payload,
  };
}

// ─── Canonical bug creation + merge ─────────────────────────────────────

function createCanonicalBug(bug, target, fingerprintResult) {
  const now = Date.now();
  return {
    id: fingerprintResult.bug_id,
    fingerprint: fingerprintResult.fingerprint,
    target_id: target.id,
    target_url: target.url,
    target_origin: normalizeOrigin(target.url),

    category: normalizeCategory(bug.category),
    method: normalizeMethod(bug.method || bug.http_method),
    path: normalizePath(bug.endpoint || bug.path || bug.url),
    component: normalizeComponent(bug.component),
    cookie_name: normalizeCookieName(bug.cookie_name),
    title: bug.title || `${bug.category} on ${bug.endpoint || bug.path || target.url}`,

    // FASE 2 (revised): two independent axes
    lifecycle_status: LIFECYCLE_STATUS.CANONICAL,
    technical_status: TECHNICAL_STATUS.CANDIDATE,    // set by VerificationEngine
    reportability_status: null,                       // set by ReportabilityEngine
    // Backward-compat alias: quality_status mirrors reportability_status for
    // existing API consumers. New code should read reportability_status directly.
    quality_status: null,

    severity: String(bug.severity || 'medium').toLowerCase(),
    confidence: Number(bug.confidence) || 0,

    observation_count: 1,
    session_count: 1,
    reproduction_count: bug.reproduction_count || (bug.reproduced ? 1 : 0),
    first_seen_at: bug.first_seen_at || bug.discovered_at || now,
    last_seen_at: bug.last_seen_at || bug.discovered_at || now,

    affected_endpoints: Array.from(new Set([
      normalizePath(bug.endpoint || bug.path || bug.url),
    ].filter(Boolean))),

    evidence: Array.isArray(bug.evidence) ? bug.evidence.slice() : [],
    evidence_quality: Number(bug.evidence_quality) || 0,

    validation_history: bug.validation_history ? [bug.validation_history] : [],
    reportability: null,
    estimated_bounty_usd: null,

    observations: [{
      observed_at: now,
      session_id: bug.session_id || null,
      raw: _snapshotObservation(bug),
    }],
  };
}

function _snapshotObservation(bug) {
  try {
    return JSON.parse(JSON.stringify(bug));
  } catch {
    return { error: 'non_serializable_observation', keys: Object.keys(bug) };
  }
}

/**
 * Merge a new observation of the same bug into the canonical record.
 * Does NOT inflate the visible bug count — same bug stays as ONE canonical
 * entry, only observation_count goes up.
 */
function mergeBugObservation(canonical, newBug) {
  if (!canonical || !newBug) return canonical;
  const now = Date.now();

  canonical.observation_count += 1;

  const newSession = newBug.session_id || null;
  const knownSessions = new Set(canonical.observations.map(o => o.session_id));
  if (newSession && !knownSessions.has(newSession)) {
    canonical.session_count += 1;
  }

  if (newBug.reproduced === true || newBug.reproduction_count > 0) {
    canonical.reproduction_count += 1;
  }

  const newFirst = newBug.first_seen_at || newBug.discovered_at;
  if (newFirst && newFirst < canonical.first_seen_at) {
    canonical.first_seen_at = newFirst;
  }
  const newLast = newBug.last_seen_at || newBug.discovered_at || now;
  if (newLast > canonical.last_seen_at) {
    canonical.last_seen_at = newLast;
  }

  const ep = normalizePath(newBug.endpoint || newBug.path || newBug.url);
  if (ep && !canonical.affected_endpoints.includes(ep)) {
    canonical.affected_endpoints.push(ep);
  }

  if (Array.isArray(newBug.evidence) && newBug.evidence.length > 0) {
    const newQ = Number(newBug.evidence_quality) || 0;
    if (newQ > canonical.evidence_quality) {
      canonical.evidence = newBug.evidence.slice();
      canonical.evidence_quality = newQ;
    }
  }

  const newConf = Number(newBug.confidence) || 0;
  if (newConf > canonical.confidence) {
    canonical.confidence = newConf;
  }

  const SEV_RANK = { informational: 1, low: 2, medium: 3, high: 4, critical: 5 };
  const newSev = String(newBug.severity || '').toLowerCase();
  if (SEV_RANK[newSev] && SEV_RANK[newSev] > (SEV_RANK[canonical.severity] || 0)) {
    canonical.severity = newSev;
  }

  if (newBug.validation_history) {
    canonical.validation_history.push(newBug.validation_history);
  }

  canonical.observations.push({
    observed_at: now,
    session_id: newBug.session_id || null,
    raw: _snapshotObservation(newBug),
  });

  return canonical;
}

// ─── CanonicalBugStore ──────────────────────────────────────────────────

class CanonicalBugStore {
  constructor() {
    this.bugs = new Map();
  }

  observe(bug, target) {
    if (!bug) throw new Error('observe: bug required');
    if (!target) throw new Error('observe: target required');

    const fp = buildBugFingerprint(bug, target);

    if (this.bugs.has(fp.fingerprint)) {
      const canonical = this.bugs.get(fp.fingerprint);
      mergeBugObservation(canonical, bug);
      return { bug: canonical, is_new: false };
    }

    const canonical = createCanonicalBug(bug, target, fp);
    this.bugs.set(fp.fingerprint, canonical);
    return { bug: canonical, is_new: true };
  }

  get(fingerprint) { return this.bugs.get(fingerprint); }

  get_by_id(bugId) {
    if (!bugId) return undefined;
    const fp = bugId.startsWith('BUG-') ? bugId.slice(4) : bugId;
    return this.bugs.get(fp);
  }

  all() { return Array.from(this.bugs.values()); }

  by_target(targetId) {
    return this.all().filter(b => b.target_id === targetId);
  }

  /**
   * Filter by reportability_status (preferred) OR technical_status.
   * For backward-compat, accepts: 'all', 'reportable', 'needs_review',
   * 'rejected', 'blocked_scope', 'blocked_evidence', 'blocked_program_rules',
   * 'blocked_duplicate_risk', 'not_reportable', 'disclosed',
   * OR any technical_status value ('confirmed', 'candidate', etc.).
   */
  by_quality_status(status) {
    if (!status || status === 'all') return this.all();
    return this.all().filter(b =>
      b.reportability_status === status ||
      b.quality_status === status ||  // backward-compat
      b.technical_status === status
    );
  }

  /**
   * Filter strictly by technical_status.
   */
  by_technical_status(status) {
    if (!status || status === 'all') return this.all();
    return this.all().filter(b => b.technical_status === status);
  }

  /**
   * Filter strictly by reportability_status.
   */
  by_reportability_status(status) {
    if (!status || status === 'all') return this.all();
    return this.all().filter(b => b.reportability_status === status);
  }

  size() { return this.bugs.size; }

  to_serializable() {
    return {
      version: 1,
      generated_at: Date.now(),
      bug_count: this.bugs.size,
      bugs: this.all(),
    };
  }

  static from_serializable(data) {
    const store = new CanonicalBugStore();
    if (!data || !Array.isArray(data.bugs)) return store;
    for (const bug of data.bugs) {
      if (bug && bug.fingerprint) {
        store.bugs.set(bug.fingerprint, bug);
      }
    }
    return store;
  }
}

module.exports = {
  LIFECYCLE_STATUS,
  TERMINAL_STATUSES,
  TECHNICAL_STATUS,
  REPORTABILITY_STATUS,
  normalizeOrigin,
  normalizePath,
  normalizeCategory,
  normalizeMethod,
  normalizeComponent,
  normalizeCookieName,
  buildEvidenceSignature,
  buildBugFingerprint,
  createCanonicalBug,
  mergeBugObservation,
  CanonicalBugStore,
};

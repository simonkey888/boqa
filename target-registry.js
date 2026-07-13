'use strict';

/**
 * target-registry.js
 *
 * Fase 13 — Authorized multi-target registry.
 *
 * BOQA never scans random sites. Every target must be explicitly registered
 * with an authorization_source and a scope snapshot.
 *
 * Schema per target:
 *   id, name, base_url, url, authorization_status, authorization_source,
 *   program_name, program_url, scope_snapshot_at, scope_snapshot_hash,
 *   scope_allowlist, scope_denylist, allowed_methods,
 *   allow_authenticated_testing, max_requests_per_minute, max_concurrency,
 *   max_depth, bounty_policy, enabled
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_TARGETS_PATH = path.resolve(__dirname, 'output', 'targets', 'targets.json');

class TargetRegistry {
  constructor(opts = {}) {
    this.path = opts.path || DEFAULT_TARGETS_PATH;
    this.targets = new Map();
    this._load();
  }

  _load() {
    if (!fs.existsSync(this.path)) {
      // No file → no targets. Caller may call register() to add one.
      return;
    }
    try {
      const data = JSON.parse(fs.readFileSync(this.path, 'utf-8'));
      const list = Array.isArray(data) ? data : (data.targets || []);
      for (const t of list) {
        if (t && t.id) this.targets.set(t.id, t);
      }
    } catch (e) {
      console.error(`[target-registry] failed to load ${this.path}: ${e.message}`);
    }
  }

  _saveAtomic() {
    const dir = path.dirname(this.path);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = this.path + '.tmp';
    const payload = JSON.stringify({
      version: 1,
      generated_at: Date.now(),
      targets: this.all(),
    }, null, 2);
    fs.writeFileSync(tmp, payload);
    fs.renameSync(tmp, this.path);
  }

  /**
   * Register a new target. Refuses targets without authorization_source.
   *
   * FASE C — Targets marked `authorized` MUST also provide:
   *   - authorization_source_url (official program URL)
   *   - authorization_checked_at (ISO date when scope was last verified)
   *   - scope_allowlist with at least one entry
   *
   * Targets may be registered with authorization_status="pending_verification"
   * (no scan will run) for later promotion.
   */
  register(spec) {
    if (!spec || !spec.id) throw new Error('register: id required');
    if (!spec.base_url && !spec.url) throw new Error('register: base_url or url required');

    const authStatus = spec.authorization_status || 'pending_verification';

    // Only `authorized` requires full proof. `pending_verification` is allowed
    // for staging but the scheduler will refuse to run scans against it.
    if (authStatus === 'authorized') {
      if (!spec.authorization_source) {
        throw new Error('register: authorization_source required for authorized targets');
      }
      if (!spec.authorization_source_url) {
        throw new Error('register: authorization_source_url required for authorized targets (official program URL)');
      }
      if (!spec.authorization_checked_at) {
        throw new Error('register: authorization_checked_at required for authorized targets (ISO date when scope was verified)');
      }
      if (!spec.scope_allowlist || spec.scope_allowlist.length === 0) {
        throw new Error('register: scope_allowlist must have at least one entry for authorized targets');
      }
    } else if (authStatus !== 'pending_verification') {
      throw new Error(`register: authorization_status must be 'authorized' or 'pending_verification' (got '${authStatus}')`);
    }

    const target = {
      id: spec.id,
      name: spec.name || spec.id,
      base_url: spec.base_url || spec.url,
      url: spec.url || spec.base_url,
      authorization_status: authStatus,
      authorization_source:       authStatus === 'authorized' ? spec.authorization_source       : null,
      authorization_source_url:   authStatus === 'authorized' ? spec.authorization_source_url   : null,
      authorization_checked_at:   authStatus === 'authorized' ? spec.authorization_checked_at   : null,
      program_name: spec.program_name || '',
      program_url:  spec.program_url  || '',
      scope_snapshot_at:   spec.scope_snapshot_at   || Date.now(),
      scope_snapshot_hash: spec.scope_snapshot_hash || _hashScope(spec.scope_allowlist || []),
      scope_allowlist: authStatus === 'authorized' ? (spec.scope_allowlist || []) : [],
      scope_denylist:  spec.scope_denylist || [],
      allowed_methods: spec.allowed_methods || ['GET', 'HEAD', 'OPTIONS'],
      allow_authenticated_testing: !!spec.allow_authenticated_testing,
      max_requests_per_minute: authStatus === 'authorized' ? (spec.max_requests_per_minute || 20) : 0,
      max_concurrency:         authStatus === 'authorized' ? (spec.max_concurrency         || 1)  : 0,
      max_depth:               authStatus === 'authorized' ? (spec.max_depth               || 3)  : 0,
      bounty_policy:   spec.bounty_policy || {},
      enabled: spec.enabled !== false,
    };

    this.targets.set(target.id, target);
    this._saveAtomic();
    return target;
  }

  get(id) { return this.targets.get(id); }
  all() { return Array.from(this.targets.values()); }

  /**
   * FASE C — A target is "executable" only if ALL of:
   *   - authorization_status === 'authorized'
   *   - enabled === true
   *   - authorization_source_url is non-empty
   *   - scope_allowlist has at least one entry
   *   - authorization_checked_at is a valid ISO date
   *
   * Otherwise the scheduler MUST refuse to scan it.
   */
  isExecutable(target) {
    if (!target) return false;
    if (target.authorization_status !== 'authorized') return false;
    if (!target.enabled) return false;
    if (!target.authorization_source_url) return false;
    if (!target.scope_allowlist || target.scope_allowlist.length === 0) return false;
    if (!target.authorization_checked_at) return false;
    // Validate ISO date parseable
    const checkedAt = new Date(target.authorization_checked_at);
    if (isNaN(checkedAt.getTime())) return false;
    return true;
  }

  /**
   * Returns only targets that pass isExecutable().
   * This is what the scheduler is allowed to scan.
   */
  executable() {
    return this.all().filter(t => this.isExecutable(t));
  }

  /**
   * Backward-compat alias for executable() — but with stricter semantics.
   * Old code that called `enabled()` expecting authorized targets now gets
   * ONLY fully-verified targets.
   */
  enabled() {
    return this.executable();
  }

  /**
   * Verify whether a URL is in scope for the given target.
   * Returns { in_scope: bool, reason: string }.
   *
   * FASE C — Returns in_scope=false for any target that is not isExecutable().
   */
  verifyScope(targetId, url) {
    const t = this.targets.get(targetId);
    if (!t) return { in_scope: false, reason: 'unknown_target' };
    if (!this.isExecutable(t)) {
      return { in_scope: false, reason: `target_not_executable (status=${t.authorization_status}, enabled=${t.enabled}, has_url=${!!t.authorization_source_url}, scope=${t.scope_allowlist?.length || 0}, checked_at=${!!t.authorization_checked_at})` };
    }

    let parsed;
    try { parsed = new URL(url); } catch { return { in_scope: false, reason: 'invalid_url' }; }

    const origin = `${parsed.protocol}//${parsed.host}`;
    const targetOrigin = _originOf(t.url);
    if (origin !== targetOrigin) {
      return { in_scope: false, reason: 'cross_origin_redirect_blocked' };
    }

    if (t.scope_denylist?.length && _matchesAny(parsed.pathname, t.scope_denylist)) {
      return { in_scope: false, reason: 'endpoint_in_denylist' };
    }
    if (t.scope_allowlist?.length && !_matchesAny(parsed.pathname, t.scope_allowlist)) {
      return { in_scope: false, reason: 'endpoint_not_in_allowlist' };
    }
    return { in_scope: true, reason: 'ok' };
  }

  /**
   * Check whether a method is allowed for this target.
   */
  isMethodAllowed(targetId, method) {
    const t = this.targets.get(targetId);
    if (!t || !t.allowed_methods?.length) return false;
    return t.allowed_methods.includes((method || 'GET').toUpperCase());
  }
}

function _originOf(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}`; } catch { return ''; }
}

function _glob(url) {
  if (!url) return '/*';
  const origin = _originOf(url);
  return origin ? `${origin}/*` : '/*';
}

function _hashScope(patterns) {
  return crypto.createHash('sha256').update(JSON.stringify(patterns.sort())).digest('hex').slice(0, 16);
}

function _matchesAny(pathname, patterns) {
  for (const p of patterns) {
    if (!p) continue;
    // Allow origin prefix in patterns
    let pattern = p;
    if (pattern.includes('://')) {
      try { pattern = new URL(p).pathname; } catch { /* keep */ }
    }
    const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
    if (re.test(pathname)) return true;
  }
  return false;
}

module.exports = { TargetRegistry };

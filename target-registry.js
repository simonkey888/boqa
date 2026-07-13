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
   */
  register(spec) {
    if (!spec || !spec.id) throw new Error('register: id required');
    if (!spec.base_url && !spec.url) throw new Error('register: base_url or url required');
    if (!spec.authorization_source) {
      throw new Error('register: authorization_source required (BOQA does not scan unauthorized targets)');
    }
    if (spec.authorization_status && spec.authorization_status !== 'authorized') {
      throw new Error(`register: authorization_status must be 'authorized' (got '${spec.authorization_status}')`);
    }

    const target = {
      id: spec.id,
      name: spec.name || spec.id,
      base_url: spec.base_url || spec.url,
      url: spec.url || spec.base_url,
      authorization_status: 'authorized',
      authorization_source: spec.authorization_source,
      program_name: spec.program_name || '',
      program_url: spec.program_url || '',
      scope_snapshot_at: spec.scope_snapshot_at || Date.now(),
      scope_snapshot_hash: spec.scope_snapshot_hash || _hashScope(spec.scope_allowlist || []),
      scope_allowlist: spec.scope_allowlist || [_glob(spec.base_url || spec.url)],
      scope_denylist: spec.scope_denylist || [],
      allowed_methods: spec.allowed_methods || ['GET', 'HEAD', 'OPTIONS'],
      allow_authenticated_testing: !!spec.allow_authenticated_testing,
      max_requests_per_minute: spec.max_requests_per_minute || 20,
      max_concurrency: spec.max_concurrency || 1,
      max_depth: spec.max_depth || 3,
      bounty_policy: spec.bounty_policy || {},
      enabled: spec.enabled !== false,
    };

    this.targets.set(target.id, target);
    this._saveAtomic();
    return target;
  }

  get(id) { return this.targets.get(id); }
  all() { return Array.from(this.targets.values()); }
  enabled() { return this.all().filter(t => t.enabled && t.authorization_status === 'authorized'); }

  /**
   * Verify whether a URL is in scope for the given target.
   * Returns { in_scope: bool, reason: string }.
   */
  verifyScope(targetId, url) {
    const t = this.targets.get(targetId);
    if (!t) return { in_scope: false, reason: 'unknown_target' };
    if (t.authorization_status !== 'authorized') return { in_scope: false, reason: 'target_not_authorized' };

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

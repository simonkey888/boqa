'use strict';

/**
 * Central, fail-closed authorization for every BOQA execution boundary.
 * Resolver and clock dependencies are injectable so integration tests never
 * need network access and authorization age checks remain deterministic.
 */

const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');

const NETWORK_ACTIONS = new Set([
  'navigation', 'authenticated_replay', 'request_replay',
  'header_variation', 'cookie_variation', 'cache_validation',
  'permission_validation', 'workflow_validation',
]);

function allow(extra = {}) { return { allowed: true, code: 'OK', reason: 'Authorized', ...extra }; }
function deny(code, reason, extra = {}) { return { allowed: false, code, reason, ...extra }; }

function parseIPv4(ip) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return null;
  const parts = ip.split('.').map(Number);
  if (parts.some(part => part < 0 || part > 255)) return null;
  return parts;
}

function ipv4ToInt(ip) {
  const parts = parseIPv4(ip);
  if (!parts) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function ipv4InCidr(ip, range, bits) {
  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range);
  if (ipInt === null || rangeInt === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

function normalizeIPv6(ip) {
  const withoutZone = String(ip).toLowerCase().split('%')[0];
  if (withoutZone.startsWith('::ffff:')) {
    const mapped = withoutZone.slice(7);
    if (parseIPv4(mapped)) return { mappedIPv4: mapped };
    const hex = mapped.split(':');
    if (hex.length === 2 && hex.every(part => /^[0-9a-f]{1,4}$/.test(part))) {
      const high = parseInt(hex[0], 16);
      const low = parseInt(hex[1], 16);
      return { mappedIPv4: `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}` };
    }
  }
  return { value: withoutZone };
}

function isBlockedIP(ip) {
  const raw = String(ip || '').replace(/^\[|\]$/g, '').toLowerCase();
  const kind = net.isIP(raw.split('%')[0]);
  if (kind === 4) {
    return [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
      ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
      ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
      ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
      ['224.0.0.0', 4], ['240.0.0.0', 4], ['255.255.255.255', 32],
    ].some(([range, bits]) => ipv4InCidr(raw, range, bits));
  }
  if (kind === 6) {
    const normalized = normalizeIPv6(raw);
    if (normalized.mappedIPv4) return isBlockedIP(normalized.mappedIPv4);
    const value = normalized.value;
    return value === '::' || value === '::1' ||
      /^f[cd]/.test(value) || /^f[f]/.test(value) ||
      /^(fe8|fe9|fea|feb)/.test(value);
  }
  return false;
}

function validateUrlStructure(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return deny('INVALID_URL', 'URL is null or not a string');
  let parsed;
  try { parsed = new URL(urlStr); } catch { return deny('INVALID_URL', 'URL cannot be parsed'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return deny('INVALID_PROTOCOL', `Protocol ${parsed.protocol} is not allowed`);
  }
  if (parsed.username || parsed.password) return deny('USERINFO_IN_URL', 'URL must not contain embedded credentials');
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return deny('LOCALHOST_BLOCKED', 'Localhost is not allowed');
  if (net.isIP(hostname) && isBlockedIP(hostname)) return deny('BLOCKED_IP', 'IP address is in a blocked range');
  return allow({ parsed });
}

function globMatchesPath(pathname, pattern) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(pathname);
}

function matchesScope(hostname, pathname, scopeAllowlist, protocol = null, port = null) {
  if (!Array.isArray(scopeAllowlist) || scopeAllowlist.length === 0) return false;
  for (const original of scopeAllowlist) {
    if (!original || typeof original !== 'string') continue;
    let pathPattern = original;
    if (original.includes('://')) {
      let scoped;
      try { scoped = new URL(original); } catch { continue; }
      if (scoped.hostname.toLowerCase() !== hostname.toLowerCase()) continue;
      if (protocol && scoped.protocol !== protocol) continue;
      const scopedPort = scoped.port || (scoped.protocol === 'https:' ? '443' : '80');
      if (port && scopedPort !== port) continue;
      pathPattern = scoped.pathname;
    }
    if (pathPattern === '*' || pathPattern === '/*') return true;
    if (globMatchesPath(pathname, pathPattern)) return true;
  }
  return false;
}

function getTarget(registry, targetId) {
  if (!registry) return null;
  if (typeof registry.get === 'function') return registry.get(targetId);
  if (typeof registry.getTarget === 'function') return registry.getTarget(targetId);
  return null;
}

function authorizeTarget(targetId, registry, now = Date.now()) {
  if (!targetId) return deny('TARGET_REQUIRED', 'target_id is required');
  const target = getTarget(registry, targetId);
  if (!target) return deny('TARGET_NOT_FOUND', `Target ${targetId} does not exist in registry`);
  if (target.authorization_status !== 'authorized') return deny('TARGET_NOT_AUTHORIZED', 'Target is not authorized');
  if (target.enabled !== true) return deny('TARGET_DISABLED', 'Target is not enabled');
  if (target.execution_authorized !== true) return deny('TARGET_NOT_EXECUTION_AUTHORIZED', 'Target execution_authorized is false');
  if (!Array.isArray(target.scope_allowlist) || target.scope_allowlist.length === 0) return deny('SCOPE_EMPTY', 'Target has no scope_allowlist');
  if (!target.authorization_checked_at) return deny('AUTH_NOT_CHECKED', 'authorization_checked_at is missing');
  const checkedAt = new Date(target.authorization_checked_at);
  if (Number.isNaN(checkedAt.getTime())) return deny('AUTH_CHECK_INVALID', 'authorization_checked_at is invalid');
  if (now - checkedAt.getTime() > 90 * 24 * 60 * 60 * 1000) return deny('AUTH_EXPIRED', 'Authorization is older than 90 days');
  return allow({ target });
}

function validateUrl(targetId, urlStr, registry, options = {}) {
  const structure = validateUrlStructure(urlStr);
  if (!structure.allowed) return structure;
  const targetCheck = authorizeTarget(targetId, registry, options.now);
  if (!targetCheck.allowed) return targetCheck;
  const { parsed } = structure;
  const target = targetCheck.target;
  let targetUrl;
  try { targetUrl = new URL(target.url || target.base_url); } catch { return deny('TARGET_URL_INVALID', 'Canonical target URL is invalid'); }
  const hostname = parsed.hostname.toLowerCase();
  if (hostname !== targetUrl.hostname.toLowerCase()) return deny('HOSTNAME_OUT_OF_SCOPE', 'Hostname does not match canonical target');
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  if (!matchesScope(hostname, parsed.pathname, target.scope_allowlist, parsed.protocol, port)) {
    return deny('PATH_OUT_OF_SCOPE', `Path ${parsed.pathname} is not in target scope`);
  }
  if (Array.isArray(target.scope_denylist) && matchesScope(hostname, parsed.pathname, target.scope_denylist, parsed.protocol, port)) {
    return deny('PATH_DENIED', `Path ${parsed.pathname} is denied`);
  }
  if (Array.isArray(target.allowed_ports) && target.allowed_ports.length && !target.allowed_ports.map(String).includes(port)) {
    return deny('PORT_NOT_ALLOWED', `Port ${port} is not allowed`);
  }
  const method = String(options.method || 'GET').toUpperCase();
  if (Array.isArray(target.allowed_methods) && target.allowed_methods.length && !target.allowed_methods.includes(method)) {
    return deny('METHOD_NOT_ALLOWED', `Method ${method} is not allowed`);
  }
  return allow({ parsed, target, method });
}

async function callResolver(resolver, method, hostname) {
  if (!resolver || typeof resolver[method] !== 'function') return [];
  try { return await resolver[method](hostname); } catch (error) {
    if (['ENODATA', 'ENOTFOUND', 'ENOTIMP'].includes(error.code)) return [];
    throw error;
  }
}

async function resolveAndValidate(hostname, resolver = dns) {
  if (net.isIP(hostname)) return isBlockedIP(hostname) ? deny('DNS_RESOLVES_TO_BLOCKED', 'Address is blocked') : allow({ addresses: [hostname] });
  try {
    const [v4, v6] = await Promise.all([
      callResolver(resolver, 'resolve4', hostname),
      callResolver(resolver, 'resolve6', hostname),
    ]);
    const addresses = [...v4, ...v6];
    if (addresses.length === 0) return deny('DNS_RESOLUTION_FAILED', 'Resolver returned no A or AAAA records');
    if (addresses.some(isBlockedIP)) return deny('DNS_RESOLVES_TO_BLOCKED', 'A or AAAA record is in a blocked range');
    return allow({ addresses });
  } catch (error) {
    return deny('DNS_RESOLUTION_FAILED', `Could not resolve hostname: ${error.message}`);
  }
}

async function validateUrlAsync(targetId, urlStr, registry, options = {}) {
  const structural = validateUrl(targetId, urlStr, registry, options);
  if (!structural.allowed) return structural;
  const dnsCheck = await resolveAndValidate(structural.parsed.hostname, options.resolver || dns);
  if (!dnsCheck.allowed) return dnsCheck;
  return allow({ parsed: structural.parsed, target: structural.target, addresses: dnsCheck.addresses, method: structural.method });
}

function extractTaskUrls(task) {
  const found = [];
  const seen = new Set();
  function add(value, method = 'GET', path = '') {
    if (typeof value !== 'string' || !value) return;
    const key = `${path}\0${value}\0${method}`;
    if (!seen.has(key)) { seen.add(key); found.push({ url: value, method: String(method || 'GET').toUpperCase(), path }); }
  }
  function visit(value, path = '', inheritedMethod = 'GET') {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${path}[${index}]`, inheritedMethod));
      return;
    }
    const method = value.method || inheritedMethod;
    for (const [key, child] of Object.entries(value)) {
      const childPath = path ? `${path}.${key}` : key;
      if ((key === 'url' || key.endsWith('_url')) && typeof child === 'string') {
        add(child, method, childPath);
      } else if (child && typeof child === 'object') {
        visit(child, childPath, method);
      }
    }
  }
  visit(task);
  return found;
}

function validateTask(task, registry, options = {}) {
  if (!task || typeof task !== 'object') return deny('TASK_REQUIRED', 'Task is null');
  if ((options.adminExecutionEnabled ?? process.env.BOQA_ADMIN_EXECUTION_ENABLED === 'true') !== true) {
    return deny('ADMIN_EXECUTION_DISABLED', 'Administrative execution is disabled');
  }
  const targetCheck = authorizeTarget(task.target_id, registry, options.now);
  if (!targetCheck.allowed) return targetCheck;
  const urls = extractTaskUrls(task);
  if (NETWORK_ACTIONS.has(task.action) && urls.length === 0) return deny('TASK_URL_REQUIRED', `Action ${task.action} requires a URL`);
  for (const item of urls) {
    const result = validateUrl(task.target_id, item.url, registry, { ...options, method: item.method });
    if (!result.allowed) {
      const code = item.path.startsWith('params.request_sequence[')
        ? 'SEQUENCE_STEP_INVALID'
        : item.path.startsWith('params.steps[')
          ? 'WORKFLOW_STEP_INVALID'
          : 'TASK_URL_INVALID';
      return deny(code, `${item.path}: ${result.reason}`, { cause: result.code, path: item.path });
    }
  }
  return allow({ urls });
}

async function validateTaskAsync(task, registry, options = {}) {
  const sync = validateTask(task, registry, options);
  if (!sync.allowed) return sync;
  for (const item of sync.urls) {
    const result = await validateUrlAsync(task.target_id, item.url, registry, { ...options, method: item.method });
    if (!result.allowed) {
      const code = item.path.startsWith('params.request_sequence[')
        ? 'SEQUENCE_STEP_INVALID'
        : item.path.startsWith('params.steps[')
          ? 'WORKFLOW_STEP_INVALID'
          : 'TASK_URL_INVALID';
      return deny(code, `${item.path}: ${result.reason}`, { cause: result.code, path: item.path });
    }
  }
  return allow({ urls: sync.urls });
}

async function validateRedirectAsync(targetId, fromUrl, toUrl, registry, options = {}) {
  const result = await validateUrlAsync(targetId, toUrl, registry, options);
  return result.allowed ? result : deny('REDIRECT_OUT_OF_SCOPE', `Redirect rejected: ${result.reason}`, { cause: result.code, from_url: fromUrl });
}

function stableSerialize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableSerialize(value[key])}`).join(',')}}`;
}

function deepClone(value) { return JSON.parse(JSON.stringify(value)); }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function taskPayload(task) {
  return {
    id: task.id || null,
    hypothesis_id: task.hypothesis_id || null,
    action: task.action || null,
    target_id: task.target_id || null,
    method: task.method || null,
    url: task.url || null,
    navigation_url: task.navigation_url || null,
    target_url: task.target_url || null,
    params: task.params || {},
  };
}

function hashTaskPayload(task) {
  return crypto.createHash('sha256').update(stableSerialize(taskPayload(task))).digest('hex');
}

function sealTask(task) {
  const clone = deepClone(task);
  clone.params = deepFreeze(deepClone(clone.params || {}));
  clone.authorized_payload_hash = hashTaskPayload(clone);
  for (const key of ['id', 'hypothesis_id', 'action', 'target_id', 'params']) {
    Object.defineProperty(clone, key, { value: clone[key], enumerable: true, writable: false, configurable: false });
  }
  return clone;
}

function verifyTaskIntegrity(task) {
  if (!task?.authorized_payload_hash) return deny('TASK_NOT_SEALED', 'Task has no authorized payload hash');
  const actual = hashTaskPayload(task);
  return actual === task.authorized_payload_hash ? allow({ hash: actual }) : deny('TASK_MUTATED', 'Task payload changed after authorization');
}

function validateRedirect(targetId, fromUrl, toUrl, registry, options = {}) {
  const result = validateUrl(targetId, toUrl, registry, options);
  return result.allowed ? result : deny('REDIRECT_OUT_OF_SCOPE', `Redirect rejected: ${result.reason}`, { cause: result.code, from_url: fromUrl });
}

function validateResolvedAddress(address) {
  return isBlockedIP(address) ? deny('BLOCKED_IP', 'Address is in a blocked range') : allow();
}

module.exports = {
  NETWORK_ACTIONS,
  allow, deny, authorizeTarget,
  validateUrlStructure, matchesScope, validateUrl, validateUrlAsync,
  resolveAndValidate, validateResolvedAddress, isBlockedIP,
  extractTaskUrls, validateTask, validateTaskAsync,
  validateRedirect, validateRedirectAsync,
  stableSerialize, hashTaskPayload, sealTask, verifyTaskIntegrity,
};

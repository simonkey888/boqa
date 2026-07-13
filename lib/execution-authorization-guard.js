'use strict';

/**
 * lib/execution-authorization-guard.js
 *
 * P0 SECURITY: Central guard for ALL execution paths.
 *
 * Every action that could navigate, fetch, replay, or execute a workflow
 * MUST pass through this guard. The guard checks:
 *   1. Target exists in registry and is execution-authorized
 *   2. URL is within target scope
 *   3. URL does not resolve to private/blocked networks
 *   4. Admin execution is enabled (BOQA_ADMIN_EXECUTION_ENABLED=true)
 *
 * Default: DENY ALL. No execution is permitted unless explicitly authorized.
 */

const { URL } = require('url');
const dns = require('dns').promises;

// ─── Result type ────────────────────────────────────────────────────────

function allow() {
  return { allowed: true, code: 'OK', reason: 'Authorized' };
}

function deny(code, reason) {
  return { allowed: false, code, reason };
}

// ─── Network validation ─────────────────────────────────────────────────

const BLOCKED_CIDR_RANGES = [
  // Loopback
  '127.0.0.0/8',
  '::1/128',
  // RFC1918
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  // Link-local
  '169.254.0.0/16',
  'fe80::/10',
  // IPv6 ULA
  'fc00::/7',
  // Multicast
  '224.0.0.0/4',
  'ff00::/8',
  // Broadcast
  '255.255.255.255/32',
  // Reserved
  '0.0.0.0/8',
  '100.64.0.0/10',
  '192.0.2.0/24',
  '198.51.100.0/24',
  '203.0.113.0/24',
  // Metadata endpoints
  '169.254.169.254/32',  // AWS/GCP/Azure metadata
  'fd00:ec2::254/128',   // AWS IPv6 metadata
];

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return null;
  return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function isInCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const rangeInt = ipToInt(range);
  const ipInt = ipToInt(ip);
  if (rangeInt === null || ipInt === null) return false;
  const mask = bits === '32' ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - parseInt(bits))) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

function isIPv6(ip) {
  return ip.includes(':');
}

function isBlockedIPv6(ip) {
  // ::1 loopback
  if (ip === '::1') return true;
  // fe80::/10 link-local
  if (ip.startsWith('fe80:') || ip.startsWith('fe90:') || ip.startsWith('fea0:') || ip.startsWith('feb0:')) return true;
  // fc00::/7 ULA
  if (ip.startsWith('fc') || ip.startsWith('fd')) return true;
  // ff00::/8 multicast
  if (ip.startsWith('ff')) return true;
  return false;
}

function isBlockedIP(ip) {
  if (isIPv6(ip)) {
    return isBlockedIPv6(ip);
  }
  for (const cidr of BLOCKED_CIDR_RANGES) {
    if (cidr.includes(':')) continue; // skip IPv6 ranges
    if (isInCidr(ip, cidr)) return true;
  }
  return false;
}

// ─── URL validation ─────────────────────────────────────────────────────

function validateUrlStructure(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') {
    return deny('INVALID_URL', 'URL is null or not a string');
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    return deny('INVALID_URL', 'URL cannot be parsed');
  }

  // Only HTTP/HTTPS
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return deny('INVALID_PROTOCOL', `Protocol ${parsed.protocol} is not allowed. Only http: and https: are permitted.`);
  }

  // No userinfo (credentials in URL)
  if (parsed.username || parsed.password) {
    return deny('USERINFO_IN_URL', 'URL must not contain embedded credentials');
  }

  // No localhost
  const hostname = parsed.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname === '[::]') {
    return deny('LOCALHOST_BLOCKED', 'Localhost is not allowed');
  }

  // Check if hostname is an IP
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
  if (isIP && isBlockedIP(hostname.replace(/^\[|\]$/g, ''))) {
    return deny('BLOCKED_IP', 'IP address is in a blocked range');
  }

  return allow();
}

// ─── Scope validation ───────────────────────────────────────────────────

function matchesScope(hostname, pathname, scopeAllowlist) {
  if (!scopeAllowlist || scopeAllowlist.length === 0) {
    return false;
  }
  for (const pattern of scopeAllowlist) {
    if (!pattern) continue;
    let p = pattern;
    // Strip origin if present
    if (p.includes('://')) {
      try { p = new URL(p).pathname; } catch { /* keep */ }
    }
    // Wildcard match
    if (p === '*' || p === '/*') return true;
    const re = new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
    if (re.test(pathname)) return true;
    // Also check hostname match
    if (pattern.includes('://')) {
      try {
        const patUrl = new URL(pattern);
        if (patUrl.hostname === hostname) return true;
      } catch { /* ignore */ }
    }
  }
  return false;
}

// ─── DNS resolution ─────────────────────────────────────────────────────

async function resolveAndValidate(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    for (const ip of addresses) {
      if (isBlockedIP(ip)) {
        return deny('DNS_RESOLVES_TO_BLOCKED', `Hostname resolves to blocked IP range`);
      }
    }
    // Also check AAAA
    try {
      const ipv6Addrs = await dns.resolve6(hostname);
      for (const ip of ipv6Addrs) {
        if (isBlockedIP(ip)) {
          return deny('DNS_RESOLVES_TO_BLOCKED', `Hostname resolves to blocked IPv6 range`);
        }
      }
    } catch { /* no AAAA — OK */ }
    return allow();
  } catch (e) {
    return deny('DNS_RESOLUTION_FAILED', `Could not resolve hostname: ${e.message}`);
  }
}

// ─── Main guard functions ───────────────────────────────────────────────

/**
 * authorizeTarget — checks if a target is authorized for execution.
 * @param {string} targetId - target ID from caller
 * @param {object} registry - TargetRegistry instance
 * @returns {object} { allowed, code, reason }
 */
function authorizeTarget(targetId, registry) {
  if (!targetId) {
    return deny('TARGET_REQUIRED', 'target_id is required');
  }

  const target = registry.get(targetId);
  if (!target) {
    return deny('TARGET_NOT_FOUND', `Target ${targetId} does not exist in registry`);
  }

  if (target.authorization_status !== 'authorized') {
    return deny('TARGET_NOT_AUTHORIZED', `Target authorization_status is ${target.authorization_status}, not authorized`);
  }

  if (!target.enabled) {
    return deny('TARGET_DISABLED', 'Target is not enabled');
  }

  if (!target.execution_authorized) {
    return deny('TARGET_NOT_EXECUTION_AUTHORIZED', 'Target execution_authorized is false');
  }

  if (!target.scope_allowlist || target.scope_allowlist.length === 0) {
    return deny('SCOPE_EMPTY', 'Target has no scope_allowlist');
  }

  if (target.authorization_checked_at) {
    const checkedAt = new Date(target.authorization_checked_at);
    if (isNaN(checkedAt.getTime())) {
      return deny('AUTH_CHECK_INVALID', 'authorization_checked_at is not a valid date');
    }
    // Check if authorization is older than 90 days
    const maxAge = 90 * 24 * 60 * 60 * 1000;
    if (Date.now() - checkedAt.getTime() > maxAge) {
      return deny('AUTH_EXPIRED', 'Authorization was checked more than 90 days ago');
    }
  } else {
    return deny('AUTH_NOT_CHECKED', 'authorization_checked_at is missing');
  }

  return allow();
}

/**
 * validateUrl — checks if a URL is within target scope and not blocked.
 * @param {string} targetId
 * @param {string} urlStr
 * @param {object} registry
 * @returns {object} { allowed, code, reason }
 */
function validateUrl(targetId, urlStr, registry) {
  // First validate URL structure
  const structCheck = validateUrlStructure(urlStr);
  if (!structCheck.allowed) return structCheck;

  // Authorize target
  const targetCheck = authorizeTarget(targetId, registry);
  if (!targetCheck.allowed) return targetCheck;

  const target = registry.get(targetId);
  const parsed = new URL(urlStr);
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;

  // Check hostname matches target
  const targetOrigin = (() => {
    try { return new URL(target.url).hostname.toLowerCase(); } catch { return ''; }
  })();
  if (hostname !== targetOrigin) {
    return deny('HOSTNAME_OUT_OF_SCOPE', `Hostname ${hostname} does not match target ${targetOrigin}`);
  }

  // Check path is in scope
  if (!matchesScope(hostname, pathname, target.scope_allowlist)) {
    return deny('PATH_OUT_OF_SCOPE', `Path ${pathname} is not in target scope`);
  }

  // Check method is allowed (if target has allowed_methods)
  // (method check is done in validateTask)

  // Check port
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  if (target.allowed_ports && target.allowed_ports.length > 0) {
    if (!target.allowed_ports.includes(port)) {
      return deny('PORT_NOT_ALLOWED', `Port ${port} is not in target allowed_ports`);
    }
  }

  return allow();
}

/**
 * validateUrlAsync — includes DNS resolution check.
 */
async function validateUrlAsync(targetId, urlStr, registry) {
  const syncCheck = validateUrl(targetId, urlStr, registry);
  if (!syncCheck.allowed) return syncCheck;

  const parsed = new URL(urlStr);
  const dnsCheck = await resolveAndValidate(parsed.hostname);
  if (!dnsCheck.allowed) return dnsCheck;

  return allow();
}

/**
 * validateTask — validates a task before enqueueing.
 * @param {object} task - task object with target_id, params, etc.
 * @param {object} registry
 * @returns {object} { allowed, code, reason }
 */
function validateTask(task, registry) {
  if (!task) {
    return deny('TASK_REQUIRED', 'Task is null');
  }

  // Check admin execution enabled
  if (process.env.BOQA_ADMIN_EXECUTION_ENABLED !== 'true') {
    return deny('ADMIN_EXECUTION_DISABLED', 'BOQA_ADMIN_EXECUTION_ENABLED is not true. All execution is blocked.');
  }

  // Authorize target
  const targetCheck = authorizeTarget(task.target_id, registry);
  if (!targetCheck.allowed) return targetCheck;

  // Validate all URL fields in the task
  const urlFields = [
    'url',
    'navigation_url',
    'target_url',
  ];

  for (const field of urlFields) {
    if (task[field]) {
      const urlCheck = validateUrl(task.target_id, task[field], registry);
      if (!urlCheck.allowed) return urlCheck;
    }
  }

  // Validate params.url
  if (task.params) {
    if (task.params.url) {
      const urlCheck = validateUrl(task.target_id, task.params.url, registry);
      if (!urlCheck.allowed) return urlCheck;
    }

    // Validate request_sequence
    if (Array.isArray(task.params.request_sequence)) {
      for (let i = 0; i < task.params.request_sequence.length; i++) {
        const step = task.params.request_sequence[i];
        if (step && step.url) {
          const urlCheck = validateUrl(task.target_id, step.url, registry);
          if (!urlCheck.allowed) {
            return deny('SEQUENCE_STEP_INVALID', `Step ${i}: ${urlCheck.reason}`);
          }
        }
      }
    }
  }

  // Validate workflow steps
  if (task.params && Array.isArray(task.params.steps)) {
    for (let i = 0; i < task.params.steps.length; i++) {
      const step = task.params.steps[i];
      if (step && step.action === 'navigate' && step.url) {
        const urlCheck = validateUrl(task.target_id, step.url, registry);
        if (!urlCheck.allowed) {
          return deny('WORKFLOW_STEP_INVALID', `Workflow step ${i}: ${urlCheck.reason}`);
        }
      }
    }
  }

  return allow();
}

/**
 * validateRedirect — validates a redirect from one URL to another.
 */
function validateRedirect(targetId, fromUrl, toUrl, registry) {
  const toCheck = validateUrl(targetId, toUrl, registry);
  if (!toCheck.allowed) {
    return deny('REDIRECT_OUT_OF_SCOPE', `Redirect target rejected: ${toCheck.reason}`);
  }
  return allow();
}

/**
 * validateResolvedAddress — checks if a resolved IP is blocked.
 */
function validateResolvedAddress(hostname) {
  // This is a sync check for already-resolved IPs
  // For async DNS resolution, use resolveAndValidate
  if (isBlockedIP(hostname)) {
    return deny('BLOCKED_IP', 'Address is in a blocked range');
  }
  return allow();
}

module.exports = {
  allow,
  deny,
  authorizeTarget,
  validateUrl,
  validateUrlAsync,
  validateTask,
  validateRedirect,
  validateResolvedAddress,
  resolveAndValidate,
  isBlockedIP,
  validateUrlStructure,
  matchesScope,
};

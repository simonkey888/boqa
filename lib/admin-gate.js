'use strict';

/**
 * lib/admin-gate.js
 *
 * P0 SECURITY: Middleware that blocks ALL mutating/admin endpoints
 * when BOQA_ADMIN_EXECUTION_ENABLED is not "true".
 *
 * Default: false (fail-closed). All POST/PUT/PATCH/DELETE on admin
 * routes return 403 even with valid HMAC + API key.
 */

function createAdminGate(options = {}) {
  const adminEnabled = process.env.BOQA_ADMIN_EXECUTION_ENABLED === 'true';
  const telemetry = options.telemetry || null;

  return function adminGate(req, res, next) {
    // Only block mutating methods
    const method = req.method.toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      return next();
    }

    // If admin execution is enabled, allow through (target guard will still check)
    if (adminEnabled) {
      telemetry?.recordSecurityDecision('admin_gate', { allowed: true, code: 'ADMIN_EXECUTION_ENABLED' }, {
        method,
        route: req.route?.path || req.path || 'unknown',
      });
      return next();
    }

    // Block all mutations
    telemetry?.recordSecurityDecision('admin_gate', { allowed: false, code: 'ADMIN_EXECUTION_DISABLED' }, {
      method,
      route: req.route?.path || req.path || 'unknown',
    });
    return res.status(403).json({
      error: 'admin_execution_disabled',
      message: 'BOQA_ADMIN_EXECUTION_ENABLED is false. All mutations are blocked.',
    });
  };
}

module.exports = { createAdminGate };

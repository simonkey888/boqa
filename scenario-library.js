/**
 * BOQA scenario-library.js — ScenarioLibrary v1.5 (P5)
 *
 * Stores reusable multi-step workflow scenarios with versioning
 * and dependencies. Scenarios are template recordings that can be
 * parameterized and replayed across different targets or versions.
 *
 * Scenario types:
 *   login, mfa, oauth, checkout, wizard, spa_navigation,
 *   iframe_flow, file_upload, popup_flow, infinite_scroll
 *
 * Each scenario contains:
 *   - Step definitions with parameterized targets
 *   - Precondition requirements
 *   - Expected outcomes per step
 *   - Version history for drift detection
 *   - Dependencies on other scenarios
 *
 * Safe mode: scenarios define observability-only workflows.
 * No exploitation, no destructive actions.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');
const SCENARIOS_DIR = path.join(REPLAYS_DIR, 'snapshots', 'scenarios');

fs.mkdirSync(SCENARIOS_DIR, { recursive: true });

// ─── Scenario Types ────────────────────────────────────────────────

const SCENARIO_TYPES = {
  LOGIN: 'login',
  MFA: 'mfa',
  OAUTH: 'oauth',
  CHECKOUT: 'checkout',
  WIZARD: 'wizard',
  SPA_NAVIGATION: 'spa_navigation',
  IFRAME_FLOW: 'iframe_flow',
  FILE_UPLOAD: 'file_upload',
  POPUP_FLOW: 'popup_flow',
  INFINITE_SCROLL: 'infinite_scroll',
};

// ─── Default Scenario Templates ────────────────────────────────────

const DEFAULT_SCENARIOS = {
  [SCENARIO_TYPES.LOGIN]: {
    name: 'Login Flow',
    description: 'Standard authentication flow with username/password',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/login', description: 'Navigate to login page' },
      { step: 2, action: 'input', target: 'input[name="username"]', description: 'Enter username' },
      { step: 3, action: 'input', target: 'input[name="password"]', description: 'Enter password', isSensitive: true },
      { step: 4, action: 'click', target: 'button[type="submit"]', description: 'Submit login form' },
      { step: 5, action: 'observe', target: 'post-login-page', description: 'Verify successful login' },
      { step: 6, action: 'verify', target: 'auth-cookies', description: 'Verify authentication cookies are set' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
    parameters: ['base_url', 'username', 'password'],
  },

  [SCENARIO_TYPES.MFA]: {
    name: 'MFA Flow',
    description: 'Authentication with multi-factor challenge',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/login', description: 'Navigate to login page' },
      { step: 2, action: 'input', target: 'input[name="username"]', description: 'Enter username' },
      { step: 3, action: 'input', target: 'input[name="password"]', description: 'Enter password', isSensitive: true },
      { step: 4, action: 'click', target: 'button[type="submit"]', description: 'Submit login' },
      { step: 5, action: 'observe', target: 'mfa-challenge', description: 'Verify MFA challenge page' },
      { step: 6, action: 'input', target: 'input[name="otp"]', description: 'Enter OTP code', isSensitive: true },
      { step: 7, action: 'click', target: 'button[type="submit"]', description: 'Submit MFA code' },
      { step: 8, action: 'verify', target: 'auth-complete', description: 'Verify full authentication' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
    parameters: ['base_url', 'username', 'password', 'otp_code'],
  },

  [SCENARIO_TYPES.OAUTH]: {
    name: 'OAuth Flow',
    description: 'Third-party OAuth authentication flow',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/login', description: 'Navigate to login page' },
      { step: 2, action: 'click', target: 'a[href*="oauth"]', description: 'Click OAuth provider button' },
      { step: 3, action: 'observe', target: 'oauth-provider', description: 'Verify redirect to OAuth provider' },
      { step: 4, action: 'observe', target: 'oauth-callback', description: 'Wait for OAuth callback' },
      { step: 5, action: 'verify', target: 'auth-cookies', description: 'Verify OAuth session established' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
    parameters: ['base_url', 'oauth_provider'],
  },

  [SCENARIO_TYPES.CHECKOUT]: {
    name: 'Checkout Flow',
    description: 'E-commerce checkout process with auth verification',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/products', description: 'Browse products' },
      { step: 2, action: 'click', target: '.add-to-cart', description: 'Add item to cart' },
      { step: 3, action: 'navigate', target: '{base_url}/cart', description: 'View cart' },
      { step: 4, action: 'click', target: '.checkout-btn', description: 'Proceed to checkout' },
      { step: 5, action: 'observe', target: 'checkout-auth', description: 'Verify auth required for checkout' },
      { step: 6, action: 'verify', target: 'session-security', description: 'Verify session security during checkout' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
    parameters: ['base_url', 'product_id'],
  },

  [SCENARIO_TYPES.WIZARD]: {
    name: 'Wizard Flow',
    description: 'Multi-step form wizard with state transitions',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/wizard', description: 'Start wizard' },
      { step: 2, action: 'input', target: 'step-1-fields', description: 'Fill step 1 fields' },
      { step: 3, action: 'click', target: '.next-step', description: 'Advance to step 2' },
      { step: 4, action: 'observe', target: 'step-2', description: 'Verify step 2 loaded' },
      { step: 5, action: 'input', target: 'step-2-fields', description: 'Fill step 2 fields' },
      { step: 6, action: 'click', target: '.submit', description: 'Submit wizard' },
      { step: 7, action: 'verify', target: 'completion', description: 'Verify wizard completed' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
    parameters: ['base_url'],
  },

  [SCENARIO_TYPES.SPA_NAVIGATION]: {
    name: 'SPA Navigation',
    description: 'Single-page application route transitions',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/', description: 'Load SPA root' },
      { step: 2, action: 'click', target: 'a[href="/dashboard"]', description: 'Navigate to dashboard' },
      { step: 3, action: 'observe', target: 'url-change', description: 'Verify URL changed without full reload' },
      { step: 4, action: 'click', target: 'a[href="/settings"]', description: 'Navigate to settings' },
      { step: 5, action: 'observe', target: 'spa-transition', description: 'Verify SPA navigation' },
      { step: 6, action: 'verify', target: 'auth-persistence', description: 'Verify auth persists across routes' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
    parameters: ['base_url'],
  },

  [SCENARIO_TYPES.IFRAME_FLOW]: {
    name: 'Iframe Flow',
    description: 'Cross-iframe interaction and security boundary check',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/embedded', description: 'Navigate to page with iframe' },
      { step: 2, action: 'observe', target: 'iframe-load', description: 'Verify iframe loaded' },
      { step: 3, action: 'observe', target: 'iframe-origin', description: 'Check iframe origin' },
      { step: 4, action: 'verify', target: 'cross-origin-policy', description: 'Verify cross-origin policy' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
    parameters: ['base_url', 'iframe_src'],
  },

  [SCENARIO_TYPES.FILE_UPLOAD]: {
    name: 'File Upload Flow',
    description: 'File upload with auth and CSRF verification',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/upload', description: 'Navigate to upload page' },
      { step: 2, action: 'observe', target: 'upload-form', description: 'Verify upload form exists' },
      { step: 3, action: 'observe', target: 'csrf-token', description: 'Verify CSRF token present' },
      { step: 4, action: 'verify', target: 'auth-required', description: 'Verify auth required for upload' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
    parameters: ['base_url'],
  },

  [SCENARIO_TYPES.POPUP_FLOW]: {
    name: 'Popup Flow',
    description: 'Authentication via popup window',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/', description: 'Load main page' },
      { step: 2, action: 'click', target: '.auth-popup-trigger', description: 'Trigger auth popup' },
      { step: 3, action: 'observe', target: 'popup-window', description: 'Verify popup opened' },
      { step: 4, action: 'observe', target: 'popup-callback', description: 'Wait for popup callback' },
      { step: 5, action: 'verify', target: 'auth-established', description: 'Verify auth from popup' },
    ],
    preconditions: { requires_auth: false, requires_baseline: false },
    parameters: ['base_url'],
  },

  [SCENARIO_TYPES.INFINITE_SCROLL]: {
    name: 'Infinite Scroll',
    description: 'Scroll-triggered content loading and session persistence',
    steps: [
      { step: 1, action: 'navigate', target: '{base_url}/feed', description: 'Load feed page' },
      { step: 2, action: 'scroll', target: 'page-bottom', description: 'Scroll to bottom' },
      { step: 3, action: 'observe', target: 'new-content', description: 'Verify new content loaded' },
      { step: 4, action: 'scroll', target: 'page-bottom', description: 'Scroll more' },
      { step: 5, action: 'verify', target: 'session-persistence', description: 'Verify session persists through scroll' },
    ],
    preconditions: { requires_auth: true, requires_baseline: false },
    parameters: ['base_url'],
  },
};

// ─── ScenarioLibrary ───────────────────────────────────────────────

class ScenarioLibrary {
  /**
   * @param {object} options
   * @param {string} [options.storageDir] - Directory for scenario persistence
   */
  constructor(options = {}) {
    this.storageDir = options.storageDir || SCENARIOS_DIR;
    this.scenarios = new Map(); // scenarioId → scenario
    this.versions = new Map(); // scenarioId → version[]

    // Load built-in default scenarios
    for (const [type, template] of Object.entries(DEFAULT_SCENARIOS)) {
      const id = `SCN-${type.toUpperCase()}-${crypto.randomUUID().substring(0, 6)}`;
      this.scenarios.set(id, {
        id,
        type,
        ...template,
        version: 1,
        is_builtin: true,
        created_at: Date.now(),
        updated_at: Date.now(),
      });
    }

    // Load custom scenarios from disk
    this._loadFromDisk();
  }

  /**
   * Create a new custom scenario.
   *
   * @param {object} params
   * @param {string} params.name - Scenario name
   * @param {string} params.type - Scenario type (from SCENARIO_TYPES)
   * @param {string} params.description - Description
   * @param {object[]} params.steps - Step definitions
   * @param {object} [params.preconditions] - Preconditions
   * @param {string[]} [params.parameters] - Parameter names
   * @param {string[]} [params.tags] - Categorization tags
   * @param {string[]} [params.dependencies] - IDs of prerequisite scenarios
   * @returns {object} Created scenario
   */
  create(params = {}) {
    const id = `SCN-${crypto.randomUUID().substring(0, 8)}`;
    const scenario = {
      id,
      name: params.name || 'Unnamed Scenario',
      type: params.type || SCENARIO_TYPES.SPA_NAVIGATION,
      description: params.description || '',
      steps: params.steps || [],
      preconditions: params.preconditions || {},
      parameters: params.parameters || [],
      tags: params.tags || [],
      dependencies: params.dependencies || [],
      version: 1,
      is_builtin: false,
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    this.scenarios.set(id, scenario);
    this.versions.set(id, [{ version: 1, snapshot: JSON.parse(JSON.stringify(scenario)), ts: Date.now() }]);

    return scenario;
  }

  /**
   * Create a scenario from a recording.
   *
   * @param {object} recording - Recording export from UniversalSessionRecorder
   * @param {string} name - Scenario name
   * @param {object} [options] - Additional options
   * @returns {object} Created scenario
   */
  createFromRecording(recording, name, options = {}) {
    const events = recording.events || [];
    const boundaries = recording.step_boundaries || [];

    // Convert step boundaries to scenario steps
    const steps = boundaries.map((b, idx) => ({
      step: idx + 1,
      action: 'observe',
      target: `(from recording step: ${b.name})`,
      description: `Step ${idx + 1}: ${b.name}`,
      from_recording: true,
      original_step_name: b.name,
    }));

    // If no boundaries, create a single-step scenario from all events
    if (steps.length === 0 && events.length > 0) {
      steps.push({
        step: 1,
        action: 'observe',
        target: '(full recording)',
        description: `Recorded session with ${events.length} events`,
        from_recording: true,
      });
    }

    return this.create({
      name,
      type: options.type || SCENARIO_TYPES.SPA_NAVIGATION,
      description: `Auto-generated from recording ${recording.recorder_id}`,
      steps,
      preconditions: {
        requires_auth: events.some(e => e.type === 'auth_signal'),
        requires_baseline: false,
      },
      parameters: options.parameters || [],
      tags: [...(options.tags || []), 'auto-generated', 'from-recording'],
      dependencies: options.dependencies || [],
    });
  }

  /**
   * Get a scenario by ID.
   */
  get(scenarioId) {
    return this.scenarios.get(scenarioId) || null;
  }

  /**
   * List scenarios with optional filtering.
   *
   * @param {object} [filter] - { type, tag, is_builtin }
   * @returns {object[]} Matching scenarios
   */
  list(filter = {}) {
    let results = [...this.scenarios.values()];

    if (filter.type) {
      results = results.filter(s => s.type === filter.type);
    }
    if (filter.tag) {
      results = results.filter(s => s.tags.includes(filter.tag));
    }
    if (filter.is_builtin !== undefined) {
      results = results.filter(s => s.is_builtin === filter.is_builtin);
    }

    return results;
  }

  /**
   * Update a scenario (creates a new version).
   *
   * @param {string} scenarioId
   * @param {object} updates
   * @returns {object} Updated scenario
   */
  update(scenarioId, updates = {}) {
    const scenario = this.scenarios.get(scenarioId);
    if (!scenario) throw new Error(`Scenario not found: ${scenarioId}`);

    const updated = {
      ...scenario,
      ...updates,
      id: scenario.id, // preserve ID
      version: scenario.version + 1,
      updated_at: Date.now(),
    };

    this.scenarios.set(scenarioId, updated);

    // Track version history
    if (!this.versions.has(scenarioId)) {
      this.versions.set(scenarioId, []);
    }
    this.versions.get(scenarioId).push({
      version: updated.version,
      snapshot: JSON.parse(JSON.stringify(updated)),
      ts: Date.now(),
    });

    return updated;
  }

  /**
   * Get version history for a scenario.
   */
  getVersionHistory(scenarioId) {
    return this.versions.get(scenarioId) || [];
  }

  /**
   * Resolve parameterized steps for a scenario.
   *
   * @param {string} scenarioId
   * @param {object} params - Parameter key-value pairs
   * @returns {object[]} Resolved steps
   */
  resolveSteps(scenarioId, params = {}) {
    const scenario = this.scenarios.get(scenarioId);
    if (!scenario) return [];

    return scenario.steps.map(step => {
      const resolved = { ...step };
      // Replace {param_name} placeholders in target and description
      if (resolved.target) {
        resolved.target = resolved.target.replace(/\{(\w+)\}/g, (_, key) => params[key] || `{${key}}`);
      }
      if (resolved.description) {
        resolved.description = resolved.description.replace(/\{(\w+)\}/g, (_, key) => params[key] || `{${key}}`);
      }
      return resolved;
    });
  }

  /**
   * Persist all scenarios to disk.
   */
  save() {
    const data = {
      version: '1.5',
      saved_at: Date.now(),
      scenarios: [...this.scenarios.values()],
    };
    const filePath = path.join(this.storageDir, 'scenarios.json');
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Reset in-memory state.
   */
  reset() {
    this.scenarios.clear();
    this.versions.clear();
  }

  _loadFromDisk() {
    const filePath = path.join(this.storageDir, 'scenarios.json');
    if (!fs.existsSync(filePath)) return;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      for (const s of (data.scenarios || [])) {
        if (!s.is_builtin) {
          this.scenarios.set(s.id, s);
        }
      }
    } catch (_) {
      // Ignore load errors
    }
  }
}

module.exports = {
  ScenarioLibrary,
  SCENARIO_TYPES,
  DEFAULT_SCENARIOS,
  SCENARIOS_DIR,
};


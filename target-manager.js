/**
 * BOQA target-manager.js — Target Manager
 *
 * Maintains an inventory of authorized targets for the BOQA
 * (Browser Observability & QA Agent) system.
 *
 * Manages target registration, scope validation, authorization enforcement,
 * and persistence of the target inventory to disk.
 *
 * Target schema:
 *   id:                  TGT-XXXX
 *   name:                string
 *   scope:               array of URL glob patterns
 *   owner:               string
 *   environment:         prod | staging | dev
 *   authorization_status: approved | pending | revoked
 *   last_scan:           timestamp (ms)
 *   created_at:          timestamp (ms)
 *   updated_at:          timestamp (ms)
 *   metadata:            object
 *
 * Safe mode: only targets with authorization_status === 'approved'
 *            may be scanned. The scheduler must check this before
 *            initiating any scan.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Constants ─────────────────────────────────────────────────────

const VALID_ENVIRONMENTS = new Set(['prod', 'staging', 'dev']);
const VALID_AUTH_STATUSES = new Set(['approved', 'pending', 'revoked']);
const DEFAULT_AUTH_STATUS = 'approved';
const TARGET_ID_PREFIX = 'TGT-';
const TARGET_ID_PAD_LENGTH = 4;

const OUTPUT_DIR = path.join(__dirname, 'output', 'targets');
const TARGETS_FILE = path.join(OUTPUT_DIR, 'targets.json');

// ─── TargetManager ─────────────────────────────────────────────────

class TargetManager {
  /**
   * Create a new TargetManager instance.
   * Ensures the output directory exists and auto-loads any persisted
   * targets from disk on construction.
   */
  constructor() {
    /** @type {Map<string, object>} target id → target object */
    this.targets = new Map();

    /** @type {number} monotonically increasing counter for ID generation */
    this._counter = 1;

    // Ensure output directory exists
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });

    // Auto-load persisted targets if available
    this.load();
  }

  // ─── Target CRUD ──────────────────────────────────────────────

  /**
   * Register a new target.
   *
   * Validates the configuration and generates a unique TGT-XXXX ID.
   * Rejects duplicate targets by name.
   *
   * @param {object} config - Target configuration
   * @param {string} config.name - Required target name (must be unique)
   * @param {string[]} config.scope - Array of URL glob patterns
   * @param {string} config.owner - Target owner identifier
   * @param {string} [config.environment='prod'] - One of: prod, staging, dev
   * @param {string} [config.authorization_status='approved'] - Authorization status
   * @param {object} [config.metadata={}] - Additional metadata
   * @returns {object} The created target object
   * @throws {Error} If name is missing, scope is invalid, environment is invalid,
   *                 or a target with the same name already exists
   */
  addTarget(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('Target config must be an object');
    }

    // Validate name (required)
    if (!config.name || typeof config.name !== 'string' || config.name.trim() === '') {
      throw new Error('Target name is required');
    }

    // Validate scope (must be array of URL patterns)
    if (!Array.isArray(config.scope)) {
      throw new Error('Target scope must be an array of URL patterns');
    }
    for (const pattern of config.scope) {
      if (typeof pattern !== 'string' || pattern.trim() === '') {
        throw new Error('Each scope pattern must be a non-empty string');
      }
    }

    // Validate environment
    const environment = config.environment || 'prod';
    if (!VALID_ENVIRONMENTS.has(environment)) {
      throw new Error(`Invalid environment "${environment}". Must be one of: ${[...VALID_ENVIRONMENTS].join(', ')}`);
    }

    // Validate authorization_status
    const authorizationStatus = config.authorization_status || DEFAULT_AUTH_STATUS;
    if (!VALID_AUTH_STATUSES.has(authorizationStatus)) {
      throw new Error(`Invalid authorization_status "${authorizationStatus}". Must be one of: ${[...VALID_AUTH_STATUSES].join(', ')}`);
    }

    // Check for duplicate by name
    const existingByName = this.findTarget(config.name);
    if (existingByName) {
      throw new Error(`Target with name "${config.name}" already exists (id: ${existingByName.id})`);
    }

    // Generate ID
    const id = this._generateId();
    const now = Date.now();

    const target = {
      id,
      name: config.name.trim(),
      scope: [...config.scope],
      owner: config.owner || '',
      environment,
      authorization_status: authorizationStatus,
      last_scan: null,
      created_at: now,
      updated_at: now,
      metadata: config.metadata ? { ...config.metadata } : {},
    };

    this.targets.set(id, target);
    this._counter++;

    return { ...target };
  }

  /**
   * Remove a target by ID.
   *
   * @param {string} id - The target ID (TGT-XXXX)
   * @returns {object|null} The removed target, or null if not found
   */
  removeTarget(id) {
    const target = this.targets.get(id);
    if (!target) {
      return null;
    }
    this.targets.delete(id);
    return { ...target };
  }

  /**
   * Get a target by ID.
   *
   * @param {string} id - The target ID (TGT-XXXX)
   * @returns {object|null} The target object, or null if not found
   */
  getTarget(id) {
    const target = this.targets.get(id);
    return target ? { ...target } : null;
  }

  /**
   * Find a target by name or by URL match against scope patterns.
   *
   * First checks for an exact name match. If no name match is found,
   * attempts to match the provided URL against each target's scope patterns.
   *
   * @param {string} nameOrUrl - Target name or URL to search for
   * @returns {object|null} The matching target, or null if not found
   */
  findTarget(nameOrUrl) {
    if (!nameOrUrl || typeof nameOrUrl !== 'string') {
      return null;
    }

    // Try exact name match first
    for (const target of this.targets.values()) {
      if (target.name === nameOrUrl) {
        return { ...target };
      }
    }

    // Try URL match against scope patterns
    for (const target of this.targets.values()) {
      for (const pattern of target.scope) {
        if (this._matchGlob(nameOrUrl, pattern)) {
          return { ...target };
        }
      }
    }

    return null;
  }

  /**
   * List all targets, optionally filtered.
   *
   * @param {object} [filter={}] - Filter criteria
   * @param {string} [filter.environment] - Filter by environment (prod|staging|dev)
   * @param {string} [filter.authorization_status] - Filter by authorization status
   * @param {string} [filter.owner] - Filter by owner
   * @returns {object[]} Array of matching target objects
   */
  listTargets(filter = {}) {
    let results = [...this.targets.values()];

    if (filter.environment) {
      results = results.filter(t => t.environment === filter.environment);
    }

    if (filter.authorization_status) {
      results = results.filter(t => t.authorization_status === filter.authorization_status);
    }

    if (filter.owner) {
      results = results.filter(t => t.owner === filter.owner);
    }

    return results.map(t => ({ ...t }));
  }

  /**
   * Update a target's fields.
   *
   * Automatically updates the `updated_at` timestamp.
   * Cannot change the target `id` or `name` via this method.
   *
   * @param {string} id - The target ID (TGT-XXXX)
   * @param {object} updates - Fields to update
   * @returns {object|null} The updated target, or null if not found
   * @throws {Error} If environment or authorization_status is invalid,
   *                 or if scope is not an array
   */
  updateTarget(id, updates) {
    const target = this.targets.get(id);
    if (!target) {
      return null;
    }

    if (!updates || typeof updates !== 'object') {
      throw new Error('Updates must be an object');
    }

    // Prevent changing id
    if (updates.id !== undefined && updates.id !== target.id) {
      throw new Error('Cannot change target id');
    }

    // Validate environment if provided
    if (updates.environment !== undefined && !VALID_ENVIRONMENTS.has(updates.environment)) {
      throw new Error(`Invalid environment "${updates.environment}". Must be one of: ${[...VALID_ENVIRONMENTS].join(', ')}`);
    }

    // Validate authorization_status if provided
    if (updates.authorization_status !== undefined && !VALID_AUTH_STATUSES.has(updates.authorization_status)) {
      throw new Error(`Invalid authorization_status "${updates.authorization_status}". Must be one of: ${[...VALID_AUTH_STATUSES].join(', ')}`);
    }

    // Validate scope if provided
    if (updates.scope !== undefined) {
      if (!Array.isArray(updates.scope)) {
        throw new Error('Target scope must be an array of URL patterns');
      }
      for (const pattern of updates.scope) {
        if (typeof pattern !== 'string' || pattern.trim() === '') {
          throw new Error('Each scope pattern must be a non-empty string');
        }
      }
    }

    // Apply allowed updates
    const allowedFields = ['scope', 'owner', 'environment', 'authorization_status', 'metadata'];
    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        if (field === 'scope') {
          target.scope = [...updates.scope];
        } else if (field === 'metadata') {
          target.metadata = { ...updates.metadata };
        } else {
          target[field] = updates[field];
        }
      }
    }

    // Always update the timestamp
    target.updated_at = Date.now();

    return { ...target };
  }

  /**
   * Set a target's last_scan timestamp to Date.now().
   *
   * @param {string} id - The target ID (TGT-XXXX)
   * @returns {object|null} The updated target, or null if not found
   */
  updateLastScan(id) {
    const target = this.targets.get(id);
    if (!target) {
      return null;
    }

    target.last_scan = Date.now();
    target.updated_at = Date.now();

    return { ...target };
  }

  // ─── Authorization & Scope ────────────────────────────────────

  /**
   * Return only targets where authorization_status === 'approved'.
   *
   * This is the primary method for the scheduler to determine which
   * targets are eligible for scanning. Safe mode enforcement.
   *
   * @returns {object[]} Array of approved target objects
   */
  getAuthorizedTargets() {
    const approved = [];
    for (const target of this.targets.values()) {
      if (target.authorization_status === 'approved') {
        approved.push({ ...target });
      }
    }
    return approved;
  }

  /**
   * Check if a URL falls within a target's defined scope patterns.
   *
   * Uses minimatch-style glob matching:
   *   - `*` matches any characters except `/` within a path segment
   *   - `**` matches any path depth (including zero segments)
   *
   * @param {string} targetId - The target ID (TGT-XXXX)
   * @param {string} url - The URL to check against scope
   * @returns {boolean} True if the URL matches any of the target's scope patterns
   */
  isInScope(targetId, url) {
    const target = this.targets.get(targetId);
    if (!target) {
      return false;
    }

    if (!url || typeof url !== 'string') {
      return false;
    }

    for (const pattern of target.scope) {
      if (this._matchGlob(url, pattern)) {
        return true;
      }
    }

    return false;
  }

  // ─── Statistics ───────────────────────────────────────────────

  /**
   * Return aggregate statistics about the target inventory.
   *
   * @returns {object} Stats object with:
   *   - total: total number of targets
   *   - by_environment: counts keyed by environment
   *   - by_authorization_status: counts keyed by authorization status
   *   - authorized_count: number of approved targets
   */
  getStats() {
    const byEnvironment = {};
    const byAuthorizationStatus = {};
    let authorizedCount = 0;

    for (const target of this.targets.values()) {
      // Count by environment
      byEnvironment[target.environment] = (byEnvironment[target.environment] || 0) + 1;

      // Count by authorization status
      byAuthorizationStatus[target.authorization_status] = (byAuthorizationStatus[target.authorization_status] || 0) + 1;

      // Count authorized
      if (target.authorization_status === 'approved') {
        authorizedCount++;
      }
    }

    return {
      total: this.targets.size,
      by_environment: byEnvironment,
      by_authorization_status: byAuthorizationStatus,
      authorized_count: authorizedCount,
    };
  }

  // ─── Persistence ──────────────────────────────────────────────

  /**
   * Persist all targets to disk.
   *
   * Writes the full target inventory as JSON to
   * `/home/z/my-project/download/boqa/output/targets/targets.json`.
   *
   * @returns {string} The file path written to
   */
  save() {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });

    const data = {
      version: '0.5.0',
      saved_at: Date.now(),
      counter: this._counter,
      targets: [...this.targets.values()],
    };

    fs.writeFileSync(TARGETS_FILE, JSON.stringify(data, null, 2));
    return TARGETS_FILE;
  }

  /**
   * Load targets from disk.
   *
   * Reads the persisted target inventory from `targets.json`.
   * Restores the counter to the highest existing target ID number
   * so that subsequent IDs remain unique.
   *
   * Called automatically on construction. Safe to call multiple times;
   * each call replaces the in-memory state.
   *
   * @returns {boolean} True if targets were loaded, false otherwise
   */
  load() {
    if (!fs.existsSync(TARGETS_FILE)) {
      return false;
    }

    try {
      const raw = fs.readFileSync(TARGETS_FILE, 'utf-8');
      const data = JSON.parse(raw);

      if (!data || !Array.isArray(data.targets)) {
        return false;
      }

      // Clear existing state
      this.targets.clear();

      // Restore targets
      let maxCounter = 0;
      for (const target of data.targets) {
        if (target && target.id && target.id.startsWith(TARGET_ID_PREFIX)) {
          this.targets.set(target.id, target);

          // Extract counter value from ID to maintain uniqueness
          const counterStr = target.id.substring(TARGET_ID_PREFIX.length);
          const counterVal = parseInt(counterStr, 10);
          if (!isNaN(counterVal) && counterVal >= maxCounter) {
            maxCounter = counterVal;
          }
        }
      }

      // Restore counter: use saved counter if available and higher,
      // otherwise derive from max existing ID
      this._counter = Math.max(
        data.counter || 0,
        maxCounter + 1
      );

      return true;
    } catch (_) {
      return false;
    }
  }

  // ─── Export ───────────────────────────────────────────────────

  /**
   * Return all targets as a plain array.
   *
   * @returns {object[]} Array of all target objects (shallow copies)
   */
  exportAll() {
    return [...this.targets.values()].map(t => ({ ...t }));
  }

  // ─── Private Helpers ──────────────────────────────────────────

  /**
   * Generate a target ID in the format TGT-XXXX.
   *
   * Uses the internal counter, padded to 4 digits.
   *
   * @returns {string} The generated target ID
   * @private
   */
  _generateId() {
    return `${TARGET_ID_PREFIX}${String(this._counter).padStart(TARGET_ID_PAD_LENGTH, '0')}`;
  }

  /**
   * Match a URL against a glob pattern.
   *
   * Supports:
   *   - `*`  matches any characters except `/` (single path segment)
   *   - `**` matches any characters including `/` (any path depth)
   *
   * The pattern is matched against the full URL string.
   *
   * @param {string} url - The URL to test
   * @param {string} pattern - The glob pattern
   * @returns {boolean} True if the URL matches the pattern
   * @private
   */
  _matchGlob(url, pattern) {
    if (!url || !pattern) {
      return false;
    }

    // Convert glob pattern to regex
    let regexStr = '';
    let i = 0;

    while (i < pattern.length) {
      const ch = pattern[i];

      if (ch === '*') {
        // Check for double-star (**)
        if (i + 1 < pattern.length && pattern[i + 1] === '*') {
          // ** matches any depth including zero segments
          // Consume any trailing slash after ** as well
          regexStr += '.*';
          i += 2;
          // Skip trailing slash after ** for flexibility
          if (i < pattern.length && pattern[i] === '/') {
            // Allow the slash to be optional in the match
            regexStr += '/?';
            i++;
          }
        } else {
          // * matches any characters except /
          regexStr += '[^/]*';
          i++;
        }
      } else if (ch === '?') {
        // ? matches any single character except /
        regexStr += '[^/]';
        i++;
      } else if (this._isRegexSpecial(ch)) {
        // Escape regex special characters
        regexStr += '\\' + ch;
        i++;
      } else {
        regexStr += ch;
        i++;
      }
    }

    try {
      const regex = new RegExp('^' + regexStr + '$');
      return regex.test(url);
    } catch (_) {
      return false;
    }
  }

  /**
   * Check if a character has special meaning in regular expressions.
   *
   * @param {string} ch - A single character
   * @returns {boolean} True if the character is regex-special
   * @private
   */
  _isRegexSpecial(ch) {
    return '\\.+^${}()|[]'.includes(ch);
  }
}

module.exports = { TargetManager };


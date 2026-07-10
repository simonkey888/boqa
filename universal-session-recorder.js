/**
 * BOQA universal-session-recorder.js — UniversalSessionRecorder v1.5 (P5)
 *
 * Captures every user/browser/system action in a deterministic event
 * stream suitable for exact replay. Goes beyond the existing EventBus
 * by adding:
 *   - Deterministic ordering with monotonic sequence numbers
 *   - DOM snapshots at navigation boundaries
 *   - Screenshot metadata (not the images themselves)
 *   - Storage write tracking (redacted)
 *   - WebSocket traffic capture
 *   - Step boundary markers for replay segmentation
 *   - Full context hash linking to a ReplayManifest
 *
 * This recorder is designed to feed into the DeterministicReplayEngine
 * for exact reproduction of multi-step workflows.
 *
 * Safe mode: all secret values are redacted at capture time.
 * No passwords, tokens, or session secrets are stored in plaintext.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');
const SNAPSHOTS_DIR = path.join(REPLAYS_DIR, 'snapshots');
const DOM_DIR = path.join(REPLAYS_DIR, 'dom');
const NETWORK_DIR = path.join(REPLAYS_DIR, 'network');

for (const dir of [REPLAYS_DIR, SNAPSHOTS_DIR, DOM_DIR, NETWORK_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

// ─── Redaction Patterns ────────────────────────────────────────────

const SECRET_KEY_PATTERNS = [
  /password/i, /token/i, /secret/i, /api.?key/i, /private.?key/i,
  /csrf/i, /oauth/i, /session.?id/i, /access.?key/i, /auth/i,
  /bearer/i, /credential/i, /refresh/i,
];

const SECRET_VALUE_PATTERNS = [
  /^Bearer\s+/i,
  /^U2FsdGVkX1/, // AES-CBC encrypted prefix
  /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/, // JWT format
];

function isSecretKey(key) {
  return SECRET_KEY_PATTERNS.some(p => p.test(key));
}

function redactValue(value) {
  if (value === null || value === undefined) return value;
  const s = String(value);
  if (s.length <= 6) return '***REDACTED***';
  return s.substring(0, 3) + '***REDACTED***' + s.substring(s.length - 3);
}

function redactObject(obj, depth = 0) {
  if (depth > 5) return '(max_depth)';
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;

  const result = Array.isArray(obj) ? [] : {};
  for (const [key, value] of Object.entries(obj)) {
    if (isSecretKey(key)) {
      result[key] = redactValue(value);
    } else if (typeof value === 'string' && SECRET_VALUE_PATTERNS.some(p => p.test(value))) {
      result[key] = redactValue(value);
    } else if (typeof value === 'object' && value !== null) {
      result[key] = redactObject(value, depth + 1);
    } else {
      result[key] = value;
    }
  }
  return result;
}

// ─── Captured Event Types ──────────────────────────────────────────

const RECORDABLE_TYPES = new Set([
  // Browser events (from EventBus)
  'network_request', 'network_response', 'network_failure',
  'websocket_open', 'websocket_message_in', 'websocket_message_out', 'websocket_close',
  'console_log', 'console_error', 'page_navigation',
  'cookie_snapshot', 'auth_signal', 'performance_resource',
  // P5 recording-specific events
  'replay_step_boundary', 'replay_dom_snapshot', 'replay_screenshot_meta',
  'replay_storage_write', 'replay_focus_change', 'replay_keyboard_event',
  'replay_click', 'replay_input', 'replay_scroll',
  'replay_navigation_timing', 'replay_resource_timing',
]);

// ─── UniversalSessionRecorder ──────────────────────────────────────

class UniversalSessionRecorder {
  /**
   * @param {object} options
   * @param {string} [options.recorderId] - Unique ID for this recorder
   * @param {boolean} [options.redactSecrets=true] - Redact secret values
   * @param {boolean} [options.captureDomSnapshots=true] - Capture DOM at nav boundaries
   * @param {boolean} [options.captureScreenshotMeta=true] - Record screenshot metadata
   * @param {number} [options.maxEventSize=50000] - Max size per event payload (bytes)
   * @param {string} [options.manifestId] - Link to ReplayManifest
   */
  constructor(options = {}) {
    this.recorderId = options.recorderId || `REC-${crypto.randomUUID().substring(0, 8)}`;
    this.manifestId = options.manifestId || null;
    this.options = {
      redactSecrets: options.redactSecrets !== false,
      captureDomSnapshots: options.captureDomSnapshots !== false,
      captureScreenshotMeta: options.captureScreenshotMeta !== false,
      maxEventSize: options.maxEventSize || 50000,
    };

    // Deterministic event stream
    this.sequenceNumber = 0;
    this.events = [];
    this.stepBoundaries = []; // indices where steps change
    this.currentStep = 0;

    // Recording state
    this.isRecording = false;
    this.recordingStart = null;
    this.recordingEnd = null;
    this.contextHash = null;

    // Stats
    this.stats = {
      total_captured: 0,
      total_redacted: 0,
      dom_snapshots: 0,
      screenshot_metas: 0,
      storage_writes: 0,
      ws_frames: 0,
      step_boundaries: 0,
    };
  }

  /**
   * Start recording a session.
   *
   * @param {object} [meta] - Recording metadata
   * @returns {object} Recording start info
   */
  startRecording(meta = {}) {
    if (this.isRecording) {
      throw new Error('Recording already in progress');
    }

    this.isRecording = true;
    this.recordingStart = Date.now();
    this.sequenceNumber = 0;
    this.events = [];
    this.stepBoundaries = [];
    this.currentStep = 0;

    // Emit recording start marker
    this._capture({
      type: 'replay_step_boundary',
      payload: { action: 'recording_start', step: 0, meta },
      source: 'recorder',
    });

    return {
      recorder_id: this.recorderId,
      manifest_id: this.manifestId,
      started_at: this.recordingStart,
    };
  }

  /**
   * Stop recording and return the captured stream.
   *
   * @returns {object} Recording result
   */
  stopRecording() {
    if (!this.isRecording) {
      throw new Error('No recording in progress');
    }

    this.isRecording = false;
    this.recordingEnd = Date.now();

    // Emit recording end marker
    this._capture({
      type: 'replay_step_boundary',
      payload: { action: 'recording_end', step: this.currentStep },
      source: 'recorder',
    });

    // Compute context hash over all captured events
    this.contextHash = this._computeContextHash();

    return {
      recorder_id: this.recorderId,
      manifest_id: this.manifestId,
      started_at: this.recordingStart,
      ended_at: this.recordingEnd,
      duration_ms: this.recordingEnd - this.recordingStart,
      events_count: this.events.length,
      step_boundaries: this.stepBoundaries.length,
      context_hash: this.contextHash,
      stats: { ...this.stats },
    };
  }

  /**
   * Mark a step boundary in the recording.
   * Used for multi-step scenario segmentation.
   *
   * @param {string} stepName - Name of the step
   * @param {object} [meta] - Step metadata
   */
  markStepBoundary(stepName, meta = {}) {
    this.currentStep++;
    this.stepBoundaries.push({
      step: this.currentStep,
      name: stepName,
      event_index: this.events.length,
      ts: Date.now(),
    });

    this._capture({
      type: 'replay_step_boundary',
      payload: { action: 'step_boundary', step: this.currentStep, name: stepName, meta },
      source: 'recorder',
    });

    this.stats.step_boundaries++;
  }

  /**
   * Capture a DOM snapshot.
   *
   * @param {string} url - Current page URL
   * @param {string} [domHtml] - DOM HTML content (will be truncated)
   * @param {object} [meta] - Additional metadata
   */
  captureDomSnapshot(url, domHtml = null, meta = {}) {
    const truncated = domHtml
      ? domHtml.substring(0, this.options.maxEventSize)
      : null;

    this._capture({
      type: 'replay_dom_snapshot',
      url,
      payload: {
        html_length: domHtml ? domHtml.length : 0,
        html_truncated: truncated,
        url,
        title: meta.title || null,
        ...meta,
      },
      source: 'recorder',
    });

    this.stats.dom_snapshots++;
  }

  /**
   * Capture screenshot metadata (not the image).
   *
   * @param {string} url - Page URL at screenshot time
   * @param {object} [meta] - Screenshot metadata
   */
  captureScreenshotMeta(url, meta = {}) {
    this._capture({
      type: 'replay_screenshot_meta',
      url,
      payload: {
        url,
        viewport: meta.viewport || null,
        timestamp: Date.now(),
        file_ref: meta.fileRef || null, // path to screenshot file if saved
      },
      source: 'recorder',
    });

    this.stats.screenshot_metas++;
  }

  /**
   * Capture a storage write event (redacted).
   *
   * @param {string} storageType - 'localStorage', 'sessionStorage', 'cookie', 'indexedDB'
   * @param {string} key - Storage key
   * @param {string} [value] - Storage value (will be redacted)
   * @param {object} [meta] - Additional metadata
   */
  captureStorageWrite(storageType, key, value = null, meta = {}) {
    const redacted = this.options.redactSecrets && isSecretKey(key);

    this._capture({
      type: 'replay_storage_write',
      payload: {
        storage_type: storageType,
        key,
        value: redacted ? redactValue(value) : value,
        value_redacted: redacted,
        ...meta,
      },
      source: 'recorder',
    });

    this.stats.storage_writes++;
    if (redacted) this.stats.total_redacted++;
  }

  /**
   * Capture a user interaction event.
   *
   * @param {string} interactionType - 'click', 'input', 'keyboard', 'scroll', 'focus'
   * @param {object} detail - Interaction details
   */
  captureInteraction(interactionType, detail = {}) {
    const typeMap = {
      click: 'replay_click',
      input: 'replay_input',
      keyboard: 'replay_keyboard_event',
      scroll: 'replay_scroll',
      focus: 'replay_focus_change',
    };

    const eventType = typeMap[interactionType];
    if (!eventType) return;

    // Redact sensitive input values
    let valueToStore = detail.value;
    if (this.options.redactSecrets && detail.isSensitive && detail.value) {
      valueToStore = redactValue(detail.value);
    } else if (this.options.redactSecrets && detail.value && typeof detail.value === 'string') {
      // Also check if the value itself matches a secret pattern
      if (SECRET_VALUE_PATTERNS.some(p => p.test(detail.value))) {
        valueToStore = redactValue(detail.value);
      }
    }

    this._capture({
      type: eventType,
      url: detail.url || null,
      payload: {
        interaction_type: interactionType,
        selector: detail.selector || null,
        value: valueToStore,
        value_redacted: detail.isSensitive === true,
        key: detail.key || null,
        coordinates: detail.coordinates || null,
      },
      source: 'recorder',
    });
  }

  /**
   * Ingest events from an existing EventBus event log.
   * This bridges the gap between the existing event system
   * and the P5 recording system.
   *
   * @param {object[]} events - Events from EventBus.eventLog
   */
  ingestEventLog(events) {
    for (const event of events) {
      if (RECORDABLE_TYPES.has(event.type)) {
        this._captureFromEventBus(event);
      } else if (event.type) {
        // Capture all event types for completeness, with redaction
        this._captureFromEventBus(event);
      }
    }
  }

  /**
   * Export the recording as a deterministic event stream.
   *
   * @returns {object} Recording export
   */
  export() {
    return {
      recorder_id: this.recorderId,
      manifest_id: this.manifestId,
      context_hash: this.contextHash,
      started_at: this.recordingStart,
      ended_at: this.recordingEnd,
      duration_ms: this.recordingEnd
        ? this.recordingEnd - this.recordingStart
        : Date.now() - this.recordingStart,
      total_events: this.events.length,
      step_boundaries: this.stepBoundaries,
      stats: { ...this.stats },
      events: this.events,
    };
  }

  /**
   * Save recording to disk.
   *
   * @param {string} [filename] - Custom filename
   * @returns {string} Path to saved file
   */
  save(filename) {
    const fn = filename || `recording-${this.recorderId}-${Date.now()}.json`;
    const filePath = path.join(SNAPSHOTS_DIR, fn);
    fs.writeFileSync(filePath, JSON.stringify(this.export(), null, 2));
    return filePath;
  }

  /**
   * Load a recording from disk.
   *
   * @param {string} filePath - Path to recording JSON
   * @returns {object} Recording data
   */
  static load(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }

  /**
   * Get events for a specific step.
   *
   * @param {number} step - Step number (1-indexed)
   * @returns {object[]} Events in that step
   */
  getStepEvents(step) {
    if (step < 1 || step > this.stepBoundaries.length) return [];

    const startIdx = this.stepBoundaries[step - 1].event_index;
    const endIdx = step < this.stepBoundaries.length
      ? this.stepBoundaries[step].event_index
      : this.events.length;

    return this.events.slice(startIdx, endIdx);
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  _capture(rawEvent) {
    const event = {
      seq: this.sequenceNumber++,
      ts: rawEvent.ts || Date.now(),
      type: rawEvent.type,
      url: rawEvent.url || null,
      method: rawEvent.method || null,
      status: rawEvent.status || null,
      headers: this._redactHeaders(rawEvent.headers),
      payload: this._redactPayload(rawEvent.payload),
      source: rawEvent.source || 'recorder',
      meta: rawEvent.meta || {},
      step: this.currentStep,
      recorder_id: this.recorderId,
    };

    this.events.push(event);
    this.stats.total_captured++;
  }

  _captureFromEventBus(event) {
    // Convert EventBus event to recorder format
    this._capture({
      ts: event.ts,
      type: event.type,
      url: event.url,
      method: event.method,
      status: event.status,
      headers: event.headers,
      payload: event.payload,
      source: event.source || 'eventbus',
      meta: event.meta,
    });
  }

  _redactHeaders(headers) {
    if (!headers || !this.options.redactSecrets) return headers;
    return redactObject(headers);
  }

  _redactPayload(payload) {
    if (!payload || !this.options.redactSecrets) return payload;
    if (typeof payload === 'string') {
      // Check for secret value patterns
      if (SECRET_VALUE_PATTERNS.some(p => p.test(payload))) {
        return redactValue(payload);
      }
      return payload;
    }
    return redactObject(payload);
  }

  _computeContextHash() {
    const content = JSON.stringify(this.events.map(e => ({
      seq: e.seq,
      type: e.type,
      url: e.url,
      method: e.method,
      status: e.status,
    })));
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Reset the recorder for reuse.
   */
  reset() {
    this.sequenceNumber = 0;
    this.events = [];
    this.stepBoundaries = [];
    this.currentStep = 0;
    this.isRecording = false;
    this.recordingStart = null;
    this.recordingEnd = null;
    this.contextHash = null;
    this.stats = {
      total_captured: 0,
      total_redacted: 0,
      dom_snapshots: 0,
      screenshot_metas: 0,
      storage_writes: 0,
      ws_frames: 0,
      step_boundaries: 0,
    };
  }
}

module.exports = {
  UniversalSessionRecorder,
  RECORDABLE_TYPES,
  redactValue,
  redactObject,
  isSecretKey,
  SNAPSHOTS_DIR,
};


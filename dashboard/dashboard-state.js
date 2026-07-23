(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.BOQADashboardState = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const VIEW_STATES = Object.freeze({
    LOADING: 'LOADING',
    FRESH: 'FRESH',
    STALE: 'STALE',
    DEGRADED: 'DEGRADED',
    UNAVAILABLE: 'UNAVAILABLE',
    ND: 'N/D',
  });

  const HUNTER_STATES = new Set(['STOPPED', 'STARTING', 'ACTIVE', 'DEGRADED', 'BLOCKED', 'ERROR']);
  const LAB_VIEW_STATES = new Set(['FRESH', 'STALE', 'UNAVAILABLE']);
  const LAB_CONTRACT_KEYS = new Set([
    'schema_version', 'environment', 'status', 'hunter_state', 'reportable',
    'authorized_scope', 'target_kind', 'policy_id', 'source_sha', 'run_id',
    'cycle_started_at', 'cycle_finished_at', 'observed_at', 'fresh_until', 'unavailable_after',
    'finding_count', 'control_finding_count', 'false_positive_count', 'false_negative_count',
    'unauthorized_connection_count', 'cleanup_verified', 'egress_blocked', 'storage_valid',
    'request_budget_verified', 'evidence_checksum', 'message',
  ]);
  const DEFAULT_MAX_AGE_MS = 90_000;

  function isObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  function validIso(value) {
    if (typeof value !== 'string' || value.trim() === '') return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
  }

  function safeString(value) {
    return typeof value === 'string' && value.trim() ? value.trim() : null;
  }

  function initialSource(name, endpoint) {
    return {
      name,
      endpoint,
      view_state: VIEW_STATES.LOADING,
      reason: 'awaiting_first_response',
      source_timestamp: null,
      received_at: null,
      age_ms: null,
      http_status: null,
      payload: null,
    };
  }

  function createInitialModel() {
    return {
      overall: {
        view_state: VIEW_STATES.LOADING,
        reason: 'awaiting_required_sources',
        timestamp: null,
      },
      sources: {
        hunter: initialSource('hunter', '/api/hunter/status'),
        health: initialSource('health', '/api/health'),
      },
      environment: null,
      release_sha: null,
      release_changed: false,
      updated_at: null,
    };
  }

  function validateLabHunterPayload(payload) {
    const keys = Object.keys(payload);
    if (keys.length !== LAB_CONTRACT_KEYS.size || keys.some((key) => !LAB_CONTRACT_KEYS.has(key))) {
      return { valid: false, reason: 'lab_contract_fields_invalid' };
    }
    if (payload.schema_version !== 1 || payload.environment !== 'controlled_lab') {
      return { valid: false, reason: 'lab_contract_identity_invalid' };
    }
    if (payload.reportable !== false || payload.hunter_state !== 'LAB_COMPLETE' || !LAB_VIEW_STATES.has(payload.status)) {
      return { valid: false, reason: 'lab_contract_state_invalid' };
    }
    if (!/^[a-f0-9]{40}$/.test(String(payload.source_sha || '')) ||
        !/^sha256:[a-f0-9]{16}$/.test(String(payload.run_id || '')) ||
        !/^sha256:[a-f0-9]{64}$/.test(String(payload.evidence_checksum || '')) ||
        payload.policy_id !== 'safe-lab-readonly-v1' ||
        payload.authorized_scope !== 'synthetic_fixture' ||
        payload.target_kind !== 'owasp_juice_shop_pinned') {
      return { valid: false, reason: 'lab_contract_provenance_invalid' };
    }
    const started = validIso(payload.cycle_started_at);
    const finished = validIso(payload.cycle_finished_at);
    const observed = validIso(payload.observed_at);
    const freshUntil = validIso(payload.fresh_until);
    const unavailableAfter = validIso(payload.unavailable_after);
    if (!started || !finished || !observed || !freshUntil || !unavailableAfter) {
      return { valid: false, reason: 'lab_contract_timestamp_invalid' };
    }
    const ordered = [started, finished, observed, freshUntil, unavailableAfter].map(Date.parse);
    if (!(ordered[0] <= ordered[1] && ordered[1] <= ordered[2] && ordered[2] <= ordered[3] && ordered[3] <= ordered[4])) {
      return { valid: false, reason: 'lab_contract_timestamps_inconsistent' };
    }
    if (payload.finding_count !== 1 || payload.control_finding_count !== 0 || payload.false_positive_count !== 0 || payload.false_negative_count !== 0 || payload.unauthorized_connection_count !== 0) {
      return { valid: false, reason: 'lab_contract_controls_invalid' };
    }
    if (payload.cleanup_verified !== true || payload.egress_blocked !== true || payload.storage_valid !== true || payload.request_budget_verified !== true) {
      return { valid: false, reason: 'lab_contract_gates_invalid' };
    }
    return { valid: true, timestamp: observed, kind: 'controlled_lab', freshUntil, unavailableAfter };
  }

  function validateHunterPayload(payload) {
    if (!isObject(payload)) return { valid: false, reason: 'hunter_payload_not_object' };
    if (payload.environment === 'controlled_lab') return validateLabHunterPayload(payload);
    if (!HUNTER_STATES.has(payload.state)) return { valid: false, reason: 'hunter_state_invalid_or_missing' };
    const timestamp = validIso(payload.timestamp);
    if (!timestamp) return { valid: false, reason: 'hunter_timestamp_invalid_or_missing' };
    if (payload.freshness !== undefined && !isObject(payload.freshness)) {
      return { valid: false, reason: 'hunter_freshness_invalid' };
    }
    return { valid: true, timestamp, kind: 'runtime' };
  }

  function validateHealthPayload(payload) {
    if (!isObject(payload)) return { valid: false, reason: 'health_payload_not_object' };
    if (!['ok', 'degraded'].includes(payload.status)) return { valid: false, reason: 'health_status_invalid_or_missing' };
    const timestamp = validIso(payload.timestamp);
    if (!timestamp) return { valid: false, reason: 'health_timestamp_invalid_or_missing' };
    return { valid: true, timestamp };
  }

  function sourceFromTransport(name, endpoint, transport, nowMs, maxAgeMs) {
    const base = initialSource(name, endpoint);
    const receivedAt = new Date(nowMs).toISOString();

    if (!transport || transport.pending === true) return base;

    if (transport.error) {
      return {
        ...base,
        view_state: VIEW_STATES.UNAVAILABLE,
        reason: safeString(transport.error.code) || safeString(transport.error.message) || 'network_error',
        received_at: receivedAt,
        http_status: Number.isInteger(transport.status) ? transport.status : null,
      };
    }

    if (!transport.ok) {
      return {
        ...base,
        view_state: VIEW_STATES.UNAVAILABLE,
        reason: Number.isInteger(transport.status) ? `http_${transport.status}` : 'non_success_response',
        received_at: receivedAt,
        http_status: Number.isInteger(transport.status) ? transport.status : null,
      };
    }

    const validation = name === 'hunter'
      ? validateHunterPayload(transport.payload)
      : validateHealthPayload(transport.payload);

    if (!validation.valid) {
      return {
        ...base,
        view_state: VIEW_STATES.ND,
        reason: validation.reason,
        received_at: receivedAt,
        http_status: Number.isInteger(transport.status) ? transport.status : 200,
      };
    }

    const sourceMs = Date.parse(validation.timestamp);
    if (validation.kind === 'controlled_lab' && sourceMs > nowMs) {
      return {
        ...base,
        view_state: VIEW_STATES.ND,
        reason: 'lab_contract_timestamp_future',
        received_at: receivedAt,
        http_status: Number.isInteger(transport.status) ? transport.status : 200,
      };
    }
    const ageMs = Math.max(0, nowMs - sourceMs);
    let viewState = VIEW_STATES.FRESH;
    let reason = 'contract_valid_and_fresh';

    if (validation.kind === 'controlled_lab') {
      if (nowMs > Date.parse(validation.unavailableAfter) || transport.payload.status === 'UNAVAILABLE') {
        viewState = VIEW_STATES.UNAVAILABLE;
        reason = 'lab_evidence_expired';
      } else if (nowMs > Date.parse(validation.freshUntil) || transport.payload.status === 'STALE') {
        viewState = VIEW_STATES.STALE;
        reason = 'lab_evidence_stale';
      } else {
        viewState = VIEW_STATES.FRESH;
        reason = 'lab_contract_valid_and_fresh';
      }
    } else if (ageMs > maxAgeMs) {
      viewState = VIEW_STATES.STALE;
      reason = 'source_timestamp_stale';
    } else if (name === 'hunter') {
      const freshness = transport.payload.freshness;
      const explicitStale = isObject(freshness) && ['heartbeat_fresh', 'cycle_fresh', 'invariants_fresh']
        .some((key) => freshness[key] === false);
      if (explicitStale) {
        viewState = VIEW_STATES.STALE;
        reason = 'hunter_freshness_contract_stale';
      } else if (transport.payload.state !== 'ACTIVE') {
        viewState = VIEW_STATES.DEGRADED;
        reason = `hunter_state_${String(transport.payload.state).toLowerCase()}`;
      }
    } else if (transport.payload.status !== 'ok') {
      viewState = VIEW_STATES.DEGRADED;
      reason = 'health_status_degraded';
    }

    return {
      ...base,
      view_state: viewState,
      reason,
      source_timestamp: validation.timestamp,
      received_at: receivedAt,
      age_ms: ageMs,
      http_status: Number.isInteger(transport.status) ? transport.status : 200,
      payload: JSON.parse(JSON.stringify(transport.payload)),
    };
  }

  function deriveOverall(sources, nowMs) {
    const states = Object.values(sources).map((source) => source.view_state);
    if (states.every((state) => state === VIEW_STATES.LOADING)) {
      return { view_state: VIEW_STATES.LOADING, reason: 'awaiting_required_sources', timestamp: new Date(nowMs).toISOString() };
    }
    if (states.every((state) => state === VIEW_STATES.UNAVAILABLE)) {
      return { view_state: VIEW_STATES.UNAVAILABLE, reason: 'all_required_sources_unavailable', timestamp: new Date(nowMs).toISOString() };
    }
    if (states.includes(VIEW_STATES.DEGRADED)) {
      return { view_state: VIEW_STATES.DEGRADED, reason: 'explicit_degraded_contract', timestamp: new Date(nowMs).toISOString() };
    }
    if (states.includes(VIEW_STATES.STALE)) {
      return { view_state: VIEW_STATES.STALE, reason: 'required_source_stale', timestamp: new Date(nowMs).toISOString() };
    }
    if (states.includes(VIEW_STATES.UNAVAILABLE)) {
      return { view_state: VIEW_STATES.DEGRADED, reason: 'partial_source_unavailable', timestamp: new Date(nowMs).toISOString() };
    }
    if (states.includes(VIEW_STATES.ND)) {
      return { view_state: VIEW_STATES.ND, reason: 'required_contract_incomplete_or_invalid', timestamp: new Date(nowMs).toISOString() };
    }
    if (states.every((state) => state === VIEW_STATES.FRESH)) {
      return { view_state: VIEW_STATES.FRESH, reason: 'all_required_sources_fresh', timestamp: new Date(nowMs).toISOString() };
    }
    return { view_state: VIEW_STATES.ND, reason: 'state_combination_not_defined', timestamp: new Date(nowMs).toISOString() };
  }

  function buildModel(options = {}) {
    const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
    const maxAgeMs = Number.isFinite(options.maxAgeMs) ? options.maxAgeMs : DEFAULT_MAX_AGE_MS;
    const previous = options.previous && isObject(options.previous) ? options.previous : createInitialModel();

    const healthCandidate = sourceFromTransport('health', '/api/health', options.health, nowMs, maxAgeMs);
    const nextRelease = safeString(healthCandidate.payload && healthCandidate.payload.release_sha);
    const releaseChanged = Boolean(previous.release_sha && nextRelease && previous.release_sha !== nextRelease);

    const baseline = releaseChanged ? createInitialModel() : previous;
    const hunter = options.hunter === undefined
      ? baseline.sources.hunter
      : sourceFromTransport('hunter', '/api/hunter/status', options.hunter, nowMs, maxAgeMs);
    const health = options.health === undefined ? baseline.sources.health : healthCandidate;
    const sources = { hunter, health };
    const environment = hunter.payload && hunter.payload.environment === 'controlled_lab'
      ? 'controlled_lab'
      : (hunter.payload ? 'production' : previous.environment);

    return {
      overall: deriveOverall(sources, nowMs),
      sources,
      environment,
      release_sha: environment === 'controlled_lab' ? null : (nextRelease || (releaseChanged ? null : previous.release_sha)),
      release_changed: releaseChanged,
      updated_at: new Date(nowMs).toISOString(),
    };
  }

  async function fetchJsonContract(fetchImpl, url, options = {}) {
    const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 8_000;
    const AbortControllerImpl = options.AbortControllerImpl || (typeof AbortController !== 'undefined' ? AbortController : null);
    const controller = AbortControllerImpl ? new AbortControllerImpl() : null;
    let timeoutHandle = null;

    try {
      if (controller) timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);
      const response = await fetchImpl(url, {
        method: 'GET',
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller ? controller.signal : undefined,
      });
      let payload = null;
      try {
        payload = await response.json();
      } catch (_) {
        return { ok: false, status: response.status, error: { code: 'invalid_json' } };
      }
      if (!response.ok) return { ok: false, status: response.status, payload };
      return { ok: true, status: response.status, payload };
    } catch (error) {
      const aborted = error && (error.name === 'AbortError' || error.code === 'ABORT_ERR');
      return { ok: false, status: null, error: { code: aborted ? 'timeout' : 'network_error', message: error && error.message } };
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }
  }

  return {
    VIEW_STATES,
    DEFAULT_MAX_AGE_MS,
    createInitialModel,
    validateHunterPayload,
    validateLabHunterPayload,
    validateHealthPayload,
    sourceFromTransport,
    deriveOverall,
    buildModel,
    fetchJsonContract,
  };
});

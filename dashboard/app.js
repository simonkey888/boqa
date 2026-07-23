(() => {
  'use strict';
  const State = window.BOQADashboardState;
  if (!State) throw new Error('BOQA dashboard state module unavailable');
  const $ = (id) => document.getElementById(id);
  const ENDPOINTS = Object.freeze({ hunter: '/api/hunter/status', health: '/api/health' });
  const POLL_MS = 15_000;
  const MAX_AGE_MS = 90_000;
  const COMPILED_LAB = document.body.dataset.environment === 'controlled_lab';
  const REASON_LABELS = Object.freeze({
    awaiting_first_response: 'Esperando primera respuesta', awaiting_required_sources: 'Esperando fuentes requeridas',
    contract_valid_and_fresh: 'Contrato válido y actualizado', lab_contract_valid_and_fresh: 'Evidencia de laboratorio válida y vigente',
    lab_evidence_stale: 'Evidencia de laboratorio vencida', lab_evidence_expired: 'Evidencia de laboratorio no disponible por antigüedad',
    lab_contract_timestamp_future: 'Timestamp futuro inválido en evidencia de laboratorio', controlled_lab_not_allowed_in_production_build: 'Contrato de laboratorio rechazado por build productivo',
    source_timestamp_stale: 'Timestamp de fuente vencido', hunter_freshness_contract_stale: 'Señal del hunter vencida', health_status_degraded: 'Health degradado',
    all_required_sources_unavailable: 'Fuentes requeridas no disponibles', explicit_degraded_contract: 'Contrato degradado', required_source_stale: 'Una fuente requerida está vencida',
    partial_source_unavailable: 'Una fuente requerida no está disponible', required_contract_incomplete_or_invalid: 'Contrato requerido incompleto o inválido',
    all_required_sources_fresh: 'Todas las fuentes están actualizadas', state_combination_not_defined: 'Combinación de estados no definida',
    hunter_payload_not_object: 'Respuesta del hunter inválida', hunter_state_invalid_or_missing: 'Estado del hunter inválido o ausente',
    hunter_timestamp_invalid_or_missing: 'Timestamp del hunter inválido o ausente', hunter_freshness_invalid: 'Contrato de frescura del hunter inválido',
    health_payload_not_object: 'Respuesta de health inválida', health_status_invalid_or_missing: 'Estado de health inválido o ausente',
    health_timestamp_invalid_or_missing: 'Timestamp de health inválido o ausente', network_error: 'Error de red', timeout: 'Tiempo de espera agotado',
    invalid_json: 'Respuesta JSON inválida', non_success_response: 'Respuesta HTTP no exitosa', lab_contract_fields_invalid: 'Campos del contrato de laboratorio inválidos',
    lab_contract_identity_invalid: 'Identidad del contrato de laboratorio inválida', lab_contract_state_invalid: 'Estado del contrato de laboratorio inválido',
    lab_contract_provenance_invalid: 'Provenance del contrato de laboratorio inválida', lab_contract_scope_invalid: 'Scope del contrato de laboratorio inválido',
    lab_contract_timestamp_invalid: 'Timestamps del contrato de laboratorio inválidos', lab_contract_timestamps_inconsistent: 'Timestamps del contrato de laboratorio inconsistentes',
    lab_contract_controls_invalid: 'Controles del contrato de laboratorio inválidos', lab_contract_gates_invalid: 'Gates del contrato de laboratorio inválidos',
  });
  let model = State.createInitialModel({ allowControlledLab: COMPILED_LAB });
  let polling = false;
  let timer = null;

  const text = (value) => value === null || value === undefined || value === '' ? 'N/D' : String(value);
  function sentence(value) { const source = text(value); if (source === 'N/D') return source; const normalized = source.replace(/[_-]+/g, ' ').trim(); return normalized.charAt(0).toUpperCase() + normalized.slice(1); }
  function reasonText(value) { const key = value == null ? '' : String(value); if (!key) return 'N/D'; if (REASON_LABELS[key]) return REASON_LABELS[key]; if (key.startsWith('hunter_state_')) return `Hunter ${sentence(key.slice(13)).toLowerCase()}`; if (/^http_\d{3}$/.test(key)) return `Respuesta HTTP ${key.slice(5)}`; return sentence(key); }
  function parseTime(value) { return value ? Date.parse(value) : NaN; }
  function formatIso(value) { const parsed = parseTime(value); if (!Number.isFinite(parsed)) return 'N/D'; return new Intl.DateTimeFormat('es-AR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(new Date(parsed)); }
  function renderTime(node, value) { const parsed = parseTime(value); node.textContent = formatIso(value); if (Number.isFinite(parsed)) { const iso = new Date(parsed).toISOString(); node.title = iso; node.setAttribute('aria-label', iso); } else { node.removeAttribute('title'); node.removeAttribute('aria-label'); } }
  function formatDuration(value) { if (!Number.isFinite(value)) return 'N/D'; if (value < 1000) return `${value} ms`; if (value < 60000) return `${(value / 1000).toFixed(1)} s`; return `${Math.floor(value / 60000)} min ${Math.floor((value % 60000) / 1000)} s`; }
  function renderRelease(node, value) { const release = text(value); if (/^[a-f0-9]{40}$/i.test(release)) { node.textContent = `${release.slice(0, 10)}…${release.slice(-6)}`; node.title = release; node.setAttribute('aria-label', `Release completa: ${release}`); } else { node.textContent = release; node.removeAttribute('title'); node.removeAttribute('aria-label'); } }
  function setState(node, state) { node.textContent = state; node.dataset.state = state; }
  function renderSource(name, source) { setState($(`${name}-view-state`), source.view_state); $(`${name}-source`).textContent = source.endpoint; renderTime($(`${name}-timestamp`), source.source_timestamp); renderTime($(`${name}-received`), source.received_at); $(`${name}-reason`).textContent = reasonText(source.reason); }
  function cycleIsRunning(payload) { if (!payload || payload.state !== 'STARTING') return false; const startedAt = parseTime(payload.last_started_at), completedAt = parseTime(payload.last_completed_at); return Number.isFinite(startedAt) && (!Number.isFinite(completedAt) || startedAt > completedAt); }

  function renderHuntLive(hunter) {
    const strip = $('hunt-live');
    let mode = 'waiting', label = 'Esperando estado real', detail = 'Sin datos del runtime.';
    const payload = hunter.payload;
    if (COMPILED_LAB) {
      if (hunter.view_state === 'FRESH') { mode = 'lab-complete'; label = 'Ciclo de laboratorio completado'; detail = 'Evidencia sintética vigente. El hunter permanece detenido.'; }
      else if (hunter.view_state === 'STALE') { mode = 'stale'; label = 'Evidencia de laboratorio vencida'; detail = 'El ciclo terminó y su evidencia perdió frescura.'; }
      else { mode = 'alert'; label = 'Evidencia de laboratorio no disponible'; detail = 'El contrato expiró, es inválido o no respondió.'; }
    } else if (!payload) {
      if (hunter.view_state === 'STALE') { mode = 'stale'; label = 'Señal vencida'; detail = 'El último estado perdió vigencia.'; }
      else if (hunter.view_state === 'UNAVAILABLE') { mode = 'alert'; label = 'Hunter no disponible'; detail = 'El contrato público no respondió.'; }
    } else if (cycleIsRunning(payload)) { mode = 'running'; label = 'Ciclo en curso'; detail = 'Verificando un activo autorizado.'; }
    else if (payload.state === 'ACTIVE') { mode = 'ready'; label = 'Hunter listo'; detail = payload.next_scheduled_at ? `Próximo ciclo: ${formatIso(payload.next_scheduled_at)}.` : 'Esperando la próxima ejecución programada.'; }
    else if (payload.state === 'STARTING') { mode = 'starting'; label = 'Inicializando hunter'; detail = 'Validando dependencias antes del próximo ciclo.'; }
    else if (payload.state === 'DEGRADED') { mode = 'stale'; label = 'Hunter degradado'; detail = 'El runtime no cumple todas las condiciones de frescura.'; }
    else if (payload.state === 'BLOCKED') { mode = 'alert'; label = 'Hunter bloqueado'; detail = 'La política impide ejecutar el ciclo.'; }
    else if (payload.state === 'ERROR') { mode = 'alert'; label = 'Hunter con error'; detail = 'El runtime requiere revisión.'; }
    else if (payload.state === 'STOPPED') { mode = 'stopped'; label = 'Hunter detenido'; detail = 'No hay un ciclo activo.'; }
    strip.dataset.mode = mode; $('hunt-live-label').textContent = label; $('hunt-live-detail').textContent = detail; strip.setAttribute('aria-label', `Actividad del hunter: ${label}. ${detail}`);
  }

  function render(next) {
    model = next;
    document.body.dataset.viewState = next.overall.view_state;
    document.body.dataset.environment = COMPILED_LAB ? 'controlled_lab' : 'production';
    $('lab-banner').hidden = !COMPILED_LAB;
    setState($('overall-state'), next.overall.view_state);
    $('overall-reason').textContent = reasonText(next.overall.reason);
    renderTime($('dashboard-updated'), next.updated_at);
    const hunter = next.sources.hunter, health = next.sources.health;
    $('hunter-source-title').textContent = COMPILED_LAB ? 'Hunter · LAB CONTROLADO' : 'Hunter runtime';
    $('health-source-title').textContent = COMPILED_LAB ? 'Preview health' : 'Backend health';
    $('hero-title').textContent = COMPILED_LAB ? 'Laboratorio controlado. Estado verificable.' : 'Sin ruido. Sólo estado real.';
    $('hero-lede').innerHTML = COMPILED_LAB ? 'Evidencia sintética y autorizada. <strong>No reportable</strong>; vista exclusiva del laboratorio controlado.' : 'Datos públicos verificables. <strong>N/D</strong> si falta una fuente; <strong>STALE</strong> si perdió vigencia.';
    renderSource('hunter', hunter); renderSource('health', health); renderHuntLive(hunter);
    $('lab-panel').hidden = !COMPILED_LAB; $('runtime-panel').hidden = COMPILED_LAB; $('health-panel').hidden = COMPILED_LAB; $('findings-panel').hidden = COMPILED_LAB; $('qualification-panel').hidden = COMPILED_LAB;
    const labPayload = COMPILED_LAB && hunter.payload && hunter.payload.environment === 'controlled_lab' ? hunter.payload : null;
    $('lab-state').textContent = COMPILED_LAB ? hunter.view_state : 'N/D'; $('lab-reportable').textContent = 'NO'; renderTime($('lab-cycle'), labPayload && labPayload.cycle_finished_at); $('lab-policy').textContent = text(labPayload && labPayload.policy_id); $('lab-control').textContent = labPayload && labPayload.control_finding_count === 0 ? 'LIMPIO · 0' : 'N/D'; $('lab-egress').textContent = labPayload && labPayload.egress_blocked === true ? 'BLOQUEADO' : 'N/D'; $('lab-cleanup').textContent = labPayload && labPayload.cleanup_verified === true ? 'VERIFICADO' : 'N/D';
    $('hunter-state').textContent = text(hunter.payload && hunter.payload.state); renderTime($('heartbeat-at'), hunter.payload && hunter.payload.heartbeat_at); renderTime($('last-started-at'), hunter.payload && hunter.payload.last_started_at); renderTime($('last-completed-at'), hunter.payload && hunter.payload.last_completed_at); renderTime($('next-scheduled-at'), hunter.payload && hunter.payload.next_scheduled_at);
    $('health-status').textContent = text(health.payload && health.payload.status); $('health-version').textContent = text(health.payload && health.payload.version); renderRelease($('health-release'), health.payload && health.payload.release_sha); $('health-uptime').textContent = formatDuration(health.payload && health.payload.process_uptime_ms);
    $('release-change').hidden = !next.release_changed;
    const dataAvailable = Boolean(hunter.payload || health.payload);
    $('empty-state').hidden = dataAvailable || COMPILED_LAB;
    $('status-grid').hidden = !(dataAvailable || COMPILED_LAB);
  }

  async function poll() {
    if (polling || document.hidden) return;
    polling = true;
    try {
      const [hunter, health] = await Promise.all([State.fetchJsonContract(window.fetch.bind(window), ENDPOINTS.hunter), State.fetchJsonContract(window.fetch.bind(window), ENDPOINTS.health)]);
      render(State.buildModel({ previous: model, hunter, health, nowMs: Date.now(), maxAgeMs: MAX_AGE_MS, allowControlledLab: COMPILED_LAB }));
    } finally { polling = false; }
  }
  function schedule() { if (timer) clearInterval(timer); timer = setInterval(poll, POLL_MS); }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  render(model); poll(); schedule();
})();

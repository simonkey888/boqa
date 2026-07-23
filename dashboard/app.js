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
    awaiting_first_response: 'Esperando primera respuesta',
    awaiting_required_sources: 'Esperando fuentes requeridas',
    contract_valid_and_fresh: 'Contrato válido y actualizado',
    lab_contract_valid_and_fresh: 'Evidencia de laboratorio válida y vigente',
    lab_evidence_stale: 'Evidencia de laboratorio vencida',
    lab_evidence_expired: 'Evidencia de laboratorio no disponible por antigüedad',
    lab_contract_timestamp_future: 'Timestamp futuro inválido en evidencia de laboratorio',
    source_timestamp_stale: 'Timestamp de fuente vencido',
    hunter_freshness_contract_stale: 'Señal del hunter vencida',
    health_status_degraded: 'Health degradado',
    all_required_sources_unavailable: 'Fuentes requeridas no disponibles',
    explicit_degraded_contract: 'Contrato degradado',
    required_source_stale: 'Una fuente requerida está vencida',
    partial_source_unavailable: 'Una fuente requerida no está disponible',
    required_contract_incomplete_or_invalid: 'Contrato requerido incompleto o inválido',
    all_required_sources_fresh: 'Todas las fuentes están actualizadas',
    state_combination_not_defined: 'Combinación de estados no definida',
    hunter_payload_not_object: 'Respuesta del hunter inválida',
    hunter_state_invalid_or_missing: 'Estado del hunter inválido o ausente',
    hunter_timestamp_invalid_or_missing: 'Timestamp del hunter inválido o ausente',
    hunter_freshness_invalid: 'Contrato de frescura del hunter inválido',
    health_payload_not_object: 'Respuesta de health inválida',
    health_status_invalid_or_missing: 'Estado de health inválido o ausente',
    health_timestamp_invalid_or_missing: 'Timestamp de health inválido o ausente',
    network_error: 'Error de red',
    timeout: 'Tiempo de espera agotado',
    invalid_json: 'Respuesta JSON inválida',
    non_success_response: 'Respuesta HTTP no exitosa',
  });
  let model = State.createInitialModel();
  let polling = false;
  let timer = null;

  function text(value) {
    return value === null || value === undefined || value === '' ? 'N/D' : String(value);
  }

  function sentence(value) {
    const source = text(value);
    if (source === 'N/D') return source;
    const normalized = source.replace(/[_-]+/g, ' ').trim();
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }

  function reasonText(value) {
    const key = value === null || value === undefined ? '' : String(value);
    if (!key) return 'N/D';
    if (REASON_LABELS[key]) return REASON_LABELS[key];
    if (key.startsWith('hunter_state_')) return `Hunter ${sentence(key.slice('hunter_state_'.length)).toLowerCase()}`;
    if (/^http_\d{3}$/.test(key)) return `Respuesta HTTP ${key.slice(5)}`;
    return sentence(key);
  }

  function parseTime(value) {
    if (!value) return NaN;
    return Date.parse(value);
  }

  function formatIso(value) {
    const parsed = parseTime(value);
    if (!Number.isFinite(parsed)) return 'N/D';
    return new Intl.DateTimeFormat('es-AR', {
      day: '2-digit',
      month: '2-digit',
      year: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    }).format(new Date(parsed));
  }

  function renderTime(node, value) {
    const parsed = parseTime(value);
    node.textContent = formatIso(value);
    if (Number.isFinite(parsed)) {
      const iso = new Date(parsed).toISOString();
      node.title = iso;
      node.setAttribute('aria-label', iso);
    } else {
      node.removeAttribute('title');
      node.removeAttribute('aria-label');
    }
  }

  function formatDuration(value) {
    if (!Number.isFinite(value)) return 'N/D';
    if (value < 1_000) return `${value} ms`;
    if (value < 60_000) return `${(value / 1_000).toFixed(1)} s`;
    const minutes = Math.floor(value / 60_000);
    const seconds = Math.floor((value % 60_000) / 1_000);
    return `${minutes} min ${seconds} s`;
  }

  function renderRelease(node, value) {
    const release = text(value);
    if (/^[a-f0-9]{40}$/i.test(release)) {
      node.textContent = `${release.slice(0, 10)}…${release.slice(-6)}`;
      node.title = release;
      node.setAttribute('aria-label', `Release completa: ${release}`);
      return;
    }
    node.textContent = release;
    node.removeAttribute('title');
    node.removeAttribute('aria-label');
  }

  function setState(node, state) {
    node.textContent = state;
    node.dataset.state = state;
  }

  function renderSource(name, source) {
    setState($(`${name}-view-state`), source.view_state);
    $(`${name}-source`).textContent = source.endpoint;
    renderTime($(`${name}-timestamp`), source.source_timestamp);
    renderTime($(`${name}-received`), source.received_at);
    $(`${name}-reason`).textContent = reasonText(source.reason);
  }

  function cycleIsRunning(payload) {
    if (!payload || payload.state !== 'STARTING') return false;
    const startedAt = parseTime(payload.last_started_at);
    const completedAt = parseTime(payload.last_completed_at);
    return Number.isFinite(startedAt) && (!Number.isFinite(completedAt) || startedAt > completedAt);
  }

  function renderHuntLive(hunter) {
    const strip = $('hunt-live');
    const label = $('hunt-live-label');
    const detail = $('hunt-live-detail');
    const payload = hunter.payload;
    let mode = 'waiting';
    let labelText = 'Esperando estado real';
    let detailText = 'Sin datos del runtime.';

    if (payload && payload.environment === 'controlled_lab') {
      if (hunter.view_state === 'FRESH') {
        mode = 'lab-complete';
        labelText = 'Ciclo de laboratorio completado';
        detailText = 'Evidencia sintética vigente. El hunter permanece detenido.';
      } else if (hunter.view_state === 'STALE') {
        mode = 'stale';
        labelText = 'Evidencia de laboratorio vencida';
        detailText = 'El ciclo terminó y su evidencia perdió frescura.';
      } else {
        mode = 'alert';
        labelText = 'Evidencia de laboratorio no disponible';
        detailText = 'El contrato expiró o no superó la validación.';
      }
    } else if (!payload) {
      if (hunter.view_state === 'STALE') {
        mode = 'stale';
        labelText = 'Señal vencida';
        detailText = 'El último estado perdió vigencia.';
      } else if (hunter.view_state === 'UNAVAILABLE') {
        mode = 'alert';
        labelText = 'Hunter no disponible';
        detailText = 'El contrato público no respondió.';
      }
    } else if (cycleIsRunning(payload)) {
      mode = 'running';
      labelText = 'Ciclo en curso';
      detailText = 'Verificando un activo autorizado.';
    } else if (payload.state === 'ACTIVE') {
      mode = 'ready';
      labelText = 'Hunter listo';
      detailText = payload.next_scheduled_at
        ? `Próximo ciclo: ${formatIso(payload.next_scheduled_at)}.`
        : 'Esperando la próxima ejecución programada.';
    } else if (payload.state === 'STARTING') {
      mode = 'starting';
      labelText = 'Inicializando hunter';
      detailText = 'Validando dependencias antes del próximo ciclo.';
    } else if (payload.state === 'DEGRADED') {
      mode = 'stale';
      labelText = 'Hunter degradado';
      detailText = 'El runtime no cumple todas las condiciones de frescura.';
    } else if (payload.state === 'BLOCKED') {
      mode = 'alert';
      labelText = 'Hunter bloqueado';
      detailText = 'La política impide ejecutar el ciclo.';
    } else if (payload.state === 'ERROR') {
      mode = 'alert';
      labelText = 'Hunter con error';
      detailText = 'El runtime requiere revisión.';
    } else if (payload.state === 'STOPPED') {
      mode = 'stopped';
      labelText = 'Hunter detenido';
      detailText = 'No hay un ciclo activo.';
    }

    strip.dataset.mode = mode;
    label.textContent = labelText;
    detail.textContent = detailText;
    strip.setAttribute('aria-label', `Actividad del hunter: ${labelText}. ${detailText}`);
  }

  function render(next) {
    model = next;
    document.body.dataset.viewState = next.overall.view_state;
    setState($('overall-state'), next.overall.view_state);
    $('overall-reason').textContent = reasonText(next.overall.reason);
    renderTime($('dashboard-updated'), next.updated_at);

    const hunter = next.sources.hunter;
    const health = next.sources.health;
    const payload = hunter.payload;
    const isLab = Boolean(payload && payload.environment === 'controlled_lab');
    const labVisible = COMPILED_LAB || isLab;
    document.body.dataset.environment = labVisible ? 'controlled_lab' : 'production';
    $('lab-banner').hidden = !labVisible;
    $('hunter-source-title').textContent = labVisible ? 'Hunter · LAB CONTROLADO' : 'Hunter runtime';
    $('health-source-title').textContent = labVisible ? 'Preview health' : 'Backend health';
    $('hero-title').textContent = labVisible ? 'Laboratorio controlado. Estado verificable.' : 'Sin ruido. Sólo estado real.';
    $('hero-lede').innerHTML = labVisible
      ? 'Evidencia sintética y autorizada. <strong>No reportable</strong>; vista exclusiva del laboratorio controlado.'
      : 'Datos públicos verificables. <strong>N/D</strong> si falta una fuente; <strong>STALE</strong> si perdió vigencia.';

    renderSource('hunter', hunter);
    renderSource('health', health);
    renderHuntLive(hunter);

    $('lab-panel').hidden = !labVisible;
    $('runtime-panel').hidden = labVisible;
    $('health-panel').hidden = labVisible;
    $('findings-panel').hidden = labVisible;
    $('qualification-panel').hidden = labVisible;
    $('lab-state').textContent = isLab ? hunter.view_state : 'UNAVAILABLE';
    $('lab-reportable').textContent = 'NO';
    renderTime($('lab-cycle'), isLab && payload.cycle_finished_at);
    $('lab-policy').textContent = text(isLab && payload.policy_id);
    $('lab-control').textContent = isLab && payload.control_finding_count === 0 ? 'LIMPIO · 0' : 'N/D';
    $('lab-egress').textContent = isLab && payload.egress_blocked === true ? 'BLOQUEADO' : 'N/D';
    $('lab-cleanup').textContent = isLab && payload.cleanup_verified === true ? 'VERIFICADO' : 'N/D';

    $('hunter-state').textContent = text(hunter.payload && hunter.payload.state);
    renderTime($('heartbeat-at'), hunter.payload && hunter.payload.heartbeat_at);
    renderTime($('last-started-at'), hunter.payload && hunter.payload.last_started_at);
    renderTime($('last-completed-at'), hunter.payload && hunter.payload.last_completed_at);
    renderTime($('next-scheduled-at'), hunter.payload && hunter.payload.next_scheduled_at);

    $('health-status').textContent = text(health.payload && health.payload.status);
    $('health-version').textContent = text(health.payload && health.payload.version);
    renderRelease($('health-release'), health.payload && health.payload.release_sha);
    $('health-uptime').textContent = formatDuration(health.payload && health.payload.process_uptime_ms);

    const changed = $('release-change');
    changed.hidden = !next.release_changed;
    changed.textContent = next.release_changed
      ? 'La release cambió. El estado anterior fue descartado antes de renderizar esta respuesta.'
      : '';

    const dataAvailable = Boolean(hunter.payload || health.payload);
    $('empty-state').hidden = dataAvailable || labVisible;
    $('status-grid').hidden = !(dataAvailable || labVisible);
  }

  async function poll() {
    if (polling || document.hidden) return;
    polling = true;
    try {
      const [hunter, health] = await Promise.all([
        State.fetchJsonContract(window.fetch.bind(window), ENDPOINTS.hunter),
        State.fetchJsonContract(window.fetch.bind(window), ENDPOINTS.health),
      ]);
      render(State.buildModel({ previous: model, hunter, health, nowMs: Date.now(), maxAgeMs: MAX_AGE_MS }));
    } finally {
      polling = false;
    }
  }

  function schedule() {
    if (timer) clearInterval(timer);
    timer = setInterval(poll, POLL_MS);
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) poll();
  });

  render(model);
  poll();
  schedule();
})();

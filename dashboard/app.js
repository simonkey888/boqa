(() => {
  'use strict';

  const State = window.BOQADashboardState;
  if (!State) throw new Error('BOQA dashboard state module unavailable');

  const $ = (id) => document.getElementById(id);
  const ENDPOINTS = Object.freeze({ hunter: '/api/hunter/status', health: '/api/health' });
  const POLL_MS = 15_000;
  const MAX_AGE_MS = 90_000;
  let model = State.createInitialModel();
  let polling = false;
  let timer = null;

  function text(value) {
    return value === null || value === undefined || value === '' ? 'N/D' : String(value);
  }

  function parseTime(value) {
    if (!value) return NaN;
    return Date.parse(value);
  }

  function formatIso(value) {
    const parsed = parseTime(value);
    return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : 'N/D';
  }

  function formatDuration(value) {
    if (!Number.isFinite(value)) return 'N/D';
    if (value < 1_000) return `${value} ms`;
    return `${(value / 1_000).toFixed(1)} s`;
  }

  function setState(node, state) {
    node.textContent = state;
    node.dataset.state = state;
  }

  function renderSource(name, source) {
    setState($(`${name}-view-state`), source.view_state);
    $(`${name}-source`).textContent = source.endpoint;
    $(`${name}-timestamp`).textContent = formatIso(source.source_timestamp);
    $(`${name}-received`).textContent = formatIso(source.received_at);
    $(`${name}-reason`).textContent = text(source.reason);
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

    if (!payload) {
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
    $('overall-reason').textContent = text(next.overall.reason);
    $('dashboard-updated').textContent = formatIso(next.updated_at);

    const hunter = next.sources.hunter;
    const health = next.sources.health;
    renderSource('hunter', hunter);
    renderSource('health', health);
    renderHuntLive(hunter);

    $('hunter-state').textContent = text(hunter.payload && hunter.payload.state);
    $('heartbeat-at').textContent = formatIso(hunter.payload && hunter.payload.heartbeat_at);
    $('last-started-at').textContent = formatIso(hunter.payload && hunter.payload.last_started_at);
    $('last-completed-at').textContent = formatIso(hunter.payload && hunter.payload.last_completed_at);
    $('next-scheduled-at').textContent = formatIso(hunter.payload && hunter.payload.next_scheduled_at);

    $('health-status').textContent = text(health.payload && health.payload.status);
    $('health-version').textContent = text(health.payload && health.payload.version);
    $('health-release').textContent = text(health.payload && health.payload.release_sha);
    $('health-uptime').textContent = formatDuration(health.payload && health.payload.process_uptime_ms);

    const changed = $('release-change');
    changed.hidden = !next.release_changed;
    changed.textContent = next.release_changed
      ? 'La release cambió. El estado anterior fue descartado antes de renderizar esta respuesta.'
      : '';

    const dataAvailable = Boolean(hunter.payload || health.payload);
    $('empty-state').hidden = dataAvailable;
    $('status-grid').hidden = !dataAvailable;
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

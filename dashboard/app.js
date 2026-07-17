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

  function formatIso(value) {
    if (!value) return 'N/D';
    const parsed = Date.parse(value);
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

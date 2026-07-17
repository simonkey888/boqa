(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const safe = value => value === null || value === undefined ? 'Sin datos' : String(value);
  const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const relative = iso => { if (!iso) return 'Sin datos'; const seconds = Math.round((new Date(iso) - Date.now()) / 1000); const abs = Math.abs(seconds); const value = abs < 60 ? abs : abs < 3600 ? Math.round(abs / 60) : Math.round(abs / 3600); const unit = abs < 60 ? 's' : abs < 3600 ? 'min' : 'h'; return seconds >= 0 ? `en ${value} ${unit}` : `hace ${value} ${unit}`; };
  const stageOrder = ['authorization','preparation','validation','evidence','classification'];
  let controller = null;

  function setTrace(stage, running) {
    const trace = $('trace'); trace.dataset.stage = stage; trace.classList.toggle('running', running);
    const current = Math.max(0, stageOrder.indexOf(stage));
    trace.querySelectorAll('span').forEach((node, i) => { node.className = i < current ? 'passed' : i === current && running ? 'current' : ''; });
  }
  function render(state, health, bugs) {
    const running = state.scheduler_status === 'RUNNING';
    $('connection').textContent = 'Conectado'; $('connection-dot').className = 'online';
    $('overall').textContent = state.engine_status === 'ACTIVE' ? 'Motor operativo' : 'Motor bloqueado';
    $('operational-copy').textContent = state.authorized_assets > 0 ? (running ? 'Validando laboratorio controlado' : 'Laboratorio controlado activo · Esperando activos externos autorizados') : 'En espera de un activo autorizado';
    $('version').textContent = `v${health.version || '—'}`; $('footer-version').textContent = `BOQA v${health.version || '—'}`;
    $('footer-sha').textContent = `SHA ${(health.release_sha || '—').slice(0, 8)}`; $('footer-backend').textContent = `Backend ${health.status || 'sin datos'}`; $('footer-scheduler').textContent = `Scheduler ${state.scheduler_status || 'sin datos'}`;
    $('k-engine').textContent = safe(state.engine_status); $('k-engine-note').textContent = state.mode || 'Sin datos';
    $('k-cycle').textContent = safe(state.current_cycle_stage); $('k-cycle-note').textContent = relative(state.last_cycle);
    $('k-assets').textContent = safe(state.authorized_assets); $('k-checks').textContent = safe(state.controls_completed);
    $('k-validated').textContent = safe(state.validated_findings); $('k-reportable').textContent = safe(state.reportable_findings);
    $('next-cycle').textContent = relative(state.next_cycle); $('integrity').textContent = safe(state.evidence_integrity_status);
    setTrace(stageOrder.includes(state.current_cycle_stage) ? state.current_cycle_stage : 'authorization', running);
    const summary = bugs.summary || {};
    $('f-confirmed').textContent = safe(summary.technical?.confirmed ?? summary.confirmed ?? 0); $('f-review').textContent = safe(summary.technical?.needs_review ?? summary.technical_needs_review ?? 0); $('f-blocked').textContent = safe(summary.reportability?.blocked_scope ?? summary.blocked_scope ?? 0); $('f-rejected').textContent = safe(summary.technical?.rejected ?? summary.technical_rejected ?? 0); $('f-reportable').textContent = safe(summary.reportable ?? 0);
    $('activity-list').innerHTML = state.activity?.length ? state.activity.map(item => `<article class="row activity-row"><time>${escapeHtml(new Date(item.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}))}</time><div><b>${escapeHtml(item.asset)}</b><span>${escapeHtml(item.control)}</span></div><em class="status">${escapeHtml(item.result)}</em><span>${safe(item.duration_ms)} ms</span><code>${escapeHtml(item.evidence || '—')}</code></article>`).join('') : '<div class="empty">Esperando el primer ciclo real.</div>';
    $('evidence-list').innerHTML = state.evidence?.length ? state.evidence.map(item => `<article class="row evidence-row"><b>${escapeHtml(item.id)}</b><time>${escapeHtml(relative(item.date))}</time><span>${escapeHtml(item.origin)}</span><em class="status">${escapeHtml(item.integrity)}</em><code>${escapeHtml(item.hash.slice(0, 20))}…</code></article>`).join('') : '<div class="empty">Sin evidencia disponible.</div>';
  }
  async function poll() {
    if (document.hidden) return;
    controller?.abort(); controller = new AbortController();
    try { const [s,h,b] = await Promise.all(['/api/defensive/status','/api/health','/api/bugs?status=all'].map(url => fetch(url,{signal:controller.signal}).then(r => { if (!r.ok) throw Error(); return r.json(); }))); render(s,h,b); }
    catch (error) { if (error.name !== 'AbortError') { $('connection').textContent = 'Sin conexión'; $('connection-dot').className = ''; } }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  poll(); setInterval(poll, 15000);
})();

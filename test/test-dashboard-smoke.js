'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'dashboard', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'dashboard', 'app.js'), 'utf8');
const state = fs.readFileSync(path.join(root, 'dashboard', 'dashboard-state.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'dashboard', 'style.css'), 'utf8');
const mobileCss = fs.readFileSync(path.join(root, 'dashboard', 'mobile.css'), 'utf8');
const worker = fs.readFileSync(path.join(root, 'worker.js'), 'utf8');

assert.match(html, /<script\s+src=["']\/dashboard-state\.js["']\s+defer><\/script>/, 'dashboard must load the state contract');
assert.match(html, /<script\s+src=["']\/app\.js["']\s+defer><\/script>/, 'dashboard must load /app.js');
assert.match(html, /<link\s+rel=["']stylesheet["']\s+href=["']\/mobile\.css["']>/, 'dashboard must load mobile overrides');
assert.match(app, /poll\(\)/, 'dashboard must initialize');
assert.doesNotMatch(app, /['"]X-API-Key['"]\s*:/, 'browser must not send backend API key');
assert.doesNotMatch(app + html, /localStorage|auth-gate|modal de clave/i, 'dashboard must not contain a browser credential gate');
assert.doesNotMatch(app, /uptimeStart\s*:\s*Date\.now/, 'browser must not invent server uptime');
assert.match(app, /\/api\/hunter\/status/, 'dashboard must consume the public hunter contract');
assert.match(app, /\/api\/health/, 'dashboard must consume health');
assert.doesNotMatch(app, /defensive\/status|\/api\/bugs|\/api\/findings/, 'dashboard must not consume legacy synthetic sources');
assert.match(app, /document\.hidden/, 'polling must pause while hidden');
assert.match(html, /id=["']hunt-live["']/, 'dashboard must expose the lightweight live hunter trace');
assert.match(app, /function cycleIsRunning\(payload\)/, 'live trace must use an explicit real-cycle predicate');
assert.match(app, /payload\.state !== 'STARTING'/, 'live movement must require the runtime STARTING state');
assert.match(app, /startedAt > completedAt/, 'live movement must require an unfinished real cycle');
assert.match(app, /Todas las fuentes están actualizadas/, 'raw overall reason must have a human label');
assert.match(app, /Contrato válido y actualizado/, 'raw source reason must have a human label');
assert.match(app, /release\.slice\(0, 10\)/, 'visible release SHA must be abbreviated');
assert.match(app, /Release completa:/, 'complete release SHA must remain accessible');
assert.match(css, /@keyframes hunt-sweep/, 'live trace must include the lightweight sweep animation');
assert.match(css, /prefers-reduced-motion:reduce/, 'live trace must respect reduced-motion preferences');
assert.match(mobileCss, /grid-template-columns:\s*repeat\(2/, 'mobile sources and secondary panels must compact into two columns');
assert.match(mobileCss, /max-width:\s*340px/, 'narrow-device fallback must remain single-column');
assert.doesNotMatch(css + mobileCss, /@import|https?:\/\//i, 'dashboard CSS must not load remote fonts or visual dependencies');
assert.match(state, /LOADING/);
assert.match(state, /FRESH/);
assert.match(state, /STALE/);
assert.match(state, /UNAVAILABLE/);

assert.match(html, /data-environment=["']unknown["']/, 'source dashboard must default to non-lab mode');
assert.match(html, /id=["']lab-banner["'][^>]*hidden/, 'source dashboard lab banner must be hidden until explicit lab build');
assert.match(html, />LAB CONTROLADO</, 'dashboard must contain an explicit textual lab label');
assert.match(html, /id=["']lab-panel["']/, 'dashboard must expose the controlled-lab evidence panel');
for (const field of ['lab-state', 'lab-reportable', 'lab-cycle', 'lab-policy', 'lab-control', 'lab-egress', 'lab-cleanup']) {
  assert.match(html, new RegExp(`id=[\"']${field}[\"']`), `dashboard must expose ${field}`);
}
assert.doesNotMatch(html.match(/id=["']lab-banner["'][\s\S]*?<\/section>/)[0], /producci[oó]n/i, 'visible lab banner must not use production wording');
assert.match(app, /COMPILED_LAB/, 'lab label persistence must be compiled into the preview build');
assert.match(app, /mode = 'lab-complete'/, 'completed one-shot lab cycle must use a stopped animation mode');
assert.match(app, /El hunter permanece detenido/, 'completed lab cycle must state that the hunter is stopped');
assert.match(app, /labVisible = COMPILED_LAB \|\| isLab/, 'compiled lab banner must persist during transport errors');
assert.match(state, /lab_evidence_stale/, 'dashboard state must self-expire FRESH evidence to STALE');
assert.match(state, /lab_evidence_expired/, 'dashboard state must self-expire old evidence to UNAVAILABLE');
assert.match(state, /lab_contract_fields_invalid/, 'dashboard must reject unknown lab contract fields');
assert.match(css, /data-mode=["']lab-complete["']/, 'completed lab mode must have a dedicated stopped visual state');
assert.doesNotMatch(css.match(/\.hunt-live\[data-mode=["']lab-complete["']\][\s\S]*?\}/)[0], /animation\s*:\s*[^n]/i, 'completed lab mode must not animate');
assert.match(worker, /url\.pathname === '\/api\/health'\) return safeLabHealthResponse/, 'lab preview health must not depend on production backend health');
assert.match(worker, /SAFE_LAB_PREVIEW_BUILD\.enabled === true/, 'lab behavior must be gated by an explicit build-time block');
assert.match(worker, /promotion_blocker !== 'CONTROLLED_LAB_PREVIEW'/, 'invalid promotion blocker must fail closed');
assert.match(worker, /proxyHeaders\.set\('X-API-Key', workerApiKey\)/, 'Worker must overwrite upstream API key');
assert.match(worker, /'\/api\/hunter\/status'/, 'Worker must proxy hunter status');
assert.doesNotMatch(worker, /default_api_key|DEMO_BUGS|DEMO_HEALTH|demoJsonEvidence|example\.com|mock data/i, 'Worker must not expose keys or demo state');
assert.match(worker, /function isPrivateSurface\(pathname\)/, 'public Worker must identify private routes before proxy/assets');
assert.match(worker, /function hiddenPrivateResponse\(pathname\)/, 'public Worker must conceal private routes');
assert.match(worker, /normalized\.startsWith\('\/api\/private\/billing\/'\)/, 'private billing API must be explicitly concealed');
assert.doesNotMatch(worker, /isPrivateBilling/, 'private billing must not remain in the public API allowlist');
assert.match(worker, /X-BOQA-Sig/);
assert.match(worker, /X-BOQA-Ts/);
assert.match(worker, /no-store, max-age=0/);
assert.doesNotMatch(worker, /cacheTtl|caches\.default|s-maxage/i, 'runtime state must not be edge-cached');
assert.doesNotMatch(worker, /Could not reach BOQA backend at/, 'Worker errors must not disclose backend URL');

console.log('Dashboard smoke test: PASS');

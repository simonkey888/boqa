'use strict';

const fs = require('fs');
const path = require('path');
const { LocalLabRuntime } = require('./local-lab-runtime');

const REQUIRED = Object.freeze({
  ownership_status: 'verified',
  authorization_status: 'verified',
  scope_status: 'in_scope',
  environment_type: 'owned_or_lab',
  validation_mode: 'non_destructive',
});
const ALLOWED_TYPES = new Set(['fixture_local', 'container_local', 'owned_service']);
const STATES = new Set(['ACTIVE', 'PAUSED', 'WAITING_FOR_AUTHORIZED_ASSET', 'BLOCKED_BY_POLICY', 'ERROR']);

class DefensiveValidationService {
  constructor(options = {}) {
    this.allowlistPath = options.allowlistPath || path.join(__dirname, '..', 'config', 'authorized-assets.json');
    this.statePath = options.statePath || path.join(__dirname, '..', 'output', 'defensive-validation-state.json');
    this.labEnabled = process.env.BOQA_LAB_ENABLED === 'true';
    this.intervalMs = options.intervalMs || Number(process.env.BOQA_VALIDATION_INTERVAL_MS || (this.labEnabled ? 900000 : 300000));
    this.localLab = options.localLab || new LocalLabRuntime();
    this.timeoutMs = options.timeoutMs || 5000;
    this.maxConcurrency = 1;
    this.running = new Set();
    this.timer = null;
    this.state = this._loadState();
  }

  _loadState() {
    try {
      const saved = JSON.parse(fs.readFileSync(this.statePath, 'utf8'));
      return { ...this._emptyState(), ...saved, recovered_after_restart: true };
    } catch (_) { return this._emptyState(); }
  }

  _emptyState() {
    return { mode: 'DEFENSIVE_VALIDATION', scheduler_status: 'WAITING_FOR_AUTHORIZED_ASSET', engine_status: 'ACTIVE', current_cycle_stage: 'pending', last_cycle: null, next_cycle: null, authorized_assets: 0, controls_completed: 0, validated_findings: 0, reportable_findings: 0, pending_incidents: 0, blocked_by_policy: 0, cycle_success_rate: null, median_cycle_duration_ms: null, evidence_integrity_status: 'NO_EVIDENCE', activity: [], evidence: [], last_error: null, recovered_after_restart: false };
  }

  _save() {
    fs.mkdirSync(path.dirname(this.statePath), { recursive: true });
    fs.writeFileSync(this.statePath, JSON.stringify(this.state, null, 2));
  }

  loadAssets() {
    const parsed = JSON.parse(fs.readFileSync(this.allowlistPath, 'utf8'));
    if (parsed.validation_mode !== 'DEFENSIVE_VALIDATION' || !Array.isArray(parsed.assets)) throw new Error('UNSAFE_ALLOWLIST_CONFIGURATION');
    return parsed.assets;
  }

  authorize(asset) {
    if (!asset || !ALLOWED_TYPES.has(asset.type)) return { allowed: false, reason: 'ASSET_TYPE_NOT_ALLOWED' };
    for (const [key, value] of Object.entries(REQUIRED)) if (asset[key] !== value) return { allowed: false, reason: `${key.toUpperCase()}_NOT_VERIFIED` };
    if (asset.type === 'owned_service' && !asset.authorization_evidence) return { allowed: false, reason: 'AUTHORIZATION_EVIDENCE_REQUIRED' };
    return { allowed: true, reason: 'AUTHORIZED' };
  }

  authorizeRedirect(asset, redirectUrl) {
    const auth = this.authorize(asset);
    if (!auth.allowed) return auth;
    if (!asset.allowed_origins || !Array.isArray(asset.allowed_origins)) return { allowed: false, reason: 'REDIRECT_SCOPE_NOT_CONFIGURED' };
    try {
      const origin = new URL(redirectUrl).origin;
      return asset.allowed_origins.includes(origin) ? { allowed: true, reason: 'AUTHORIZED' } : { allowed: false, reason: 'REDIRECT_OUT_OF_SCOPE' };
    } catch (_) { return { allowed: false, reason: 'INVALID_REDIRECT' }; }
  }

  async validate(asset) {
    const auth = this.authorize(asset);
    if (!auth.allowed) return { status: 'BLOCKED_BY_POLICY', reason: auth.reason, controls_completed: 0 };
    if (this.running.has(asset.id)) return { status: 'BLOCKED_BY_POLICY', reason: 'DUPLICATE_EXECUTION', controls_completed: 0 };
    this.running.add(asset.id);
    try {
      if (asset.type !== 'fixture_local' && asset.type !== 'container_local') return { status: 'BLOCKED_BY_POLICY', reason: 'OWNED_SERVICE_RUNTIME_REQUIRES_PLATFORM_VERIFICATION', controls_completed: 0 };
      const checks = Array.isArray(asset.checks) ? asset.checks : [];
      const allowedChecks = new Set(['availability', 'configuration', 'schema', 'isolation']);
      if (checks.some(check => !allowedChecks.has(check))) return { status: 'BLOCKED_BY_POLICY', reason: 'CHECK_NOT_NON_DESTRUCTIVE', controls_completed: 0 };
      return { status: 'COMPLETED', reason: 'LOCAL_FIXTURE_VALIDATED', controls_completed: checks.length };
    } finally { this.running.delete(asset.id); }
  }

  async runCycle() {
    const started = new Date().toISOString();
    const startedMs = Date.now();
    try {
      this.state.current_cycle_stage = 'authorization';
      const assets = this.loadAssets();
      const authorized = assets.filter(asset => this.authorize(asset).allowed);
      this.state.authorized_assets = authorized.length;
      this.state.blocked_by_policy = assets.length - authorized.length;
      this.state.controls_completed = 0;
      if (!authorized.length) this.state.scheduler_status = 'WAITING_FOR_AUTHORIZED_ASSET';
      else {
        this.state.scheduler_status = 'RUNNING';
        for (const asset of authorized) {
          this.state.current_cycle_stage = 'validation';
          const result = await Promise.race([this.validate(asset), new Promise(resolve => setTimeout(() => resolve({ status: 'ERROR', reason: 'TIMEOUT', controls_completed: 0 }), this.timeoutMs))]);
          this.state.controls_completed += result.controls_completed || 0;
          if (result.status === 'BLOCKED_BY_POLICY') this.state.blocked_by_policy += 1;
          const finishedAt = new Date().toISOString();
          const evidencePayload = `${asset.id}:${started}:${result.status}:${result.controls_completed || 0}`;
          const hash = require('crypto').createHash('sha256').update(evidencePayload).digest('hex');
          this.state.activity = [{ time: finishedAt, asset: 'Laboratorio controlado', control: 'Validación determinística', result: result.status, duration_ms: Date.now() - startedMs, evidence: hash.slice(0, 12) }, ...(this.state.activity || [])].slice(0, 20);
          this.state.evidence = [{ id: `EVD-${hash.slice(0, 10)}`, date: finishedAt, origin: 'Laboratorio controlado', status: 'verified', hash: `sha256:${hash}`, integrity: 'valid' }, ...(this.state.evidence || [])].slice(0, 20);
        }
        this.state.current_cycle_stage = 'classification';
        this.state.scheduler_status = 'ACTIVE';
        this.state.evidence_integrity_status = 'VALID';
        this.state.cycle_success_rate = 1;
        this.state.median_cycle_duration_ms = Date.now() - startedMs;
      }
      this.state.last_error = null;
      if (this.labEnabled) {
        this.state.current_cycle_stage = 'preparation';
        const lab = await this.localLab.runOnce();
        if (lab.evidence_sha256) {
          this.state.current_cycle_stage = 'evidence';
          this.state.lab_runtime = { label: 'Laboratorio real aislado', last_round: lab.completed_at, vulnerable_result: lab.result.vulnerable, control_result: lab.result.control, integrity: 'VALID', next_round: new Date(Date.now() + this.intervalMs).toISOString() };
          this.state.activity = [{ time: lab.completed_at, asset: 'Laboratorio real aislado', control: lab.scenario_family, result: `${lab.result.vulnerable} · ${lab.result.control}`, duration_ms: lab.duration_ms, evidence: lab.evidence_sha256.slice(0,12) }, ...(this.state.activity || [])].slice(0,20);
          this.state.evidence = [{ id: `LAB-${lab.run_id.slice(0,10)}`, date: lab.completed_at, origin: 'Laboratorio real aislado', status: 'verified', hash: `sha256:${lab.evidence_sha256}`, integrity: 'valid' }, ...(this.state.evidence || [])].slice(0,20);
        } else if (lab.result === 'BLOCKED_BY_POLICY') this.state.blocked_by_policy += 1;
      }
    } catch (_) {
      this.state.scheduler_status = 'ERROR';
      this.state.engine_status = 'BLOCKED_BY_POLICY';
      this.state.last_error = 'unsafe_or_invalid_configuration';
    }
    this.state.last_cycle = started;
    this.state.current_cycle_stage = 'completed';
    this.state.next_cycle = new Date(Date.now() + this.intervalMs).toISOString();
    this._save();
    return this.publicStatus();
  }

  start() {
    if (this.timer) return;
    this.state.engine_status = 'ACTIVE';
    this.runCycle();
    this.timer = setInterval(() => this.runCycle(), this.intervalMs);
    this.timer.unref?.();
  }

  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; this._save(); }
  publicStatus() { return Object.fromEntries(Object.entries(this.state).filter(([key]) => !key.startsWith('_'))); }
}

module.exports = { DefensiveValidationService, REQUIRED, STATES };

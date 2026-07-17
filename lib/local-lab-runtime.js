'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const MANIFEST_PATH = path.join(__dirname, '..', 'qualification', 'labs', 'juice-shop-v1', 'manifest.json');
const CONTROL_PATH = path.join(__dirname, '..', 'qualification', 'labs', 'juice-shop-v1', 'control-server.js');
const RESULTS = new Set(['LAB_FINDING_CONFIRMED', 'LAB_CONTROL_CLEAN', 'INDETERMINATE', 'BLOCKED_BY_POLICY', 'ERROR']);

function digestFile(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

class LocalLabRuntime {
  constructor(options = {}) {
    this.manifestPath = options.manifestPath || MANIFEST_PATH;
    this.imageDigest = options.imageDigest ?? process.env.BOQA_LAB_IMAGE_DIGEST;
    this.usesDefaultFetcher = !options.fetcher;
    this.fetcher = options.fetcher || this._http.bind(this);
    this.lockPath = options.lockPath || path.join(os.tmpdir(), 'boqa-local-lab-runtime.lock');
    this.requestCount = 0;
  }

  loadManifest() {
    const manifest = JSON.parse(fs.readFileSync(this.manifestPath, 'utf8'));
    if (manifest.schema_version !== 1 || manifest.upstream_version !== '19.1.1') throw new Error('INVALID_MANIFEST');
    if (!Array.isArray(manifest.allowed_origins) || manifest.allowed_origins.length !== 2) throw new Error('INVALID_ORIGINS');
    if (!manifest.image_manifest_digest || !manifest.image_config_digest) throw new Error('INVALID_IMAGE_IDENTITY');
    return manifest;
  }

  validateConfig() {
    let manifest;
    try {
      manifest = this.loadManifest();
    } catch (error) {
      return { allowed: false, reason: 'MANIFEST_MISSING_OR_INVALID', error: error.message };
    }
    if (this.imageDigest !== manifest.image_manifest_digest) {
      return { allowed: false, reason: 'IMAGE_DIGEST_MISMATCH' };
    }
    return { allowed: true, manifest };
  }

  validateUrl(raw, manifest) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      return { allowed: false, reason: 'INVALID_URL' };
    }
    const allowedOrigins = new Set(manifest.allowed_origins);
    if (url.protocol !== 'http:' || !allowedOrigins.has(url.origin)) return { allowed: false, reason: 'HOST_BLOCKED' };
    if (!['/', '/health', '/rest/products/search'].includes(url.pathname)) return { allowed: false, reason: 'PATH_BLOCKED' };
    return { allowed: true, url };
  }

  _http(raw, { timeoutMs, manifest }) {
    const policy = this.validateUrl(raw, manifest);
    if (!policy.allowed) return Promise.resolve({ status: 0, body: '', error: policy.reason });
    this.requestCount += 1;
    return new Promise((resolve) => {
      const req = http.get(policy.url, {
        timeout: timeoutMs,
        headers: { Accept: 'application/json,text/html;q=0.9', 'User-Agent': 'boqa-controlled-lab/1' },
      }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          res.resume();
          resolve({ status: res.statusCode, body: '', redirect: res.headers.location || '' });
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (body.length < 65536) body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode || 0, body, redirect: null }));
      });
      req.on('timeout', () => {
        req.destroy();
        resolve({ status: 0, body: '', error: 'TIMEOUT' });
      });
      req.on('error', (error) => resolve({ status: 0, body: '', error: error.code || 'ERROR' }));
    });
  }

  async fetch(raw, manifest) {
    if (this.usesDefaultFetcher) return this.fetcher(raw, { timeoutMs: manifest.timeout_ms, manifest });
    this.requestCount += 1;
    return this.fetcher(raw, { timeoutMs: manifest.timeout_ms, maxRedirects: 0, manifest });
  }

  async health(origin, manifest, kind) {
    const endpoint = kind === 'control' ? '/health' : '/';
    const response = await this.fetch(`${origin}${endpoint}`, manifest);
    if (response.error || response.redirect || response.status !== 200) return false;
    if (kind === 'control') {
      try {
        return JSON.parse(response.body).status === 'ok';
      } catch {
        return false;
      }
    }
    return response.body.length > 0;
  }

  async scenario(origin, manifest, kind) {
    const query = manifest.probe_query || 'apple';
    const url = `${origin}/rest/products/search?q=${encodeURIComponent(query)}`;
    const policy = this.validateUrl(url, manifest);
    if (!policy.allowed) return { result: 'BLOCKED_BY_POLICY' };
    const response = await this.fetch(url, manifest);
    if (response.redirect) return { result: 'BLOCKED_BY_POLICY' };
    if (response.error) return { result: response.error === 'TIMEOUT' ? 'ERROR' : 'INDETERMINATE' };
    if (response.status !== 200) return { result: 'INDETERMINATE' };
    let data;
    try {
      data = JSON.parse(response.body).data;
    } catch {
      return { result: 'INDETERMINATE' };
    }
    const hasData = Array.isArray(data) && data.length > 0;
    return {
      result: kind === 'candidate'
        ? (hasData ? 'LAB_FINDING_CONFIRMED' : 'INDETERMINATE')
        : (hasData ? 'INDETERMINATE' : 'LAB_CONTROL_CLEAN'),
    };
  }

  acquireLock() {
    try {
      fs.mkdirSync(this.lockPath);
      return true;
    } catch (error) {
      if (error.code === 'EEXIST') return false;
      throw error;
    }
  }

  releaseLock() {
    fs.rmSync(this.lockPath, { recursive: true, force: true });
  }

  async runOnce(options = {}) {
    if (!this.acquireLock()) return { result: 'BLOCKED_BY_POLICY', reason: 'LAB_LOCKED' };
    const startedAt = new Date().toISOString();
    const started = Date.now();
    this.requestCount = 0;
    try {
      const config = this.validateConfig();
      if (!config.allowed) return { result: 'BLOCKED_BY_POLICY', reason: config.reason };
      const manifest = config.manifest;
      const [candidateOrigin, controlOrigin] = manifest.allowed_origins;
      if (!await this.health(candidateOrigin, manifest, 'candidate') || !await this.health(controlOrigin, manifest, 'control')) {
        return { result: 'INDETERMINATE', reason: 'LAB_UNHEALTHY' };
      }

      const runId = options.runId || crypto.randomBytes(12).toString('hex');
      const candidate = await this.scenario(candidateOrigin, manifest, 'candidate');
      const control = await this.scenario(controlOrigin, manifest, 'control');
      const requestBudgetVerified = this.requestCount <= manifest.request_budget_per_scenario * 2 + 2;
      const stable = {
        lab_id: manifest.lab_id,
        run_id: runId,
        manifest_digest: crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex'),
        image_digest: manifest.image_manifest_digest,
        control_digest: digestFile(CONTROL_PATH),
        source_digest: digestFile(__filename),
        scenario_family: manifest.scenario_family,
        request_count: this.requestCount,
        result: { vulnerable: candidate.result, control: control.result },
        request_budget_verified: requestBudgetVerified,
        policy_status: 'AUTHORIZED',
        environment: 'controlled_lab',
        reportability: 'not_reportable',
        external_target: false,
      };
      return {
        ...stable,
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - started,
        runtime_identity: {
          uid: typeof process.getuid === 'function' ? process.getuid() : null,
          gid: typeof process.getgid === 'function' ? process.getgid() : null,
          hostname: os.hostname(),
          node: process.version,
        },
        evidence_sha256: crypto.createHash('sha256').update(JSON.stringify(stable)).digest('hex'),
      };
    } finally {
      this.releaseLock();
    }
  }
}

module.exports = { LocalLabRuntime, MANIFEST_PATH, RESULTS };

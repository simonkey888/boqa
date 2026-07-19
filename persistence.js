'use strict';

/**
 * persistence.js
 *
 * Fase 15 — Atomic persistence layer.
 *
 * All writes go through:
 *   1. write temp file (.tmp)
 *   2. fsync
 *   3. rename (atomic on POSIX)
 *
 * On startup:
 *   - load persisted state
 *   - validate schema version
 *   - migrate from previous version if needed
 *   - do not duplicate already-processed observations
 */

const fs = require('fs');
const path = require('path');
const { CanonicalBugStore } = require('./canonical-bug-store');

const SCHEMA_VERSION = 1;

class Persistence {
  constructor(opts = {}) {
    this.root = opts.root || path.resolve(__dirname, 'output');
    this.canonicalDir = path.join(this.root, 'canonical');
    this.targetsDir   = path.join(this.root, 'targets');
    this.portfolioDir = path.join(this.root, 'portfolio');
  }

  _ensureDirs() {
    for (const d of [this.canonicalDir, this.targetsDir, this.portfolioDir]) {
      if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    }
  }

  /**
   * Atomic write: temp + fsync + rename.
   */
  writeAtomic(filepath, data) {
    const tmp = filepath + '.tmp';
    const buf = Buffer.from(JSON.stringify(data, null, 2), 'utf-8');
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, buf, 0, buf.length, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, filepath);
  }

  /**
   * Read JSON safely. Returns null if missing or invalid.
   */
  readJson(filepath) {
    if (!fs.existsSync(filepath)) return null;
    try {
      return JSON.parse(fs.readFileSync(filepath, 'utf-8'));
    } catch {
      return null;
    }
  }

  /**
   * Persist the canonical bug store.
   */
  persistCanonicalStore(store) {
    this._ensureDirs();
    const file = path.join(this.canonicalDir, 'bugs.json');
    this.writeAtomic(file, {
      schema_version: SCHEMA_VERSION,
      generated_at: Date.now(),
      bug_count: store.size(),
      bugs: store.all(),
    });
  }

  /**
   * Persist the per-status buckets.
   */
  persistStatusBuckets(store) {
    this._ensureDirs();
    const reportable  = store.by_quality_status('reportable');
    const needsReview = store.by_quality_status('needs_review');
    const rejected    = store.by_quality_status('rejected');
    this.writeAtomic(path.join(this.canonicalDir, 'bugs.json'),         { schema_version: SCHEMA_VERSION, generated_at: Date.now(), count: reportable.length,  bugs: reportable  });
    this.writeAtomic(path.join(this.canonicalDir, 'needs-review.json'), { schema_version: SCHEMA_VERSION, generated_at: Date.now(), count: needsReview.length, bugs: needsReview });
    this.writeAtomic(path.join(this.canonicalDir, 'rejected.json'),     { schema_version: SCHEMA_VERSION, generated_at: Date.now(), count: rejected.length,    bugs: rejected    });
  }

  /**
   * Persist portfolio summary.
   */
  persistPortfolio(summary) {
    this._ensureDirs();
    this.writeAtomic(path.join(this.portfolioDir, 'summary.json'), {
      schema_version: SCHEMA_VERSION,
      generated_at: Date.now(),
      ...summary,
    });
  }

  /**
   * Load canonical store from disk.
   */
  loadCanonicalStore() {
    const file = path.join(this.canonicalDir, 'bugs.json');
    const data = this.readJson(file);
    if (!data) return new CanonicalBugStore();
    // Schema migration hook (currently v1 → v1 = identity)
    if (data.schema_version && data.schema_version > SCHEMA_VERSION) {
      console.warn(`[persistence] canonical bugs schema ${data.schema_version} > supported ${SCHEMA_VERSION}, attempting load anyway`);
    }
    return CanonicalBugStore.from_serializable(data);
  }

  /**
   * Load targets from disk via TargetRegistry.
   */
  loadTargets() {
    const file = path.join(this.targetsDir, 'targets.json');
    const data = this.readJson(file);
    if (!data) return [];
    return Array.isArray(data) ? data : (data.targets || []);
  }
}

module.exports = { Persistence, SCHEMA_VERSION };

/**
 * BOQA evidence-quality-engine.js — Evidence Quality Engine v0.7
 *
 * Scores evidence packages for disclosure readiness.
 * A finding is disclosure-ready when its evidence package meets
 * quality thresholds for:
 *
 *   - completeness:    all required evidence fields present
 *   - reproducibility: clear reproduction steps
 *   - chain_of_custody: evidence timeline is coherent
 *   - independence:    confirmed by independent verification
 *   - recency:         evidence is not stale
 *   - specificity:     evidence is specific to the finding (not generic)
 *
 * Scoring model:
 *   completeness(0.25) + reproducibility(0.25) + chain_of_custody(0.15) +
 *   independence(0.15) + recency(0.10) + specificity(0.10)
 *
 * Each dimension scored 0-100. Overall evidence readiness 0-100.
 * Disclosure threshold: >= 95 (per v0.7 success criteria)
 *
 * The engine also generates:
 *   - Evidence gap reports: what's missing for disclosure
 *   - Quality improvement suggestions: what to collect next
 *   - Disclosure readiness certificates: when threshold is met
 *
 * Safe mode: only evaluates evidence quality; never fabricates
 * or modifies evidence.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Quality Dimensions ────────────────────────────────────────────

const QUALITY_DIMENSIONS = {
  completeness:     { weight: 0.25, description: 'All required evidence fields present' },
  reproducibility:  { weight: 0.25, description: 'Clear reproduction steps' },
  chain_of_custody: { weight: 0.15, description: 'Coherent evidence timeline' },
  independence:     { weight: 0.15, description: 'Confirmed by independent verification' },
  recency:          { weight: 0.10, description: 'Evidence is not stale' },
  specificity:      { weight: 0.10, description: 'Specific to the finding' },
};

// ─── Evidence Requirements per Category ─────────────────────────────

const CATEGORY_REQUIREMENTS = {
  auth_bypass: {
    required_fields: ['request_response', 'timeline', 'reproduction_steps'],
    optional_fields: ['cross_session', 'state_diff', 'permission_boundary'],
  },
  session_hijacking: {
    required_fields: ['request_response', 'timeline', 'cookie_analysis'],
    optional_fields: ['reproduction_steps', 'cross_session'],
  },
  csrf: {
    required_fields: ['request_response', 'reproduction_steps', 'token_analysis'],
    optional_fields: ['timeline', 'cross_session'],
  },
  cookie_security: {
    required_fields: ['request_response', 'cookie_analysis'],
    optional_fields: ['timeline', 'reproduction_steps'],
  },
  api_exposure: {
    required_fields: ['request_response', 'reproduction_steps'],
    optional_fields: ['timeline', 'state_diff'],
  },
  idor: {
    required_fields: ['request_response', 'reproduction_steps', 'permission_boundary'],
    optional_fields: ['timeline', 'cross_session'],
  },
  default: {
    required_fields: ['request_response', 'timeline'],
    optional_fields: ['reproduction_steps', 'cross_session'],
  },
};

// ─── Recency Thresholds ────────────────────────────────────────────

const EVIDENCE_STALE_MS = 7 * 86400000;     // 7 days
const EVIDENCE_VERY_STALE_MS = 30 * 86400000; // 30 days

// ─── Disclosure Readiness Threshold ────────────────────────────────

const DISCLOSURE_READINESS_THRESHOLD = 95;

// ─── Persistence ────────────────────────────────────────────────────

const EVIDENCE_DIR = path.join(__dirname, 'output', 'knowledge', 'evidence-quality');

// =====================================================================
//  EvidenceQualityEngine
// =====================================================================

class EvidenceQualityEngine {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]     - KnowledgeBase instance
   * @param {object} [options.correlationEngine]  - CorrelationEngine for independence scoring
   * @param {object} [options.findingMemory]      - FindingMemory for cross-target specificity
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.correlationEngine = options.correlationEngine || null;
    this.findingMemory = options.findingMemory || null;

    /** @type {Map<string, object>} finding_id → quality score */
    this.qualityScores = new Map();

    /** @type {object[]} disclosure readiness certificates */
    this.certificates = [];

    /** @type {object[]} quality improvement suggestions */
    this.suggestions = [];

    // Ensure directory exists
    fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

    // Auto-load
    this.load();
  }

  // ─── Quality Scoring ────────────────────────────────────────────

  /**
   * Score an evidence package for a finding.
   *
   * @param {object} finding - the finding with attached evidence
   * @param {object} [evidence] - explicit evidence package (or use finding.evidence)
   * @returns {object} quality assessment
   */
  score(finding, evidence) {
    const ev = evidence || finding.evidence || {};
    const category = (finding.category || '').toLowerCase();
    const requirements = CATEGORY_REQUIREMENTS[category] || CATEGORY_REQUIREMENTS.default;

    // Score each dimension
    const dimensions = {
      completeness:     this._scoreCompleteness(ev, requirements),
      reproducibility:  this._scoreReproducibility(ev, finding),
      chain_of_custody: this._scoreChainOfCustody(ev, finding),
      independence:     this._scoreIndependence(finding),
      recency:          this._scoreRecency(ev, finding),
      specificity:      this._scoreSpecificity(ev, finding),
    };

    // Compute weighted overall score
    let overallScore = 0;
    for (const [dimension, score] of Object.entries(dimensions)) {
      const weight = QUALITY_DIMENSIONS[dimension]?.weight || 0;
      overallScore += score * weight;
    }

    overallScore = Math.round(overallScore);

    // Determine disclosure readiness
    const isReady = overallScore >= DISCLOSURE_READINESS_THRESHOLD;

    // Generate gap report
    const gaps = this._generateGapReport(dimensions, requirements);

    // Generate improvement suggestions
    const suggestions = this._generateSuggestions(dimensions, gaps, requirements);

    // Build assessment
    const assessment = {
      id: `QA-${crypto.randomUUID().substring(0, 8)}`,
      finding_id: finding.id || finding.finding_id,
      category,
      dimensions,
      overall_score: overallScore,
      disclosure_ready: isReady,
      gaps,
      suggestions,
      assessed_at: Date.now(),
    };

    // Cache
    this.qualityScores.set(assessment.finding_id, assessment);

    // Generate certificate if ready
    if (isReady) {
      const existingCert = this.certificates.find(c => c.finding_id === assessment.finding_id);
      if (!existingCert) {
        const cert = this._generateCertificate(assessment, finding);
        this.certificates.push(cert);
      }
    }

    // Store suggestions
    for (const suggestion of suggestions) {
      this.suggestions.push({
        ...suggestion,
        finding_id: assessment.finding_id,
        suggested_at: Date.now(),
      });
    }

    // Cap suggestions
    if (this.suggestions.length > 1000) {
      this.suggestions = this.suggestions.slice(-1000);
    }

    return assessment;
  }

  /**
   * Score all findings with evidence.
   *
   * @param {object[]} findings
   * @returns {object[]} assessments
   */
  scoreAll(findings) {
    return findings.map(f => this.score(f));
  }

  // ─── Dimension Scoring ──────────────────────────────────────────

  /**
   * Score completeness: are all required evidence fields present?
   * @private
   */
  _scoreCompleteness(evidence, requirements) {
    const required = requirements.required_fields || [];
    const optional = requirements.optional_fields || [];

    if (required.length === 0) return 50; // neutral

    let filled = 0;
    for (const field of required) {
      if (evidence[field] !== undefined && evidence[field] !== null && evidence[field] !== '') {
        filled++;
      }
    }

    // Required fields: 0-80 points
    let score = (filled / required.length) * 80;

    // Optional fields: up to 20 bonus points
    let optionalFilled = 0;
    for (const field of optional) {
      if (evidence[field] !== undefined && evidence[field] !== null && evidence[field] !== '') {
        optionalFilled++;
      }
    }

    if (optional.length > 0) {
      score += (optionalFilled / optional.length) * 20;
    }

    return Math.round(Math.min(100, score));
  }

  /**
   * Score reproducibility: are there clear reproduction steps?
   * @private
   */
  _scoreReproducibility(evidence, finding) {
    let score = 0;

    // Reproduction steps present?
    const steps = evidence.reproduction_steps || finding.reproduction || [];
    if (steps.length > 0) {
      score += 40;
      if (steps.length >= 3) score += 20; // detailed steps
      if (steps.length >= 5) score += 10; // very detailed
    }

    // Request/response pairs present?
    if (evidence.request_response || evidence.request_response_pairs) {
      score += 20;
    }

    // State diff available?
    if (evidence.state_diff || evidence.before_after) {
      score += 15;
    }

    // Multiple reproductions?
    if (evidence.cross_session || finding.reproduced_count > 1) {
      score += 15;
    }

    return Math.round(Math.min(100, score));
  }

  /**
   * Score chain of custody: is the evidence timeline coherent?
   * @private
   */
  _scoreChainOfCustody(evidence, finding) {
    let score = 30; // base score for having any evidence

    const timeline = evidence.timeline || finding.timeline || [];
    if (timeline.length > 0) {
      score += 30;
      if (timeline.length >= 3) score += 15;
      if (timeline.length >= 5) score += 10;
    }

    // Timestamp coherence check
    if (timeline.length >= 2) {
      const sorted = [...timeline].sort((a, b) => (a.ts || a.timestamp || 0) - (b.ts || b.timestamp || 0));
      let gaps = 0;
      for (let i = 1; i < sorted.length; i++) {
        const prev = sorted[i - 1].ts || sorted[i - 1].timestamp || 0;
        const curr = sorted[i].ts || sorted[i].timestamp || 0;
        if (curr - prev > 300000) gaps++; // > 5 min gap
      }
      if (gaps === 0) score += 15;
      else if (gaps <= 2) score += 8;
    }

    return Math.round(Math.min(100, score));
  }

  /**
   * Score independence: confirmed by independent verification?
   * @private
   */
  _scoreIndependence(finding) {
    let score = 20; // base: single observation

    // Check for verification results
    if (this.kb) {
      const validations = this.kb.getValidationsForFinding(finding.id || finding.finding_id);

      if (validations.length >= 1) {
        score += 30;
        if (validations.some(v => v.verdict === 'confirmed')) {
          score += 30;
        }
      }

      if (validations.length >= 2) {
        score += 20; // multiple independent validations
      }
    }

    // Check for correlation (independent observation)
    if (this.correlationEngine) {
      const correlations = this.correlationEngine.getCorrelationsForFinding(
        finding.id || finding.finding_id
      );
      const independentCorrelations = correlations.filter(
        c => c.type === 'repeated_finding' || c.type === 'cross_target'
      );
      if (independentCorrelations.length > 0) {
        score += 15;
      }
    }

    return Math.round(Math.min(100, score));
  }

  /**
   * Score recency: is the evidence fresh?
   * @private
   */
  _scoreRecency(evidence, finding) {
    const now = Date.now();
    const evidenceTs = evidence.captured_at || evidence.ts || finding.created_at || finding.observed_at;

    if (!evidenceTs) return 30; // unknown timestamp

    const age = now - evidenceTs;

    if (age < 86400000) return 100;        // < 1 day
    if (age < 3 * 86400000) return 80;     // < 3 days
    if (age < EVIDENCE_STALE_MS) return 60; // < 7 days
    if (age < EVIDENCE_VERY_STALE_MS) return 30; // < 30 days
    return 10; // very stale
  }

  /**
   * Score specificity: is evidence specific to this finding?
   * @private
   */
  _scoreSpecificity(evidence, finding) {
    let score = 50; // base

    // Specific cookies mentioned?
    if ((finding.affected_cookies || []).length > 0) {
      score += 15;
    }

    // Specific endpoints mentioned?
    if ((finding.affected_endpoints || []).length > 0) {
      score += 15;
    }

    // Specific request/response (not generic)?
    if (evidence.request_response && typeof evidence.request_response === 'object') {
      const rr = evidence.request_response;
      if (rr.url || rr.path) score += 10; // tied to specific endpoint
      if (rr.headers) score += 5;          // has specific headers
      if (rr.body) score += 5;             // has specific body
    }

    return Math.round(Math.min(100, score));
  }

  // ─── Gap Reports and Suggestions ────────────────────────────────

  _generateGapReport(dimensions, requirements) {
    const gaps = [];

    for (const [dimension, score] of Object.entries(dimensions)) {
      if (score < 70) {
        gaps.push({
          dimension,
          current_score: score,
          target_score: 95,
          gap: 95 - score,
          description: QUALITY_DIMENSIONS[dimension]?.description || dimension,
        });
      }
    }

    // Sort by gap size (largest gap first)
    gaps.sort((a, b) => b.gap - a.gap);
    return gaps;
  }

  _generateSuggestions(dimensions, gaps, requirements) {
    const suggestions = [];

    for (const gap of gaps) {
      switch (gap.dimension) {
        case 'completeness':
          suggestions.push({
            action: 'collect_missing_evidence',
            priority: 'high',
            detail: `Missing required fields: ${requirements.required_fields?.filter(f => !f).join(', ') || 'unknown'}`,
          });
          break;

        case 'reproducibility':
          suggestions.push({
            action: 'capture_reproduction_steps',
            priority: 'high',
            detail: 'Record detailed step-by-step reproduction with request/response pairs',
          });
          break;

        case 'chain_of_custody':
          suggestions.push({
            action: 'capture_timeline',
            priority: 'medium',
            detail: 'Record timestamps for each evidence capture step',
          });
          break;

        case 'independence':
          suggestions.push({
            action: 'verify_independently',
            priority: 'high',
            detail: 'Submit for independent verification through the verification farm',
          });
          break;

        case 'recency':
          suggestions.push({
            action: 'refresh_evidence',
            priority: 'medium',
            detail: 'Re-observe the finding to get fresh evidence',
          });
          break;

        case 'specificity':
          suggestions.push({
            action: 'add_specific_details',
            priority: 'low',
            detail: 'Add specific cookies, endpoints, and request details to evidence',
          });
          break;
      }
    }

    return suggestions;
  }

  _generateCertificate(assessment, finding) {
    return {
      id: `CERT-${crypto.randomUUID().substring(0, 8)}`,
      finding_id: assessment.finding_id,
      category: assessment.category,
      overall_score: assessment.overall_score,
      dimensions: assessment.dimensions,
      disclosure_ready: true,
      certified_at: Date.now(),
      finding_title: finding.title || finding.description || 'Untitled Finding',
      finding_severity: finding.severity,
    };
  }

  // ─── Query Methods ──────────────────────────────────────────────

  /**
   * Get quality score for a finding.
   *
   * @param {string} findingId
   * @returns {object|null}
   */
  getQualityScore(findingId) {
    return this.qualityScores.get(findingId) || null;
  }

  /**
   * Get all disclosure-ready findings.
   * @returns {object[]}
   */
  getDisclosureReady() {
    return [...this.qualityScores.values()]
      .filter(a => a.disclosure_ready)
      .sort((a, b) => b.overall_score - a.overall_score);
  }

  /**
   * Get all certificates.
   * @returns {object[]}
   */
  getCertificates() {
    return this.certificates.sort((a, b) => b.certified_at - a.certified_at);
  }

  /**
   * Get quality improvement suggestions.
   *
   * @param {object} [filter] - { finding_id, priority }
   * @returns {object[]}
   */
  getSuggestions(filter = {}) {
    let results = this.suggestions;

    if (filter.finding_id) {
      results = results.filter(s => s.finding_id === filter.finding_id);
    }
    if (filter.priority) {
      results = results.filter(s => s.priority === filter.priority);
    }

    return results.sort((a, b) => b.suggested_at - a.suggested_at);
  }

  /**
   * Get overall evidence readiness statistics.
   * @returns {object}
   */
  getStats() {
    const all = [...this.qualityScores.values()];

    const avgScore = all.length > 0
      ? Math.round(all.reduce((s, a) => s + a.overall_score, 0) / all.length)
      : 0;

    const readyCount = all.filter(a => a.disclosure_ready).length;

    return {
      total_assessed: all.length,
      disclosure_ready: readyCount,
      readiness_rate: all.length > 0 ? Math.round((readyCount / all.length) * 10000) / 10000 : 0,
      avg_score: avgScore,
      certificates_issued: this.certificates.length,
      pending_suggestions: this.suggestions.length,
      by_dimension: this._dimensionAverages(all),
    };
  }

  _dimensionAverages(assessments) {
    const dims = {};
    for (const dim of Object.keys(QUALITY_DIMENSIONS)) {
      const scores = assessments.map(a => a.dimensions[dim] || 0);
      dims[dim] = scores.length > 0
        ? Math.round(scores.reduce((s, v) => s + v, 0) / scores.length)
        : 0;
    }
    return dims;
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Save quality state to disk.
   * @returns {string}
   */
  save() {
    const filePath = path.join(EVIDENCE_DIR, 'evidence-quality.json');

    const data = {
      version: '0.7',
      saved_at: Date.now(),
      quality_scores: [...this.qualityScores.entries()].slice(-500),
      certificates: this.certificates.slice(-200),
      suggestions: this.suggestions.slice(-200),
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  /**
   * Load quality state from disk.
   * @returns {boolean}
   */
  load() {
    const filePath = path.join(EVIDENCE_DIR, 'evidence-quality.json');
    if (!fs.existsSync(filePath)) return false;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      this.qualityScores = new Map(data.quality_scores || []);
      this.certificates = data.certificates || [];
      this.suggestions = data.suggestions || [];

      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = { EvidenceQualityEngine, QUALITY_DIMENSIONS, DISCLOSURE_READINESS_THRESHOLD, EVIDENCE_DIR };


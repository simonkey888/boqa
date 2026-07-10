/**
 * BOQA risk.js — Risk Engine + Finding Engine
 *
 * Normalizes validated hypotheses into findings with severity and confidence.
 * Assigns risk scores based on:
 *   - Category base severity
 *   - Confidence adjustment from validation
 *   - Contextual factors (production vs test, affected cookie sensitivity)
 *   - Anomaly corroboration
 *
 * Finding schema:
 *   id, title, category, severity, confidence,
 *   evidence, affected_endpoints, affected_cookies,
 *   timeline, reproduction, recommended_fix
 */

const crypto = require('crypto');

// ─── Category Severity Matrix ───────────────────────────────────────

const CATEGORY_SEVERITY = {
  missing_httpOnly:                    { base: 'high',      score: 75 },
  missing_secure:                     { base: 'high',      score: 70 },
  weak_samesite:                      { base: 'medium',    score: 55 },
  bearer_token_exposure:              { base: 'high',      score: 80 },
  jwt_in_browser_memory:              { base: 'critical',  score: 95 },
  session_fixation_indicators:        { base: 'high',      score: 75 },
  session_rotation_failure:           { base: 'medium',    score: 50 },
  cache_control_misconfiguration:     { base: 'medium',    score: 55 },
  csrf_signal_anomaly:                { base: 'high',      score: 80 },
  cors_misconfiguration:              { base: 'critical',  score: 90 },
  cookie_scope_oversharing:           { base: 'medium',    score: 55 },
  cross_subdomain_trust_expansion:    { base: 'medium',    score: 60 },
  unexpected_auth_model_change:       { base: 'high',      score: 75 },
  sensitive_data_exposure:            { base: 'high',      score: 80 },
  excessive_client_side_secrets:      { base: 'high',      score: 70 },
  auth_state_desynchronization:       { base: 'high',      score: 70 },
  ws_auth_inconsistency:              { base: 'medium',    score: 55 },
  permission_boundary_anomaly:        { base: 'medium',    score: 60 },
  regression_security_change:         { base: 'high',      score: 75 },
};

// ─── Cookie Sensitivity Weights ─────────────────────────────────────

const COOKIE_SENSITIVITY = {
  ripio_access: 1.1,    // Encrypted JWT — highest sensitivity
  sessionid: 1.0,       // Django session
  access_token: 1.0,    // Bearer token
  refresh_token: 0.9,   // Token rotation
  id_token: 0.9,        // OIDC
  csrftoken: 0.6,       // CSRF (less sensitive on its own)
  auth_token: 1.0,
  _jwt: 1.0,
  _session: 0.8,
};

class RiskEngine {
  constructor() {
    this.findings = [];
  }

  /**
   * Convert validated hypotheses into normalized findings
   * @param {array} hypotheses - from HypothesisEngine
   * @param {array} validationResults - from ValidatorEngine
   * @param {object} context - { report, anomalies, baseline }
   * @returns {array} normalized findings
   */
  normalize(hypotheses, validationResults, context = {}) {
    const { report = {}, anomalies = [], baseline = null } = context;
    this.findings = [];

    const validationMap = new Map();
    for (const vr of validationResults) {
      validationMap.set(vr.hypothesis_id, vr);
    }

    // Only process validated hypotheses
    const validatedHypotheses = hypotheses.filter(h => {
      const vr = validationMap.get(h.id);
      return vr && vr.validated;
    });

    // Deduplicate by category + affected resources
    const deduped = this._deduplicate(validatedHypotheses);

    for (const hyp of deduped) {
      const vr = validationMap.get(hyp.id);
      const finding = this._createFinding(hyp, vr, report, anomalies, baseline);
      this.findings.push(finding);
    }

    // Sort by severity (critical first), then by confidence (highest first)
    this.findings.sort((a, b) => {
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const sevDiff = (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });

    return this.findings;
  }

  /**
   * Create a normalized finding from a hypothesis + validation
   */
  _createFinding(hypothesis, validationResult, report, anomalies, baseline) {
    const category = hypothesis.category;
    const categoryInfo = CATEGORY_SEVERITY[category] || { base: 'info', score: 20 };

    // Compute adjusted severity
    const severity = this._computeSeverity(category, hypothesis, validationResult, report);

    // Compute adjusted confidence
    const confidence = this._computeConfidence(hypothesis, validationResult, anomalies);

    // Risk score (0-100)
    const riskScore = this._computeRiskScore(category, severity, confidence, hypothesis, report);

    return {
      id: `FND-${crypto.randomUUID ? crypto.randomUUID().substring(0, 8) : Date.now().toString(36) + Math.random().toString(36).substring(2, 6)}`,
      hypothesis_id: hypothesis.id,
      title: hypothesis.title,
      category,
      severity,
      confidence,
      risk_score: riskScore,
      description: hypothesis.description,

      // Affected resources
      affected_endpoints: hypothesis.affected_endpoints || [],
      affected_cookies: hypothesis.affected_cookies || [],

      // Validation info
      validation_method: validationResult?.validation_method || 'none',
      validation_notes: validationResult?.validation_notes || '',

      // Evidence reference (will be populated by evidence engine)
      evidence: [],
      timeline: [],
      reproduction: [],
      recommended_fix: '',

      // Metadata
      created_at: Date.now(),
      source: hypothesis.source,
      category_base_severity: categoryInfo.base,
      category_base_score: categoryInfo.score,
    };
  }

  /**
   * Compute severity with contextual adjustments
   */
  _computeSeverity(category, hypothesis, validationResult, report) {
    const categoryInfo = CATEGORY_SEVERITY[category] || { base: 'info', score: 20 };
    let score = categoryInfo.score;

    // Adjust for cookie sensitivity
    for (const cookieName of (hypothesis.affected_cookies || [])) {
      const weight = COOKIE_SENSITIVITY[cookieName] || 0.7;
      score = Math.round(score * weight + score * (1 - weight) * weight);
    }

    // Adjust for validation confidence
    const conf = validationResult?.confidence_adjusted || 50;
    if (conf >= 90) score += 5;
    else if (conf < 50) score -= 15;

    // Adjust for multiple affected cookies (compounding risk)
    if (hypothesis.affected_cookies?.length >= 3) score += 5;

    // Clamp
    score = Math.max(0, Math.min(100, score));

    // Map to severity level
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 50) return 'medium';
    if (score >= 30) return 'low';
    return 'info';
  }

  /**
   * Compute confidence with anomaly corroboration
   */
  _computeConfidence(hypothesis, validationResult, anomalies) {
    let conf = validationResult?.confidence_adjusted || hypothesis.confidence || 50;

    // Bonus for anomaly corroboration
    const category = hypothesis.category;
    const relatedAnomalyRules = this._getRelatedAnomalyRules(category);
    const corroboratingAnomalies = anomalies.filter(a => relatedAnomalyRules.includes(a.rule));
    if (corroboratingAnomalies.length > 0) {
      conf = Math.min(conf + corroboratingAnomalies.length * 3, 98);
    }

    return Math.max(0, Math.min(100, Math.round(conf)));
  }

  /**
   * Compute risk score (0-100)
   */
  _computeRiskScore(category, severity, confidence, hypothesis, report) {
    const categoryInfo = CATEGORY_SEVERITY[category] || { score: 20 };
    const sevMultiplier = { critical: 1.0, high: 0.8, medium: 0.6, low: 0.3, info: 0.1 };
    const confWeight = confidence / 100;

    let score = categoryInfo.score * (sevMultiplier[severity] || 0.5) * confWeight;

    // Production multiplier (if we detect real Ripio domain)
    const target = report.target || '';
    if (target.includes('ripio.com') && !target.includes('staging') && !target.includes('dev')) {
      score *= 1.1;
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Get anomaly rules related to a finding category
   */
  _getRelatedAnomalyRules(category) {
    const mapping = {
      missing_httpOnly: ['cookie_httpOnly_downgrade'],
      missing_secure: ['cookie_secure_downgrade'],
      bearer_token_exposure: ['new_bearer_usage_detected'],
      jwt_in_browser_memory: ['new_bearer_usage_detected'],
      session_fixation_indicators: ['auth_model_change'],
      session_rotation_failure: ['auth_model_change'],
      unexpected_auth_model_change: ['auth_model_change'],
      auth_state_desynchronization: ['error_rate_spike'],
      regression_security_change: ['cookie_httpOnly_downgrade', 'auth_model_change', 'error_rate_spike'],
      cors_misconfiguration: [],
      csrf_signal_anomaly: [],
      cache_control_misconfiguration: [],
    };
    return mapping[category] || [];
  }

  /**
   * Deduplicate hypotheses by category + affected cookie overlap
   */
  _deduplicate(hypotheses) {
    const seen = new Map(); // category → hypothesis (keep highest confidence)

    for (const hyp of hypotheses) {
      const key = `${hyp.category}:${(hyp.affected_cookies || []).sort().join(',')}`;
      const existing = seen.get(key);
      if (!existing || hyp.confidence > existing.confidence) {
        seen.set(key, hyp);
      }
    }

    return [...seen.values()];
  }

  // ─── Accessors ────────────────────────────────────────────────

  getFindings() {
    return this.findings;
  }

  getFindingsBySeverity() {
    const bySeverity = { critical: [], high: [], medium: [], low: [], info: [] };
    for (const f of this.findings) {
      bySeverity[f.severity] = bySeverity[f.severity] || [];
      bySeverity[f.severity].push(f);
    }
    return bySeverity;
  }

  getFindingsByCategory() {
    const byCategory = {};
    for (const f of this.findings) {
      byCategory[f.category] = byCategory[f.category] || [];
      byCategory[f.category].push(f);
    }
    return byCategory;
  }

  getSummary() {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byCategory = {};
    let totalRisk = 0;

    for (const f of this.findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
      totalRisk += f.risk_score;
    }

    return {
      total: this.findings.length,
      by_severity: bySeverity,
      by_category: byCategory,
      average_risk_score: this.findings.length > 0 ? Math.round(totalRisk / this.findings.length) : 0,
      max_risk_score: this.findings.length > 0 ? Math.max(...this.findings.map(f => f.risk_score)) : 0,
      has_critical: bySeverity.critical > 0,
      has_high: bySeverity.high > 0,
    };
  }
}

module.exports = { RiskEngine, CATEGORY_SEVERITY };


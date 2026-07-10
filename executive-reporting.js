/**
 * BOQA executive-reporting.js — Executive Reporting v0.7
 *
 * Generates stakeholder-ready summaries from BOQA's knowledge base.
 * Designed for different audiences:
 *
 *   - executive:  high-level risk summary, key metrics, trend indicators
 *   - technical:  detailed findings, evidence, reproduction steps
 *   - compliance: structured finding catalog with severity mappings
 *   - campaign:   campaign progress, ROI, resource utilization
 *
 * Report types:
 *   - daily_digest:    daily summary of discoveries and progress
 *   - campaign_report: campaign progress and outcomes
 *   - risk_assessment: current risk posture across portfolio
 *   - disclosure_pack: complete disclosure package for a finding
 *   - learning_report: learning engine effectiveness and improvements
 *
 * Output formats:
 *   - JSON: structured data for programmatic consumption
 *   - Markdown: human-readable reports
 *
 * Safe mode: reports only contain observability data that was
 * captured through authorized instrumentation.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Report Output ──────────────────────────────────────────────────

const REPORTS_DIR = path.join(__dirname, 'output', 'reports', 'executive');

// =====================================================================
//  ExecutiveReporting
// =====================================================================

class ExecutiveReporting {
  /**
   * @param {object} options
   * @param {object} [options.knowledgeBase]        - KnowledgeBase instance
   * @param {object} [options.brainRegistry]         - BrainRegistry instance
   * @param {object} [options.campaignEngine]         - CampaignEngine instance
   * @param {object} [options.learningEngine]         - LearningEngine instance
   * @param {object} [options.resourceOptimizer]       - ResourceOptimizer instance
   * @param {object} [options.evidenceQualityEngine]   - EvidenceQualityEngine instance
   * @param {object} [options.findingMemory]           - FindingMemory instance
   * @param {object} [options.coverageEngine]           - CoverageEngine instance
   * @param {object} [options.hypothesisPrioritizer]    - HypothesisPrioritizer instance
   */
  constructor(options = {}) {
    this.kb = options.knowledgeBase || null;
    this.brainRegistry = options.brainRegistry || null;
    this.campaignEngine = options.campaignEngine || null;
    this.learningEngine = options.learningEngine || null;
    this.resourceOptimizer = options.resourceOptimizer || null;
    this.evidenceQuality = options.evidenceQualityEngine || null;
    this.findingMemory = options.findingMemory || null;
    this.coverageEngine = options.coverageEngine || null;
    this.hypothesisPrioritizer = options.hypothesisPrioritizer || null;

    /** @type {object[]} generated report index */
    this.reportIndex = [];

    // Ensure directory exists
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  // ─── Daily Digest ───────────────────────────────────────────────

  /**
   * Generate a daily digest report.
   *
   * @param {string} [targetId] - optional target filter
   * @returns {object} daily digest
   */
  generateDailyDigest(targetId) {
    const now = Date.now();
    const dayStart = now - 86400000;

    // Collect metrics
    const kbMetrics = this.kb ? this.kb.getMetrics() : {};
    const learningMetrics = this.learningEngine ? this.learningEngine.getMetrics() : {};
    const campaignStats = this.campaignEngine ? this.campaignEngine.getStats() : {};
    const optimizerStats = this.resourceOptimizer ? this.resourceOptimizer.getStats() : {};
    const evidenceStats = this.evidenceQuality ? this.evidenceQuality.getStats() : {};
    const memoryStats = this.findingMemory ? this.findingMemory.getStats() : {};

    // Collect findings from today
    let todayFindings = [];
    if (this.kb) {
      todayFindings = this.kb.queryFindings({ limit: 1000 })
        .filter(f => (f.created_at || f.updated_at || 0) >= dayStart);
    }

    // Build digest
    const digest = {
      id: `DIGEST-${crypto.randomUUID().substring(0, 8)}`,
      type: 'daily_digest',
      date: new Date(now).toISOString().split('T')[0],
      generated_at: now,

      summary: {
        total_findings_today: todayFindings.length,
        critical: todayFindings.filter(f => f.severity === 'critical').length,
        high: todayFindings.filter(f => f.severity === 'high').length,
        medium: todayFindings.filter(f => f.severity === 'medium').length,
        low: todayFindings.filter(f => f.severity === 'low').length,
        info: todayFindings.filter(f => f.severity === 'info').length,
        confirmed_bugs: todayFindings.filter(f =>
          f.lifecycle_state === 'confirmed' || f.lifecycle_state === 'ranked'
        ).length,
        disclosure_ready: evidenceStats.disclosure_ready || 0,
      },

      metrics: {
        coverage_score: kbMetrics.coverage_score || 0,
        validated_bugs_per_hour: kbMetrics.validated_bugs_per_hour || 0,
        false_positive_rate: kbMetrics.false_positive_rate || 0,
        evidence_readiness: evidenceStats.readiness_rate || 0,
        learning_improvement: learningMetrics.improvement_per_month || 0,
      },

      campaigns: {
        active: campaignStats.by_state?.running || 0,
        total_bugs_confirmed: campaignStats.total_bugs_confirmed || 0,
        total_iterations: campaignStats.total_iterations || 0,
      },

      portfolio: {
        total_targets: optimizerStats.total_targets || 0,
        worker_distribution: optimizerStats.distribution || {},
      },

      memory: {
        total_patterns: memoryStats.total_patterns || 0,
        cross_target_patterns: memoryStats.cross_target_patterns || 0,
        regressions_detected: memoryStats.total_regressions || 0,
      },

      learning: {
        total_observations: learningMetrics.total_observations || 0,
        success_rate: learningMetrics.overall_success_rate || 0,
        current_weights: learningMetrics.current_weights || {},
        total_reweights: learningMetrics.total_reweights || 0,
      },

      top_findings: todayFindings
        .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
        .slice(0, 10)
        .map(f => ({
          id: f.finding_id || f.id,
          title: f.title || f.category,
          severity: f.severity,
          category: f.category,
          risk_score: f.risk_score,
          lifecycle_state: f.lifecycle_state,
        })),

      trends: this._computeTrends(targetId),

      recommendations: this._generateRecommendations(todayFindings, kbMetrics, learningMetrics),
    };

    // Save to disk
    this._saveReport(digest);

    return digest;
  }

  // ─── Campaign Report ────────────────────────────────────────────

  /**
   * Generate a campaign progress report.
   *
   * @param {string} campaignId
   * @returns {object} campaign report
   */
  generateCampaignReport(campaignId) {
    if (!this.campaignEngine) return { error: 'Campaign engine not available' };

    const campaign = this.campaignEngine.get(campaignId);
    if (!campaign) return { error: `Campaign not found: ${campaignId}` };

    const report = {
      id: `CAMP-RPT-${crypto.randomUUID().substring(0, 8)}`,
      type: 'campaign_report',
      campaign_id: campaignId,
      campaign_name: campaign.name,
      generated_at: Date.now(),

      overview: {
        type: campaign.type,
        state: campaign.state,
        targets: campaign.target_ids,
        duration_ms: campaign.started_at ? Date.now() - campaign.started_at : 0,
        total_runs: campaign.runs.length,
        total_iterations: campaign.total_iterations,
      },

      results: {
        hypotheses_generated: campaign.total_hypotheses,
        verifications_dispatched: campaign.total_verifications,
        bugs_confirmed: campaign.total_bugs_confirmed,
        events_processed: campaign.total_events_processed,
      },

      effectiveness: campaign.effectiveness,

      goals: {
        coverage_target: campaign.goals.coverage_target,
        finding_target: campaign.goals.finding_target,
        goals_met: campaign.goalsMet(),
        budget_exceeded: campaign.budgetExceeded(),
      },

      budget: campaign.budget,

      runs: campaign.runs.slice(-20).map(r => ({
        id: r.id,
        started_at: r.started_at,
        duration_ms: r.ended_at ? r.ended_at - r.started_at : null,
        iterations: r.iterations,
        bugs_confirmed: r.bugs_confirmed,
        coverage_delta: r.coverage_after != null && r.coverage_before != null
          ? r.coverage_after - r.coverage_before : null,
      })),
    };

    this._saveReport(report);
    return report;
  }

  // ─── Risk Assessment ────────────────────────────────────────────

  /**
   * Generate a portfolio risk assessment.
   *
   * @returns {object} risk assessment
   */
  generateRiskAssessment() {
    const targets = this.brainRegistry ? this.brainRegistry.list() : [];
    const targetEvs = this.resourceOptimizer ? this.resourceOptimizer.computeAllEVs() : [];

    // Build risk profile per target
    const targetRisks = targets.map(t => {
      const brain = this.brainRegistry ? this.brainRegistry.get(t.target_id) : null;
      const ev = targetEvs.find(e => e.target_id === t.target_id);

      return {
        target_id: t.target_id,
        findings: t.findings || 0,
        coverage: t.coverage || 0,
        expected_value: ev?.ev || 0,
        risk_level: this._computeRiskLevel(brain, ev),
        critical_findings: brain ? brain.historicalFindings.filter(f => f.severity === 'critical').length : 0,
        high_findings: brain ? brain.historicalFindings.filter(f => f.severity === 'high').length : 0,
      };
    });

    const assessment = {
      id: `RISK-${crypto.randomUUID().substring(0, 8)}`,
      type: 'risk_assessment',
      generated_at: Date.now(),

      portfolio_summary: {
        total_targets: targets.length,
        total_findings: targets.reduce((s, t) => s + (t.findings || 0), 0),
        critical_count: targetRisks.reduce((s, t) => s + t.critical_findings, 0),
        high_count: targetRisks.reduce((s, t) => s + t.high_findings, 0),
        avg_coverage: targets.length > 0
          ? Math.round(targets.reduce((s, t) => s + (t.coverage || 0), 0) / targets.length)
          : 0,
      },

      risk_distribution: {
        critical: targetRisks.filter(t => t.risk_level === 'critical').length,
        high: targetRisks.filter(t => t.risk_level === 'high').length,
        medium: targetRisks.filter(t => t.risk_level === 'medium').length,
        low: targetRisks.filter(t => t.risk_level === 'low').length,
      },

      targets: targetRisks.sort((a, b) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return (order[b.risk_level] || 0) - (order[a.risk_level] || 0);
      }),

      cross_target_patterns: this.findingMemory
        ? this.findingMemory.getCrossTargetPatterns(2).slice(0, 20).map(p => ({
            pattern: p.category,
            targets: p.target_count,
            confidence: p.confidence,
          }))
        : [],
    };

    this._saveReport(assessment);
    return assessment;
  }

  // ─── Disclosure Pack ────────────────────────────────────────────

  /**
   * Generate a complete disclosure package for a finding.
   *
   * @param {string} findingId
   * @returns {object} disclosure pack
   */
  generateDisclosurePack(findingId) {
    if (!this.kb) return { error: 'Knowledge base not available' };

    const finding = this.kb.getFinding(findingId);
    if (!finding) return { error: `Finding not found: ${findingId}` };

    const evidence = this.evidenceQuality ? this.evidenceQuality.getQualityScore(findingId) : null;
    const validations = this.kb.getValidationsForFinding(findingId);
    const correlations = this.findingMemory ? this.findingMemory.findSimilarPatterns(finding) : [];

    const pack = {
      id: `DISC-${crypto.randomUUID().substring(0, 8)}`,
      type: 'disclosure_pack',
      finding_id: findingId,
      generated_at: Date.now(),

      finding: {
        id: finding.finding_id || finding.id,
        title: finding.title || finding.category,
        category: finding.category,
        severity: finding.severity,
        confidence: finding.confidence,
        risk_score: finding.risk_score,
        description: finding.description,
        lifecycle_state: finding.lifecycle_state,
        affected_cookies: finding.affected_cookies || [],
        affected_endpoints: finding.affected_endpoints || [],
      },

      evidence_quality: evidence ? {
        overall_score: evidence.overall_score,
        disclosure_ready: evidence.disclosure_ready,
        dimensions: evidence.dimensions,
        gaps: evidence.gaps,
      } : null,

      verification: {
        total_validations: validations.length,
        confirmed: validations.filter(v => v.verdict === 'confirmed').length,
        rejected: validations.filter(v => v.verdict === 'rejected').length,
        results: validations.slice(-5),
      },

      correlations: correlations.slice(0, 5),

      timeline: finding.evidence?.timeline || finding.timeline || [],
      reproduction: finding.reproduction || finding.evidence?.reproduction_steps || [],
    };

    this._saveReport(pack);
    return pack;
  }

  // ─── Learning Report ────────────────────────────────────────────

  /**
   * Generate a learning effectiveness report.
   *
   * @returns {object}
   */
  generateLearningReport() {
    if (!this.learningEngine) return { error: 'Learning engine not available' };

    const metrics = this.learningEngine.getMetrics();
    const categoryScores = this.learningEngine.getHypothesisSuccessScores();
    const verificationScores = this.learningEngine.getVerificationSuccessScores();

    const report = {
      id: `LRN-RPT-${crypto.randomUUID().substring(0, 8)}`,
      type: 'learning_report',
      generated_at: Date.now(),

      overall: {
        total_observations: metrics.total_observations,
        overall_success_rate: metrics.overall_success_rate,
        improvement_per_month: metrics.improvement_per_month,
        total_reweights: metrics.total_reweights,
      },

      current_weights: metrics.current_weights,

      hypothesis_scores: categoryScores,
      verification_scores: verificationScores,

      weight_evolution: this.learningEngine.weightHistory.slice(-10),

      top_performing_categories: categoryScores.slice(0, 5),
      underperforming_categories: categoryScores.filter(c => c.success_rate < 0.1),

      recommendations: this._learningRecommendations(categoryScores, metrics),
    };

    this._saveReport(report);
    return report;
  }

  // ─── Markdown Generation ────────────────────────────────────────

  /**
   * Convert a report to Markdown format.
   *
   * @param {object} report - any report object
   * @returns {string} Markdown text
   */
  toMarkdown(report) {
    const lines = [];

    switch (report.type) {
      case 'daily_digest':
        lines.push(`# BOQA Daily Digest — ${report.date}`);
        lines.push('');
        lines.push('## Summary');
        lines.push('');
        lines.push(`- **Findings Today:** ${report.summary.total_findings_today}`);
        lines.push(`- **Critical:** ${report.summary.critical} | **High:** ${report.summary.high} | **Medium:** ${report.summary.medium}`);
        lines.push(`- **Confirmed Bugs:** ${report.summary.confirmed_bugs}`);
        lines.push(`- **Disclosure Ready:** ${report.summary.disclosure_ready}`);
        lines.push('');
        lines.push('## Key Metrics');
        lines.push('');
        lines.push(`- **Coverage Score:** ${report.metrics.coverage_score}/100`);
        lines.push(`- **Validated Bugs/Hour:** ${report.metrics.validated_bugs_per_hour}`);
        lines.push(`- **False Positive Rate:** ${(report.metrics.false_positive_rate * 100).toFixed(1)}%`);
        lines.push(`- **Evidence Readiness:** ${(report.metrics.evidence_readiness * 100).toFixed(1)}%`);
        lines.push(`- **Learning Improvement:** ${report.metrics.learning_improvement > 0 ? '+' : ''}${(report.metrics.learning_improvement * 100).toFixed(2)}%/month`);
        lines.push('');

        if (report.top_findings.length > 0) {
          lines.push('## Top Findings');
          lines.push('');
          lines.push('| # | Finding | Severity | Category | Risk Score |');
          lines.push('|---|---------|----------|----------|------------|');
          report.top_findings.forEach((f, i) => {
            lines.push(`| ${i + 1} | ${f.title} | ${f.severity} | ${f.category} | ${f.risk_score || '—'} |`);
          });
          lines.push('');
        }

        if (report.recommendations.length > 0) {
          lines.push('## Recommendations');
          lines.push('');
          for (const rec of report.recommendations) {
            lines.push(`- **${rec.priority.toUpperCase()}**: ${rec.action} — ${rec.detail}`);
          }
          lines.push('');
        }
        break;

      case 'campaign_report':
        lines.push(`# Campaign Report — ${report.campaign_name}`);
        lines.push('');
        lines.push(`**Campaign ID:** ${report.campaign_id}`);
        lines.push(`**Type:** ${report.overview.type}`);
        lines.push(`**State:** ${report.overview.state}`);
        lines.push(`**Duration:** ${Math.round(report.overview.duration_ms / 3600000)}h`);
        lines.push('');
        lines.push('## Results');
        lines.push('');
        lines.push(`- **Hypotheses Generated:** ${report.results.hypotheses_generated}`);
        lines.push(`- **Verifications Dispatched:** ${report.results.verifications_dispatched}`);
        lines.push(`- **Bugs Confirmed:** ${report.results.bugs_confirmed}`);
        lines.push(`- **Events Processed:** ${report.results.events_processed}`);
        lines.push(`- **Goals Met:** ${report.goals.goals_met ? 'Yes' : 'No'}`);
        break;

      case 'risk_assessment':
        lines.push('# Portfolio Risk Assessment');
        lines.push('');
        lines.push(`**Total Targets:** ${report.portfolio_summary.total_targets}`);
        lines.push(`**Total Findings:** ${report.portfolio_summary.total_findings}`);
        lines.push(`**Critical Findings:** ${report.portfolio_summary.critical_count}`);
        lines.push(`**Average Coverage:** ${report.portfolio_summary.avg_coverage}/100`);
        lines.push('');
        lines.push('## Risk Distribution');
        lines.push('');
        lines.push(`- Critical: ${report.risk_distribution.critical} targets`);
        lines.push(`- High: ${report.risk_distribution.high} targets`);
        lines.push(`- Medium: ${report.risk_distribution.medium} targets`);
        lines.push(`- Low: ${report.risk_distribution.low} targets`);
        break;

      default:
        lines.push(`# ${report.type} Report`);
        lines.push('');
        lines.push(`Generated: ${new Date(report.generated_at).toISOString()}`);
        lines.push('```json');
        lines.push(JSON.stringify(report, null, 2));
        lines.push('```');
    }

    return lines.join('\n');
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  _computeTrends(targetId) {
    if (!this.brainRegistry) return {};

    const brain = this.brainRegistry.get(targetId);
    if (!brain) return {};

    return {
      coverage_trend: brain.getCoverageTrend().slice(-7).map(s => ({
        date: new Date(s.ts).toISOString().split('T')[0],
        score: s.score,
      })),
      coverage_growth_rate: brain.getCoverageGrowthRate(),
    };
  }

  _generateRecommendations(findings, kbMetrics, learningMetrics) {
    const recs = [];

    // Coverage recommendation
    const coverage = kbMetrics.coverage_score || 0;
    if (coverage < 70) {
      recs.push({
        priority: 'high',
        action: 'increase_exploration',
        detail: `Coverage at ${coverage}% — increase exploration to discover more attack surface`,
      });
    } else if (coverage < 90) {
      recs.push({
        priority: 'medium',
        action: 'targeted_exploration',
        detail: `Coverage at ${coverage}% — focus on gaps in auth flows and API endpoints`,
      });
    }

    // False positive recommendation
    const fpr = kbMetrics.false_positive_rate || 0;
    if (fpr > 0.10) {
      recs.push({
        priority: 'high',
        action: 'improve_hypothesis_quality',
        detail: `False positive rate at ${(fpr * 100).toFixed(1)}% — improve hypothesis filtering`,
      });
    }

    // Learning recommendation
    if (learningMetrics.improvement_per_month !== undefined && learningMetrics.improvement_per_month < 0) {
      recs.push({
        priority: 'medium',
        action: 'review_learning_weights',
        detail: 'Learning improvement negative — review and adjust hypothesis prioritization weights',
      });
    }

    return recs;
  }

  _computeRiskLevel(brain, ev) {
    if (!brain) return 'low';

    const critical = brain.historicalFindings.filter(f => f.severity === 'critical').length;
    const high = brain.historicalFindings.filter(f => f.severity === 'high').length;

    if (critical > 0) return 'critical';
    if (high >= 3) return 'high';
    if (high >= 1) return 'medium';
    if (brain.historicalFindings.length > 5) return 'medium';
    return 'low';
  }

  _learningRecommendations(categoryScores, metrics) {
    const recs = [];

    const underexplored = categoryScores.filter(c => c.exploration_bonus > 0);
    if (underexplored.length > 0) {
      recs.push({
        action: 'explore_underrepresented_categories',
        categories: underexplored.map(c => c.category),
        detail: 'These categories have few observations and may contain undiscovered bugs',
      });
    }

    if (metrics.improvement_per_month < 0) {
      recs.push({
        action: 'reset_weights',
        detail: 'Learning improvement is negative — consider resetting to default weights',
      });
    }

    return recs;
  }

  _saveReport(report) {
    const filePath = path.join(REPORTS_DIR, `${report.id}.json`);
    try {
      fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
      this.reportIndex.push({
        id: report.id,
        type: report.type,
        generated_at: report.generated_at,
        path: filePath,
      });
    } catch (_) {}
  }
}

module.exports = { ExecutiveReporting, REPORTS_DIR };


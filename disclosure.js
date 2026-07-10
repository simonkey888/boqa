/**
 * BOQA disclosure.js — Disclosure Exporter
 *
 * Generates disclosure-ready reports from validated findings.
 * Safe mode: no exploitation steps, no full token values,
 * no privilege escalation instructions.
 *
 * Output formats:
 *   - JSON: Machine-readable finding_report.json
 *   - Markdown: Human-readable disclosure report
 *   - Summary: Executive summary for security teams
 */

const fs = require('fs');
const path = require('path');

const REPORTS_DIR = path.join(__dirname, 'output', 'reports');

class DisclosureExporter {
  constructor() {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  /**
   * Generate a complete disclosure report
   * @param {array} findings - normalized findings from RiskEngine
   * @param {array} evidencePackages - from EvidenceEngine
   * @param {object} sessionMeta - session metadata
   * @returns {object} disclosure report
   */
  generateReport(findings, evidencePackages, sessionMeta = {}) {
    const report = {
      // Report metadata
      report_id: `RPT-${Date.now().toString(36)}`,
      generated_at: new Date().toISOString(),
      generator: 'BOQA v0.3 — Evidence-Based Bug Discovery Engine',
      safe_mode: true,

      // Session context
      session: {
        id: sessionMeta.sessionId || 'unknown',
        target: sessionMeta.target || 'unknown',
        start: sessionMeta.sessionStart || null,
        end: sessionMeta.sessionEnd || null,
        duration_ms: sessionMeta.duration || null,
        total_events: sessionMeta.totalEvents || 0,
      },

      // Executive summary
      executive_summary: this._generateExecutiveSummary(findings),

      // Findings
      findings: findings.map(f => this._formatFinding(f, evidencePackages)),

      // Statistics
      statistics: this._computeStatistics(findings),

      // Disclosure metadata
      disclosure: {
        responsible_disclosure_only: true,
        no_exploitation: true,
        no_privilege_escalation: true,
        no_destructive_actions: true,
        reproduction_safe: true,
        contact: 'Report to security team via responsible disclosure channel',
      },
    };

    return report;
  }

  /**
   * Save report to disk
   */
  saveReport(report, filename) {
    const filePath = path.join(REPORTS_DIR, filename || `finding-report-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  /**
   * Generate Markdown version
   */
  generateMarkdown(report) {
    const lines = [];

    lines.push('# BOQA Security Findings Report');
    lines.push('');
    lines.push(`**Report ID:** ${report.report_id}`);
    lines.push(`**Generated:** ${report.generated_at}`);
    lines.push(`**Target:** ${report.session.target}`);
    lines.push(`**Session:** ${report.session.id}`);
    lines.push(`**Total Events:** ${report.session.total_events}`);
    lines.push('');

    // Executive Summary
    lines.push('---');
    lines.push('');
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(report.executive_summary.text);
    lines.push('');
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Total Findings | ${report.statistics.total_findings} |`);
    lines.push(`| Critical | ${report.statistics.by_severity.critical || 0} |`);
    lines.push(`| High | ${report.statistics.by_severity.high || 0} |`);
    lines.push(`| Medium | ${report.statistics.by_severity.medium || 0} |`);
    lines.push(`| Low | ${report.statistics.by_severity.low || 0} |`);
    lines.push(`| Average Risk Score | ${report.statistics.average_risk_score} |`);
    lines.push(`| Max Risk Score | ${report.statistics.max_risk_score} |`);
    lines.push('');

    // Findings by severity
    for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
      const sevFindings = report.findings.filter(f => f.severity === severity);
      if (sevFindings.length === 0) continue;

      lines.push('---');
      lines.push('');
      lines.push(`## ${severity.toUpperCase()} Findings (${sevFindings.length})`);
      lines.push('');

      for (const f of sevFindings) {
        lines.push(`### ${f.title}`);
        lines.push('');
        lines.push(`- **ID:** ${f.id}`);
        lines.push(`- **Category:** ${f.category}`);
        lines.push(`- **Severity:** ${f.severity}`);
        lines.push(`- **Confidence:** ${f.confidence}%`);
        lines.push(`- **Risk Score:** ${f.risk_score}/100`);
        lines.push('');

        lines.push('**Description:**');
        lines.push('');
        lines.push(f.description);
        lines.push('');

        if (f.affected_cookies.length > 0) {
          lines.push(`**Affected Cookies:** ${f.affected_cookies.join(', ')}`);
          lines.push('');
        }

        if (f.affected_endpoints.length > 0) {
          lines.push('**Affected Endpoints:**');
          lines.push('');
          for (const ep of f.affected_endpoints.slice(0, 10)) {
            lines.push(`- \`${ep}\``);
          }
          lines.push('');
        }

        if (f.evidence_chain && f.evidence_chain.length > 0) {
          lines.push('**Evidence Chain:**');
          lines.push('');
          for (const e of f.evidence_chain.slice(0, 10)) {
            lines.push(`- [${e.type}] ${e.detail}`);
          }
          lines.push('');
        }

        if (f.reproduction && f.reproduction.length > 0) {
          lines.push('**Reproduction (Safe Observation Only):**');
          lines.push('');
          for (const step of f.reproduction) {
            lines.push(`${step.step}. **[${step.action}]** ${step.description}`);
          }
          lines.push('');
        }

        if (f.recommended_fix) {
          lines.push('**Recommended Fix:**');
          lines.push('');
          lines.push(f.recommended_fix);
          lines.push('');
        }
      }
    }

    // Disclosure footer
    lines.push('---');
    lines.push('');
    lines.push('## Disclosure Policy');
    lines.push('');
    lines.push('This report was generated by BOQA in safe observation mode.');
    lines.push('No exploitation, privilege escalation, or destructive actions were performed.');
    lines.push('All findings are based on passive observability data.');
    lines.push('Report findings through responsible disclosure channels only.');
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Save Markdown report
   */
  saveMarkdown(markdown, filename) {
    const filePath = path.join(REPORTS_DIR, filename || `finding-report-${Date.now()}.md`);
    fs.writeFileSync(filePath, markdown, 'utf8');
    return filePath;
  }

  // ─── Internal ─────────────────────────────────────────────────

  _generateExecutiveSummary(findings) {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const total = findings.length;

    let riskLevel = 'LOW';
    let text = '';

    if (critical > 0) {
      riskLevel = 'CRITICAL';
      text = `BOQA identified ${total} security finding(s) including ${critical} critical and ${high} high severity issues. ` +
        `Critical findings require immediate attention. `;
    } else if (high > 0) {
      riskLevel = 'HIGH';
      text = `BOQA identified ${total} security finding(s) including ${high} high severity issues. `;
    } else if (medium > 0) {
      riskLevel = 'MODERATE';
      text = `BOQA identified ${total} security finding(s) including ${medium} medium severity issues. `;
    } else if (total > 0) {
      riskLevel = 'LOW';
      text = `BOQA identified ${total} low/info severity finding(s). `;
    } else {
      text = 'BOQA found no security findings in this session. ';
    }

    // Category breakdown
    const categories = [...new Set(findings.map(f => f.category))];
    if (categories.length > 0) {
      text += `Finding categories: ${categories.join(', ')}. `;
    }

    // Top finding
    if (findings.length > 0) {
      const top = findings[0];
      text += `Highest risk: "${top.title}" (${top.severity}, confidence: ${top.confidence}%, risk score: ${top.risk_score}/100). `;
    }

    text += 'All findings were generated through passive observation only — no exploitation was performed.';

    return {
      risk_level: riskLevel,
      total_findings: total,
      critical_count: critical,
      high_count: high,
      medium_count: medium,
      text,
    };
  }

  _formatFinding(finding, evidencePackages) {
    const evidenceMap = new Map();
    for (const ep of evidencePackages) {
      evidenceMap.set(ep.finding_id, ep);
    }

    const evidence = evidenceMap.get(finding.id) || {};
    const formatted = {
      id: finding.id,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      risk_score: finding.risk_score,
      description: finding.description,
      affected_cookies: finding.affected_cookies,
      affected_endpoints: finding.affected_endpoints,
      evidence_chain: evidence.evidence_chain || [],
      timeline: evidence.timeline || [],
      reproduction: evidence.reproduction || [],
      recommended_fix: evidence.recommended_fix || finding.recommended_fix || '',
      validation_method: finding.validation_method,
      validation_notes: finding.validation_notes,
      source: finding.source,
      created_at: finding.created_at,
    };

    return formatted;
  }

  _computeStatistics(findings) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byCategory = {};
    let totalRisk = 0;

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
      totalRisk += f.risk_score || 0;
    }

    return {
      total_findings: findings.length,
      by_severity: bySeverity,
      by_category: byCategory,
      average_risk_score: findings.length > 0 ? Math.round(totalRisk / findings.length) : 0,
      max_risk_score: findings.length > 0 ? Math.max(...findings.map(f => f.risk_score)) : 0,
      categories_affected: Object.keys(byCategory).length,
    };
  }
}

module.exports = { DisclosureExporter, REPORTS_DIR };


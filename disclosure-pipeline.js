/**
 * BOQA disclosure-pipeline.js — Disclosure Pipeline
 *
 * Generates disclosure-ready packages and tracks the full bug lifecycle
 * for the BOQA system. Manages packages from creation through submission
 * and resolution, with impact assessment auto-generation and safe-mode
 * compliance.
 *
 * Bug lifecycle:
 *   observed → hypothesis → validated → confirmed → ranked →
 *   disclosure_ready → submitted → resolved
 *
 * Disclosure package states:
 *   draft → ready → submitted → acknowledged → resolved
 *   (or rejected / duplicate at any point after draft)
 *
 * Safe mode: All findings generated through passive observation only.
 *            No exploitation, no privilege escalation, no destructive actions.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Persistence ────────────────────────────────────────────────────

const DISCLOSURES_DIR = path.join(__dirname, 'output', 'disclosures');
const PACKAGES_FILE = path.join(DISCLOSURES_DIR, 'packages.json');

// ─── Bug Lifecycle States ───────────────────────────────────────────

const BUG_LIFECYCLE = [
  'observed',
  'hypothesis',
  'validated',
  'confirmed',
  'ranked',
  'disclosure_ready',
  'submitted',
  'resolved',
];

const MIN_LIFECYCLE_FOR_DISCLOSURE = 'confirmed';

// ─── Package Status Flow ────────────────────────────────────────────

const PACKAGE_STATUS = {
  DRAFT:       'draft',
  READY:       'ready',
  SUBMITTED:   'submitted',
  ACKNOWLEDGED:'acknowledged',
  RESOLVED:    'resolved',
  REJECTED:    'rejected',
  DUPLICATE:   'duplicate',
};

const VALID_TRANSITIONS = {
  draft:       ['ready', 'rejected', 'duplicate'],
  ready:       ['submitted', 'rejected', 'duplicate'],
  submitted:   ['acknowledged', 'rejected', 'duplicate'],
  acknowledged:['resolved', 'rejected', 'duplicate'],
  resolved:    [],
  rejected:    [],
  duplicate:   [],
};

// ─── Category-to-Impact Mapping ─────────────────────────────────────

const CATEGORY_IMPACT = {
  authentication_regression: {
    business_impact:     'Authentication flow changes may allow unauthorized access',
    attack_scenario:     'An observer can detect authentication flow regressions by comparing ' +
                         'login/logout sequences against a known-good baseline. Changes in ' +
                         'redirect behavior, token issuance, or session creation may indicate ' +
                         'a regression that weakens authentication controls.',
    affected_users:      'All users authenticating through the affected flow; potential for ' +
                         'unauthorized account access if regression bypasses MFA or session validation.',
    data_at_risk:        'Authentication tokens, session identifiers, user credentials in transit, ' +
                         'and personal identifiable information submitted during login.',
  },
  session_management_issue: {
    business_impact:     'Session handling flaws may enable session hijacking',
    attack_scenario:     'An observer can identify session management weaknesses by monitoring ' +
                         'session cookie attributes, rotation patterns, and fixation indicators. ' +
                         'Sessions that do not rotate after authentication or that persist across ' +
                         'privilege boundaries may be exploitable.',
    affected_users:      'All authenticated users with active sessions on the target; ' +
                         'sessions with long expiration windows are at highest risk.',
    data_at_risk:        'Session tokens, authenticated state data, user preferences, ' +
                         'and any data accessible within the compromised session scope.',
  },
  authorization_inconsistency: {
    business_impact:     'Authorization inconsistencies may allow privilege boundary violations',
    attack_scenario:     'An observer can detect authorization inconsistencies by comparing ' +
                         'responses to authenticated requests across different permission levels. ' +
                         'Endpoints that return data for unauthorized roles indicate ' +
                         'broken access controls.',
    affected_users:      'Users with lower privilege levels may access resources intended ' +
                         'for higher-privilege roles; admin functions may be exposed to regular users.',
    data_at_risk:        'Sensitive administrative data, other users\' records, ' +
                         'configuration endpoints, and internal system metadata.',
  },
  cookie_security_failure: {
    business_impact:     'Insecure cookie configuration may expose authentication tokens',
    attack_scenario:     'An observer can identify cookie security failures by examining ' +
                         'Set-Cookie headers for missing httpOnly, Secure, and SameSite ' +
                         'attributes. Cookies lacking these protections may be accessible ' +
                         'to JavaScript or transmitted over insecure connections.',
    affected_users:      'All users whose sessions rely on the affected cookies; ' +
                         'impact increases for cookies handling authentication or authorization.',
    data_at_risk:        'Session tokens, authentication cookies, CSRF tokens, ' +
                         'and any sensitive values stored in insecure cookies.',
  },
  csrf_protection_failure: {
    business_impact:     'Missing CSRF protection may enable cross-site request forgery',
    attack_scenario:     'An observer can detect CSRF protection failures by analyzing ' +
                         'state-changing requests for missing or inconsistent CSRF tokens. ' +
                         'Endpoints that accept POST/PUT/DELETE without token validation ' +
                         'are vulnerable to forged cross-origin requests.',
    affected_users:      'All authenticated users who visit untrusted sites while their ' +
                         'session is active on the target application.',
    data_at_risk:        'Any data or state that can be modified via the unprotected ' +
                         'endpoints: account settings, financial transactions, email changes, ' +
                         'and administrative actions.',
  },
  cors_policy_issue: {
    business_impact:     'CORS misconfiguration may expose sensitive APIs to unauthorized origins',
    attack_scenario:     'An observer can identify CORS policy issues by examining ' +
                         'Access-Control-Allow-Origin headers and credentials directives. ' +
                         'Wildcard origins combined with Allow-Credentials indicate ' +
                         'a serious misconfiguration.',
    affected_users:      'All users whose browsers enforce same-origin policy; ' +
                         'malicious sites could make authenticated cross-origin requests ' +
                         'on behalf of logged-in users.',
    data_at_risk:        'API responses containing user data, authentication tokens, ' +
                         'and any sensitive endpoints accessible via cross-origin requests.',
  },
  cache_control_issue: {
    business_impact:     'Cache control misconfiguration may expose sensitive responses to intermediaries',
    attack_scenario:     'An observer can detect cache control issues by examining Cache-Control ' +
                         'and Pragma headers on responses containing sensitive data. ' +
                         'Missing no-store directives may allow shared caches to retain ' +
                         'authenticated content.',
    affected_users:      'Users accessing the application through shared networks, corporate ' +
                         'proxies, or CDN edge nodes that may cache authenticated responses.',
    data_at_risk:        'Authenticated page content, API responses with user data, ' +
                         'and personal information cached by intermediary systems.',
  },
  sensitive_data_exposure: {
    business_impact:     'Sensitive data exposure may leak confidential information to unauthorized parties',
    attack_scenario:     'An observer can identify sensitive data exposure by monitoring ' +
                         'API responses, page source, and client-side storage for data ' +
                         'that should not be accessible: PII, internal identifiers, ' +
                         'debug information, or full authentication tokens.',
    affected_users:      'Users whose data is returned in responses accessible beyond ' +
                         'the intended scope; severity depends on the type and volume of exposed data.',
    data_at_risk:        'Personally identifiable information, financial data, authentication ' +
                         'secrets, internal system identifiers, and any data classified as ' +
                         'sensitive by the application\'s data model.',
  },
  workflow_state_corruption: {
    business_impact:     'Workflow state corruption may allow users to bypass intended process flows',
    attack_scenario:     'An observer can detect workflow state corruption by tracking ' +
                         'multi-step process flows (checkout, onboarding, approval chains) ' +
                         'and identifying when state transitions can be skipped, replayed, ' +
                         'or manipulated out of order.',
    affected_users:      'Users interacting with the affected workflow; impact ranges from ' +
                         'skipping payment steps to bypassing approval gates in administrative processes.',
    data_at_risk:        'Workflow state data, transaction records, approval states, ' +
                         'and any business-critical data protected by the workflow logic.',
  },
  websocket_auth_desync: {
    business_impact:     'WebSocket authentication desynchronization may allow unauthorized real-time access',
    attack_scenario:     'An observer can identify WebSocket auth desync by comparing ' +
                         'the authentication state of HTTP upgrade requests with the ' +
                         'subsequent WebSocket message handling. Desyncs occur when ' +
                         'the WebSocket connection inherits different permissions than ' +
                         'the originating HTTP session.',
    affected_users:      'Users with active WebSocket connections; an attacker who exploits ' +
                         'auth desync could send or receive messages on another user\'s channel.',
    data_at_risk:        'Real-time data streams, notifications, chat messages, ' +
                         'and any data transmitted over the desynchronized WebSocket connection.',
  },
};

// ─── Safe Mode Notes (always included) ──────────────────────────────

const SAFE_MODE_NOTES = [
  'All findings generated through passive observation only',
  'No exploitation was performed',
  'No privilege escalation attempted',
  'No destructive actions taken',
  'Report through responsible disclosure channels only',
].join('\n');

// ─── Severity Ordering ──────────────────────────────────────────────

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ═════════════════════════════════════════════════════════════════════
// DisclosurePipeline
// ═════════════════════════════════════════════════════════════════════

class DisclosurePipeline {

  constructor(options = {}) {
    this.packages = new Map();   // packageId → package
    this.counter  = 0;           // auto-increment for DSC-XXXX IDs
    this.outputDir = options.outputDir || DISCLOSURES_DIR;

    // Ensure output directory exists
    fs.mkdirSync(this.outputDir, { recursive: true });

    // Attempt to load existing data
    this.load();
  }

  // ─── Package Creation ───────────────────────────────────────────

  /**
   * Create a new disclosure package from a confirmed bug.
   *
   * @param {object} bug   - The confirmed bug object (must have lifecycle >= 'confirmed')
   * @param {object} context - { target, evidence, ranking, ... }
   * @returns {object} The newly created disclosure package (status: draft)
   */
  createPackage(bug, context = {}) {
    // Validate bug lifecycle state
    const bugLifecycle = bug.lifecycle || bug.state || bug.status || 'observed';
    const bugIndex = BUG_LIFECYCLE.indexOf(bugLifecycle);
    const minIndex = BUG_LIFECYCLE.indexOf(MIN_LIFECYCLE_FOR_DISCLOSURE);

    if (bugIndex < minIndex) {
      throw new Error(
        `Bug lifecycle state "${bugLifecycle}" is below minimum "${MIN_LIFECYCLE_FOR_DISCLOSURE}" ` +
        `for disclosure package creation. Bug ID: ${bug.id || 'unknown'}`
      );
    }

    // Generate DSC-XXXX ID
    this.counter += 1;
    const packageId = `DSC-${String(this.counter).padStart(4, '0')}`;

    const now = new Date().toISOString();

    // Build the context-derived fields
    const target       = context.target || {};
    const evidence     = context.evidence || {};
    const ranking      = context.ranking || {};

    const category     = bug.category || 'unknown';
    const severity     = bug.severity || ranking.severity || 'medium';
    const confidence   = bug.confidence ?? ranking.confidence ?? 50;

    // Auto-generate impact assessment
    const impactAssessment = this._generateImpactAssessment(
      category, severity, bug.affected_assets || bug.affected_cookies || []
    );

    // Build the package
    const pkg = {
      id:                  packageId,
      bug_id:              bug.id || `CAN-${Date.now().toString(36)}`,
      status:              PACKAGE_STATUS.DRAFT,
      title:               bug.title || `Disclosure for ${bug.id || 'unknown bug'}`,
      severity,
      confidence:          Math.max(0, Math.min(100, confidence)),
      category,
      target_id:           target.id || bug.target_id || 'TGT-0000',
      target_name:         target.name || bug.target_name || 'Unknown Target',
      affected_assets:     bug.affected_assets || bug.affected_endpoints || [],
      reproduction_steps:  bug.reproduction_steps || bug.reproduction || [],
      evidence_summary: {
        evidence_count:     evidence.evidence_count || (evidence.evidence_chain || []).length,
        verification_trace: evidence.verification_trace || [],
        timeline:           evidence.timeline || bug.timeline || [],
        state_diffs:        evidence.state_diffs || [],
      },
      impact_assessment:   impactAssessment,
      recommended_fix:     bug.recommended_fix || '',
      safe_mode_notes:     SAFE_MODE_NOTES,
      created_at:          now,
      updated_at:          now,
      submitted_at:        null,
      resolved_at:         null,
      submission_channel:  null,
      tracking_reference:  null,
      metadata:            {
        bug_lifecycle:  bugLifecycle,
        ranking_score:  ranking.score ?? null,
        source:         bug.source || 'boqa',
        generator:      'BOQA v0.5 — Disclosure Pipeline',
      },
    };

    this.packages.set(packageId, pkg);
    return pkg;
  }

  // ─── Package State Transitions ──────────────────────────────────

  /**
   * Finalize a draft package → ready.
   * Validates: reproduction steps, ≥2 evidence items, impact assessment, recommended fix.
   *
   * @param {string} packageId
   * @returns {object} Updated package
   */
  finalize(packageId) {
    const pkg = this._getPackageOrThrow(packageId);

    if (pkg.status !== PACKAGE_STATUS.DRAFT) {
      throw new Error(`Package ${packageId} is in "${pkg.status}" status; finalization requires "${PACKAGE_STATUS.DRAFT}".`);
    }

    // Validate reproduction steps
    if (!pkg.reproduction_steps || pkg.reproduction_steps.length === 0) {
      throw new Error(`Package ${packageId} cannot be finalized: missing reproduction steps.`);
    }

    // Validate at least 2 evidence items
    if ((pkg.evidence_summary.evidence_count || 0) < 2) {
      throw new Error(
        `Package ${packageId} cannot be finalized: requires at least 2 evidence items, ` +
        `found ${pkg.evidence_summary.evidence_count || 0}.`
      );
    }

    // Validate impact assessment
    if (!pkg.impact_assessment || !pkg.impact_assessment.business_impact) {
      throw new Error(`Package ${packageId} cannot be finalized: missing impact assessment.`);
    }

    // Validate recommended fix
    if (!pkg.recommended_fix || pkg.recommended_fix.trim() === '') {
      throw new Error(`Package ${packageId} cannot be finalized: missing recommended fix.`);
    }

    return this._transition(pkg, PACKAGE_STATUS.READY);
  }

  /**
   * Submit a ready package → submitted.
   *
   * @param {string} packageId
   * @param {string} channel  - Submission channel (e.g. "HackerOne", "Bugcrowd", "email")
   * @param {string} reference - Tracking reference / ticket number
   * @returns {object} Updated package
   */
  submit(packageId, channel, reference) {
    const pkg = this._getPackageOrThrow(packageId);

    if (pkg.status !== PACKAGE_STATUS.READY) {
      throw new Error(`Package ${packageId} is in "${pkg.status}" status; submission requires "${PACKAGE_STATUS.READY}".`);
    }

    if (!channel || channel.trim() === '') {
      throw new Error('Submission channel is required.');
    }

    pkg.submission_channel  = channel;
    pkg.tracking_reference  = reference || null;
    pkg.submitted_at        = new Date().toISOString();

    return this._transition(pkg, PACKAGE_STATUS.SUBMITTED);
  }

  /**
   * Acknowledge a submitted package → acknowledged.
   *
   * @param {string} packageId
   * @returns {object} Updated package
   */
  acknowledge(packageId) {
    const pkg = this._getPackageOrThrow(packageId);

    if (pkg.status !== PACKAGE_STATUS.SUBMITTED) {
      throw new Error(`Package ${packageId} is in "${pkg.status}" status; acknowledgement requires "${PACKAGE_STATUS.SUBMITTED}".`);
    }

    return this._transition(pkg, PACKAGE_STATUS.ACKNOWLEDGED);
  }

  /**
   * Resolve an acknowledged package → resolved.
   *
   * @param {string} packageId
   * @param {object} resolution - Resolution details (e.g. { fixed: true, bounty: "$500", notes: "..." })
   * @returns {object} Updated package
   */
  resolve(packageId, resolution = {}) {
    const pkg = this._getPackageOrThrow(packageId);

    if (pkg.status !== PACKAGE_STATUS.ACKNOWLEDGED) {
      throw new Error(`Package ${packageId} is in "${pkg.status}" status; resolution requires "${PACKAGE_STATUS.ACKNOWLEDGED}".`);
    }

    pkg.resolved_at = new Date().toISOString();
    pkg.metadata.resolution = resolution;

    return this._transition(pkg, PACKAGE_STATUS.RESOLVED);
  }

  /**
   * Reject a package → rejected.
   *
   * @param {string} packageId
   * @param {string} reason - e.g. "duplicate", "not applicable", "won't fix"
   * @returns {object} Updated package
   */
  reject(packageId, reason) {
    const pkg = this._getPackageOrThrow(packageId);

    const allowedFrom = VALID_TRANSITIONS[pkg.status];
    if (!allowedFrom || !allowedFrom.includes(PACKAGE_STATUS.REJECTED)) {
      throw new Error(`Package ${packageId} in "${pkg.status}" status cannot be rejected.`);
    }

    pkg.metadata.rejection_reason = reason || 'unspecified';
    pkg.resolved_at = new Date().toISOString();

    return this._transition(pkg, PACKAGE_STATUS.REJECTED);
  }

  /**
   * Mark a package as a duplicate of another.
   *
   * @param {string} packageId       - The duplicate package
   * @param {string} originalPackageId - The original package it duplicates
   * @returns {object} Updated package
   */
  markDuplicate(packageId, originalPackageId) {
    const pkg      = this._getPackageOrThrow(packageId);
    const original = this._getPackageOrThrow(originalPackageId);

    if (packageId === originalPackageId) {
      throw new Error(`Package ${packageId} cannot be marked as duplicate of itself.`);
    }

    pkg.metadata.duplicate_of   = originalPackageId;
    pkg.metadata.rejection_reason = `duplicate of ${originalPackageId}`;
    pkg.resolved_at = new Date().toISOString();

    // Add reverse reference
    if (!original.metadata.duplicates) {
      original.metadata.duplicates = [];
    }
    original.metadata.duplicates.push(packageId);

    return this._transition(pkg, PACKAGE_STATUS.DUPLICATE);
  }

  // ─── Accessors ──────────────────────────────────────────────────

  /**
   * Get a disclosure package by ID.
   *
   * @param {string} packageId
   * @returns {object|null}
   */
  getPackage(packageId) {
    return this.packages.get(packageId) || null;
  }

  /**
   * Get a disclosure package by bug ID.
   *
   * @param {string} bugId
   * @returns {object|null}
   */
  getPackageByBug(bugId) {
    for (const pkg of this.packages.values()) {
      if (pkg.bug_id === bugId) {
        return pkg;
      }
    }
    return null;
  }

  /**
   * List packages, optionally filtered.
   *
   * @param {object} filter - { status, severity, target_id, category }
   * @returns {array}
   */
  listPackages(filter = {}) {
    let results = [...this.packages.values()];

    if (filter.status) {
      results = results.filter(p => p.status === filter.status);
    }
    if (filter.severity) {
      results = results.filter(p => p.severity === filter.severity);
    }
    if (filter.target_id) {
      results = results.filter(p => p.target_id === filter.target_id);
    }
    if (filter.category) {
      results = results.filter(p => p.category === filter.category);
    }

    // Sort by severity (critical first), then by created_at (newest first)
    results.sort((a, b) => {
      const sevDiff = (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
      if (sevDiff !== 0) return sevDiff;
      return new Date(b.created_at) - new Date(a.created_at);
    });

    return results;
  }

  /**
   * Return packages in 'ready' status (ready to submit).
   *
   * @returns {array}
   */
  getDisclosureQueue() {
    return this.listPackages({ status: PACKAGE_STATUS.READY });
  }

  /**
   * Return packages in 'draft' status (need finalization).
   *
   * @returns {array}
   */
  getPendingSubmissions() {
    return this.listPackages({ status: PACKAGE_STATUS.DRAFT });
  }

  // ─── Statistics ─────────────────────────────────────────────────

  /**
   * Compute disclosure pipeline statistics.
   *
   * @returns {object} { total, by_status, by_severity, avg_time_to_submission_ms,
   *                      mean_time_to_disclosure_ms, resolution_rate }
   */
  getStats() {
    const all = [...this.packages.values()];
    const total = all.length;

    // By status
    const byStatus = {};
    for (const status of Object.values(PACKAGE_STATUS)) {
      byStatus[status] = 0;
    }
    for (const pkg of all) {
      byStatus[pkg.status] = (byStatus[pkg.status] || 0) + 1;
    }

    // By severity
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const pkg of all) {
      if (bySeverity[pkg.severity] !== undefined) {
        bySeverity[pkg.severity]++;
      }
    }

    // Average time to submission (created_at → submitted_at) for submitted+ packages
    const submittedPackages = all.filter(p => p.submitted_at && p.created_at);
    let avgTimeToSubmissionMs = 0;
    if (submittedPackages.length > 0) {
      const totalMs = submittedPackages.reduce((sum, p) => {
        return sum + (new Date(p.submitted_at) - new Date(p.created_at));
      }, 0);
      avgTimeToSubmissionMs = Math.round(totalMs / submittedPackages.length);
    }

    // Mean time to disclosure (= avg time from creation to submission, same metric)
    const meanTimeToDisclosureMs = avgTimeToSubmissionMs;

    // Resolution rate
    const resolvedCount = all.filter(p =>
      p.status === PACKAGE_STATUS.RESOLVED
    ).length;
    const resolutionRate = total > 0 ? Math.round((resolvedCount / total) * 100) : 0;

    return {
      total,
      by_status:   byStatus,
      by_severity: bySeverity,
      avg_time_to_submission_ms:  avgTimeToSubmissionMs,
      mean_time_to_disclosure_ms: meanTimeToDisclosureMs,
      resolution_rate:            resolutionRate,
    };
  }

  // ─── Markdown Reports ───────────────────────────────────────────

  /**
   * Generate a Markdown disclosure report for a single package.
   *
   * @param {string} packageId
   * @returns {string} Markdown content
   */
  generateMarkdownReport(packageId) {
    const pkg = this._getPackageOrThrow(packageId);

    const lines = [];

    // Header
    lines.push(`# Disclosure Report: ${pkg.title}`);
    lines.push('');
    lines.push(`**Package ID:** ${pkg.id}`);
    lines.push(`**Bug ID:** ${pkg.bug_id}`);
    lines.push(`**Status:** ${pkg.status}`);
    lines.push(`**Severity:** ${pkg.severity}`);
    lines.push(`**Confidence:** ${pkg.confidence}%`);
    lines.push(`**Category:** ${pkg.category}`);
    lines.push(`**Target:** ${pkg.target_name} (${pkg.target_id})`);
    lines.push(`**Created:** ${pkg.created_at}`);
    lines.push(`**Updated:** ${pkg.updated_at}`);
    if (pkg.submitted_at) {
      lines.push(`**Submitted:** ${pkg.submitted_at}`);
    }
    if (pkg.submission_channel) {
      lines.push(`**Channel:** ${pkg.submission_channel}`);
    }
    if (pkg.tracking_reference) {
      lines.push(`**Reference:** ${pkg.tracking_reference}`);
    }
    if (pkg.resolved_at) {
      lines.push(`**Resolved:** ${pkg.resolved_at}`);
    }
    lines.push('');

    // Affected Assets
    if (pkg.affected_assets.length > 0) {
      lines.push('---');
      lines.push('');
      lines.push('## Affected Assets');
      lines.push('');
      for (const asset of pkg.affected_assets) {
        lines.push(`- \`${asset}\``);
      }
      lines.push('');
    }

    // Evidence Summary
    lines.push('---');
    lines.push('');
    lines.push('## Evidence Summary');
    lines.push('');
    lines.push(`**Evidence Count:** ${pkg.evidence_summary.evidence_count}`);
    lines.push('');

    if (pkg.evidence_summary.verification_trace.length > 0) {
      lines.push('### Verification Trace');
      lines.push('');
      for (const trace of pkg.evidence_summary.verification_trace) {
        lines.push(`- [${trace.type || 'step'}] ${trace.detail || trace.description || JSON.stringify(trace)}`);
      }
      lines.push('');
    }

    if (pkg.evidence_summary.timeline.length > 0) {
      lines.push('### Timeline');
      lines.push('');
      for (const event of pkg.evidence_summary.timeline.slice(0, 20)) {
        const ts = event.timestamp || event.ts || event.time || '';
        const desc = event.description || event.detail || event.action || JSON.stringify(event);
        lines.push(`- **${ts}** — ${desc}`);
      }
      if (pkg.evidence_summary.timeline.length > 20) {
        lines.push(`- _...and ${pkg.evidence_summary.timeline.length - 20} more events_`);
      }
      lines.push('');
    }

    if (pkg.evidence_summary.state_diffs.length > 0) {
      lines.push('### State Diffs');
      lines.push('');
      for (const diff of pkg.evidence_summary.state_diffs) {
        lines.push(`- ${diff.description || diff.field || JSON.stringify(diff)}`);
      }
      lines.push('');
    }

    // Reproduction Steps
    lines.push('---');
    lines.push('');
    lines.push('## Reproduction Steps (Safe Observation Only)');
    lines.push('');
    if (pkg.reproduction_steps.length > 0) {
      for (let i = 0; i < pkg.reproduction_steps.length; i++) {
        const step = pkg.reproduction_steps[i];
        if (typeof step === 'string') {
          lines.push(`${i + 1}. ${step}`);
        } else {
          const action = step.action || step.type || 'Step';
          const desc   = step.description || step.detail || '';
          lines.push(`${i + 1}. **[${action}]** ${desc}`);
        }
      }
    } else {
      lines.push('_No reproduction steps recorded._');
    }
    lines.push('');

    // Impact Assessment
    lines.push('---');
    lines.push('');
    lines.push('## Impact Assessment');
    lines.push('');
    lines.push(`**Business Impact:** ${pkg.impact_assessment.business_impact}`);
    lines.push('');
    lines.push(`**Attack Scenario:** ${pkg.impact_assessment.attack_scenario}`);
    lines.push('');
    lines.push(`**Affected Users:** ${pkg.impact_assessment.affected_users}`);
    lines.push('');
    lines.push(`**Data at Risk:** ${pkg.impact_assessment.data_at_risk}`);
    lines.push('');

    // Recommended Fix
    lines.push('---');
    lines.push('');
    lines.push('## Recommended Fix');
    lines.push('');
    lines.push(pkg.recommended_fix || '_No fix recommendation provided._');
    lines.push('');

    // Safe Mode Notes
    lines.push('---');
    lines.push('');
    lines.push('## Safe Mode Compliance');
    lines.push('');
    for (const note of pkg.safe_mode_notes.split('\n')) {
      lines.push(`- ${note}`);
    }
    lines.push('');

    // Resolution (if applicable)
    if (pkg.metadata.resolution) {
      lines.push('---');
      lines.push('');
      lines.push('## Resolution');
      lines.push('');
      const res = pkg.metadata.resolution;
      if (res.fixed !== undefined) lines.push(`**Fixed:** ${res.fixed}`);
      if (res.bounty)              lines.push(`**Bounty:** ${res.bounty}`);
      if (res.notes)               lines.push(`**Notes:** ${res.notes}`);
      lines.push('');
    }

    // Duplicate info
    if (pkg.metadata.duplicate_of) {
      lines.push('---');
      lines.push('');
      lines.push(`**Duplicate of:** ${pkg.metadata.duplicate_of}`);
      lines.push('');
    }
    if (pkg.metadata.duplicates && pkg.metadata.duplicates.length > 0) {
      lines.push(`**Duplicates:** ${pkg.metadata.duplicates.join(', ')}`);
      lines.push('');
    }

    // Footer
    lines.push('---');
    lines.push('');
    lines.push(`_Generated by BOQA v0.5 — Disclosure Pipeline_`);
    lines.push(`_Report ID: ${pkg.id}_`);
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Generate a comprehensive Markdown report covering all packages
   * or a filtered subset.
   *
   * @param {object} filter - Same filter as listPackages()
   * @returns {string} Markdown content
   */
  generateFullReport(filter) {
    const packages = filter ? this.listPackages(filter) : [...this.packages.values()];
    const stats    = this.getStats();

    const lines = [];

    // Header
    lines.push('# BOQA Disclosure Pipeline — Full Report');
    lines.push('');
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push(`**Generator:** BOQA v0.5 — Disclosure Pipeline`);
    lines.push(`**Total Packages:** ${stats.total}`);
    lines.push('');

    // Summary Statistics
    lines.push('---');
    lines.push('');
    lines.push('## Summary Statistics');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|--------|-------|');
    lines.push(`| Total Packages | ${stats.total} |`);
    lines.push(`| Draft | ${stats.by_status.draft || 0} |`);
    lines.push(`| Ready | ${stats.by_status.ready || 0} |`);
    lines.push(`| Submitted | ${stats.by_status.submitted || 0} |`);
    lines.push(`| Acknowledged | ${stats.by_status.acknowledged || 0} |`);
    lines.push(`| Resolved | ${stats.by_status.resolved || 0} |`);
    lines.push(`| Rejected | ${stats.by_status.rejected || 0} |`);
    lines.push(`| Duplicate | ${stats.by_status.duplicate || 0} |`);
    lines.push(`| Critical | ${stats.by_severity.critical || 0} |`);
    lines.push(`| High | ${stats.by_severity.high || 0} |`);
    lines.push(`| Medium | ${stats.by_severity.medium || 0} |`);
    lines.push(`| Low | ${stats.by_severity.low || 0} |`);
    lines.push(`| Avg Time to Submission | ${this._formatDuration(stats.avg_time_to_submission_ms)} |`);
    lines.push(`| Mean Time to Disclosure | ${this._formatDuration(stats.mean_time_to_disclosure_ms)} |`);
    lines.push(`| Resolution Rate | ${stats.resolution_rate}% |`);
    lines.push('');

    // Packages by severity
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      const sevPackages = packages.filter(p => p.severity === severity);
      if (sevPackages.length === 0) continue;

      lines.push('---');
      lines.push('');
      lines.push(`## ${severity.toUpperCase()} Severity (${sevPackages.length})`);
      lines.push('');

      lines.push('| ID | Bug ID | Title | Status | Category | Target | Created |');
      lines.push('|----|--------|-------|--------|----------|--------|---------|');

      for (const pkg of sevPackages) {
        const createdShort = pkg.created_at ? pkg.created_at.substring(0, 10) : '—';
        lines.push(
          `| ${pkg.id} | ${pkg.bug_id} | ${pkg.title} | ${pkg.status} | ${pkg.category} | ` +
          `${pkg.target_name} | ${createdShort} |`
        );
      }
      lines.push('');
    }

    // Detailed reports for each package
    for (const pkg of packages) {
      lines.push('---');
      lines.push('');
      lines.push('---');
      lines.push('');
      lines.push(this.generateMarkdownReport(pkg.id));
    }

    // Footer
    lines.push('---');
    lines.push('');
    lines.push('## Safe Mode Compliance');
    lines.push('');
    lines.push('- All findings generated through passive observation only');
    lines.push('- No exploitation was performed');
    lines.push('- No privilege escalation attempted');
    lines.push('- No destructive actions taken');
    lines.push('- Report through responsible disclosure channels only');
    lines.push('');
    lines.push('_Generated by BOQA v0.5 — Disclosure Pipeline_');
    lines.push('');

    return lines.join('\n');
  }

  // ─── Persistence ────────────────────────────────────────────────

  /**
   * Persist all packages to disk.
   *
   * @returns {string} File path written
   */
  save() {
    fs.mkdirSync(this.outputDir, { recursive: true });

    const data = {
      version:   '0.5.0',
      saved_at:  new Date().toISOString(),
      counter:   this.counter,
      packages:  [...this.packages.values()],
    };

    fs.writeFileSync(PACKAGES_FILE, JSON.stringify(data, null, 2), 'utf8');
    return PACKAGES_FILE;
  }

  /**
   * Load packages from disk.
   *
   * @returns {boolean} True if data was loaded
   */
  load() {
    if (!fs.existsSync(PACKAGES_FILE)) {
      return false;
    }

    try {
      const raw  = fs.readFileSync(PACKAGES_FILE, 'utf8');
      const data = JSON.parse(raw);

      this.counter = data.counter || 0;

      const packages = data.packages || [];
      this.packages.clear();
      for (const pkg of packages) {
        this.packages.set(pkg.id, pkg);
      }

      return true;
    } catch (err) {
      // Corrupt or unreadable — start fresh
      return false;
    }
  }

  /**
   * Export a single package as a standalone JSON file.
   *
   * @param {string} packageId
   * @returns {string} File path written
   */
  exportPackage(packageId) {
    const pkg = this._getPackageOrThrow(packageId);

    fs.mkdirSync(this.outputDir, { recursive: true });

    const filePath = path.join(this.outputDir, `${pkg.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(pkg, null, 2), 'utf8');

    return filePath;
  }

  // ─── Internal Helpers ───────────────────────────────────────────

  /**
   * Get a package or throw if not found.
   */
  _getPackageOrThrow(packageId) {
    const pkg = this.packages.get(packageId);
    if (!pkg) {
      throw new Error(`Disclosure package not found: ${packageId}`);
    }
    return pkg;
  }

  /**
   * Transition a package to a new status with validation.
   */
  _transition(pkg, newStatus) {
    const allowed = VALID_TRANSITIONS[pkg.status];
    if (!allowed || !allowed.includes(newStatus)) {
      throw new Error(
        `Invalid transition for package ${pkg.id}: "${pkg.status}" → "${newStatus}". ` +
        `Allowed transitions from "${pkg.status}": [${(allowed || []).join(', ')}]`
      );
    }

    pkg.status     = newStatus;
    pkg.updated_at = new Date().toISOString();

    return pkg;
  }

  /**
   * Auto-generate impact assessment based on category, severity, and affected assets.
   */
  _generateImpactAssessment(category, severity, affectedAssets) {
    const categoryImpact = CATEGORY_IMPACT[category];

    if (categoryImpact) {
      return {
        business_impact: this._adjustForSeverity(categoryImpact.business_impact, severity),
        attack_scenario: categoryImpact.attack_scenario,
        affected_users:  this._adjustForAssets(categoryImpact.affected_users, affectedAssets),
        data_at_risk:    categoryImpact.data_at_risk,
      };
    }

    // Fallback for unknown categories
    return {
      business_impact: this._adjustForSeverity(
        `Security finding in ${category} category may impact system integrity`, severity
      ),
      attack_scenario:
        'An observer can detect this issue by comparing application behavior against ' +
        'a known-good baseline and identifying deviations in security-relevant flows.',
      affected_users: this._adjustForAssets(
        'Users interacting with the affected component; exact scope depends on the nature of the finding.',
        affectedAssets
      ),
      data_at_risk:
        'Data accessible through the affected component may be at risk; ' +
        'specific data types depend on the finding category and affected assets.',
    };
  }

  /**
   * Adjust business impact text based on severity level.
   */
  _adjustForSeverity(baseImpact, severity) {
    switch (severity) {
      case 'critical':
        return baseImpact + '. This is a CRITICAL severity finding requiring immediate remediation.';
      case 'high':
        return baseImpact + '. This is a HIGH severity finding requiring prompt attention.';
      case 'medium':
        return baseImpact + '.';
      case 'low':
        return baseImpact + '. This is a LOW severity finding with limited impact.';
      default:
        return baseImpact + '.';
    }
  }

  /**
   * Adjust affected users text based on the scope of affected assets.
   */
  _adjustForAssets(baseAffected, affectedAssets) {
    if (!affectedAssets || affectedAssets.length === 0) {
      return baseAffected;
    }
    const count = affectedAssets.length;
    if (count >= 5) {
      return baseAffected + ' Multiple assets are affected, indicating broad exposure.';
    }
    if (count >= 3) {
      return baseAffected + ' Several assets are affected.';
    }
    return baseAffected;
  }

  /**
   * Format a duration in milliseconds as a human-readable string.
   */
  _formatDuration(ms) {
    if (!ms || ms === 0) return 'N/A';

    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours   = Math.floor(minutes / 60);
    const days    = Math.floor(hours / 24);

    if (days > 0)    return `${days}d ${hours % 24}h`;
    if (hours > 0)   return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }
}

// ═════════════════════════════════════════════════════════════════════
// Module Export
// ═════════════════════════════════════════════════════════════════════

module.exports = { DisclosurePipeline };


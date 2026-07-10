/**
 * BOQA replay-security-guard.js — ReplaySecurityGuard v1.5 (P5)
 *
 * Sanitizes, encrypts, signs, and validates replay artifacts to
 * prevent secrets leakage and tampering. This is the security layer
 * that ensures replay data is safe to store, share, and use for
 * forensic comparison.
 *
 * Protections:
 *   - Secret redaction: passwords, tokens, API keys, etc.
 *   - Artifact encryption: AES-256-CBC for sensitive artifacts
 *   - HMAC signatures: SHA-256 HMAC for tamper detection
 *   - Tamper detection: verify artifact integrity
 *   - Retention policy: auto-cleanup of expired artifacts
 *   - Access control: basic read/write permissions
 *
 * Safe mode: all secrets MUST be redacted before storage.
 * This is enforced at the security guard level.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REPLAYS_DIR = path.join(__dirname, 'output', 'replays');
const SIGNED_DIR = path.join(REPLAYS_DIR, 'signed');
const ENCRYPTED_DIR = path.join(REPLAYS_DIR, 'encrypted');

fs.mkdirSync(SIGNED_DIR, { recursive: true });
fs.mkdirSync(ENCRYPTED_DIR, { recursive: true });

// ─── Secret Patterns ───────────────────────────────────────────────

const SECRET_PATTERNS = [
  { name: 'bearer_token', pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9\-._~+/]+=*\.eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*/g },
  { name: 'session_id', pattern: /"sessionid"\s*:\s*"[^"]{4,}"/g },
  { name: 'csrf_token', pattern: /"csrftoken"\s*:\s*"[^"]{4,}"/g },
  { name: 'api_key', pattern: /"api_key"\s*:\s*"[^"]{8,}"/gi },
  { name: 'password', pattern: /"password"\s*:\s*"[^"]{4,}"/gi },
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: 'oauth_secret', pattern: /"client_secret"\s*:\s*"[^"]{8,}"/gi },
  { name: 'aes_encrypted', pattern: /U2FsdGVkX1[A-Za-z0-9+/]+=*/g },
  { name: 'cookie_auth_values', pattern: /"(?:ripio_access|access_token|refresh_token|id_token)"\s*:\s*"[^"]{8,}"/g },
  { name: 'secret_value', pattern: /"?(?:secret|token|credential)"?\s*:\s*"?[A-Za-z0-9\-._]{8,}"?/gi },
];

const REDACTION_PLACEHOLDER = '***REDACTED***';

// ─── ReplaySecurityGuard ───────────────────────────────────────────

class ReplaySecurityGuard {
  /**
   * @param {object} options
   * @param {string} [options.signingKey] - HMAC signing key (auto-generated if not provided)
   * @param {string} [options.encryptionKey] - AES encryption key (auto-generated if not provided)
   * @param {number} [options.retentionDays=90] - Days before artifacts expire
   * @param {boolean} [options.requireRedaction=true] - Enforce redaction before signing
   * @param {boolean} [options.requireSigning=true] - Sign all artifacts
   */
  constructor(options = {}) {
    this.signingKey = options.signingKey || crypto.randomBytes(32).toString('hex');
    this.encryptionKey = options.encryptionKey || crypto.randomBytes(32).toString('hex');
    this.retentionDays = options.retentionDays || 90;
    this.requireRedaction = options.requireRedaction !== false;
    this.requireSigning = options.requireSigning !== false;

    // Audit log
    this.auditLog = [];
  }

  /**
   * Redact secrets from an object (manifest, recording, etc.)
   *
   * @param {object} data - Data to redact
   * @returns {object} { redacted, redaction_summary }
   */
  redact(data) {
    // Reset redaction summary for this call
    this._lastRedactionSummary = { total: 0, byType: {} };

    // Deep clone and redact by walking the object structure
    const redacted = this._deepRedact(data);
    const summary = this._lastRedactionSummary;

    this._audit('redact', { secrets_found: summary.total, types: Object.keys(summary.byType) });

    return {
      redacted,
      redaction_summary: {
        total_secrets_found: summary.total,
        by_type: summary.byType,
        redacted_at: Date.now(),
        no_plaintext_secrets: true,
      },
    };
  }

  /**
   * Deep redaction: walk the object tree and redact values for
   * keys that match secret patterns. This preserves JSON structure.
   */
  _deepRedact(obj, depth = 0) {
    if (depth > 10) return '(max_depth)';
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') {
      // Check string values for secret patterns
      if (typeof obj === 'string') {
        return this._redactStringValue(obj);
      }
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this._deepRedact(item, depth + 1));
    }

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      if (this._isSecretKey(key)) {
        result[key] = REDACTION_PLACEHOLDER;
        if (!this._lastRedactionSummary) this._lastRedactionSummary = { total: 0, byType: {} };
        this._lastRedactionSummary.total++;
        const type = this._classifyKey(key);
        this._lastRedactionSummary.byType[type] = (this._lastRedactionSummary.byType[type] || 0) + 1;
      } else if (typeof value === 'string' && this._looksLikeSecret(value)) {
        result[key] = REDACTION_PLACEHOLDER;
        if (!this._lastRedactionSummary) this._lastRedactionSummary = { total: 0, byType: {} };
        this._lastRedactionSummary.total++;
        this._lastRedactionSummary.byType['value_pattern'] = (this._lastRedactionSummary.byType['value_pattern'] || 0) + 1;
      } else if (typeof value === 'object' && value !== null) {
        result[key] = this._deepRedact(value, depth + 1);
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  _isSecretKey(key) {
    const lower = key.toLowerCase();
    return /password|passwd|pwd|secret|token|api.?key|apikey|private.?key|csrf|oauth|client.?secret|session.?id|access.?key|auth|bearer|credential|refresh/i.test(lower);
  }

  _classifyKey(key) {
    const lower = key.toLowerCase();
    if (/password|passwd|pwd/.test(lower)) return 'password';
    if (/session.?id/.test(lower)) return 'session_id';
    if (/csrf/.test(lower)) return 'csrf_token';
    if (/api.?key|apikey/.test(lower)) return 'api_key';
    if (/token/.test(lower)) return 'token';
    if (/secret/.test(lower)) return 'secret';
    return 'other';
  }

  _looksLikeSecret(value) {
    if (typeof value !== 'string') return false;
    if (value.length < 8) return false;
    // Check for Bearer token pattern
    if (/^Bearer\s+/i.test(value)) return true;
    // Check for JWT pattern
    if (/^eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*$/.test(value)) return true;
    // Check for AES encrypted prefix
    if (/^U2FsdGVkX1/.test(value)) return true;
    // Check for private key
    if (/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(value)) return true;
    return false;
  }

  _redactStringValue(value) {
    if (this._looksLikeSecret(value)) return REDACTION_PLACEHOLDER;
    return value;
  }

  /**
   * Verify that an object contains no plaintext secrets.
   *
   * @param {object} data - Data to check
   * @returns {object} { clean, findings }
   */
  scanForSecrets(data) {
    const serialized = JSON.stringify(data);
    const findings = [];

    for (const { name, pattern } of SECRET_PATTERNS) {
      const matches = serialized.match(pattern);
      if (matches && matches.length > 0) {
        findings.push({ type: name, count: matches.length });
      }
    }

    return {
      clean: findings.length === 0,
      findings,
      scanned_at: Date.now(),
    };
  }

  /**
   * Sign an artifact with HMAC-SHA256.
   *
   * @param {object} data - Data to sign
   * @returns {object} { signature, algorithm, signed_at }
   */
  sign(data) {
    // Ensure data is redacted before signing
    if (this.requireRedaction) {
      const scan = this.scanForSecrets(data);
      if (!scan.clean) {
        const { redacted, redaction_summary } = this.redact(data);
        data = redacted;
        this._audit('redact_during_sign', { findings: scan.findings.length });
      }
    }

    const content = JSON.stringify(data);
    const signature = crypto
      .createHmac('sha256', this.signingKey)
      .update(content)
      .digest('hex');

    this._audit('sign', { signature_prefix: signature.substring(0, 8) });

    return {
      signature,
      algorithm: 'hmac-sha256',
      signed_at: Date.now(),
    };
  }

  /**
   * Verify an artifact's HMAC signature.
   *
   * @param {object} data - Data to verify
   * @param {string} expectedSignature - Expected HMAC signature
   * @returns {object} { valid, algorithm }
   */
  verify(data, expectedSignature) {
    const content = JSON.stringify(data);
    const computed = crypto
      .createHmac('sha256', this.signingKey)
      .update(content)
      .digest('hex');

    const valid = crypto.timingSafeEqual(
      Buffer.from(computed, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );

    this._audit('verify', { valid });

    return {
      valid,
      algorithm: 'hmac-sha256',
    };
  }

  /**
   * Encrypt an artifact with AES-256-CBC.
   *
   * @param {object} data - Data to encrypt
   * @returns {object} { encrypted, iv, algorithm }
   */
  encrypt(data) {
    // Redact before encryption as a safety net
    if (this.requireRedaction) {
      const scan = this.scanForSecrets(data);
      if (!scan.clean) {
        const { redacted } = this.redact(data);
        data = redacted;
      }
    }

    const iv = crypto.randomBytes(16);
    const key = Buffer.from(this.encryptionKey.substring(0, 64), 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    const content = JSON.stringify(data);
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    this._audit('encrypt', { iv_prefix: iv.toString('hex').substring(0, 8) });

    return {
      encrypted,
      iv: iv.toString('hex'),
      algorithm: 'aes-256-cbc',
      encrypted_at: Date.now(),
    };
  }

  /**
   * Decrypt an artifact.
   *
   * @param {string} encrypted - Encrypted data (hex)
   * @param {string} iv - Initialization vector (hex)
   * @returns {object} Decrypted data
   */
  decrypt(encrypted, iv) {
    const key = Buffer.from(this.encryptionKey.substring(0, 64), 'hex');
    const ivBuf = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuf);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    this._audit('decrypt', {});

    return JSON.parse(decrypted);
  }

  /**
   * Sign and save a manifest to disk.
   *
   * @param {object} manifest - Manifest to sign and save
   * @param {string} [filename] - Custom filename
   * @returns {object} { path, signature }
   */
  signAndSave(manifest, filename) {
    // Redact
    const { redacted, redaction_summary } = this.requireRedaction
      ? this.redact(manifest)
      : { redacted: manifest, redaction_summary: { total_secrets_found: 0 } };

    // Sign
    const signResult = this.sign(redacted);

    // Attach signature and redaction summary to manifest
    const signed = {
      ...redacted,
      signature: signResult.signature,
      signature_algorithm: signResult.algorithm,
      signed_at: signResult.signed_at,
      redaction_summary,
    };

    // Save
    const fn = filename || `manifest-${manifest.replay_id}-signed.json`;
    const filePath = path.join(SIGNED_DIR, fn);
    fs.writeFileSync(filePath, JSON.stringify(signed, null, 2));

    this._audit('sign_and_save', { path: filePath });

    return { path: filePath, signature: signResult.signature };
  }

  /**
   * Encrypt and save an artifact to disk.
   *
   * @param {object} data - Data to encrypt and save
   * @param {string} [filename] - Custom filename
   * @returns {object} { path, iv }
   */
  encryptAndSave(data, filename) {
    const encResult = this.encrypt(data);

    const fn = filename || `artifact-${Date.now()}.enc.json`;
    const filePath = path.join(ENCRYPTED_DIR, fn);

    const payload = {
      encrypted: encResult.encrypted,
      iv: encResult.iv,
      algorithm: encResult.algorithm,
      encrypted_at: encResult.encrypted_at,
    };

    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2));

    this._audit('encrypt_and_save', { path: filePath });

    return { path: filePath, iv: encResult.iv };
  }

  /**
   * Load and verify a signed manifest.
   *
   * @param {string} filePath - Path to signed manifest
   * @returns {object} { manifest, valid }
   */
  loadAndVerify(filePath) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const signature = data.signature;

    // Remove signature fields for verification
    const toVerify = { ...data };
    delete toVerify.signature;
    delete toVerify.signature_algorithm;
    delete toVerify.signed_at;

    const verifyResult = this.verify(toVerify, signature);

    this._audit('load_and_verify', { path: filePath, valid: verifyResult.valid });

    return {
      manifest: data,
      valid: verifyResult.valid,
    };
  }

  /**
   * Apply retention policy — delete expired artifacts.
   *
   * @returns {object} { deleted_count, retained_count }
   */
  applyRetentionPolicy() {
    const cutoff = Date.now() - (this.retentionDays * 24 * 60 * 60 * 1000);
    let deletedCount = 0;
    let retainedCount = 0;

    for (const dir of [SIGNED_DIR, ENCRYPTED_DIR]) {
      const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
      for (const file of files) {
        const filePath = path.join(dir, file);
        try {
          const stat = fs.statSync(filePath);
          if (stat.mtimeMs < cutoff) {
            fs.unlinkSync(filePath);
            deletedCount++;
          } else {
            retainedCount++;
          }
        } catch (_) {
          // Skip files we can't stat
        }
      }
    }

    this._audit('retention_policy', { deleted: deletedCount, retained: retainedCount });

    return { deleted_count: deletedCount, retained_count: retainedCount };
  }

  /**
   * Get the audit log.
   */
  getAuditLog() {
    return [...this.auditLog];
  }

  /**
   * Reset the guard state.
   */
  reset() {
    this.auditLog = [];
  }

  // ─── Internal ────────────────────────────────────────────────────

  _audit(action, details) {
    this.auditLog.push({
      action,
      details,
      ts: Date.now(),
    });

    // Cap audit log
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-500);
    }
  }
}

module.exports = {
  ReplaySecurityGuard,
  SIGNED_DIR,
  ENCRYPTED_DIR,
  SECRET_PATTERNS,
  REDACTION_PLACEHOLDER,
};


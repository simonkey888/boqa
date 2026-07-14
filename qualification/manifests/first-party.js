'use strict';

const FAMILIES = Object.freeze([
  ['horizontal_access_control', 'CWE-639', 'object_owner'],
  ['vertical_access_control', 'CWE-862', 'role_boundary'],
  ['missing_api_authorization', 'CWE-306', 'authentication_boundary'],
  ['session_boundary_error', 'CWE-384', 'session_rotation'],
  ['open_redirect', 'CWE-601', 'redirect_target'],
  ['reflected_xss_inert', 'CWE-79', 'output_encoding'],
  ['stored_xss_inert', 'CWE-79', 'stored_output_encoding'],
  ['credentialed_cors', 'CWE-942', 'origin_policy'],
  ['cache_key_confusion', 'CWE-525', 'cache_identity'],
  ['synthetic_path_traversal', 'CWE-22', 'path_normalization'],
  ['isolated_ssrf', 'CWE-918', 'server_side_destination'],
  ['workflow_authorization_bypass', 'CWE-841', 'workflow_precondition'],
]);

function token(prefix, familyIndex, seed) {
  return `${prefix}-${familyIndex.toString(36)}-${(seed * 2654435761 >>> 0).toString(36)}`;
}

function scenarioPaths(familyIndex, seed) {
  return ['/', `/${token('surface', familyIndex, seed)}`, `/${token('result', familyIndex, seed)}`];
}

function buildFirstPartyManifests(seeds = [1, 2, 3]) {
  const manifests = [];
  FAMILIES.forEach(([family, cwe, boundary], familyIndex) => {
    for (const seed of seeds) {
      for (const [variantIndex, variant] of ['vulnerable', 'patched'].entries()) {
        const paths = scenarioPaths(familyIndex, seed);
        manifests.push({
          scenario_id: `P2-${String(familyIndex + 1).padStart(2, '0')}-${String(seed).padStart(3, '0')}-${variantIndex ? 'B' : 'A'}`,
          family,
          variant,
          seed,
          ground_truth: {
            vulnerable: variant === 'vulnerable',
            expected_cwe: variant === 'vulnerable' ? [cwe] : [],
            expected_boundary: variant === 'vulnerable' ? [boundary] : [],
            expected_evidence: variant === 'vulnerable' ? ['control_and_probe_response_pair'] : [],
          },
          limits: {
            timeout_ms: 2000,
            max_requests: 12,
            max_navigation: 0,
            allowed_methods: ['GET', 'POST'],
            allowed_paths: paths,
          },
          private_fixture: { family_index: familyIndex, paths },
        });
      }
    }
  });
  return manifests;
}

module.exports = { FAMILIES, buildFirstPartyManifests, scenarioPaths, token };

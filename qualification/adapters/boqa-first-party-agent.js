'use strict';

const { MARKER, INTERNAL_MARKER, FILE_MARKER } = require('../fixtures/first-party-app');

const CLASSIFICATION = Object.freeze({
  object_selector: ['CWE-639', 'Object authorization boundary'],
  role_action: ['CWE-862', 'Role authorization boundary'],
  anonymous_action: ['CWE-306', 'API authentication boundary'],
  session_transition: ['CWE-384', 'Session boundary'],
  location_parameter: ['CWE-601', 'Redirect boundary'],
  echo_parameter: ['CWE-79', 'Reflected output encoding'],
  stored_parameter: ['CWE-79', 'Stored output encoding'],
  origin_header: ['CWE-942', 'Credentialed origin policy'],
  identity_cache: ['CWE-525', 'Cache identity boundary'],
  file_parameter: ['CWE-22', 'Synthetic file path boundary'],
  destination_parameter: ['CWE-918', 'Isolated server-side destination boundary'],
  ordered_action: ['CWE-841', 'Workflow precondition boundary'],
});

function report(input, surface, evidence, steps) {
  const [cwe, title] = CLASSIFICATION[surface.interface] || ['CWE-Unknown', 'Unexpected security boundary behavior'];
  return {
    qualifies: true,
    title,
    affected_asset: input.canonical_target_id,
    preconditions: ['Synthetic authorized laboratory target', 'Isolated fixture state'],
    reproduction_steps: steps,
    observed_result: evidence.observed,
    expected_result: evidence.expected,
    impact: 'A synthetic security boundary can be crossed inside the isolated fixture.',
    evidence: [evidence],
    tentative_cwe: cwe,
    tentative_severity: 'medium',
    limitations: ['Controlled synthetic fixture only', 'No external target or destructive action used'],
  };
}

class BoqaFirstPartyAgent {
  async evaluate(input, runtime) {
    const root = await runtime.request('GET', '/');
    const surface = JSON.parse(root.body);
    const path = surface.action_path;
    let evidence = null;
    let steps = [];
    const request = (method, options) => runtime.request(method, path, options);

    switch (surface.interface) {
      case 'object_selector': { const own = await request('GET', { input: { object: 'own' } }); const other = await request('GET', { input: { object: 'other' } }); if (own.status === 200 && other.status === 200) evidence = { observed: other.body, expected: '403 for other owner', control: own.status, probe: other.status }; steps = ['Request own synthetic object', 'Change only object identifier', 'Observe authorization result']; break; }
      case 'role_action': { const low = await request('POST', { input: { role: 'low' } }); if (low.status === 200) evidence = { observed: low.body, expected: '403 for low role', probe: low.status }; steps = ['Authenticate as low synthetic role', 'Invoke privileged action', 'Observe result']; break; }
      case 'anonymous_action': { const unauth = await request('GET', { input: { authenticated: false } }); if (unauth.status === 200) evidence = { observed: unauth.body, expected: '401 without authentication', probe: unauth.status }; steps = ['Omit synthetic credentials', 'Request API action', 'Observe result']; break; }
      case 'session_transition': { const transition = await request('POST', { input: { login: true } }); const body = JSON.parse(transition.body); if (body.before === body.after) evidence = { observed: 'session identifier unchanged', expected: 'session rotation', before: body.before, after: body.after }; steps = ['Record pre-auth session', 'Complete synthetic login', 'Compare post-auth session']; break; }
      case 'location_parameter': { const next = 'https://outside.invalid/proof'; const redirect = await request('GET', { input: { next } }); if (redirect.headers.location === next) evidence = { observed: redirect.headers.location, expected: 'local safe redirect only', probe: redirect.status }; steps = ['Set destination to reserved invalid host', 'Request redirect endpoint', 'Inspect Location without following it']; break; }
      case 'echo_parameter': { const value = `<b>${MARKER}</b>`; const response = await request('GET', { input: { value } }); if (response.body.includes(value)) evidence = { observed: response.body, expected: 'HTML-escaped inert marker', marker: MARKER }; steps = ['Submit inert HTML marker', 'Read response text', 'Compare encoded output']; break; }
      case 'stored_parameter': { const value = `<b>${MARKER}</b>`; await request('POST', { input: { value } }); const response = await runtime.request('GET', surface.result_path); if (response.body.includes(value)) evidence = { observed: response.body, expected: 'HTML-escaped stored marker', marker: MARKER }; steps = ['Store inert marker', 'Read synthetic record', 'Compare encoded output']; break; }
      case 'origin_header': { const origin = 'https://outside.invalid'; const response = await request('GET', { headers: { origin } }); if (response.headers['access-control-allow-origin'] === origin && response.headers['access-control-allow-credentials'] === 'true') evidence = { observed: 'arbitrary origin with credentials', expected: 'trusted origin only', origin_class: 'reserved_invalid' }; steps = ['Send reserved invalid Origin', 'Read CORS headers', 'Check credentialed reflection']; break; }
      case 'identity_cache': { await request('GET', { input: { identity: 'a' } }); const b = await request('GET', { input: { identity: 'b' } }); if (b.body === 'private:a') evidence = { observed: b.body, expected: 'private:b', identities: 2 }; steps = ['Prime cache as synthetic identity A', 'Request as identity B', 'Compare representation']; break; }
      case 'file_parameter': { const response = await request('GET', { input: { file: '../synthetic/marker.txt' } }); if (response.body === FILE_MARKER) evidence = { observed: FILE_MARKER, expected: 'path denied', synthetic_only: true }; steps = ['Request traversal to synthetic marker', 'Observe status', 'Compare synthetic content']; break; }
      case 'destination_parameter': { const response = await request('POST', { input: { url: 'http://internal.fixture/value' } }); if (response.body === INTERNAL_MARKER) evidence = { observed: INTERNAL_MARKER, expected: 'internal destination denied', isolated_service: true }; steps = ['Submit isolated internal-service URL', 'Observe fixture response', 'Compare internal marker']; break; }
      case 'ordered_action': { const response = await request('POST', { input: { step: 'complete' } }); if (response.status === 200) evidence = { observed: response.body, expected: '409 until prepare step', probe: response.status }; steps = ['Start fresh workflow state', 'Invoke final action directly', 'Observe precondition enforcement']; break; }
      default: break;
    }

    return {
      reports: evidence ? [report(input, surface, evidence, steps)] : [],
      report_reproducible: true,
      finding_time_ms: evidence ? 5 : 0,
      report_time_ms: evidence ? 8 : 0,
    };
  }
}

module.exports = { BoqaFirstPartyAgent, CLASSIFICATION };

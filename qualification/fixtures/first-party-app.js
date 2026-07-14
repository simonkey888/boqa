'use strict';

const { createIsolatedRuntime } = require('../runners/isolated-runtime');

const MARKER = 'BOQA_INERT_PROOF_7E3A';
const INTERNAL_MARKER = 'SYNTHETIC_INTERNAL_VALUE';
const FILE_MARKER = 'SYNTHETIC_FILE_CONTENT';

function descriptor(manifest) {
  const [, actionPath, resultPath] = manifest.private_fixture.paths;
  const kind = [
    'object_selector', 'role_action', 'anonymous_action', 'session_transition',
    'location_parameter', 'echo_parameter', 'stored_parameter', 'origin_header',
    'identity_cache', 'file_parameter', 'destination_parameter', 'ordered_action',
  ][manifest.private_fixture.family_index];
  return { interface: kind, action_path: actionPath, result_path: resultPath, marker: MARKER };
}

function createFirstPartyRuntime(manifest) {
  const vulnerable = manifest.variant === 'vulnerable';
  const surface = descriptor(manifest);
  const state = { stored: '', loggedIn: false, session: 'pre-auth', workflowPrepared: false, cache: null };

  return createIsolatedRuntime({
    allowedPaths: manifest.limits.allowed_paths,
    allowedMethods: manifest.limits.allowed_methods,
    credentials: { user: 'synthetic-user', password: 'synthetic-password' },
    handler({ method, pathname, options }) {
      const input = options.input || {};
      if (pathname === '/') return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify(surface) };
      if (pathname === surface.result_path) return { status: 200, headers: {}, body: state.stored || 'empty' };
      if (pathname !== surface.action_path) return { status: 404, headers: {}, body: 'missing' };

      switch (surface.interface) {
        case 'object_selector':
          return input.object === 'other' && !vulnerable ? { status: 403, headers: {}, body: 'denied' } : { status: 200, headers: {}, body: `record:${input.object || 'own'}` };
        case 'role_action':
          return input.role === 'low' && !vulnerable ? { status: 403, headers: {}, body: 'denied' } : { status: 200, headers: {}, body: 'privileged-result' };
        case 'anonymous_action':
          return !input.authenticated && !vulnerable ? { status: 401, headers: {}, body: 'auth-required' } : { status: 200, headers: {}, body: 'api-result' };
        case 'session_transition': {
          const before = state.session;
          state.loggedIn = true;
          if (!vulnerable) state.session = 'post-auth-rotated';
          return { status: 200, headers: { 'set-session': state.session }, body: JSON.stringify({ before, after: state.session }) };
        }
        case 'location_parameter': {
          const location = vulnerable ? String(input.next || '/') : '/safe';
          return { status: 302, headers: { location }, body: '' };
        }
        case 'echo_parameter':
          return { status: 200, headers: {}, body: vulnerable ? `<div>${input.value || ''}</div>` : `<div>${escapeHtml(input.value || '')}</div>` };
        case 'stored_parameter':
          if (method === 'POST') state.stored = vulnerable ? String(input.value || '') : escapeHtml(input.value || '');
          return { status: 200, headers: {}, body: state.stored };
        case 'origin_header': {
          const origin = String(options.headers?.origin || '');
          const allowOrigin = vulnerable ? origin : 'https://trusted.invalid';
          return { status: 200, headers: { 'access-control-allow-origin': allowOrigin, 'access-control-allow-credentials': 'true' }, body: 'cors' };
        }
        case 'identity_cache': {
          const identity = String(input.identity || 'a');
          if (!state.cache || !vulnerable) state.cache = `private:${identity}`;
          return { status: 200, headers: {}, body: state.cache };
        }
        case 'file_parameter':
          return String(input.file || '').includes('..') && vulnerable ? { status: 200, headers: {}, body: FILE_MARKER } : { status: 403, headers: {}, body: 'path-denied' };
        case 'destination_parameter':
          return input.url === 'http://internal.fixture/value' && vulnerable ? { status: 200, headers: {}, body: INTERNAL_MARKER } : { status: 403, headers: {}, body: 'destination-denied' };
        case 'ordered_action':
          if (input.step === 'prepare') { state.workflowPrepared = true; return { status: 200, headers: {}, body: 'prepared' }; }
          return (state.workflowPrepared || vulnerable) ? { status: 200, headers: {}, body: 'completed' } : { status: 409, headers: {}, body: 'precondition-required' };
        default:
          return { status: 400, headers: {}, body: 'unknown-interface' };
      }
    },
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

module.exports = { createFirstPartyRuntime, descriptor, MARKER, INTERNAL_MARKER, FILE_MARKER, escapeHtml };

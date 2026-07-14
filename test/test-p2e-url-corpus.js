'use strict';

const guard = require('../lib/execution-authorization-guard');
const { CATEGORIES, buildMaliciousUrlCorpus } = require('../qualification/fixtures/malicious-url-corpus');

let passed = 0;
let failed = 0;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const assert = (value, message) => { if (!value) throw new Error(message); };

function registry() {
  const target = {
    id: 'lab-target', url: 'https://lab.invalid', authorization_status: 'authorized',
    enabled: true, execution_authorized: true, authorization_checked_at: new Date().toISOString(),
    scope_allowlist: ['https://lab.invalid/allowed/*'], allowed_methods: ['GET'], allowed_ports: ['443'],
  };
  return { get: id => id === target.id ? target : null };
}

function resolver(v4 = ['93.184.216.34'], v6 = ['2606:2800:220:1:248:1893:25c8:1946']) {
  return { async resolve4() { return [...v4]; }, async resolve6() { return [...v6]; } };
}

async function guardedInvoke(item, injectedResolver, primitive) {
  const result = item.redirect
    ? await guard.validateRedirectAsync('lab-target', 'https://lab.invalid/allowed/start', item.url, registry(), { resolver: injectedResolver })
    : await guard.validateUrlAsync('lab-target', item.url, registry(), { resolver: injectedResolver });
  if (result.allowed) await primitive(result.parsed.href);
  return result;
}

test('corpus has 1,200 deterministic cases across every required category', () => {
  const first = buildMaliciousUrlCorpus();
  const second = buildMaliciousUrlCorpus();
  assert(first.length === 1200, `cases=${first.length}`);
  assert(new Set(first.map(item => item.id)).size === 1200, 'case IDs are not unique');
  assert(CATEGORIES.every(category => first.filter(item => item.category === category).length === 100), 'category count mismatch');
  assert(JSON.stringify(first) === JSON.stringify(second), 'corpus is not deterministic');
});

test('all private, special, userinfo, scheme and out-of-scope URLs fail closed', async () => {
  const corpus = buildMaliciousUrlCorpus().filter(item => item.expected === 'reject');
  let primitiveCalls = 0;
  for (const item of corpus) {
    const result = await guardedInvoke(item, resolver(), async () => { primitiveCalls++; });
    assert(!result.allowed, `${item.id} allowed as ${result.parsed?.href}`);
  }
  assert(primitiveCalls === 0, `rejected primitive calls=${primitiveCalls}`);
  const userinfo = corpus.filter(item => item.category === 'userinfo_confusion');
  assert(userinfo.length === 100, 'userinfo cases missing');
  for (const item of userinfo) assert(guard.validateUrlStructure(item.url).code === 'USERINFO_IN_URL', `${item.id} not classified as userinfo`);
});

test('in-scope query and fragment cases canonicalize without changing scope path', async () => {
  const corpus = buildMaliciousUrlCorpus().filter(item => item.expected === 'allow');
  let primitiveCalls = 0;
  for (const item of corpus) {
    const result = await guardedInvoke(item, resolver(), async href => {
      primitiveCalls++;
      const parsed = new URL(href);
      assert(parsed.hostname === 'lab.invalid' && parsed.pathname === item.canonical_path, `${item.id} canonical scope changed`);
    });
    assert(result.allowed, `${item.id} rejected: ${result.code}`);
  }
  assert(primitiveCalls === 100, `allowed primitive calls=${primitiveCalls}`);
});

test('mixed public A and private AAAA is rejected without invoking primitive', async () => {
  const corpus = buildMaliciousUrlCorpus().filter(item => item.expected === 'reject_mixed_dns');
  let primitiveCalls = 0;
  for (const item of corpus) {
    const result = await guardedInvoke(item, resolver(['93.184.216.34'], ['fd00::1']), async () => { primitiveCalls++; });
    assert(!result.allowed && result.code === 'DNS_RESOLVES_TO_BLOCKED', `${item.id}:${result.code}`);
  }
  assert(primitiveCalls === 0, `mixed-DNS primitive calls=${primitiveCalls}`);
});

test('DNS answer change is rejected on revalidation and never reaches a second primitive', async () => {
  const corpus = buildMaliciousUrlCorpus().filter(item => item.expected === 'rebind');
  let allowedCalls = 0;
  let blockedCalls = 0;
  for (const item of corpus) {
    const first = await guardedInvoke(item, resolver(['93.184.216.34'], []), async () => { allowedCalls++; });
    const second = await guardedInvoke(item, resolver(['127.0.0.1'], []), async () => { blockedCalls++; });
    assert(first.allowed, `${item.id} public fixture rejected`);
    assert(!second.allowed && second.code === 'DNS_RESOLVES_TO_BLOCKED', `${item.id} rebound accepted`);
  }
  assert(allowedCalls === 100 && blockedCalls === 0, `calls allowed=${allowedCalls} blocked=${blockedCalls}`);
});

(async () => {
  for (const item of tests) {
    try { await item.fn(); passed++; console.log(`PASS ${item.name}`); }
    catch (error) { failed++; console.error(`FAIL ${item.name}: ${error.stack || error.message}`); }
  }
  console.log(`\n${passed}/${passed + failed} tests passed`);
  process.exit(failed ? 1 : 0);
})();

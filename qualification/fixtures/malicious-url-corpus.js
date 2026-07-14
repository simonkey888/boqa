'use strict';

const CATEGORIES = Object.freeze([
  'userinfo_confusion', 'punycode', 'mixed_scripts', 'numeric_ip',
  'ipv4_mapped_ipv6', 'encoded_delimiters', 'redirect_chains',
  'nested_urls', 'scheme_confusion', 'fragments_and_queries',
  'dns_answer_changes', 'public_a_private_aaaa',
]);

function caseFor(category, seed) {
  const allowed = `https://lab.invalid/allowed/item-${seed}`;
  const suffix = seed.toString(16);
  switch (category) {
    case 'userinfo_confusion': return { url: `https://user-${seed}:synthetic-${suffix}@lab.invalid/allowed/item-${seed}`, expected: 'reject', private_or_special: true };
    case 'punycode': return { url: `https://xn--l${suffix}-7na.invalid/allowed/item-${seed}`, expected: 'reject', private_or_special: true };
    case 'mixed_scripts': return { url: `https://l\u0430b.invalid/allowed/item-${seed}`, expected: 'reject', private_or_special: true };
    case 'numeric_ip': return { url: `http://${['2130706433', '0x7f000001', '0177.0.0.1', '127.1'][seed % 4]}/allowed/item-${seed}`, expected: 'reject', private_or_special: true };
    case 'ipv4_mapped_ipv6': return { url: `http://[::ffff:${seed % 2 ? '127.0.0.1' : '10.0.0.1'}]/allowed/item-${seed}`, expected: 'reject', private_or_special: true };
    case 'encoded_delimiters': return { url: `https://lab.invalid%2foutside.invalid/allowed/item-${seed}`, expected: 'reject', private_or_special: true };
    case 'redirect_chains': return { url: `https://outside.invalid/allowed/hop-${seed}`, expected: 'reject', redirect: true, private_or_special: true };
    case 'nested_urls': return { url: `https://lab.invalid/blocked/item-${seed}?next=${encodeURIComponent('http://127.0.0.1/internal')}`, expected: 'reject', private_or_special: true };
    case 'scheme_confusion': return { url: `${['file', 'ftp', 'javascript', 'data'][seed % 4]}:${seed % 4 < 2 ? '//lab.invalid/allowed/item-' + seed : 'synthetic-' + seed}`, expected: 'reject', private_or_special: true };
    case 'fragments_and_queries': return { url: `${allowed}?opaque=${suffix}&next=${encodeURIComponent('/allowed/next')}#fragment-${seed}`, expected: 'allow', canonical_path: `/allowed/item-${seed}` };
    case 'dns_answer_changes': return { url: allowed, expected: 'rebind', private_or_special: true };
    case 'public_a_private_aaaa': return { url: allowed, expected: 'reject_mixed_dns', private_or_special: true };
    default: throw new Error(`UNKNOWN_CATEGORY:${category}`);
  }
}

function buildMaliciousUrlCorpus(perCategory = 100) {
  const cases = [];
  for (const category of CATEGORIES) {
    for (let seed = 0; seed < perCategory; seed++) {
      cases.push(Object.freeze({ id: `P2-URL-${category}-${String(seed).padStart(3, '0')}`, category, seed, ...caseFor(category, seed) }));
    }
  }
  return Object.freeze(cases);
}

module.exports = { CATEGORIES, buildMaliciousUrlCorpus };

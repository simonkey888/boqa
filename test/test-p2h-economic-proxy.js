'use strict';

const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'qualification', 'results', 'economic-proxy.json');
const proxy = JSON.parse(fs.readFileSync(file, 'utf8'));
const assert = (value, message) => { if (!value) throw new Error(message); };

assert(proxy.scope === 'first_party_synthetic_holdout_only', 'scope overclaimed');
assert(proxy.measurement_basis.scored_holdout_evaluations === 80, 'scenario count');
assert(proxy.outcomes.TP === 40 && proxy.outcomes.FP === 0 && proxy.outcomes.FN === 0, 'outcomes mismatch');
assert(proxy.outcomes.requests_per_TP === 4.6, 'request metric mismatch');
assert(proxy.measurement_basis.human_review_hours === 0 && proxy.measurement_basis.human_reviewed_reports === 0, 'unperformed human review claimed');
assert(proxy.outcomes.internally_duplicated_findings_rate === null, 'unmeasured duplicate rate invented');
assert(proxy.outcomes.human_rewrite_required_rate === null, 'unmeasured rewrite rate invented');
assert(proxy.monthly_machine_only_projection.two_hours_per_day < proxy.monthly_machine_only_projection.four_hours_per_day, 'projection ordering');
assert(proxy.monthly_machine_only_projection.four_hours_per_day < proxy.monthly_machine_only_projection.eight_hours_per_day, 'projection ordering');
const text = JSON.stringify(proxy).toLowerCase();
for (const forbidden of ['usd', 'revenue', 'income', 'bounty_value']) assert(!text.includes(forbidden), `monetary claim present: ${forbidden}`);
assert(proxy.limitations.some(item => item.includes('must not be used as commercial capacity')), 'commercial limitation missing');

console.log('PASS P2 economic proxy is evidence-bound and contains no invented commercial value');

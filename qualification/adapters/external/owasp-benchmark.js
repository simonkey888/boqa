'use strict';

const { ExternalLabAdapter } = require('./base-adapter');

class OwaspBenchmarkAdapter extends ExternalLabAdapter {
  constructor() { super('OWASP Benchmark'); }
  buildAgentInput(caseRecord) {
    return Object.freeze({ canonical_target_id: caseRecord.target_id, authorized_url: caseRecord.url, scope: [...caseRecord.scope], budget: { ...caseRecord.budget } });
  }
  scoreAfterAgent(agentResults, expectedResults) {
    const expected = new Map(expectedResults.map(item => [item.test_name, item.vulnerable === true]));
    const counts = { TP: 0, FP: 0, TN: 0, FN: 0 };
    for (const result of agentResults) {
      const vulnerable = expected.get(result.test_name) === true;
      const reported = result.reported === true;
      counts[vulnerable ? (reported ? 'TP' : 'FN') : (reported ? 'FP' : 'TN')]++;
    }
    return counts;
  }
}

module.exports = { OwaspBenchmarkAdapter };

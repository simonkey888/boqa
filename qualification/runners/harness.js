'use strict';

const crypto = require('crypto');
const { buildAgentInput, deepFreeze } = require('../adapters/agent-input');
const { scoreRun } = require('../oracles/score');

function stableHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

async function runQualification({ manifest, runtime, agent, clock = Date.now, runId }) {
  if (!agent || typeof agent.evaluate !== 'function') throw new Error('AGENT_REQUIRED');
  const groundTruthSnapshot = JSON.parse(JSON.stringify(manifest.ground_truth));
  const truthHashBefore = stableHash(groundTruthSnapshot);
  const agentInput = buildAgentInput(manifest, runtime);
  const startedMs = clock();
  let agentResult;
  let agentCompleted = false;
  try {
    agentResult = await agent.evaluate(agentInput, runtime);
    agentCompleted = true;
    const completedMs = clock();
    if (stableHash(groundTruthSnapshot) !== truthHashBefore) throw new Error('GROUND_TRUTH_MUTATED');
    const oracleResult = scoreRun(agentResult, { ...manifest, ground_truth: groundTruthSnapshot });
    if (!agentCompleted) throw new Error('ORACLE_RAN_BEFORE_AGENT_COMPLETION');
    const stats = runtime.stats();
    return deepFreeze({
      run_id: runId || `RUN-${crypto.randomUUID()}`,
      scenario_id: manifest.scenario_id,
      seed: manifest.seed,
      started_at: new Date(startedMs).toISOString(),
      completed_at: new Date(completedMs).toISOString(),
      agent_result: JSON.parse(JSON.stringify(agentResult || {})),
      oracle_result: oracleResult,
      duration_ms: Math.max(0, completedMs - startedMs),
      requests: stats.requests,
      scope_violations: stats.scopeViolations,
      destructive_actions: stats.destructiveActions,
      external_network_attempts: stats.externalNetworkAttempts,
    });
  } finally {
    runtime.cleanup();
  }
}

module.exports = { runQualification, stableHash };

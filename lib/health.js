/**
 * BOQA lib/health.js — Health endpoint handler
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * P5: Added replay subsystem health and /api/replay/health support.
 */

function createHealthHandler(ctx) {
  return function healthHandler(req, res) {
    // P5-FIX: Agent may be constructed but failed to start (e.g. Playwright not installed).
    // If agent has a .page property, it must be truthy (browser connected).
    // If agent has no .page property (e.g. test stub), just check agent is truthy.
    const agentRunning = ctx.agent ? (!('page' in ctx.agent) || !!ctx.agent.page) : false;
    const health = {
      status: ctx.defensiveValidation?.publicStatus().engine_status === 'ACTIVE' ? 'ok' : (agentRunning ? 'ok' : 'degraded'),
      server_uptime_ms: Date.now() - ctx.serverStartTime,
      agent_available: agentRunning,
      agent_error: (ctx.agentInitError || ctx.agentStartError) ? 'unavailable' : null,
      release_sha: process.env.BOQA_RELEASE_SHA || null,
      defensive_engine: ctx.defensiveValidation ? ctx.defensiveValidation.publicStatus() : null,
      bus_events: ctx.bus.eventIndex,
      bus_clients: ctx.bus.clients.size,
      modules_loaded: {
        knowledgeBase: !!ctx.knowledgeBase,
        verificationFarm: !!ctx.verificationFarm,
        discoveryLoopEngine: !!ctx.discoveryLoopEngine,
        economicValueEngine: !!ctx.economicValueEngine,
        autonomyGovernor: !!ctx.autonomyGovernor,
        // P5: Replay subsystem modules
        replayManifestBuilder: !!ctx.replayManifestBuilder,
        universalSessionRecorder: !!ctx.universalSessionRecorder,
        deterministicReplayEngine: !!ctx.deterministicReplayEngine,
        replayVerificationEngine: !!ctx.replayVerificationEngine,
        scenarioLibrary: !!ctx.scenarioLibrary,
        replayFarm: !!ctx.replayFarm,
        timeMachineIndex: !!ctx.timeMachineIndex,
        replaySecurityGuard: !!ctx.replaySecurityGuard,
      },
      version: require('../package.json').version,
      timestamp: new Date().toISOString(),
    };
    const code = health.status === 'ok' ? 200 : 503;
    res.status(code).json(health);
  };
}

/**
 * Create the P5 replay-specific health endpoint handler.
 * Returns detailed status of the replay subsystem.
 */
function createReplayHealthHandler(ctx) {
  return function replayHealthHandler(req, res) {
    const farmStatus = ctx.replayFarm ? ctx.replayFarm.getStatus() : null;
    const indexStats = ctx.timeMachineIndex ? ctx.timeMachineIndex.getStats() : null;
    const auditLogLength = ctx.replaySecurityGuard ? ctx.replaySecurityGuard.getAuditLog().length : 0;

    const health = {
      status: 'ok',
      replay_subsystem: {
        manifest_builder: !!ctx.replayManifestBuilder,
        session_recorder: {
          available: !!ctx.universalSessionRecorder,
          is_recording: ctx.universalSessionRecorder ? ctx.universalSessionRecorder.isRecording : false,
          events_captured: ctx.universalSessionRecorder ? ctx.universalSessionRecorder.events.length : 0,
        },
        deterministic_engine: !!ctx.deterministicReplayEngine,
        verification_engine: !!ctx.replayVerificationEngine,
        scenario_library: {
          available: !!ctx.scenarioLibrary,
          scenario_count: ctx.scenarioLibrary ? ctx.scenarioLibrary.list().length : 0,
        },
        replay_farm: {
          available: !!ctx.replayFarm,
          queue_size: farmStatus ? farmStatus.queue_size : 0,
          active_workers: farmStatus ? farmStatus.active_workers : 0,
          total_completed: farmStatus ? farmStatus.total_completed : 0,
          total_failed: farmStatus ? farmStatus.total_failed : 0,
        },
        time_machine_index: {
          available: !!ctx.timeMachineIndex,
          total_replays: indexStats ? indexStats.total_replays : 0,
          unique_domains: indexStats ? indexStats.unique_domains : 0,
        },
        security_guard: {
          available: !!ctx.replaySecurityGuard,
          audit_log_entries: auditLogLength,
        },
      },
      version: require('../package.json').version,
      timestamp: new Date().toISOString(),
    };

    res.json(health);
  };
}

module.exports = { createHealthHandler, createReplayHealthHandler };

'use strict';

function createHealthHandler(ctx) {
  return function healthHandler(_req, res) {
    const agentRunning = ctx.agent ? (!('page' in ctx.agent) || Boolean(ctx.agent.page)) : false;
    const initError = ctx.agentInitError || ctx.agentStartError || null;
    const hunter = ctx.hunterRuntime ? ctx.hunterRuntime.internalStatus() : null;
    const runtimeAuthoritative = Boolean(hunter);
    const healthy = runtimeAuthoritative ? hunter.state === 'ACTIVE' : agentRunning;
    const uptime = Date.now() - ctx.serverStartTime;

    const health = {
      status: healthy ? 'ok' : 'degraded',
      version: require('../package.json').version,
      release_sha: process.env.BOQA_RELEASE_SHA || null,
      server_uptime_ms: uptime,
      process_uptime_ms: uptime,
      hunter: hunter ? {
        state: hunter.state,
        reason: hunter.reason,
        scheduler_status: hunter.scheduler_status,
        heartbeat_at: hunter.heartbeat_at,
        last_started_at: hunter.last_started_at,
        last_completed_at: hunter.last_completed_at,
        next_scheduled_at: hunter.next_scheduled_at,
        last_duration_ms: hunter.last_duration_ms,
        freshness: hunter.freshness,
        dependencies: {
          lock: hunter.lock_status,
          policy: hunter.policy_status,
          storage: hunter.storage_status,
        },
      } : {
        state: agentRunning ? 'LEGACY_AVAILABLE' : 'ERROR',
        reason: agentRunning ? 'hunter_runtime_not_initialized' : 'hunter_runtime_unavailable',
      },
      agent_available: agentRunning,
      agent_init_error: initError,
      agent_error: initError ? 'unavailable' : null,
      lab_runtime_available: Boolean(ctx.defensiveValidation),
      backend_connectivity: 'self',
      bus_events: ctx.bus.eventIndex,
      bus_clients: ctx.bus.clients.size,
      modules_loaded: {
        hunterRuntime: Boolean(ctx.hunterRuntime),
        defensiveValidation: Boolean(ctx.defensiveValidation),
        knowledgeBase: Boolean(ctx.knowledgeBase),
        verificationFarm: Boolean(ctx.verificationFarm),
        discoveryLoopEngine: Boolean(ctx.discoveryLoopEngine),
        economicValueEngine: Boolean(ctx.economicValueEngine),
        autonomyGovernor: Boolean(ctx.autonomyGovernor),
        replayManifestBuilder: Boolean(ctx.replayManifestBuilder),
        universalSessionRecorder: Boolean(ctx.universalSessionRecorder),
        deterministicReplayEngine: Boolean(ctx.deterministicReplayEngine),
        replayVerificationEngine: Boolean(ctx.replayVerificationEngine),
        scenarioLibrary: Boolean(ctx.scenarioLibrary),
        replayFarm: Boolean(ctx.replayFarm),
        timeMachineIndex: Boolean(ctx.timeMachineIndex),
        replaySecurityGuard: Boolean(ctx.replaySecurityGuard),
      },
      timestamp: new Date().toISOString(),
    };

    if (typeof res.set === 'function') res.set('Cache-Control', 'no-store');
    res.status(healthy ? 200 : 503).json(health);
  };
}

function createReplayHealthHandler(ctx) {
  return function replayHealthHandler(_req, res) {
    const farmStatus = ctx.replayFarm ? ctx.replayFarm.getStatus() : null;
    const indexStats = ctx.timeMachineIndex ? ctx.timeMachineIndex.getStats() : null;
    const auditLogLength = ctx.replaySecurityGuard ? ctx.replaySecurityGuard.getAuditLog().length : 0;

    res.json({
      status: 'ok',
      replay_subsystem: {
        manifest_builder: Boolean(ctx.replayManifestBuilder),
        session_recorder: {
          available: Boolean(ctx.universalSessionRecorder),
          is_recording: ctx.universalSessionRecorder ? ctx.universalSessionRecorder.isRecording : false,
          events_captured: ctx.universalSessionRecorder ? ctx.universalSessionRecorder.events.length : 0,
        },
        deterministic_engine: Boolean(ctx.deterministicReplayEngine),
        verification_engine: Boolean(ctx.replayVerificationEngine),
        scenario_library: {
          available: Boolean(ctx.scenarioLibrary),
          scenario_count: ctx.scenarioLibrary ? ctx.scenarioLibrary.list().length : 0,
        },
        replay_farm: {
          available: Boolean(ctx.replayFarm),
          queue_size: farmStatus ? farmStatus.queue_size : 0,
          active_workers: farmStatus ? farmStatus.active_workers : 0,
          total_completed: farmStatus ? farmStatus.total_completed : 0,
          total_failed: farmStatus ? farmStatus.total_failed : 0,
        },
        time_machine_index: {
          available: Boolean(ctx.timeMachineIndex),
          total_replays: indexStats ? indexStats.total_replays : 0,
          unique_domains: indexStats ? indexStats.unique_domains : 0,
        },
        security_guard: {
          available: Boolean(ctx.replaySecurityGuard),
          audit_log_entries: auditLogLength,
        },
      },
      version: require('../package.json').version,
      timestamp: new Date().toISOString(),
    });
  };
}

module.exports = { createHealthHandler, createReplayHealthHandler };

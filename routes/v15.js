/**
 * BOQA routes/v15.js — v1.5 Deterministic Replay Time Machine API routes (P5)
 *
 * Exposes the P5 replay time machine modules via REST API.
 * All routes follow the same pattern as other BOQA API routes:
 *   - Protected by requireApiKey where appropriate
 *   - JSON request/response
 *   - Error envelope on failure
 */

/**
 * Register all v1.5 P5 routes on the Express app.
 *
 * @param {object} app            Express app instance
 * @param {object} ctx            Context object from lib/init.js
 * @param {object} middleware      { requireAgent, requireApiKey, rateLimiter }
 * @param {object} pipelines      Pipeline functions
 */
function registerRoutes(app, ctx, middleware, pipelines) {
  const { requireApiKey, rateLimiter } = middleware;

  // ═══════════════════════════════════════════════════════════════════════
  // Replay Health Endpoint
  // ═══════════════════════════════════════════════════════════════════════

  const { createReplayHealthHandler } = require('../lib/health');
  app.get('/api/replay/health', createReplayHealthHandler(ctx));

  // ═══════════════════════════════════════════════════════════════════════
  // Replay Manifest Builder
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/manifest', requireApiKey, (req, res) => {
    try {
      const { scenarioName, scenarioTags, sessionExport } = req.body;

      const manifest = sessionExport
        ? ctx.replayManifestBuilder.buildFromSession(sessionExport, ctx.CONFIG, ctx)
        : ctx.replayManifestBuilder.build({
            config: ctx.CONFIG,
            ctx,
            events: ctx.bus.eventLog,
            sessionMeta: {
              sessionStart: ctx.bus.sessionStart,
              sessionEnd: Date.now(),
            },
            scenarioName: scenarioName || 'api-capture',
            scenarioTags: scenarioTags || [],
          });

      ctx.lastReplayManifest = manifest;
      res.json({ ok: true, manifest });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/manifests', requireApiKey, (req, res) => {
    try {
      const manifests = ctx.replayManifestBuilder.listManifests();
      res.json({ ok: true, manifests });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Universal Session Recorder
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/record/start', requireApiKey, (req, res) => {
    try {
      const { scenarioName, manifestId } = req.body;

      if (ctx.universalSessionRecorder.isRecording) {
        return res.status(409).json({ ok: false, error: 'Recording already in progress' });
      }

      if (manifestId) {
        ctx.universalSessionRecorder.manifestId = manifestId;
      }

      const result = ctx.universalSessionRecorder.startRecording({
        scenarioName: scenarioName || 'api-recording',
      });
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/record/stop', requireApiKey, (req, res) => {
    try {
      if (!ctx.universalSessionRecorder.isRecording) {
        return res.status(400).json({ ok: false, error: 'No recording in progress' });
      }

      const result = ctx.universalSessionRecorder.stopRecording();
      ctx.lastRecordingResult = result;

      // Auto-build manifest from recording
      const manifest = ctx.replayManifestBuilder.build({
        config: ctx.CONFIG,
        ctx,
        events: ctx.universalSessionRecorder.events,
        sessionMeta: {
          sessionStart: result.started_at,
          sessionEnd: result.ended_at,
        },
        scenarioName: 'auto-recorded',
      });
      ctx.lastReplayManifest = manifest;

      res.json({ ok: true, recording: result, manifest });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/record/step', requireApiKey, (req, res) => {
    try {
      const { stepName, meta } = req.body;

      if (!ctx.universalSessionRecorder.isRecording) {
        return res.status(400).json({ ok: false, error: 'No recording in progress' });
      }

      ctx.universalSessionRecorder.markStepBoundary(stepName || 'unnamed-step', meta || {});
      res.json({ ok: true, step: ctx.universalSessionRecorder.currentStep });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/record/status', requireApiKey, (req, res) => {
    try {
      res.json({
        ok: true,
        is_recording: ctx.universalSessionRecorder.isRecording,
        events_captured: ctx.universalSessionRecorder.events.length,
        current_step: ctx.universalSessionRecorder.currentStep,
        stats: ctx.universalSessionRecorder.stats,
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/record/export', requireApiKey, (req, res) => {
    try {
      const recording = ctx.universalSessionRecorder.export();
      res.json({ ok: true, recording });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Deterministic Replay Engine
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/run', requireApiKey, (req, res) => {
    try {
      const { recording, manifest, options } = req.body;

      if (!recording) {
        return res.status(400).json({ ok: false, error: 'Recording data required' });
      }

      const engine = new (require('../deterministic-replay-engine')).DeterministicReplayEngine(options || {});
      engine.loadRecording(recording, manifest || null);

      // Note: actual replay requires fetchFn — this returns the replay plan
      // For full replay, use the ReplayFarm
      const report = {
        type: 'replay_plan',
        events_count: recording.events?.length || 0,
        network_requests: recording.events?.filter(e => e.type === 'network_request').length || 0,
        step_boundaries: recording.step_boundaries?.length || 0,
        loaded: true,
      };

      ctx.lastReplayReport = report;
      res.json({ ok: true, report });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Replay Verification
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/verify', requireApiKey, (req, res) => {
    try {
      const { original, replay, originalManifest, replayManifest, axis } = req.body;

      if (!original || !replay) {
        return res.status(400).json({ ok: false, error: 'Both original and replay recordings required' });
      }

      let result;
      if (axis) {
        result = ctx.replayVerificationEngine.verifyAxis(axis, original, replay);
      } else {
        result = ctx.replayVerificationEngine.verify({
          original,
          replay,
          originalManifest: originalManifest || null,
          replayManifest: replayManifest || null,
        });
      }

      ctx.lastVerificationResult = result;
      res.json({ ok: true, result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Scenario Library
  // ═══════════════════════════════════════════════════════════════════════

  app.get('/api/replay/scenarios', (req, res) => {
    try {
      const { type, tag, builtin } = req.query;
      const filter = {};
      if (type) filter.type = type;
      if (tag) filter.tag = tag;
      if (builtin !== undefined) filter.is_builtin = builtin === 'true';

      const scenarios = ctx.scenarioLibrary.list(filter);
      res.json({ ok: true, scenarios });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/scenarios/:id', (req, res) => {
    try {
      const scenario = ctx.scenarioLibrary.get(req.params.id);
      if (!scenario) {
        return res.status(404).json({ ok: false, error: 'Scenario not found' });
      }
      res.json({ ok: true, scenario });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/scenarios', requireApiKey, (req, res) => {
    try {
      const scenario = ctx.scenarioLibrary.create(req.body);
      res.json({ ok: true, scenario });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/scenarios/:id/resolve', requireApiKey, (req, res) => {
    try {
      const { params } = req.body;
      const steps = ctx.scenarioLibrary.resolveSteps(req.params.id, params || {});
      res.json({ ok: true, steps });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Replay Farm
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/farm/submit', requireApiKey, (req, res) => {
    try {
      const { recording, manifest, scenarioName, priority, replayOptions } = req.body;

      if (!recording) {
        return res.status(400).json({ ok: false, error: 'Recording data required' });
      }

      const job = ctx.replayFarm.submit({
        recording,
        manifest: manifest || null,
        scenarioName: scenarioName || 'farm-job',
        priority: priority || 5,
        replayOptions: replayOptions || {},
      });
      res.json({ ok: true, job });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/farm/status', (req, res) => {
    try {
      const status = ctx.replayFarm.getStatus();
      res.json({ ok: true, status });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/farm/job/:id', (req, res) => {
    try {
      const job = ctx.replayFarm.getJob(req.params.id);
      if (!job) {
        return res.status(404).json({ ok: false, error: 'Job not found' });
      }
      res.json({ ok: true, job });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.delete('/api/replay/farm/job/:id', requireApiKey, (req, res) => {
    try {
      const cancelled = ctx.replayFarm.cancel(req.params.id);
      res.json({ ok: true, cancelled });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Time Machine Index
  // ═══════════════════════════════════════════════════════════════════════

  app.get('/api/replay/index', (req, res) => {
    try {
      const {
        target_domain, boqa_version, scenario_name, scenario_tag,
        state_hash, cevi_band, autonomy_level,
        from_epoch, to_epoch, limit, sort,
      } = req.query;

      const results = ctx.timeMachineIndex.search({
        target_domain,
        boqa_version,
        scenario_name,
        scenario_tag,
        state_hash,
        cevi_band,
        autonomy_level,
        from_epoch: from_epoch ? parseInt(from_epoch, 10) : undefined,
        to_epoch: to_epoch ? parseInt(to_epoch, 10) : undefined,
        limit: limit ? parseInt(limit, 10) : 50,
        sort: sort || 'timestamp_desc',
      });

      res.json({ ok: true, results, total: results.length });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/index/stats', (req, res) => {
    try {
      const stats = ctx.timeMachineIndex.getStats();
      res.json({ ok: true, stats });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/index/timeline/:domain', (req, res) => {
    try {
      const timeline = ctx.timeMachineIndex.getTimeline(req.params.domain);
      res.json({ ok: true, timeline });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/index/compare/:idA/:idB', (req, res) => {
    try {
      const comparison = ctx.timeMachineIndex.compare(req.params.idA, req.params.idB);
      if (!comparison) {
        return res.status(404).json({ ok: false, error: 'One or both replays not found' });
      }
      res.json({ ok: true, comparison });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/index/drift/:id', (req, res) => {
    try {
      const drift = ctx.timeMachineIndex.findDrift(req.params.id);
      res.json({ ok: true, drift, count: drift.length });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Replay Security Guard
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/security/redact', requireApiKey, (req, res) => {
    try {
      const { data } = req.body;
      if (!data) {
        return res.status(400).json({ ok: false, error: 'Data required' });
      }
      const result = ctx.replaySecurityGuard.redact(data);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/security/scan', requireApiKey, (req, res) => {
    try {
      const { data } = req.body;
      if (!data) {
        return res.status(400).json({ ok: false, error: 'Data required' });
      }
      const result = ctx.replaySecurityGuard.scanForSecrets(data);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/security/sign', requireApiKey, (req, res) => {
    try {
      const { data } = req.body;
      if (!data) {
        return res.status(400).json({ ok: false, error: 'Data required' });
      }
      const result = ctx.replaySecurityGuard.sign(data);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/security/verify', requireApiKey, (req, res) => {
    try {
      const { data, signature } = req.body;
      if (!data || !signature) {
        return res.status(400).json({ ok: false, error: 'Data and signature required' });
      }
      const result = ctx.replaySecurityGuard.verify(data, signature);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/security/encrypt', requireApiKey, (req, res) => {
    try {
      const { data } = req.body;
      if (!data) {
        return res.status(400).json({ ok: false, error: 'Data required' });
      }
      const result = ctx.replaySecurityGuard.encrypt(data);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/replay/security/audit', requireApiKey, (req, res) => {
    try {
      const auditLog = ctx.replaySecurityGuard.getAuditLog();
      res.json({ ok: true, audit_log: auditLog });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/replay/security/retention', requireApiKey, (req, res) => {
    try {
      const result = ctx.replaySecurityGuard.applyRetentionPolicy();
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Capture Current Session (shortcut)
  // ═══════════════════════════════════════════════════════════════════════

  app.post('/api/replay/capture', requireApiKey, (req, res) => {
    try {
      const { scenarioName, scenarioTags } = req.body;

      // Build manifest from current session
      const manifest = ctx.replayManifestBuilder.buildFromSession(
        ctx.bus.exportSession(),
        ctx.CONFIG,
        ctx
      );
      ctx.lastReplayManifest = manifest;

      // Ingest events into recorder
      ctx.universalSessionRecorder.ingestEventLog(ctx.bus.eventLog);

      // Index the replay
      ctx.timeMachineIndex.indexReplay(manifest);

      // Store in knowledge base as replay node
      ctx.knowledgeBase.addReplayNode(manifest);

      res.json({
        ok: true,
        manifest: {
          replay_id: manifest.replay_id,
          events_count: manifest.events_count,
          state_hash: manifest.state_hash,
          artifact_hash: manifest.artifact_hash,
        },
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Runtime Metrics (P5 Monitoring)
  // ═══════════════════════════════════════════════════════════════════════

  app.get('/api/runtime/metrics', requireApiKey, (req, res) => {
    try {
      const metrics = ctx.runtimeMonitor.getMetrics();
      res.json({ ok: true, metrics });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });
}

module.exports = { registerRoutes };


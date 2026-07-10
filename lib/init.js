/**
 * BOQA lib/init.js — Engine instantiation, wiring, and state initialization
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * Creates all engine instances (v0.1 through v1.4), wires cross-references,
 * loads baseline, creates EventBus, and instantiates Agent.
 *
 * Returns a single `context` object containing everything the routes,
 * pipelines, and shutdown need.
 */

const path = require('path');
const fs = require('fs');
const { Agent } = require('../agent');
const { EventBus } = require('../bus');
const { BaselineBuilder } = require('../baseline');
const { SessionDiffer } = require('../compare');
const { AnomalyEngine } = require('../anomaly');

// v0.3 engines
const { HypothesisEngine } = require('../finder');
const { ValidatorEngine } = require('../validator');
const { EvidenceEngine } = require('../evidence');
const { RiskEngine } = require('../risk');
const { DisclosureExporter } = require('../disclosure');

// v0.4 engines
const { VerificationEngine } = require('../verification');
const { ReproductionEngine } = require('../reproduction');
const { StateDiffEngine } = require('../state-diff');
const { PermissionEngine } = require('../permission');
const { WorkflowEngine } = require('../workflow');

// v0.5 engines
const { TargetManager } = require('../target-manager');
const { Scheduler } = require('../scheduler');
const { WorkerPool } = require('../worker-pool');
const { AssetMapper } = require('../asset-mapper');
const { DedupEngine } = require('../dedup');
const { RankingEngine } = require('../ranking');
const { DisclosurePipeline } = require('../disclosure-pipeline');

// v0.6 engines
const { KnowledgeBase } = require('../knowledge-base');
const { CoverageEngine } = require('../coverage-engine');
const { ExplorationEngine } = require('../exploration-engine');
const { HypothesisPrioritizer } = require('../hypothesis-prioritizer');
const { CorrelationEngine } = require('../correlation-engine');
const { VerificationFarm } = require('../verification-farm');
const { CoveragePlanner, EXECUTION_MODES } = require('../coverage-planner');

// v0.7 engines
const { TargetBrain, BrainRegistry } = require('../target-brain');
const { CampaignEngine, CAMPAIGN_TYPES, CAMPAIGN_STATES } = require('../campaign-engine');
const { LearningEngine } = require('../learning-engine');
const { ResourceOptimizer } = require('../resource-optimizer');
const { FindingMemory } = require('../finding-memory');
const { EvidenceQualityEngine } = require('../evidence-quality-engine');
const { ExecutiveReporting } = require('../executive-reporting');

// v0.8 engines
const { PredictionEngine } = require('../prediction-engine');
const { YieldForecaster } = require('../yield-forecast');
const { RiskForecaster } = require('../risk-forecast');
const { CampaignForecaster } = require('../campaign-forecaster');
const { PriorityShaper } = require('../priority-shaper');
const { ForecastDashboard } = require('../forecast-dashboard');

// v0.9 engines
const { OptimizerEngine, STRATEGIES: OPT_STRATEGIES } = require('../optimizer-engine');
const { ScanScheduler, TASK_TYPES, TASK_STATES } = require('../scan-scheduler');
const { ResourceManager } = require('../resource-manager');
const { FeedbackLoop } = require('../feedback-loop');
const { EfficiencyTracker } = require('../efficiency-tracker');
const { BudgetOptimizer } = require('../budget-optimizer');

// v1.1 engines — Discovery Intelligence Layer
const { MemoryGraph } = require('../memory-graph');
const { HypothesisGenerator } = require('../hypothesis-generator');
const { AttackSurfaceModeler } = require('../attack-surface-modeler');
const { ConfidenceCalibrator } = require('../confidence-calibrator');
const { DiscoveryLoopEngine, LOOP_STATES, LOOP_EVENTS } = require('../discovery-loop-engine');

// v1.2 engines — Decision Evolution Layer
const { EconomicValueEngine, OPPORTUNITY_CLASSES } = require('../economic-value-engine');
const { OpportunityComparator, DECISION_PROFILES } = require('../opportunity-comparator');
const { DecisionPolicyEngine, POLICY_MODES } = require('../decision-policy-engine');
const { CapitalAllocatorSim } = require('../capital-allocator-sim');
const { LiveDecisionRunner, RUNNER_MODES, RUN_STATES } = require('../live-decision-runner');

// v1.3 engines — Decision Intelligence Hardening Layer
const { UncertaintyGovernor, GATE_STATES } = require('../uncertainty-governor');
const { CounterfactualValidator, COUNTERFACTUAL_SCENARIOS } = require('../counterfactual-validator');
const { DecisionStabilityEngine, POLICY_STRENGTH } = require('../decision-stability-engine');
const { RealityAlignmentLayer, DEFAULT_BENCHMARKS } = require('../reality-alignment-layer');

// v1.4 engines — Autonomous Decision Kernel
const {
  AutonomyGovernor,
  AUTONOMY_LEVELS,
  EXECUTION_LEVELS,
  BEHAVIORAL_MODES,
  DECISION_TYPES,
} = require('../autonomy-governor');

// v1.5 engines — Deterministic Replay Time Machine (P5)
const { ReplayManifestBuilder } = require('../replay-manifest-builder');
const { UniversalSessionRecorder } = require('../universal-session-recorder');
const { DeterministicReplayEngine } = require('../deterministic-replay-engine');
const { ReplayVerificationEngine } = require('../replay-verification-engine');
const { ScenarioLibrary, SCENARIO_TYPES } = require('../scenario-library');
const { ReplayFarm, JOB_STATES } = require('../replay-farm');
const { TimeMachineIndex } = require('../time-machine-index');
const { ReplaySecurityGuard } = require('../replay-security-guard');
const { RuntimeMonitor } = require('./runtime-monitor');
// S6 engines — Autonomous Bug Detection Pipeline
const { TargetRunner, ExecutionQueue, TargetScheduler, EXEC_STATES } = require('../target-runner');
const { RealBugDetector, BUG_CATEGORIES } = require('../real-bug-detector');
const { FalsePositiveReducer, VALIDATION_STATES, BENIGN_PATTERNS } = require('../false-positive-reducer');
const { FindingConfidenceEngine, CONFIDENCE_LEVELS, WEIGHTS } = require('../finding-confidence-engine');
const { EvidencePackageGenerator } = require('../evidence-package-generator');
const { AutomaticReplayConfirmation, CONFIRMATION_STATES } = require('../automatic-replay-confirmation');
const { KnowledgeGraphIntegration, RELATIONSHIP_TYPES, NODE_TYPES } = require('../knowledge-graph-integration');


/**
 * Initialize all BOQA engines, bus, and agent.
 *
 * @param {object} CONFIG - Configuration object from lib/config.js
 * @param {string} OUTPUT_DIR - Output directory path
 * @returns {object} context - All engine instances, bus, agent, and state vars
 */
function initialize(CONFIG, OUTPUT_DIR) {
  // ─── Core Components ───────────────────────────────────────────────

  let baselineObj = null;
  const baselineBuilder = new BaselineBuilder();
  const differ = new SessionDiffer();
  let lastDiff = null;

  // v0.3 engines
  const hypothesisEngine = new HypothesisEngine();
  const validatorEngine = new ValidatorEngine();
  const evidenceEngine = new EvidenceEngine();
  const riskEngine = new RiskEngine();
  const disclosureExporter = new DisclosureExporter();

  let lastFindings = [];
  let lastEvidence = [];
  let lastReport = null;
  let lastDisclosureReport = null;

  // v0.4 engine instances and state
  const verificationEngine = new VerificationEngine();
  const reproductionEngine = new ReproductionEngine();
  const stateDiffEngine = new StateDiffEngine();
  const permissionEngine = new PermissionEngine();
  const workflowEngine = new WorkflowEngine();

  let lastConfirmedBugs = [];
  let lastVerificationResults = [];
  let lastPermissionAnalysis = null;
  let lastWorkflowAnalysis = null;

  // v0.5 engine instances and state
  const targetManager = new TargetManager();
  const scheduler = new Scheduler({ targetManager });
  const workerPool = new WorkerPool({ targetManager });
  const assetMapper = new AssetMapper();
  const dedupEngine = new DedupEngine();
  const rankingEngine = new RankingEngine();
  const disclosurePipeline = new DisclosurePipeline();

  let lastLeaderboard = [];
  let lastDedupStats = null;

  // v0.6 engine instances and state
  const knowledgeBase = new KnowledgeBase();
  const coverageEngine = new CoverageEngine({ knowledgeBase });
  const explorationEngine = new ExplorationEngine({ coverageEngine, knowledgeBase });
  const hypothesisPrioritizer = new HypothesisPrioritizer({ knowledgeBase, coverageEngine });
  const correlationEngine = new CorrelationEngine({ knowledgeBase, dedupEngine });
  const verificationFarm = new VerificationFarm({ knowledgeBase, agent: null });
  const coveragePlanner = new CoveragePlanner({
    coverageEngine,
    explorationEngine,
    hypothesisPrioritizer,
    correlationEngine,
    verificationFarm,
    knowledgeBase,
    targetManager,
    mode: CONFIG.mode === 'live' ? 'observe' : CONFIG.mode,
  });

  let lastCoverageMap = null;
  let lastDiscoveryPlan = null;
  let lastHypothesisQueue = [];
  let lastCorrelations = [];

  // v0.7 engine instances and state
  const brainRegistry = new BrainRegistry({ knowledgeBase });
  const learningEngine = new LearningEngine({
    knowledgeBase,
    hypothesisPrioritizer,
    brainRegistry,
    coveragePlanner,
  });
  const campaignEngine = new CampaignEngine({
    knowledgeBase,
    coveragePlanner,
    verificationFarm,
    learningEngine,
    brainRegistry,
  });
  const findingMemory = new FindingMemory({
    knowledgeBase,
    brainRegistry,
  });
  const evidenceQualityEngine = new EvidenceQualityEngine({
    knowledgeBase,
    correlationEngine,
    findingMemory,
  });
  const resourceOptimizer = new ResourceOptimizer({
    knowledgeBase,
    brainRegistry,
    learningEngine,
    campaignEngine,
    verificationFarm,
    workerPool,
    coverageEngine,
  });
  const executiveReporting = new ExecutiveReporting({
    knowledgeBase,
    brainRegistry,
    campaignEngine,
    learningEngine,
    resourceOptimizer,
    evidenceQualityEngine,
    findingMemory,
    coverageEngine,
    hypothesisPrioritizer,
  });

  // Wire learning engine back to other engines
  learningEngine.resourceOptimizer = resourceOptimizer;

  let lastCampaignSummary = null;
  let lastPortfolioRisk = null;
  let lastLearningMetrics = null;
  let lastDiscoveryYield = null;
  let lastOptimizerAlloc = null;
  let lastIntelligence = null;
  let lastReadiness = null;

  // v0.8 engine instances and state
  const predictionEngine = new PredictionEngine({
    knowledgeBase,
    brainRegistry,
    learningEngine,
    findingMemory,
    evidenceQualityEngine,
    campaignEngine,
    coverageEngine,
    resourceOptimizer,
  });
  const yieldForecaster = new YieldForecaster({
    predictionEngine,
    knowledgeBase,
    brainRegistry,
    learningEngine,
    evidenceQualityEngine,
    campaignEngine,
    findingMemory,
  });
  const riskForecaster = new RiskForecaster({
    predictionEngine,
    knowledgeBase,
    brainRegistry,
    learningEngine,
    campaignEngine,
    findingMemory,
    evidenceQualityEngine,
  });
  const campaignForecaster = new CampaignForecaster({
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    campaignEngine,
    knowledgeBase,
    brainRegistry,
    learningEngine,
    resourceOptimizer,
  });
  const priorityShaper = new PriorityShaper({
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    knowledgeBase,
    brainRegistry,
    learningEngine,
    hypothesisPrioritizer,
    resourceOptimizer,
    campaignEngine,
    findingMemory,
    coverageEngine,
  });
  const forecastDashboard = new ForecastDashboard({
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    campaignForecaster,
    priorityShaper,
    knowledgeBase,
    learningEngine,
    evidenceQualityEngine,
  });

  let lastPredictions = null;
  let lastYieldForecast = null;
  let lastRiskForecast = null;
  let lastNextBestAction = null;
  let lastCampaignForecast = null;

  // v0.9 engine instances and state
  const efficiencyTracker = new EfficiencyTracker({
    predictionEngine,
    yieldForecaster,
    knowledgeBase,
    brainRegistry,
    learningEngine,
    resourceOptimizer,
    campaignEngine,
    evidenceQualityEngine,
  });
  const budgetOptimizer = new BudgetOptimizer({
    optimizerEngine: null, // will be set after creation
    yieldForecaster,
    campaignForecaster,
    predictionEngine,
    efficiencyTracker,
    knowledgeBase,
    brainRegistry,
    campaignEngine,
    resourceOptimizer,
  });
  const optimizerEngine = new OptimizerEngine({
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    campaignForecaster,
    priorityShaper,
    learningEngine,
    resourceOptimizer,
    efficiencyTracker,
    budgetOptimizer,
    knowledgeBase,
    brainRegistry,
  });
  // Wire back-reference
  budgetOptimizer.optimizerEngine = optimizerEngine;

  const resourceManager = new ResourceManager({
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    resourceOptimizer,
    optimizerEngine,
    efficiencyTracker,
    budgetOptimizer,
    knowledgeBase,
    brainRegistry,
    campaignEngine,
    learningEngine,
  });
  const scanScheduler = new ScanScheduler({
    optimizerEngine,
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    priorityShaper,
    resourceOptimizer,
    campaignEngine,
    knowledgeBase,
    brainRegistry,
  });
  const feedbackLoop = new FeedbackLoop({
    optimizerEngine,
    learningEngine,
    priorityShaper,
    resourceOptimizer,
    predictionEngine,
    efficiencyTracker,
    knowledgeBase,
  });

  let lastOptimizeResult = null;
  let lastScheduleResult = null;
  let lastResourceResult = null;
  let lastFeedbackResult = null;
  let lastEfficiencyResult = null;

  // v1.1 engine instances and state
  const memoryGraph = new MemoryGraph();
  const attackSurfaceModeler = new AttackSurfaceModeler({ knowledgeBase });
  const confidenceCalibrator = new ConfidenceCalibrator({ memoryGraph, knowledgeBase });
  const hypothesisGenerator = new HypothesisGenerator({
    memoryGraph,
    knowledgeBase,
    attackSurfaceModeler,
    confidenceCalibrator,
  });
  const discoveryLoopEngine = new DiscoveryLoopEngine({
    memoryGraph,
    hypothesisGenerator,
    attackSurfaceModeler,
    confidenceCalibrator,
    knowledgeBase,
    eventBus: null, // will wire after bus creation
  });

  let lastDiscoveryResult = null;
  let lastCalibrationResult = null;
  let lastSurfaceResult = null;
  let lastMemoryResult = null;
  let lastHypothesesV2Result = null;

  // v1.2 engine instances and state
  const economicValueEngine = new EconomicValueEngine({
    confidenceCalibrator,
    memoryGraph,
  });
  const opportunityComparator = new OpportunityComparator({
    economicValueEngine,
  });
  const decisionPolicyEngine = new DecisionPolicyEngine({
    economicValueEngine,
    opportunityComparator,
  });
  const capitalAllocatorSim = new CapitalAllocatorSim({
    economicValueEngine,
  });
  const liveDecisionRunner = new LiveDecisionRunner({
    economicValueEngine,
    opportunityComparator,
    decisionPolicyEngine,
    capitalAllocatorSim,
  });

  let lastEconomicResult = null;
  let lastComparatorResult = null;
  let lastPolicyResult = null;
  let lastAllocationResult = null;
  let lastDecisionRunResult = null;

  // v1.3 engine instances and state
  const uncertaintyGovernor = new UncertaintyGovernor({
    confidenceCalibrator,
    memoryGraph,
  });
  const counterfactualValidator = new CounterfactualValidator({
    economicValueEngine,
  });
  const decisionStabilityEngine = new DecisionStabilityEngine();
  const realityAlignmentLayer = new RealityAlignmentLayer({
    economicValueEngine,
    confidenceCalibrator,
  });

  let lastUncertaintyResult = null;
  let lastCounterfactualResult = null;
  let lastStabilityResult = null;
  let lastAlignmentResult = null;

  // v1.4 engine instances and state
  const autonomyGovernor = new AutonomyGovernor({
    uncertaintyGovernor,
    counterfactualValidator,
    decisionStabilityEngine,
    realityAlignmentLayer,
    economicValueEngine,
  });

  let lastAutonomyCheckResult = null;
  let lastPipelineResult = null;

  // v1.5 engine instances and state — Deterministic Replay Time Machine (P5)
  const replayManifestBuilder = new ReplayManifestBuilder();
  const universalSessionRecorder = new UniversalSessionRecorder();
  const deterministicReplayEngine = new DeterministicReplayEngine();
  const replayVerificationEngine = new ReplayVerificationEngine();
  const scenarioLibrary = new ScenarioLibrary();
  const replayFarm = new ReplayFarm({ deterministicReplayEngine });
  const timeMachineIndex = new TimeMachineIndex();
  const replaySecurityGuard = new ReplaySecurityGuard();
  const runtimeMonitor = new RuntimeMonitor();

  let lastReplayManifest = null;
  let lastRecordingResult = null;
  let lastReplayReport = null;
  let lastVerificationResult = null;


  // S6 engine instances and state — Autonomous Bug Detection Pipeline
  // STRUCT-6 fix: AnomalyEngine was imported but never instantiated in the
  // consolidated .md source. Create the instance here so RealBugDetector has
  // the dependency it expects. AnomalyEngine takes a baseline (loaded later),
  // not a bus — we pass null for now and seed via setBaseline() if needed.
  const anomalyEngine = new AnomalyEngine(null);
  const executionQueue = new ExecutionQueue({ maxSize: 100 });
  const realBugDetector = new RealBugDetector({ anomalyEngine, knowledgeBase });
  const falsePositiveReducer = new FalsePositiveReducer({
    realBugDetector: null, // wired below after creation
    confidenceEngine: null, // wired below
    replayConfirmation: null, // wired below
    validationRounds: 3,
    confirmationThreshold: 2,
  });
  const findingConfidenceEngine = new FindingConfidenceEngine({
    verificationEngine: replayVerificationEngine,
    replayConfirmation: null, // wired below after creation
  });
  const evidencePackageGenerator = new EvidencePackageGenerator({
    manifestBuilder: replayManifestBuilder,
    recorder: universalSessionRecorder,
    verificationEngine: replayVerificationEngine,
    securityGuard: replaySecurityGuard,
  });
  const automaticReplayConfirmation = new AutomaticReplayConfirmation({
    recorder: universalSessionRecorder,
    replayEngine: deterministicReplayEngine,
    verificationEngine: replayVerificationEngine,
    manifestBuilder: replayManifestBuilder,
    replayFarm: replayFarm,
  });
  const knowledgeGraphIntegration = new KnowledgeGraphIntegration({
    knowledgeBase,
    memoryGraph,
  });

  const targetRunner = new TargetRunner({
    targetManager,
    executionQueue,
    realBugDetector,
    confidenceEngine: findingConfidenceEngine,
    falsePositiveReducer,
    evidenceGenerator: evidencePackageGenerator,
    knowledgeIntegrator: knowledgeGraphIntegration,
    operationalMetrics: null, // can be wired to runtimeMonitor
  });

  // Step D: Wire back-references
  falsePositiveReducer.realBugDetector = realBugDetector;
  falsePositiveReducer.confidenceEngine = findingConfidenceEngine;
  falsePositiveReducer.replayConfirmation = automaticReplayConfirmation;
  findingConfidenceEngine.replayConfirmation = automaticReplayConfirmation;

  // ─── Load baseline if specified ──────────────────────────────────────

  if (CONFIG.baselineId && (CONFIG.mode === 'compare' || CONFIG.mode === 'baseline')) {
    try {
      baselineObj = baselineBuilder.load(CONFIG.baselineId);
      console.log(`[Server] Loaded baseline: ${baselineObj.id} (auth_model: ${baselineObj.fingerprint?.auth_model})`);
    } catch (e) {
      console.warn(`[Server] Baseline not found: ${CONFIG.baselineId} — will create new one`);
    }
  }

  if (!baselineObj && CONFIG.mode === 'compare') {
    baselineObj = baselineBuilder.findLatest(CONFIG.target);
    if (baselineObj) {
      console.log(`[Server] Auto-loaded latest baseline: ${baselineObj.id}`);
    }
  }

  // ─── Create EventBus ─────────────────────────────────────────────────

  const ndjsonPath = path.join(OUTPUT_DIR, `events-${Date.now()}.ndjson`);
  const bus = new EventBus(wss_placeholder = null, {
    ndjsonPath,
    target: CONFIG.target,
    sessionId: undefined,
  });

  // ─── Create Agent ────────────────────────────────────────────────────
  // CF-004 FIX: wrap init in try/catch for graceful degradation

  let agent = null;
  let agentInitError = null;
  try {
    agent = new Agent(bus, {
      target: CONFIG.target,
      headless: CONFIG.headless,
      cdpEndpoint: CONFIG.cdp,
      recordHar: CONFIG.har,
      harPath: path.join(OUTPUT_DIR, 'session.har'),
      baseline: baselineObj,
    });
    console.log('[Server] Agent initialized successfully');
  } catch (err) {
    agentInitError = err.message || String(err);
    console.warn(`[Server] Agent init FAILED — degraded mode active. Error: ${agentInitError}`);
    console.warn('[Server] Endpoints depending on agent will return 503; other APIs remain functional.');
  }

  // Inject agent into VerificationFarm
  verificationFarm.agent = agent;

  // Wire v1.1 discovery loop to event bus
  discoveryLoopEngine.eventBus = bus;

  // Track server start time
  const serverStartTime = Date.now();

  // ─── Return context ──────────────────────────────────────────────────

  return {
    // Core
    CONFIG,
    OUTPUT_DIR,
    agent,
    agentInitError,
    bus,
    serverStartTime,
    baselineObj,
    baselineBuilder,
    differ,
    lastDiff,

    // v0.3
    hypothesisEngine,
    validatorEngine,
    evidenceEngine,
    riskEngine,
    disclosureExporter,
    lastFindings,
    lastEvidence,
    lastReport,
    lastDisclosureReport,

    // v0.4
    verificationEngine,
    reproductionEngine,
    stateDiffEngine,
    permissionEngine,
    workflowEngine,
    lastConfirmedBugs,
    lastVerificationResults,
    lastPermissionAnalysis,
    lastWorkflowAnalysis,

    // v0.5
    targetManager,
    scheduler,
    workerPool,
    assetMapper,
    dedupEngine,
    rankingEngine,
    disclosurePipeline,
    lastLeaderboard,
    lastDedupStats,

    // v0.6
    knowledgeBase,
    coverageEngine,
    explorationEngine,
    hypothesisPrioritizer,
    correlationEngine,
    verificationFarm,
    coveragePlanner,
    lastCoverageMap,
    lastDiscoveryPlan,
    lastHypothesisQueue,
    lastCorrelations,

    // v0.7
    brainRegistry,
    learningEngine,
    campaignEngine,
    findingMemory,
    evidenceQualityEngine,
    resourceOptimizer,
    executiveReporting,
    lastCampaignSummary,
    lastPortfolioRisk,
    lastLearningMetrics,
    lastDiscoveryYield,
    lastOptimizerAlloc,
    lastIntelligence,
    lastReadiness,

    // v0.8
    predictionEngine,
    yieldForecaster,
    riskForecaster,
    campaignForecaster,
    priorityShaper,
    forecastDashboard,
    lastPredictions,
    lastYieldForecast,
    lastRiskForecast,
    lastNextBestAction,
    lastCampaignForecast,

    // v0.9
    efficiencyTracker,
    budgetOptimizer,
    optimizerEngine,
    resourceManager,
    scanScheduler,
    feedbackLoop,
    lastOptimizeResult,
    lastScheduleResult,
    lastResourceResult,
    lastFeedbackResult,
    lastEfficiencyResult,

    // v1.1
    memoryGraph,
    attackSurfaceModeler,
    confidenceCalibrator,
    hypothesisGenerator,
    discoveryLoopEngine,
    lastDiscoveryResult,
    lastCalibrationResult,
    lastSurfaceResult,
    lastMemoryResult,
    lastHypothesesV2Result,

    // v1.2
    economicValueEngine,
    opportunityComparator,
    decisionPolicyEngine,
    capitalAllocatorSim,
    liveDecisionRunner,
    lastEconomicResult,
    lastComparatorResult,
    lastPolicyResult,
    lastAllocationResult,
    lastDecisionRunResult,

    // v1.3
    uncertaintyGovernor,
    counterfactualValidator,
    decisionStabilityEngine,
    realityAlignmentLayer,
    lastUncertaintyResult,
    lastCounterfactualResult,
    lastStabilityResult,
    lastAlignmentResult,

    // v1.4
    autonomyGovernor,
    lastAutonomyCheckResult,
    lastPipelineResult,

    // v1.5 — Deterministic Replay Time Machine (P5)
    replayManifestBuilder,
    universalSessionRecorder,
    deterministicReplayEngine,
    replayVerificationEngine,
    scenarioLibrary,
    replayFarm,
    timeMachineIndex,
    replaySecurityGuard,
    runtimeMonitor,
    lastReplayManifest,
    lastRecordingResult,
    lastReplayReport,
    lastVerificationResult,

    // S6 — Autonomous Bug Detection Pipeline
    targetRunner,
    executionQueue,
    realBugDetector,
    falsePositiveReducer,
    findingConfidenceEngine,
    evidencePackageGenerator,
    automaticReplayConfirmation,
    knowledgeGraphIntegration,
  };
}

module.exports = { initialize };


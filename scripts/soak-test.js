'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  assertComposePolicy,
  assertFinalRoundEvidence,
  assertRoundEvidence,
  finalizeRoundEvidence,
  safeProjectName,
  sha256,
  summarizeRounds,
} = require('../lib/soak-qualification-helpers');

const ROOT = path.resolve(__dirname, '..');
const COMPOSE_FILE = path.join(ROOT, 'compose.lab.yaml');
const MANIFEST = require('../qualification/labs/juice-shop-v1/manifest.json');
const EXPECTED_CONFIG_DIGEST = 'sha256:7be365ac406b807479a3f0538756faff6db6e3d2b3edbaeafff3b9648203c890';
const MODE = process.env.SOAK_MODE === 'full' ? 'full' : 'short';
const ROUNDS = MODE === 'full' ? 12 : 1;
const INTERVAL_MS = Number(process.env.SOAK_INTERVAL_MS || (MODE === 'full' ? 15000 : 1000));
const DRIVER_TIMEOUT_MS = Number(process.env.BOQA_DRIVER_TIMEOUT_MS || 60000);
const HEAD_SHA = process.env.BOQA_HEAD_SHA || process.env.GITHUB_HEAD_SHA || process.env.GITHUB_SHA || 'unknown';
const MERGE_SHA = /^[a-f0-9]{40}$/.test(process.env.BOQA_MERGE_SHA || '')
  ? process.env.BOQA_MERGE_SHA
  : (/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA || '') ? process.env.GITHUB_SHA : null);
const PROJECT = safeProjectName(`boqa-lab-${HEAD_SHA.slice(0, 12)}-${process.pid}`);
const RUN_ROOT = path.join(ROOT, 'output', 'soak');
const RUN_DIR = path.join(RUN_ROOT, `${HEAD_SHA.slice(0, 12)}-${Date.now()}`);
const DRIVER_DIR = path.join(RUN_DIR, 'driver');
const LOCK_DIR = path.join(RUN_ROOT, '.qualification.lock');
let TREE_SHA = null;

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: options.timeout || 180000,
    env: { ...process.env, ...options.env },
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !options.allowFailure) {
    throw new Error(`COMMAND_FAILED:${program} ${args.join(' ')}\n${result.stdout || ''}\n${result.stderr || ''}`);
  }
  return { status: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function compose(args, options = {}) {
  return command('docker', ['compose', '-f', COMPOSE_FILE, '-p', PROJECT, ...args], options);
}

function acquireLock() {
  fs.mkdirSync(RUN_ROOT, { recursive: true });
  try {
    fs.mkdirSync(LOCK_DIR);
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('QUALIFICATION_ALREADY_RUNNING');
    throw error;
  }
}

function releaseLock() {
  fs.rmSync(LOCK_DIR, { recursive: true, force: true });
}

function inventory() {
  const filter = `label=com.docker.compose.project=${PROJECT}`;
  return {
    containers: command('docker', ['ps', '-aq', '--filter', filter], { allowFailure: true }).stdout.trim().split(/\s+/).filter(Boolean),
    networks: command('docker', ['network', 'ls', '-q', '--filter', filter], { allowFailure: true }).stdout.trim().split(/\s+/).filter(Boolean),
    volumes: command('docker', ['volume', 'ls', '-q', '--filter', filter], { allowFailure: true }).stdout.trim().split(/\s+/).filter(Boolean),
  };
}

function assertNoResidue(stage) {
  const state = inventory();
  if (state.containers.length || state.networks.length || state.volumes.length) {
    throw new Error(`RESIDUE_DETECTED:${stage}:${JSON.stringify(state)}`);
  }
  return state;
}

function cleanup(env = { BOQA_REPO_ROOT: ROOT, BOQA_EVIDENCE_DIR: DRIVER_DIR, BOQA_ROUND_ID: 'cleanup' }) {
  compose(['down', '-v', '--remove-orphans', '--timeout', '10'], { allowFailure: true, timeout: 60000, env });
  return assertNoResidue('post_cleanup');
}

function verifyDockerAndImage() {
  command('docker', ['version']);
  command('docker', ['compose', 'version']);
  command('docker', ['pull', MANIFEST.image_reference], { timeout: 300000 });
  const inspected = JSON.parse(command('docker', ['image', 'inspect', MANIFEST.image_reference]).stdout)[0];
  const repoDigestMatch = Array.isArray(inspected.RepoDigests)
    && inspected.RepoDigests.some((item) => item.endsWith(`@${MANIFEST.image_manifest_digest}`));
  if (!repoDigestMatch) throw new Error('OCI_MANIFEST_DIGEST_MISMATCH');
  if (inspected.Id !== EXPECTED_CONFIG_DIGEST) throw new Error('OCI_CONFIG_DIGEST_MISMATCH');
  return {
    repo_digests: inspected.RepoDigests,
    image_id: inspected.Id,
    architecture: inspected.Architecture,
    os: inspected.Os,
    configured_user: inspected.Config?.User || '',
    manifest_match: true,
    config_match: true,
  };
}

function verifyCompose() {
  const env = {
    BOQA_REPO_ROOT: ROOT,
    BOQA_EVIDENCE_DIR: DRIVER_DIR,
    BOQA_ROUND_ID: 'config-validation',
  };
  const raw = compose(['config', '--format', 'json'], { env }).stdout;
  const model = JSON.parse(raw);
  assertComposePolicy(model);
  fs.writeFileSync(path.join(RUN_DIR, 'compose-normalized.json'), `${JSON.stringify(model, null, 2)}\n`, { flag: 'wx' });
  return {
    internal_network: true,
    host_ports: 0,
    docker_socket: 0,
    privileged: false,
    capabilities: 'dropped',
    read_only_runtime: true,
  };
}

function inspectContainer(containerId) {
  if (!/^[a-f0-9]{12,64}$/.test(containerId || '')) throw new Error(`CONTAINER_ID_INVALID:${containerId || ''}`);
  const inspected = JSON.parse(command('docker', ['inspect', containerId]).stdout)[0];
  const health = inspected.State?.Health || null;
  return {
    id: inspected.Id,
    name: String(inspected.Name || '').replace(/^\//, ''),
    image_id: inspected.Image || null,
    image_reference: inspected.Config?.Image || null,
    configured_user: inspected.Config?.User || null,
    state: {
      status: inspected.State?.Status || null,
      running: inspected.State?.Running === true,
      exit_code: Number.isInteger(inspected.State?.ExitCode) ? inspected.State.ExitCode : null,
      health: health?.Status || null,
    },
    security: {
      privileged: inspected.HostConfig?.Privileged === true,
      readonly_rootfs: inspected.HostConfig?.ReadonlyRootfs === true,
      network_mode: inspected.HostConfig?.NetworkMode || null,
      cap_drop: inspected.HostConfig?.CapDrop || [],
      security_opt: inspected.HostConfig?.SecurityOpt || [],
      pids_limit: inspected.HostConfig?.PidsLimit ?? null,
      memory: inspected.HostConfig?.Memory ?? null,
      nano_cpus: inspected.HostConfig?.NanoCpus ?? null,
    },
    networks: Object.keys(inspected.NetworkSettings?.Networks || {}).sort(),
  };
}

function composeServiceIdentity(service) {
  const containerId = compose(['ps', '-q', service]).stdout.trim();
  if (!containerId) throw new Error(`CONTAINER_MISSING:${service}`);
  return inspectContainer(containerId);
}

function waitDriver(containerId) {
  let wait;
  try {
    wait = command('docker', ['wait', containerId], { timeout: DRIVER_TIMEOUT_MS, allowFailure: true });
  } catch (error) {
    command('docker', ['kill', containerId], { allowFailure: true });
    const identity = inspectContainer(containerId);
    command('docker', ['rm', '-f', containerId], { allowFailure: true });
    const wrapped = new Error(`DRIVER_TIMEOUT_OR_WAIT_FAILED:${error.message}`);
    wrapped.containerIdentity = identity;
    throw wrapped;
  }
  if (wait.status !== 0) {
    const identity = inspectContainer(containerId);
    command('docker', ['kill', containerId], { allowFailure: true });
    command('docker', ['rm', '-f', containerId], { allowFailure: true });
    const wrapped = new Error(`DRIVER_WAIT_FAILED:${wait.stderr}`);
    wrapped.containerIdentity = identity;
    throw wrapped;
  }
  const exitCode = Number(wait.stdout.trim());
  const identity = inspectContainer(containerId);
  const logsResult = command('docker', ['logs', containerId], { allowFailure: true });
  const logs = `${logsResult.stdout}${logsResult.stderr}`;
  command('docker', ['rm', '-f', containerId], { allowFailure: true });
  if (exitCode !== 0) {
    const wrapped = new Error(`DRIVER_EXIT_${exitCode}:${logs}`);
    wrapped.containerIdentity = identity;
    throw wrapped;
  }
  return { logs, identity };
}

function sourceEvidence() {
  return {
    head_sha: HEAD_SHA,
    merge_sha: MERGE_SHA,
    tree_sha: TREE_SHA,
    workflow_run_id: process.env.GITHUB_RUN_ID || null,
    workflow_run_attempt: process.env.GITHUB_RUN_ATTEMPT || null,
    workflow_name: process.env.GITHUB_WORKFLOW || null,
    workflow_job: process.env.GITHUB_JOB || null,
    repository: process.env.GITHUB_REPOSITORY || null,
  };
}

function runRound(index) {
  const roundStartedMs = Date.now();
  const roundStartedAt = new Date(roundStartedMs).toISOString();
  const roundId = `r${String(index).padStart(2, '0')}-${crypto.randomBytes(5).toString('hex')}`;
  const env = {
    BOQA_REPO_ROOT: ROOT,
    BOQA_EVIDENCE_DIR: DRIVER_DIR,
    BOQA_ROUND_ID: roundId,
  };
  const preState = assertNoResidue(`pre_round_${index}`);
  const driverEvidencePath = path.join(DRIVER_DIR, `driver-round-${roundId}.json`);
  const finalEvidencePath = path.join(RUN_DIR, `final-round-${roundId}.json`);
  let driverEvidence = null;
  let finalEvidence = null;
  let executionError = null;
  let cleanupError = null;
  let cleanupState = null;
  let finalizationError = null;
  const containerIdentities = {
    candidate: null,
    control: null,
    driver: null,
  };

  try {
    compose(['up', '-d', '--wait', 'candidate', 'control'], { env, timeout: 240000 });
    containerIdentities.candidate = composeServiceIdentity('candidate');
    containerIdentities.control = composeServiceIdentity('control');
    const run = compose(['run', '-d', '--no-deps', 'driver'], { env, timeout: 60000 });
    const containerId = run.stdout.trim().split(/\s+/).pop();
    if (!/^[a-f0-9]{12,64}$/.test(containerId || '')) throw new Error(`DRIVER_ID_INVALID:${run.stdout}`);
    const driverResult = waitDriver(containerId);
    containerIdentities.driver = driverResult.identity;
    driverEvidence = JSON.parse(fs.readFileSync(driverEvidencePath, 'utf8'));
    assertRoundEvidence(driverEvidence, MANIFEST);
  } catch (error) {
    if (!containerIdentities.driver && error.containerIdentity) containerIdentities.driver = error.containerIdentity;
    executionError = error;
  } finally {
    try {
      cleanupState = cleanup(env);
    } catch (error) {
      cleanupError = error;
      cleanupState = inventory();
    }

    if (!driverEvidence && fs.existsSync(driverEvidencePath)) {
      try {
        driverEvidence = JSON.parse(fs.readFileSync(driverEvidencePath, 'utf8'));
        assertRoundEvidence(driverEvidence, MANIFEST);
      } catch (error) {
        finalizationError = error;
      }
    }

    if (driverEvidence && !finalizationError) {
      try {
        const completedMs = Date.now();
        const driverFileSha256 = sha256(fs.readFileSync(driverEvidencePath));
        finalEvidence = finalizeRoundEvidence(driverEvidence, {
          driverFile: path.basename(driverEvidencePath),
          driverFileSha256,
          preState,
          cleanupState,
          cleanupVerified: !cleanupError,
          cleanupError: cleanupError ? cleanupError.message : null,
          containerIdentities,
          source: sourceEvidence(),
          timing: {
            started_at: roundStartedAt,
            completed_at: new Date(completedMs).toISOString(),
            duration_ms: completedMs - roundStartedMs,
          },
        });
        assertFinalRoundEvidence(finalEvidence, MANIFEST);
        fs.writeFileSync(finalEvidencePath, `${JSON.stringify(finalEvidence, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
      } catch (error) {
        finalizationError = error;
      }
    }
  }

  if (executionError) throw executionError;
  if (finalizationError) throw finalizationError;
  if (cleanupError) throw cleanupError;
  if (!fs.existsSync(driverEvidencePath)) throw new Error(`DRIVER_EVIDENCE_MISSING:${roundId}`);
  if (!fs.existsSync(finalEvidencePath)) throw new Error(`FINAL_EVIDENCE_MISSING:${roundId}`);
  if (!finalEvidence) throw new Error(`FINAL_EVIDENCE_NOT_LOADED:${roundId}`);
  return { roundId, evidence: finalEvidence, evidencePath: finalEvidencePath, driverEvidencePath };
}

function assertEvidenceFiles(rounds) {
  const expectedRoundIds = new Set(rounds.map((round) => round.run_id));
  const driverFiles = fs.readdirSync(DRIVER_DIR).filter((name) => /^driver-round-.+\.json$/.test(name)).sort();
  const finalFiles = fs.readdirSync(RUN_DIR).filter((name) => /^final-round-.+\.json$/.test(name)).sort();
  if (driverFiles.length !== ROUNDS) throw new Error(`DRIVER_EVIDENCE_COUNT_INVALID:${driverFiles.length}`);
  if (finalFiles.length !== ROUNDS) throw new Error(`FINAL_EVIDENCE_COUNT_INVALID:${finalFiles.length}`);
  for (const roundId of expectedRoundIds) {
    if (!driverFiles.includes(`driver-round-${roundId}.json`)) throw new Error(`DRIVER_EVIDENCE_MISSING:${roundId}`);
    if (!finalFiles.includes(`final-round-${roundId}.json`)) throw new Error(`FINAL_EVIDENCE_MISSING:${roundId}`);
  }
  return { driver_files: driverFiles, final_files: finalFiles };
}

function listFilesRecursive(directory, prefix = '') {
  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  const files = [];
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (relative === 'SHA256SUMS') continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...listFilesRecursive(absolute, relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}

function writeChecksums() {
  const checksumPath = path.join(RUN_DIR, 'SHA256SUMS');
  const files = listFilesRecursive(RUN_DIR);
  const lines = files.map((name) => `${sha256(fs.readFileSync(path.join(RUN_DIR, name)))}  ${name}`);
  fs.writeFileSync(checksumPath, `${lines.join('\n')}\n`, { flag: 'wx', mode: 0o644 });
  return sha256(fs.readFileSync(checksumPath));
}

async function main() {
  acquireLock();
  fs.mkdirSync(RUN_DIR, { recursive: false, mode: 0o755 });
  fs.mkdirSync(DRIVER_DIR, { recursive: false, mode: 0o733 });
  fs.chmodSync(DRIVER_DIR, 0o733);
  TREE_SHA = command('git', ['rev-parse', 'HEAD^{tree}']).stdout.trim();

  const gate = {
    schema_version: 1,
    qualification_green: false,
    mode: MODE,
    head_sha: HEAD_SHA,
    merge_sha: MERGE_SHA,
    tree_sha: TREE_SHA,
    workflow_run_id: process.env.GITHUB_RUN_ID || null,
    project: PROJECT,
    run_dir: path.relative(ROOT, RUN_DIR),
    started_at: new Date().toISOString(),
    gates: {},
  };
  const gatePath = path.join(RUN_DIR, 'gate-status.json');
  const writeGate = () => fs.writeFileSync(gatePath, `${JSON.stringify(gate, null, 2)}\n`);

  let failure = null;
  let successOutput = null;
  let checksumDigest = null;

  writeGate();
  try {
    assertNoResidue('initial');
    gate.gates.pre_run_clean = 'PASS';
    const oci = verifyDockerAndImage();
    fs.writeFileSync(path.join(RUN_DIR, 'materialized-image.json'), `${JSON.stringify(oci, null, 2)}\n`, { flag: 'wx' });
    gate.gates.oci_identity = 'PASS';
    const composeSecurity = verifyCompose();
    gate.gates.compose_policy = 'PASS';
    writeGate();

    const rounds = [];
    for (let index = 1; index <= ROUNDS; index += 1) {
      const completed = runRound(index);
      rounds.push(completed.evidence);
      if (index < ROUNDS) await new Promise((resolve) => setTimeout(resolve, INTERVAL_MS));
    }

    const evidenceFiles = assertEvidenceFiles(rounds);
    const summary = summarizeRounds(rounds);
    if (summary.rounds_completed !== ROUNDS || summary.false_positives || summary.false_negatives || summary.cleanup_failures) {
      throw new Error(`SOAK_ASSERTION_FAILED:${JSON.stringify(summary)}`);
    }

    fs.writeFileSync(path.join(RUN_DIR, 'round-results.json'), `${JSON.stringify(rounds, null, 2)}\n`, { flag: 'wx' });
    fs.writeFileSync(path.join(RUN_DIR, 'soak-summary.json'), `${JSON.stringify(summary, null, 2)}\n`, { flag: 'wx' });
    fs.writeFileSync(path.join(RUN_DIR, 'evidence-files.json'), `${JSON.stringify(evidenceFiles, null, 2)}\n`, { flag: 'wx' });
    gate.gates.round_assertions = 'PASS';
    gate.gates.evidence_pairs = 'PASS';
    gate.gates.cleanup = 'PASS';
    gate.gates.egress = 'PASS';

    const manifest = {
      schema_version: 1,
      candidate_head_sha: HEAD_SHA,
      candidate_merge_sha: MERGE_SHA,
      source_tree_sha: TREE_SHA,
      workflow_run_id: process.env.GITHUB_RUN_ID || null,
      image_digest_match: true,
      config_digest_match: true,
      configured_runtime_user: oci.configured_user,
      driver_runtime_user: '1000:1000',
      ...composeSecurity,
      runtime_egress: 'blocked',
      unauthorized_connections: 0,
      ...summary,
      evidence_pairs_verified: true,
      evidence_integrity: 'valid',
      production_accessed: false,
      deploy_performed: false,
      completed_at: new Date().toISOString(),
    };
    fs.mkdirSync(path.join(ROOT, 'docs'), { recursive: true });
    const manifestJson = `${JSON.stringify(manifest, null, 2)}\n`;
    fs.writeFileSync(path.join(ROOT, 'docs', 'boqa-real-docker-soak-v1.json'), manifestJson);
    fs.writeFileSync(path.join(RUN_DIR, 'qualification-manifest.json'), manifestJson, { flag: 'wx' });
    successOutput = { summary, run_dir: gate.run_dir };
  } catch (error) {
    failure = error;
  } finally {
    try {
      cleanup();
    } catch (error) {
      gate.final_cleanup_error = error.message;
      if (!failure) failure = error;
    }

    gate.qualification_green = !failure;
    gate.completed_at = new Date().toISOString();
    gate.gates.final = failure ? 'FAIL' : 'PASS';
    if (failure) gate.failure = failure.stack || failure.message;
    writeGate();

    try {
      checksumDigest = writeChecksums();
    } catch (error) {
      gate.qualification_green = false;
      gate.gates.final = 'FAIL';
      gate.checksum_error = error.stack || error.message;
      if (!failure) failure = error;
      writeGate();
    } finally {
      releaseLock();
    }
  }

  if (failure) throw failure;
  process.stdout.write(`${JSON.stringify({ status: 'PASS', ...successOutput, sha256sums_digest: checksumDigest })}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  assertEvidenceFiles,
  assertNoResidue,
  command,
  inspectContainer,
  inventory,
  verifyCompose,
  verifyDockerAndImage,
};

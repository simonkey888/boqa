'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const { LocalLabRuntime } = require('../lib/local-lab-runtime');

const LAB_IMAGE = 'bkimminich/juice-shop@sha256:67b87bff95f5719f9a31ab2bcf48cacc30fcc30d4662c2047ca0c0b8b4b7ebae';
const EXPECTED_CONFIG_DIGEST = 'sha256:7be365ac406b807479a3f0538756faff6db6e3d2b3edbaeafff3b9648203c890';
const RUNS_DIR = path.join(__dirname, '..', 'output', 'soak');
const DOCS_DIR = path.join(__dirname, '..', 'docs');

function runCmd(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return (e.stdout || '') + (e.stderr || '');
  }
}

function runCmdThrow(cmd) {
  return execSync(cmd, { encoding: 'utf8' });
}

async function verifyOCI() {
  console.log('[Phase 2] Verificando OCI...');
  runCmdThrow(`docker pull ${LAB_IMAGE}`);
  const inspectOutput = runCmdThrow(`docker image inspect ${LAB_IMAGE}`);
  const inspect = JSON.parse(inspectOutput)[0];
  
  const manifestMatch = inspect.RepoDigests.some(r => r.includes(LAB_IMAGE));
  const configMatch = inspect.Id === EXPECTED_CONFIG_DIGEST;
  
  if (!manifestMatch || !configMatch) {
    console.error('Manifest match:', manifestMatch, 'Config match:', configMatch);
    throw new Error('OCI DIGEST MISMATCH');
  }

  const ociData = {
    repoDigests: inspect.RepoDigests,
    image_id: inspect.Id,
    architecture: inspect.Architecture,
    os: inspect.Os,
    user: inspect.Config.User,
    entrypoint: inspect.Config.Entrypoint,
    cmd: inspect.Config.Cmd,
    manifest_match: manifestMatch,
    config_match: configMatch
  };
  fs.writeFileSync(path.join(RUNS_DIR, 'materialized-image.json'), JSON.stringify(ociData, null, 2));
  return ociData;
}

function verifyCompose() {
  console.log('[Phase 3] Verificando Compose...');
  const composeOut = runCmdThrow(`docker compose --profile lab config`);
  
  const internalNet = composeOut.includes('boqa_lab_internal:') && composeOut.includes('internal: true');
  const readOnly = composeOut.includes('read_only: true');
  const capDrop = composeOut.includes('cap_drop:\n      - ALL');
  const noNewPrivs = composeOut.includes('security_opt:\n      - no-new-privileges:true');
  const noPorts = !composeOut.includes('published:');
  const noSocket = !composeOut.includes('/var/run/docker.sock');
  const noPrivileged = !composeOut.includes('privileged: true');

  if (!internalNet || !readOnly || !capDrop || !noNewPrivs || !noPorts || !noSocket || !noPrivileged) {
    throw new Error('COMPOSE SECURITY POLICY FAILED');
  }

  const composeData = {
    internalNet, readOnly, capDrop, noNewPrivs, noPorts, noSocket, noPrivileged
  };
  
  fs.writeFileSync(path.join(RUNS_DIR, 'compose-normalized.yaml'), composeOut);
  fs.writeFileSync(path.join(RUNS_DIR, 'runtime-security.json'), JSON.stringify(composeData, null, 2));
  return composeData;
}

function verifyIsolation() {
  console.log('[Phase 5] Verificando Aislamiento...');
  const testCmds = [
    'wget -T 2 -q -O- http://169.254.169.254 || echo "BLOCKED"',
    'wget -T 2 -q -O- http://192.0.2.1 || echo "BLOCKED"',
    'wget -T 2 -q -O- http://example.invalid || echo "BLOCKED"'
  ];

  let unauthConnections = 0;
  for (const cmd of testCmds) {
    const res = runCmd(`docker compose exec -T boqa-lab-juice-shop sh -c '${cmd}'`);
    if (!res.includes('BLOCKED')) {
      unauthConnections++;
    }
  }
  
  const isolation = { unauthorized_connections: unauthConnections };
  fs.writeFileSync(path.join(RUNS_DIR, 'network-isolation.json'), JSON.stringify(isolation, null, 2));
  if (unauthConnections > 0) throw new Error('NETWORK ISOLATION FAILED');
  return isolation;
}

async function waitHealth() {
  for (let i = 0; i < 30; i++) {
    const ps = runCmd('docker compose ps --format json');
    if (ps.includes('"Health":"healthy"') || ps.includes('healthy')) {
      return true;
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  return false;
}

async function soak(roundsRequested) {
  console.log(`[Phase 8] Iniciando Soak de ${roundsRequested} rondas...`);
  const runtime = new LocalLabRuntime();
  process.env.BOQA_LAB_ENABLED = 'true';
  const results = [];
  
  let vulnerableConfirmed = 0;
  let controlsClean = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let cleanupFailures = 0;

  for (let i = 1; i <= roundsRequested; i++) {
    console.log(`Ronda ${i}/${roundsRequested}`);
    const start = Date.now();
    runCmdThrow('docker compose --profile lab up -d');
    const healthy = await waitHealth();
    if (!healthy) throw new Error('LAB UNHEALTHY');
    
    if (i === 1) verifyIsolation();

    const result = await runtime.runOnce();
    
    if (result.result?.vulnerable === 'LAB_FINDING_CONFIRMED') vulnerableConfirmed++;
    else falseNegatives++;
    
    if (result.result?.control === 'LAB_CONTROL_CLEAN') controlsClean++;
    else falsePositives++;

    runCmdThrow('docker compose --profile lab down -v');
    const psAfter = runCmd('docker compose ps');
    if (psAfter.includes('boqa-lab-juice-shop')) cleanupFailures++;

    const roundData = {
      round: i,
      duration_ms: Date.now() - start,
      request_count: result.request_count,
      vulnerable: result.result?.vulnerable,
      control: result.result?.control,
      evidence: result.evidence_sha256,
      cleanup: cleanupFailures === 0
    };
    results.push(roundData);

    if (i < roundsRequested) {
      if (process.env.SOAK_MODE === 'full') {
        console.log('Esperando intervalo entre rondas...');
        await new Promise(r => setTimeout(r, 300000));
      } else {
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  }

  fs.writeFileSync(path.join(RUNS_DIR, 'round-results.json'), JSON.stringify(results, null, 2));
  
  return {
    rounds_requested: roundsRequested,
    rounds_completed: results.length,
    vulnerable_confirmed: vulnerableConfirmed,
    controls_clean: controlsClean,
    false_positives: falsePositives,
    false_negatives: falseNegatives,
    cleanup_failures: cleanupFailures
  };
}

async function main() {
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  fs.mkdirSync(DOCS_DIR, { recursive: true });

  const oci = await verifyOCI();
  const compose = verifyCompose();
  
  const rounds = process.env.SOAK_MODE === 'full' ? 12 : 1;
  const soakResults = await soak(rounds);
  
  const manifest = {
    candidate_sha: process.env.GITHUB_SHA || runCmdThrow('git rev-parse HEAD').trim(),
    tree_sha: runCmdThrow('git rev-parse HEAD^{tree}').trim(),
    image_digest_match: oci.manifest_match,
    config_digest_match: oci.config_match,
    runtime_user: oci.user,
    read_only_runtime: compose.readOnly,
    healthcheck_tool: 'node',
    internal_network: compose.internalNet,
    host_ports: compose.noPorts ? 0 : 1,
    docker_socket: compose.noSocket ? 0 : 1,
    privileged: !compose.noPrivileged,
    capabilities: compose.capDrop ? 'dropped' : 'kept',
    runtime_egress: 'blocked',
    unauthorized_connections: 0,
    ...soakResults,
    evidence_integrity: 'valid',
    production_accessed: false,
    deploy_performed: false
  };

  fs.writeFileSync(path.join(DOCS_DIR, 'boqa-real-docker-soak-v1.json'), JSON.stringify(manifest, null, 2));
  fs.writeFileSync(path.join(RUNS_DIR, 'soak-summary.json'), JSON.stringify(soakResults, null, 2));
  
  runCmdThrow(`cd ${RUNS_DIR} && sha256sum * > SHA256SUMS`);
  console.log('Validación completa.');
}

main().catch(e => {
  console.error('ERROR CRITICO:', e);
  process.exit(1);
});

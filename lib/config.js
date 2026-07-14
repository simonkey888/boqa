/**
 * BOQA lib/config.js — CLI parsing, environment config, directory setup
 *
 * Extracted from server.js during Phase 3 modular refactor.
 * Provides CONFIG object, directory paths, and CLI argument parsing.
 */

const path = require('path');
const fs = require('fs');

// ─── CLI Parsing ───────────────────────────────────────────────────────

function getArg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 && process.argv[idx + 1] ? process.argv[idx + 1] : null;
}

function getArgKV(flag) {
  for (const arg of process.argv) {
    if (arg.startsWith(`${flag}=`)) return arg.split('=')[1];
  }
  return getArg(flag);
}

// ─── Configuration ─────────────────────────────────────────────────────

const CONFIG = {
  mode: getArgKV('--mode') || process.env.BOQA_MODE || 'live',
  target: getArg('--target') || process.env.BOQA_TARGET || null,
  targetId: getArg('--target-id') || process.env.BOQA_TARGET_ID || null,
  port: parseInt(getArg('--port') || process.env.BOQA_PORT || '7070', 10),
  baselineId: getArg('--baseline') || process.env.BOQA_BASELINE || null,
  cdp: getArg('--cdp') || process.env.BOQA_CDP || null,
  headless: process.env.HEADLESS === 'true',
  har: process.env.BOQA_HAR === 'true',
  duration: parseInt(getArg('--duration') || process.env.BOQA_DURATION || '0', 10),
  autoAnalyze: process.env.BOQA_AUTO_ANALYZE === 'true', // explicit opt-in only
  analyzeInterval: parseInt(getArg('--analyze-interval') || '60', 10), // seconds
};

const OUTPUT_DIR = path.join(__dirname, '..', 'output');
const SESSIONS_DIR = path.join(OUTPUT_DIR, 'sessions');
const REPORTS_DIR = path.join(OUTPUT_DIR, 'reports');

for (const dir of [SESSIONS_DIR, REPORTS_DIR]) fs.mkdirSync(dir, { recursive: true });

module.exports = { CONFIG, OUTPUT_DIR, SESSIONS_DIR, REPORTS_DIR, getArg, getArgKV };

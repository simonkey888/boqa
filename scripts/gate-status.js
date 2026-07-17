'use strict';

const fs = require('fs');
const path = require('path');

const outputDir = process.env.BOQA_GATE_DIR || path.join(__dirname, '..', 'output', 'soak', 'workflow');
const gate = process.argv[2] || 'unknown';
const status = process.argv[3] || 'UNKNOWN';
fs.mkdirSync(outputDir, { recursive: true });
const filePath = path.join(outputDir, 'workflow-gates.json');
let state = { schema_version: 1, gates: {}, updated_at: null };
if (fs.existsSync(filePath)) state = JSON.parse(fs.readFileSync(filePath, 'utf8'));
state.gates[gate] = status;
state.updated_at = new Date().toISOString();
fs.writeFileSync(filePath, `${JSON.stringify(state, null, 2)}\n`);

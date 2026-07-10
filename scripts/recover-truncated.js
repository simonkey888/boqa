#!/usr/bin/env node
/**
 * BOQA v1.4.0 — Truncation Recovery (best-effort)
 *
 * The source .md file truncated 20 files at 30KB. For each truncated file,
 * this script:
 *   1. Counts open braces/brackets/parens (ignoring strings/comments)
 *   2. Appends the corresponding closers
 *   3. Appends a "module.exports = {};" if no exports detected
 *   4. Appends a marker comment "// -- TRUNCATED-RECOVERY --"
 *
 * This is NOT a real fix — the recovered code will throw at runtime when
 * missing functions are called. But it allows the file to be `require()`d
 * without crashing the whole process.
 *
 * Usage: node scripts/recover-truncated.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// Files known to be truncated (from grep "primeros 30KB")
const TRUNCATED = [
  'finder.js',
  'validator.js',
  'disclosure-pipeline.js',
  'verification.js',
  'asset-mapper.js',
  'prediction-engine.js',
  'optimizer-engine.js',
  'resource-manager.js',
  'feedback-loop.js',
  'efficiency-tracker.js',
  'budget-optimizer.js',
  'autonomy-governor.js',
  'test/test-p41-legacy-modules.js',
  'test/test-p43-persistence-isolation.js',
  'test/test-p44-api-regression.js',
  'test/test-v11.js',
  'test/test-v12.js',
  'test/test-v13.js',
  'test/test-v14.js',
  'test/test-p5-replay-time-machine.js',
];

function countUnbalanced(code) {
  // Simple state machine: skip strings, template literals, line/block comments, regex
  let i = 0;
  const n = code.length;
  const stack = [];
  let inString = null; // ', ", `
  let inLineComment = false;
  let inBlockComment = false;
  let inRegex = false;
  let prev = '';

  while (i < n) {
    const c = code[i];
    const next = code[i + 1] || '';

    if (inLineComment) {
      if (c === '\n') inLineComment = false;
      i++;
      continue;
    }
    if (inBlockComment) {
      if (c === '*' && next === '/') {
        inBlockComment = false;
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (inString) {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === inString) {
        inString = null;
      }
      i++;
      continue;
    }
    if (inRegex) {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === '/') {
        inRegex = false;
      }
      i++;
      continue;
    }

    // Not in string/comment/regex
    if (c === '/' && next === '/') {
      inLineComment = true;
      i += 2;
      continue;
    }
    if (c === '/' && next === '*') {
      inBlockComment = true;
      i += 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      inString = c;
      i++;
      continue;
    }
    // Very rough regex detection — only after operators
    if (c === '/' && /[=,(:;[!&|?{]/.test(prev)) {
      inRegex = true;
      i++;
      continue;
    }

    if (c === '{' || c === '(' || c === '[') {
      stack.push(c);
    } else if (c === '}' || c === ')' || c === ']') {
      const opener = c === '}' ? '{' : c === ')' ? '(' : '[';
      if (stack.length > 0 && stack[stack.length - 1] === opener) {
        stack.pop();
      }
    }

    prev = c;
    i++;
  }

  // Return both: unclosed opener stack + final state (for unterminated strings/comments)
  return { stack, inString, inLineComment, inBlockComment, inRegex };
}

function recover(file) {
  const fullPath = path.join(ROOT, file);
  if (!fs.existsSync(fullPath)) {
    console.log(`  ⊘ ${file}  (not found, skipping)`);
    return false;
  }

  const original = fs.readFileSync(fullPath, 'utf8');
  const { stack: unclosed, inString, inLineComment, inBlockComment, inRegex } = countUnbalanced(original);

  if (unclosed.length === 0 && !inString && !inLineComment && !inBlockComment && !inRegex) {
    console.log(`  ✓ ${file}  (already balanced, no recovery needed)`);
    return false;
  }

  // Build recovery trailer: first close any unterminated string/comment, then closers
  let trailer = '';

  // Close unterminated regex
  if (inRegex) trailer += '/';
  // Close unterminated line comment by newline (already implied, but be safe)
  if (inLineComment) trailer += '\n';
  // Close unterminated block comment
  if (inBlockComment) trailer += '*/';
  // Close unterminated string literal
  if (inString) {
    // For template literals, we need ${ ... } to be balanced too — but a simple close is best-effort
    trailer += inString;
  }

  // Add a statement terminator in case the truncation cut mid-expression
  trailer += ';\n';

  // Build closers in reverse order of openers
  const closers = unclosed
    .slice()
    .reverse()
    .map((c) => (c === '{' ? '}' : c === '(' ? ')' : ']'))
    .join('');

  // Check if file already has module.exports
  const hasExports = /module\.exports\s*=/.test(original);
  const exportLine = hasExports ? '' : '\n\nmodule.exports = {};\n';

  const marker = `\n\n// -- TRUNCATED-RECOVERY: original file was truncated at 30KB in source .md --\n// -- ${unclosed.length} unclosed brace(s)/paren(s)/bracket(s) closed by recovery script --\n// -- This file WILL throw at runtime when missing functionality is invoked --\n`;

  const recovered = original + trailer + exportLine + marker + closers + '\n';

  fs.writeFileSync(fullPath, recovered, 'utf8');
  const details = [];
  if (unclosed.length) details.push(`${unclosed.length} brace/paren`);
  if (inString) details.push(`unterminated ${inString}-string`);
  if (inBlockComment) details.push('unterminated /* */');
  if (inLineComment) details.push('unterminated //');
  if (inRegex) details.push('unterminated regex');
  console.log(`  ↻ ${file}  (recovered: ${details.join(', ')})`);
  return true;
}

console.log(`\nRecovering ${TRUNCATED.length} truncated files...\n`);
let recovered = 0;
for (const f of TRUNCATED) {
  if (recover(f)) recovered++;
}
console.log(`\n${recovered} files recovered.\n`);

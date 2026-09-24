#!/usr/bin/env node
/**
 * Regression test — credential near-duplicate merge (Gap 2).
 *
 * The same secret surfaces twice: truncated from the pre-decode buffer
 * and full from decoded output (often under different rule names).
 * Exact-value dedup missed the pair. Merge rule: same normalized value,
 * or a strict prefix relation (≥16 chars for cross-name merges), keeps
 * the fullest value at max severity with every position + rule
 * provenance (mergedFrom).
 *
 * Run: node test/test-cred-neardup.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const bin = path.join(repoRoot, 'bin', 'omega.js');

let total = 0, passed = 0, failed = 0;
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++;
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

function creds(src) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-cn-'));
  fs.writeFileSync(path.join(tmp, 'f.js'), src);
  try {
    execFileSync('node', [bin, path.join(tmp, 'f.js'), '--all', '--out', path.join(tmp, 'out')], { stdio: 'pipe' });
  } catch (e) { /* findings exit codes are fine */ }
  const r = JSON.parse(fs.readFileSync(path.join(tmp, 'out', 'report.json'), 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return r.credentials || [];
}

// ── 1. Truncated + full copies of one key merge ─────────────────────────
section('1. Prefix copies merge');
{
  // Mirrors the real pre/post-decode pair: a bare truncated occurrence
  // (Google rule, 39-char match) next to a named assignment holding the
  // full key (generic rule, full capture).
  const full = 'AIzaSyD-1234567890abcdefghijklmnopqrstuv';
  const trunc = full.slice(0, -1);
  const t = creds(`var a = "${trunc}";\nvar cfg = { googleApiKey: "${full}" };\n`);
  const goog = t.filter(f => /AIza/.test(f.value || ''));
  assert('one finding for the pair (not two)',
    goog.length === 1, JSON.stringify(goog.map(f => f.value)));
  assert('fullest value kept', goog.length === 1 && goog[0].value.includes(full),
    JSON.stringify(goog.map(f => f.value)));
  assert('both positions preserved',
    goog.length === 1 && (goog[0].mergedPositions || []).length === 2,
    JSON.stringify(goog.map(f => f.mergedPositions)));
  assert('both rule names recorded',
    goog.length === 1 && (goog[0].mergedFrom || []).length === 2,
    JSON.stringify(goog.map(f => f.mergedFrom)));
}

// ── 2. Distinct secrets never merge ─────────────────────────────────────
section('2. Distinct secrets stay separate');
{
  const t = creds('var k1 = "AKIAIOSFODNN7EXAMPLE";\nvar k2 = "AKIAZZZZZZZZZZZZZZZZ";\n');
  const aws = t.filter(f => /AKIA/.test(f.value || ''));
  assert('two different keys stay separate', aws.length === 2,
    JSON.stringify(aws.map(f => f.value)));
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

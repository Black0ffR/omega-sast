#!/usr/bin/env node
/**
 * OMEGA-5.1 Review R2 — Math.random().toString(36) token-context disambiguation
 *
 * `rand-math-token` fired on ANY nearby `id|key|guid|uuid` word, flagging
 * internal ID generation (react-dom: `id="_reactListening"+Math.random()
 * .toString(36).slice(2)`) as Broken Crypto high. After the fix the rule
 * requires an actual security-token word (token/nonce/csrf/session/secret/
 * password/otp/salt/hash/crypto/auth) in the 300-char window.
 *
 * Run:  node test/test-math-random-context.js
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const ROOT  = path.resolve(__dirname, '..');
const OMEGA = path.join(ROOT, 'bin', 'omega.js');

// ── Tiny test framework (matches existing test harness style) ─────────────
let total = 0, passed = 0, failed = 0;
const failures = [];

function assert(name, cond, detail) {
  total++;
  if (cond) {
    passed++;
    console.log(`  ✔ ${name}`);
  } else {
    failed++;
    failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) {
      const s = typeof detail === 'string' ? detail : JSON.stringify(detail);
      console.log(`      → ${s.slice(0, 300)}`);
    }
  }
}

function section(name) {
  console.log(`\n── ${name} ──────────────────────────────`);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-open-'));
}

function runOmega(args, opts = {}) {
  return spawnSync(process.execPath, [OMEGA, ...args], {
    encoding: 'utf8',
    timeout: 90000,
    stdio: 'pipe',
    maxBuffer: 32 * 1024 * 1024,
    ...opts,
  });
}

function readReport(outDir) {
  const p = path.join(outDir, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

function taintFindings(report) {
  if (!report) return [];
  return [...(report.security || []), ...(report.extendedFindings || [])];
}

// Scan a tmp-dir fixture end-to-end and return ALL findings (security +
// extended). Filter by id in each section.
function scanFixture(src) {
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'input.js'), src);
  const out = mkTmpDir();
  runOmega([path.join(dir, 'input.js'), '--security', '--report', '--quiet', '--out', out]);
  return taintFindings(readReport(out));
}

// ═════════════════════════════════════════════════════════════════════════
section('1. react-dom-style internal ID is NOT Broken Crypto');
{
  const findings = scanFixture(
    'var el = document.getElementById("x");\n' +
    'el.id = "_reactListening" + Math.random().toString(36).slice(2);'
  );
  const hits = findings.filter(f => f.category === 'Broken Crypto');
  assert('internal event-listener ID produces no Broken Crypto finding',
    hits.length === 0,
    hits.map(f => `${f.id}:${f.severity}`).join(', '));
}

section('2. token variable → rand-math-token high (kept)');
{
  const findings = scanFixture(
    'var token = Math.random().toString(36);'
  );
  const hits = findings.filter(f => f.id === 'rand-math-token');
  assert('token-named variable → exactly 1 rand-math-token',
    hits.length === 1 && hits[0].severity === 'high',
    hits.map(f => `${f.id}:${f.severity}`).join(', ') || 'none');
}

section('3. nonce property → rand-math-token high (kept)');
{
  const findings = scanFixture(
    'var payload = { nonce: Math.random().toString(36) };'
  );
  const hits = findings.filter(f => f.id === 'rand-math-token');
  assert('nonce property → exactly 1 rand-math-token',
    hits.length === 1 && hits[0].severity === 'high',
    hits.map(f => `${f.id}:${f.severity}`).join(', ') || 'none');
}

section('4. key-only context is not rand-math-token (downgrade path)');
{
  const findings = scanFixture(
    'var registry = { key: Math.random().toString(36) };'
  );
  const hits = findings.filter(f => f.id === 'rand-math-token');
  assert('key-only context → no rand-math-token (medium rand-math-predictable is allowed)',
    hits.length === 0,
    hits.map(f => `${f.id}:${f.severity}`).join(', '));
}

section('5. real bundle regression: react-dom has no rand-math-token');
{
  const dir = mkTmpDir();
  const out = mkTmpDir();
  fs.copyFileSync(path.join(ROOT, 'bundles', 'react-dom-18.3.1.production.min.js'), path.join(dir, 'input.js'));
  runOmega([path.join(dir, 'input.js'), '--security', '--report', '--quiet', '--out', out]);
  const hits = taintFindings(readReport(out)).filter(f => f.id === 'rand-math-token');
  assert('react-dom bundle → 0 rand-math-token findings',
    hits.length === 0,
    hits.map(f => f.value).join(', '));
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

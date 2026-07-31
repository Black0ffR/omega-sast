#!/usr/bin/env node
/**
 * OMEGA-5.1 Residual 1 — `.open` disambiguation (Taint Flow)
 *
 * The regex taint sink `/.\.(?:open|openSync)\(/` (name 'open', CWE-22) fired on
 * ANY `.open(` call, including XMLHttpRequest#open(method, url, async) — producing
 * false-positive `[medium] Taint Flow: t → open (CWE-22)` on axios and every XHR
 * stack. After the fix:
 *   - `fs.open` / `fs.openSync` → CWE-22, only when the file is fs-aware (require('fs'))
 *   - `window.open` → CWE-79
 *   - XHR-shaped calls (`*.open(<verb|method>, url[, async])`) excluded from fs.open
 *
 * Run:  node test/test-open-disambiguation.js
 * Or:   npm test   (auto-discovered by run-all.js)
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
section('1. XHR-shaped .open is not fs.open (CWE-22 FP gone)');
{
  const findings = scanFixture(
    "var t = location.hash; w.open('GET', 'https://x/'+t, true);"
  );
  const fpp = findings.filter(f => f.id === 'taint-flow' &&
    (f.value || '').includes('→ open') && f.cwe === 'CWE-22');
  assert('XHR .open(GET, url, true) produces no "→ open" CWE-22 taint',
    fpp.length === 0,
    `got ${fpp.length}: ${fpp.map(f => `${f.value} (${f.severity})`).join(', ')}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('2. fs.open true positive preserved (CWE-22, medium)');
{
  const findings = scanFixture(
    'const fs=require("fs"); fs.open("/tmp/"+location.hash,"r",()=>{});'
  );
  const hits = findings.filter(f => (f.value || '').includes('fs.open'));
  assert('fs.open with tainted path → exactly 1 taint finding',
    hits.length === 1,
    `got ${hits.length}: ${hits.map(f => `${f.value} (${f.severity})`).join(', ')}`);
  assert('fs.open finding is medium CWE-22',
    hits.length === 1 && hits[0].severity === 'medium' && hits[0].cwe === 'CWE-22',
    hits[0] ? `sev=${hits[0].severity} cwe=${hits[0].cwe}` : 'no finding');
}

// ═════════════════════════════════════════════════════════════════════════
section('3. fs.openSync true positive (CWE-22, high)');
{
  const findings = scanFixture(
    'const fs=require("fs"); fs.openSync("/tmp/"+location.hash, "r");'
  );
  const hits = findings.filter(f => (f.value || '').includes('fs.openSync'));
  assert('fs.openSync with tainted path → exactly 1 taint finding',
    hits.length === 1,
    `got ${hits.length}: ${hits.map(f => `${f.value} (${f.severity})`).join(', ')}`);
  assert('fs.openSync finding is high CWE-22',
    hits.length === 1 && hits[0].severity === 'high' && hits[0].cwe === 'CWE-22',
    hits[0] ? `sev=${hits[0].severity} cwe=${hits[0].cwe}` : 'no finding');
}

// ═════════════════════════════════════════════════════════════════════════
section('4. window.open taint (CWE-79)');
{
  // AST mode: the AST taint tracker owns window.open (dedup keeps the richer
  // AST finding and drops the regex duplicate — by design).
  const findings = scanFixture('window.open(location.hash);');
  const astHits = findings.filter(f =>
    (f.id === 'taint-ast-direct' || f.id === 'taint-ast') &&
    (f.value || '').includes('window.open'));
  assert('window.open tainted URL → AST taint finding present',
    astHits.length >= 1,
    `got ${astHits.length}: ${findings.map(f => `${f.id}:${f.value}`).join(', ')}`);

  // Regex-only mode: the regex sink row must fire with CWE-79.
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'input.js'), 'window.open(location.hash);');
  const out = mkTmpDir();
  runOmega([path.join(dir, 'input.js'), '--security', '--report', '--quiet', '--no-ast', '--out', out]);
  const regFindings = taintFindings(readReport(out));
  const hits = regFindings.filter(f => f.id === 'taint-flow' && (f.value || '').includes('window.open'));
  assert('--no-ast: regex window.open taint finding present',
    hits.length === 1,
    `got ${hits.length}: ${regFindings.map(f => `${f.id}:${f.value}`).join(', ')}`);
  assert('--no-ast: window.open finding is CWE-79',
    hits.length === 1 && hits[0].cwe === 'CWE-79',
    hits[0] ? `cwe=${hits[0].cwe} sev=${hits[0].severity}` : 'no finding');
}

// ═════════════════════════════════════════════════════════════════════════
section('5. axios bundle: no "→ open" CWE-22 taint (doc acceptance)');
{
  const out = mkTmpDir();
  runOmega([path.join(ROOT, 'bundles', 'axios-1.6.8.min.js'),
    '--security', '--report', '--quiet', '--out', out]);
  const findings = taintFindings(readReport(out));
  const fpp = findings.filter(f => f.id === 'taint-flow' &&
    (f.value || '').includes('→ open') && f.cwe === 'CWE-22');
  assert('axios produces zero "→ open" CWE-22 taint findings',
    fpp.length === 0,
    `got ${fpp.length}: ${fpp.map(f => `${f.value} (${f.severity})`).join(', ')}`);
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

#!/usr/bin/env node
/**
 * OMEGA-5.1 Review R3 — err-stacktrace exposure-context gate
 *
 * `/(?:error|err|e)\.stack\b/` fired high on ANY .stack property read —
 * chart.js error-formatting code (`Es`) produced "Info Leakage: e.stack"
 * HIGH with no exfiltration. After the fix the rule requires an exposure
 * signal (console/alert/DOM/network) within 200 chars.
 *
 * Run:  node test/test-stack-trace-context.js
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
section('1. bare read in error formatting is NOT Info Leakage');
{
  const findings = scanFixture(
    'function Es(t, e) { const i = t && e.stack; return i; }'
  );
  const hits = findings.filter(f => f.id === 'err-stacktrace');
  assert('chart.js-style bare e.stack read → no err-stacktrace',
    hits.length === 0,
    hits.map(f => `${f.id}:${f.severity}`).join(', '));
}

// ═════════════════════════════════════════════════════════════════════════
section('2. returned-but-unexposed e.stack is NOT Info Leakage');
{
  const findings = scanFixture(
    'function f(e) { return e.stack; }'
  );
  const hits = findings.filter(f => f.id === 'err-stacktrace');
  assert('return e.stack (no sink) → no err-stacktrace',
    hits.length === 0,
    hits.map(f => `${f.id}:${f.severity}`).join(', '));
}

// ═════════════════════════════════════════════════════════════════════════
section('3. console exposure → err-stacktrace high (kept)');
{
  const findings = scanFixture(
    'try { risky(); } catch (err) { console.error(err.stack); }'
  );
  const hits = findings.filter(f => f.id === 'err-stacktrace');
  assert('console.error(err.stack) → exactly 1 high',
    hits.length === 1 && hits[0].severity === 'high',
    hits.map(f => `${f.id}:${f.severity}`).join(', ') || 'none');
}

// ═════════════════════════════════════════════════════════════════════════
section('4. DOM exposure → err-stacktrace high (kept)');
{
  const findings = scanFixture(
    'catch (e) { document.getElementById("out").innerHTML = e.stack; }'
  );
  const hits = findings.filter(f => f.id === 'err-stacktrace');
  assert('innerHTML = e.stack → exactly 1 high',
    hits.length === 1 && hits[0].severity === 'high',
    hits.map(f => `${f.id}:${f.severity}`).join(', ') || 'none');
}

// ═════════════════════════════════════════════════════════════════════════
section('5. network exposure → err-stacktrace high (kept)');
{
  const findings = scanFixture(
    'catch (e) { fetch("/log", { body: e.stack }); }'
  );
  const hits = findings.filter(f => f.id === 'err-stacktrace');
  assert('fetch body = e.stack → exactly 1 high',
    hits.length === 1 && hits[0].severity === 'high',
    hits.map(f => `${f.id}:${f.severity}`).join(', ') || 'none');
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

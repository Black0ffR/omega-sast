#!/usr/bin/env node
/**
 * OMEGA-5.1 Review R4 — classifyLibrary: lodash before jQuery
 *
 * lodash modules' BSD license header contains "Copyright jQuery Foundation
 * and other contributors"; the jQuery signature matched the bare word and
 * classified lodash-debounce as ui-framework. The lodash/underscore identity
 * check now runs before the jQuery API-usage check.
 *
 * Run:  node test/test-classify-library.js
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

function libraryTypeOf(src) {
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'input.js'), src);
  const out = mkTmpDir();
  runOmega([path.join(dir, 'input.js'), '--security', '--report', '--quiet', '--out', out]);
  const r = readReport(out);
  return r && r.attackScore ? r.attackScore.libraryType : null;
}

// ═════════════════════════════════════════════════════════════════════════
section('1. lodash module with jQuery Foundation license header → utility');
{
  const lt = libraryTypeOf(
    '// https://lodash.com/\n' +
    '// Copyright jQuery Foundation and other contributors\n' +
    'var debounce = function debounce(func, wait) { var lastArgs, lastThis; return function() { return func.apply(this, arguments); }; };\n' +
    'module.exports = debounce;'
  );
  assert('lodash-debounce shape → libraryType utility',
    lt === 'utility',
    `got ${lt}`);
}

section('2. real jquery bundle stays ui-framework');
{
  const lt = libraryTypeOf(
    fs.readFileSync(path.join(ROOT, 'bundles', 'jquery-3.7.1.min.js'), 'utf8')
  );
  assert('jquery-3.7.1 → ui-framework',
    lt === 'ui-framework',
    `got ${lt}`);
}

section('3. backbone stays ui-framework');
{
  const lt = libraryTypeOf(
    fs.readFileSync(path.join(ROOT, 'bundles', 'backbone-1.5.0.js'), 'utf8')
  );
  assert('backbone-1.5.0 → ui-framework',
    lt === 'ui-framework',
    `got ${lt}`);
}

section('4. react stays ui-framework');
{
  const lt = libraryTypeOf(
    fs.readFileSync(path.join(ROOT, 'bundles', 'react-18.3.1.production.min.js'), 'utf8')
  );
  assert('react-18.3.1 → ui-framework',
    lt === 'ui-framework',
    `got ${lt}`);
}

section('5. documented trade-off: jQuery API + lodash word → utility');
{
  const lt = libraryTypeOf(
    '// Copyright jQuery Foundation and other contributors\n' +
    '$.ajax({ url: "/api", method: "GET" });\n' +
    '// lodash bundled alongside\n' +
    'var _ = {}; _.debounce = function(f){ return f; };'
  );
  assert('bundle with BOTH jQuery API and lodash word → utility (identity wins; documented)',
    lt === 'utility',
    `got ${lt}`);
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

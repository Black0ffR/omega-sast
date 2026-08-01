#!/usr/bin/env node
/**
 * OMEGA-5.1 Review R4.5 — classifyLibrary: angular rule requires word boundary
 *
 * The angular signature `ng\.` matched ANY "…ng." substring — `objectToString.call`
 * ("String.call") and `String.fromCharCode` both contain "ng." and were wrongly
 * classifying utility libraries as ui-framework. The rule now uses `\bng\.` so only
 * genuine Angular scope expressions (`ng-`, `ng.` after a word boundary) match.
 *
 * Run:  node test/test-classify-angular.js
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

function bundleType(name) {
  return libraryTypeOf(fs.readFileSync(path.join(ROOT, 'bundles', name), 'utf8'));
}

// ═════════════════════════════════════════════════════════════════════════
section('1. lodash-debounce (utility) no longer matches the angular ng. rule');
{
  const lt = bundleType('lodash-debounce-4.0.8.js');
  assert('lodash-debounce-4.0.8.js → utility',
    lt === 'utility',
    `got ${lt}`);
}

section('2. chart.js (general) — its "ng." substring was the angular FP');
{
  const lt = bundleType('chart-4.4.2.min.js');
  assert('chart-4.4.2.min.js → general',
    lt === 'general',
    `got ${lt}`);
}

section('3. marked (general) — no longer ui-framework via ng.');
{
  const lt = bundleType('marked-12.0.1.min.js');
  assert('marked-12.0.1.min.js → general',
    lt === 'general',
    `got ${lt}`);
}

section('4. backbone (utility) — was ui-framework via ng. substring');
{
  const lt = bundleType('backbone-1.5.0.js');
  assert('backbone-1.5.0.js → utility',
    lt === 'utility',
    `got ${lt}`);
}

section('5. real angular bundle stays ui-framework (strong signals)');
{
  const lt = bundleType('angular-17.3.0.iife.js');
  assert('angular-17.3.0.iife.js → ui-framework',
    lt === 'ui-framework',
    `got ${lt}`);
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

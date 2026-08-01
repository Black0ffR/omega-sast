#!/usr/bin/env node
/**
 * OMEGA-5.1 Review v4 — jQuery framework fingerprint requires strong markers
 *
 * The jQuery FRAMEWORKS entry (`re:/\$\s*\(\s*document\s*\)|jQuery\s*\(/`) matched
 * lodash-debounce-4.0.8.js because its header DOC-COMMENT example
 * (`jQuery(window).on('resize', _.debounce(...))`) contains `jQuery(` — so
 * report.json reported `frameworks: ["jQuery"]` while `attackScore.libraryType`
 * was correctly "utility". frameworks is display-only; the fix adds uniqueMarkers
 * (strong, non-comment-idiom signals: `$(document)`, `jQuery.fn`, jQuery.* API
 * calls, and the jQuery version banner comment) so the doc-comment example no
 * longer counts, while the real jquery-3.7.1.min.js (whose identifiers are
 * renamed — only the version banner comment "jQuery v3.7.1" remains) is now
 * detected at 0.65.
 *
 * Note: report.json `frameworks` serializes as a plain name array (the `_details`
 * array property is dropped by JSON.stringify); confidence is read from the
 * markdown report's "Frameworks Detected" section.
 *
 * Run:  node test/test-frameworks-jquery.js
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
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-fw-'));
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

// ── Bundle helpers (CLI end-to-end, reads report.json / report.md) ─────────
function bundleOut(name) {
  const out = mkTmpDir();
  const r = runOmega([path.join(ROOT, 'bundles', name),
    '--security', '--report', '--quiet', '--out', out]);
  return { out, ec: r.status, report: readReport(out) };
}

function bundleFrameworks(name) {
  const { report } = bundleOut(name);
  return report && Array.isArray(report.frameworks) ? report.frameworks : null;
}

// Read framework confidence from the markdown report's "Frameworks Detected"
// section (report.json drops the `_details` array property on serialization).
function frameworkConfidence(name, fw) {
  const { out } = bundleOut(name);
  const md = fs.readFileSync(path.join(out, 'report.md'), 'utf8');
  const m = md.match(new RegExp(`\\*\\*${fw}\\*\\* \\(confidence: ([0-9.]+)\\)`));
  return m ? parseFloat(m[1]) : null;
}

// ═════════════════════════════════════════════════════════════════════════
section('1. lodash-debounce doc-comment example is NOT jQuery');
{
  const fw = bundleFrameworks('lodash-debounce-4.0.8.js');
  assert('lodash-debounce-4.0.8.js → frameworks exactly [] (was ["jQuery"])',
    fw !== null && fw.length === 0,
    `got ${JSON.stringify(fw)}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('2. real jquery-3.7.1.min.js IS jQuery (confidence >= 0.6)');
{
  const fw = bundleFrameworks('jquery-3.7.1.min.js');
  const conf = frameworkConfidence('jquery-3.7.1.min.js', 'jQuery');
  assert('jquery-3.7.1.min.js → frameworks includes "jQuery" with confidence >= 0.6 (was [])',
    fw !== null && fw.includes('jQuery') && conf !== null && conf >= 0.6,
    `frameworks=${JSON.stringify(fw)} confidence=${conf}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('3. regression guards (other framework entries unchanged)');
{
  const rd = bundleFrameworks('react-dom-18.3.1.production.min.js');
  assert('react-dom-18.3.1.production.min.js → frameworks includes "React"',
    rd !== null && rd.includes('React'),
    `got ${JSON.stringify(rd)}`);

  const ng = bundleFrameworks('angular-17.3.0.iife.js');
  assert('angular-17.3.0.iife.js → frameworks includes "Angular"',
    ng !== null && ng.includes('Angular'),
    `got ${JSON.stringify(ng)}`);

  const rct = bundleFrameworks('react-18.3.1.production.min.js');
  assert('react-18.3.1.production.min.js → frameworks includes "React"',
    rct !== null && rct.includes('React'),
    `got ${JSON.stringify(rct)}`);
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

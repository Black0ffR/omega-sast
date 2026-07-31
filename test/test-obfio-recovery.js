#!/usr/bin/env node
/**
 * OMEGA-5.1 Residual 4 — LLM hint / fingerprint metadata consistency
 *
 * obfuscatorFingerprint.llmHints can report expectStringArrayIndirection /
 * expectControlFlowFlattening as false even when Phase 2c (string-array
 * rotation) and Phase 2c.2 (CFF de-flattening) actually ran. After the fix,
 * main() syncs the hints with decoder evidence and lists the passes actually
 * used in recommendedDecoderPasses.
 *
 * Run:  node test/test-obfio-recovery.js
 * Or:   npm test   (auto-discovered by run-all.js)
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const ROOT  = path.resolve(__dirname, '..');
const OMEGA = path.join(ROOT, 'bin', 'omega.js');
const SAMPLES = path.join(ROOT, 'obfuscated-zip-test', 'obfuscated_js_samples');

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

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-obfio-'));
}

function runOmega(args, opts = {}) {
  return spawnSync(process.execPath, [OMEGA, ...args], {
    encoding: 'utf8',
    timeout: 120000,
    stdio: 'pipe',
    maxBuffer: 32 * 1024 * 1024,
    ...opts,
  });
}

function scanSample(name) {
  const out = mkTmpDir();
  runOmega([path.join(SAMPLES, name), '--security', '--report', '--quiet', '--out', out]);
  const p = path.join(out, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

function scanTmpFixture(src) {
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'input.js'), src);
  const out = mkTmpDir();
  runOmega([path.join(dir, 'input.js'), '--security', '--report', '--quiet', '--out', out]);
  const p = path.join(out, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

// ═════════════════════════════════════════════════════════════════════════
section('1. obfuscator.io sample: hints match decoder evidence');
{
  const r = scanSample('06_obfuscator_io_style.js');
  assert('06 sample: report produced', !!r && !r._parseError, r && r._parseError);
  assert('06 sample: decoder ran (decodeStats.obfuscatorIo >= 12)',
    r && r.decodeStats && r.decodeStats.obfuscatorIo >= 12,
    `obfuscatorIo=${r && r.decodeStats && r.decodeStats.obfuscatorIo}`);
  const fp = r && r.obfuscatorFingerprint;
  assert('06 sample: fingerprint present', !!fp);
  assert('06 sample: expectStringArrayIndirection === true when decoder ran',
    fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection === true,
    `hint=${fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection}`);
  assert('06 sample: recommendedDecoderPasses includes string-array-rotation',
    fp && fp.llmHints && Array.isArray(fp.llmHints.recommendedDecoderPasses) &&
      fp.llmHints.recommendedDecoderPasses.includes('string-array-rotation'),
    `passes=${fp && fp.llmHints && JSON.stringify(fp.llmHints.recommendedDecoderPasses)}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('2. CFF sample: control-flow-flattening hint set');
{
  const r = scanSample('10_control_flow_flattening.js');
  assert('10 sample: report produced', !!r && !r._parseError, r && r._parseError);
  const fp = r && r.obfuscatorFingerprint;
  assert('10 sample: fingerprint present', !!fp);
  assert('10 sample: expectControlFlowFlattening === true when CFF deflattener ran',
    fp && fp.llmHints && fp.llmHints.expectControlFlowFlattening === true,
    `hint=${fp && fp.llmHints && fp.llmHints.expectControlFlowFlattening}`);
  assert('10 sample: recommendedDecoderPasses includes control-flow-flattening',
    fp && fp.llmHints && Array.isArray(fp.llmHints.recommendedDecoderPasses) &&
      fp.llmHints.recommendedDecoderPasses.includes('control-flow-flattening'),
    `passes=${fp && fp.llmHints && JSON.stringify(fp.llmHints.recommendedDecoderPasses)}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('3. Clean sample: hints stay false (no unconditional flag-setting)');
{
  const r = scanTmpFixture('var x = 1; function add(a,b){ return a+b; }');
  assert('clean fixture: report produced', !!r && !r._parseError, r && r._parseError);
  const fp = r && r.obfuscatorFingerprint;
  assert('clean fixture: fingerprint present', !!fp);
  assert('clean fixture: expectStringArrayIndirection stays false',
    fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection === false,
    `hint=${fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection}`);
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

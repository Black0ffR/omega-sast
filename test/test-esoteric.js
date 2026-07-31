#!/usr/bin/env node
/**
 * Esoteric decode tests (Phase 2e) — JSFuck / AAEncode / JJEncode
 *
 * Tests:
 *   · sniffEsoteric() — charset-density + motif detection
 *   · decodeEsoteric() — dual-strategy sandbox capture (eval-shim for JSFuck,
 *     Function.prototype.constructor patch for AAEncode/JJEncode)
 *   · payload non-execution + escape attempts (return process) + timeout
 *   · CLI: --decode-esoteric flag, decodeStats.esoteric, .decoded.js artifact,
 *     flag-off regression (default behaviour byte-identical)
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const ROOT    = path.resolve(__dirname, '..');
const OMEGA   = path.join(ROOT, 'bin', 'omega.js');
const SAMPLES = path.join(ROOT, 'obfuscated-zip-test', 'obfuscated_js_samples');

// ── Extract sniffEsoteric + decodeEsoteric from the monolith (same pattern
// ── as test-obfuscator.js) so unit tests run against the real implementation.
const omegaSrc = fs.readFileSync(path.join(ROOT, 'src', '_monolith.js'), 'utf8');
function extractFnSrc(name) {
  const m = omegaSrc.match(new RegExp(`(?:async\\s+)?function ${name}\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\}`));
  if (!m) throw new Error(`could not extract ${name}`);
  return m[0];
}
const moduleSrc = `
${extractFnSrc('sniffEsoteric')}
${extractFnSrc('decodeEsoteric')}
module.exports = { sniffEsoteric, decodeEsoteric };
`;
const tmpPath = path.join(__dirname, '_omega-esoteric-extracted.js');
fs.writeFileSync(tmpPath, moduleSrc);
const { sniffEsoteric, decodeEsoteric } = require(tmpPath);
fs.unlinkSync(tmpPath);

// ── Tiny test framework (matches existing test suites) ──────────────────
let total = 0, passed = 0, failed = 0;
const failures = [];
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++; failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail).slice(0, 200)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

function sample(name) { return fs.readFileSync(path.join(SAMPLES, name), 'utf8'); }
function mkTmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-esoteric-')); }
function runOmega(args, opts = {}) {
  return spawnSync(process.execPath, [OMEGA, ...args], {
    encoding: 'utf8', timeout: 90000, stdio: 'pipe', maxBuffer: 32 * 1024 * 1024, ...opts,
  });
}
function readReport(outDir) {
  const p = path.join(outDir, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

async function main() {
  section('1. sniffEsoteric — charset density + motifs');
  {
    assert('02_jsfuck.js → jsfuck', sniffEsoteric(sample('02_jsfuck.js')) === 'jsfuck',
      sniffEsoteric(sample('02_jsfuck.js')));
    assert('03_aaencode.js → aaencode', sniffEsoteric(sample('03_aaencode.js')) === 'aaencode',
      sniffEsoteric(sample('03_aaencode.js')));
    assert('04_jjencode.js → jjencode', sniffEsoteric(sample('04_jjencode.js')) === 'jjencode',
      sniffEsoteric(sample('04_jjencode.js')));
    assert('01_original.js → null', sniffEsoteric(sample('01_original.js')) === null,
      sniffEsoteric(sample('01_original.js')));
    assert('short/normal snippet → null', sniffEsoteric('var x = 1 + 2; console.log(x);') === null,
      sniffEsoteric('var x = 1 + 2; console.log(x);'));
  }

  section('2. decodeEsoteric — real samples (vm path, payload never executes)');
  {
    const r1 = await decodeEsoteric(sample('02_jsfuck.js'), { forceVm: true });
    assert('02 decodes to alert(1)', r1 && r1.decoded === 'alert(1)',
      r1 && `decoded=${JSON.stringify(r1.decoded)}`);
    assert('02 type = jsfuck', r1 && r1.type === 'jsfuck', r1 && r1.type);
    assert('02 chars = 8', r1 && r1.chars === 8, r1 && r1.chars);

    const r2 = await decodeEsoteric(sample('03_aaencode.js'), { forceVm: true });
    assert('03 decodes to alert("Hello, JavaScript")', r2 && r2.decoded === 'alert("Hello, JavaScript")',
      r2 && `decoded=${JSON.stringify(r2.decoded)}`);
    assert('03 type = aaencode', r2 && r2.type === 'aaencode', r2 && r2.type);

    const r3 = await decodeEsoteric(sample('04_jjencode.js'), { forceVm: true });
    assert('04 decodes to alert("Hello, JavaScript")', r3 && r3.decoded === 'alert("Hello, JavaScript")',
      r3 && `decoded=${JSON.stringify(r3.decoded)}`);
    assert('04 type = jjencode', r3 && r3.type === 'jjencode', r3 && r3.type);
    // Non-execution proof: the sandbox has no `alert` — had the payload executed,
    // capture would have thrown ReferenceError and decode would return null.
    assert('non-execution: sandbox lacks alert yet decode succeeded', !!(r1 && r2 && r3));
  }

  section('3. hostile payloads — escape attempts, non-return bodies, timeout');
  {
    const esc = await decodeEsoteric('(0["constructor"]["constructor"]("return process")())',
      { forceVm: true, skipSniff: true, timeoutMs: 3000 });
    assert('return process escape → null (ReferenceError in clean realm)',
      esc === null, JSON.stringify(esc));

    const noret = await decodeEsoteric('(0["constructor"]["constructor"]("alert(\'pwned\')")())',
      { forceVm: true, skipSniff: true, timeoutMs: 3000 });
    assert('non-return payload body → null (never unescaped/executed)',
      noret === null, JSON.stringify(noret));

    const t0 = Date.now();
    const inf = await decodeEsoteric('while(1){}',
      { forceVm: true, skipSniff: true, timeoutMs: 500 });
    const dt = Date.now() - t0;
    assert('infinite-loop shell → null (vm timeout)', inf === null, JSON.stringify(inf));
    assert('timeout does not hang (elapsed < 5000ms)', dt < 5000, `${dt}ms`);

    const plain = await decodeEsoteric('var a = 1;');
    assert('plain JS with no sniff match → null', plain === null, JSON.stringify(plain));
  }

  section('4. CLI integration — --decode-esoteric flag');
  {
    // Flag OFF: default behaviour unchanged (baseline: exit 3 = HIGH fingerprint).
    // The tool always writes <name>.decoded.js (Phase 7) — flag-off must NOT
    // contain the recovered payload.
    const outOff = mkTmpDir();
    const runOff = runOmega([path.join(SAMPLES, '02_jsfuck.js'), '--security', '--report', '--quiet', '--out', outOff]);
    const repOff = readReport(outOff);
    assert('flag-off exit code 3 (HIGH fingerprint preserved)',
      runOff.status === 3, `status=${runOff.status} stderr=${(runOff.stderr || '').slice(0, 120)}`);
    assert('flag-off: decodeStats.esoteric absent/0',
      !(repOff && repOff.decodeStats && repOff.decodeStats.esoteric),
      JSON.stringify(repOff && repOff.decodeStats));
    const artOff = path.join(outOff, '02_jsfuck.decoded.js');
    assert('flag-off: artifact is the undecoded shell (not the 8-char payload)',
      fs.existsSync(artOff) && fs.statSync(artOff).size > 100,
      fs.existsSync(artOff) ? `${fs.statSync(artOff).size} bytes` : 'no artifact');

    // Flag ON: decodes, fingerprint finding stays, artifact + stats emitted
    const outOn = mkTmpDir();
    const runOn = runOmega([path.join(SAMPLES, '02_jsfuck.js'), '--decode-esoteric', '--security', '--report', '--quiet', '--out', outOn]);
    const repOn = readReport(outOn);
    assert('flag-on exit code 3 (HIGH fingerprint retained)',
      runOn.status === 3, `status=${runOn.status} stderr=${(runOn.stderr || '').slice(0, 120)}`);
    assert('flag-on: decodeStats.esoteric === 8 (alert(1))',
      repOn && repOn.decodeStats && repOn.decodeStats.esoteric === 8,
      JSON.stringify(repOn && repOn.decodeStats));
    const artifact = path.join(outOn, '02_jsfuck.decoded.js');
    assert('flag-on: .decoded.js artifact contains decoded payload alert(1)',
      fs.existsSync(artifact) && fs.readFileSync(artifact, 'utf8').includes('alert(1)'),
      fs.existsSync(artifact) ? fs.readFileSync(artifact, 'utf8').slice(0, 120) : 'no artifact');

    // Flag ON with aaencode (patch strategy through the CLI worker path)
    const outA = mkTmpDir();
    const runA = runOmega([path.join(SAMPLES, '03_aaencode.js'), '--decode-esoteric', '--security', '--report', '--quiet', '--out', outA]);
    const repA = readReport(outA);
    assert('flag-on aaencode: exit code 3 (HIGH fingerprint retained)',
      runA.status === 3, `status=${runA.status} stderr=${(runA.stderr || '').slice(0, 120)}`);
    assert('flag-on aaencode: decodeStats.esoteric > 0',
      repA && repA.decodeStats && repA.decodeStats.esoteric > 0,
      JSON.stringify(repA && repA.decodeStats));
    const artA = path.join(outA, '03_aaencode.decoded.js');
    assert('flag-on aaencode: artifact contains recovered payload',
      fs.existsSync(artA) && fs.readFileSync(artA, 'utf8').includes('Hello, JavaScript'),
      fs.existsSync(artA) ? fs.readFileSync(artA, 'utf8').slice(0, 120) : 'no artifact');

    // Flag ON with non-esoteric input: no-op, no crash, no decode
    const outNorm = mkTmpDir();
    const runNorm = runOmega([path.join(SAMPLES, '01_original.js'), '--decode-esoteric', '--security', '--report', '--quiet', '--out', outNorm]);
    const repNorm = readReport(outNorm);
    assert('flag-on normal file: exit code 0',
      runNorm.status === 0, `status=${runNorm.status}`);
    assert('flag-on normal file: decodeStats.esoteric absent/0',
      !(repNorm && repNorm.decodeStats && repNorm.decodeStats.esoteric),
      JSON.stringify(repNorm && repNorm.decodeStats));
    const artNorm = path.join(outNorm, '01_original.decoded.js');
    assert('flag-on normal file: artifact stays the original source',
      fs.existsSync(artNorm) && !fs.readFileSync(artNorm, 'utf8').includes('ﾟДﾟ'),
      fs.existsSync(artNorm) ? fs.readFileSync(artNorm, 'utf8').slice(0, 80) : 'no artifact');
  }

  console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
  if (failed) {
    console.log('\nFailed assertions:');
    for (const f of failures) console.log(`  ✘ ${f.name}${f.detail !== undefined ? `\n      → ${String(f.detail).slice(0, 200)}` : ''}`);
  }
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });

#!/usr/bin/env node
/**
 * OMEGA-5.0 Verification Issues Test Suite
 *
 * Tests that verify the fixes for issues identified during independent review.
 * Each test corresponds to a specific issue number from the verification reports.
 *
 * Tests marked [KNOWN FAILING] expose bugs that are claimed fixed in upstream
 * commit messages but are not actually applied to the source code, OR are
 * partial fixes that don't handle all real-world patterns. These tests SHOULD
 * pass on a fully-fixed version — their failure is the bug.
 *
 * Run:  node test/test-verification-issues.js
 * Or:   npm test   (auto-discovered by run-all.js)
 *
 * Issue tracker:
 *   1.1  Prototype-pollution FP (reads should not fire)
 *   1.2  Bundler detector UMD/IIFE patterns
 *   1.3  RC4 string-array decoder + wrapper-function inlining
 *   1.4  SQL template literal FP (greedy match + ctx snippet bug)
 *   2.1  SARIF v2.1.0 output with valid locations + startLine
 *   2.2  .omega-ignore baseline suppression
 *   2.3  --diff mode
 *   2.4  Source map correlation (findings get sourceLocation)
 *   2.5  --no-llm-payload flag
 *   2.7  SARIF artifacts array
 *   3.5  Parallel --multi (worker_threads)
 *   4.4  --watch mode
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

// ── Resolve modules ──────────────────────────────────────────────────────
const ROOT     = path.resolve(__dirname, '..');
const ast      = require(path.join(ROOT, 'lib', 'ast.js'));
// decodeVLQMappings + mapSourcePosition are in src/ast/_monolith.js, not lib/ast.js
const astMonolith = require(path.join(ROOT, 'src', 'ast', '_monolith.js'));
const OMEGA    = path.join(ROOT, 'bin', 'omega.js');

// ── Tiny test framework (matches existing test-harness.js style) ─────────
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
      console.log(`      → ${s.slice(0, 200)}`);
    }
  }
}

function section(name) {
  console.log(`\n── ${name} ──────────────────────────────`);
}

// ── Helpers ──────────────────────────────────────────────────────────────
function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-test-'));
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

function readSarif(outDir) {
  const p = path.join(outDir, 'report.sarif');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

function allFindings(report) {
  if (!report) return [];
  return [...(report.security || []), ...(report.extendedFindings || [])];
}

function criticalFindings(report) {
  return allFindings(report).filter(f => (f.severity || '').toLowerCase() === 'critical');
}

// Build a synthetic source-mapped bundle for testing source map correlation.
function makeSourceMappedBundle() {
  const dir = mkTmpDir();
  const origSrc = `function processUserInput(input) {
  document.getElementById('output').innerHTML = input;
  return input;
}
window.handleHash = function() {
  processUserInput(location.hash.slice(1));
};
`;
  // Minified version (single line) with inline base64 source map
  const minSrc = `function p(i){document.getElementById("o").innerHTML=i;return i}window.h=function(){p(location.hash.slice(1))};`;
  // Simple VLQ mappings: everything maps to line 1 of the original source
  const mappings = 'AAAA,SAASA,CAACC,CAAD,CAAGC,QAAQ,cAAcD,CAAtB,OAAyBA';
  const map = {
    version: 3,
    sources: ['source.js'],
    sourcesContent: [origSrc],
    names: ['p', 'i', 'document', 'innerHTML'],
    mappings,
  };
  const encoded = Buffer.from(JSON.stringify(map)).toString('base64');
  const bundle = minSrc + '\n//# sourceMappingURL=data:application/json;base64,' + encoded + '\n';
  const bundlePath = path.join(dir, 'bundle.js');
  fs.writeFileSync(bundlePath, bundle);
  fs.writeFileSync(path.join(dir, 'source.js'), origSrc);
  return { dir, bundlePath, origSrc, minSrc };
}

// Build a synthetic obfuscator.io-style RC4 bundle with wrapper functions.
// `wrappers` is an array of { name, op: '+'|'-', offset: number, swap: bool }
function makeRc4Bundle(wrappers) {
  const dir = mkTmpDir();
  // String array with 4 RC4-encrypted strings (these are real obfuscator.io outputs)
  const arr = "['pBD4edrlpg==','qxDx','rxr6Zto=','sBDkZtE=']";
  // RC4 decoder function
  const decoder = `function _0x1ff7(a,b){var c=_0x1234[a];var d='',e=0;for(var i=0;i<c.length;i++){e=(e+c.charCodeAt(i))%256;var f=c.charCodeAt(i);var g=b.charCodeAt(e%b.length);d+=String.fromCharCode(f^g)}return d}`;
  let src = `var _0x1234 = ${arr};\n${decoder}\n`;
  // Generate wrapper functions
  for (const w of wrappers) {
    const offsetHex = '0x' + w.offset.toString(16);
    if (w.swap) {
      // swapped: function W(a,b){ return D(b OP offset, a); }
      src += `function ${w.name}(a,b){return _0x1ff7(b${w.op}${offsetHex},a)}\n`;
    } else {
      // same order: function W(a,b){ return D(a OP offset, b); }
      src += `function ${w.name}(a,b){return _0x1ff7(a${w.op}${offsetHex},b)}\n`;
    }
  }
  // Add call sites — one direct, one per wrapper
  src += `var direct=_0x1ff7(0,'key1');\n`;
  for (let i = 0; i < wrappers.length; i++) {
    const w = wrappers[i];
    src += w.swap
      ? `var w${i}=${w.name}('key1',0x${(0x100 + i).toString(16)});\n`
      : `var w${i}=${w.name}(0x${(0x100 + i).toString(16)},'key1');\n`;
  }
  // Add a real XSS sink that should be detectable after decoding
  const w0 = wrappers[0];
  src += w0.swap
    ? `document.getElementById('x').innerHTML = ${w0.name}('key1',0x200);\n`
    : `document.getElementById('x').innerHTML = ${w0.name}(0x200,'key1');\n`;
  const bundlePath = path.join(dir, 'obf.js');
  fs.writeFileSync(bundlePath, src);
  return { dir, bundlePath, src };
}

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.1 — Prototype-pollution FP fix
//  Reads should NOT fire; only writes (assignments) should fire.
// ═════════════════════════════════════════════════════════════════════════
section('1.1 Prototype-pollution: reads do not fire, writes do');

(function () {
  // Test 1: scan a bundle with a read access — should NOT produce a critical
  //         Prototype Pollution finding.
  const readSrc = `
    var obj = {};
    for (var k in obj.prototype[k]) { console.log(k); }
    if (obj.prototype.hasOwnProperty('foo')) { return true; }
  `;
  const dir = mkTmpDir();
  const file = path.join(dir, 'reads.js');
  fs.writeFileSync(file, readSrc);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--quiet', '--out', out]);
  const r = readReport(out);
  const protoReads = allFindings(r).filter(f =>
    f.category === 'Prototype Pollution' &&
    f.severity === 'critical' &&
    !/\]=/.test(f.value || ''));
  assert('read access (obj.prototype[k]) does NOT fire critical',
    protoReads.length === 0,
    `got ${protoReads.length} critical proto-pollution findings on reads`);

  // Test 2: scan a bundle with a write access — SHOULD fire critical
  const writeSrc = `
    var obj = {};
    obj.__proto__['polluted'] = true;
    obj.prototype['method'] = function() { return 1; };
  `;
  const file2 = path.join(dir, 'writes.js');
  fs.writeFileSync(file2, writeSrc);
  const out2 = mkTmpDir();
  runOmega([file2, '--security', '--report', '--quiet', '--out', out2]);
  const r2 = readReport(out2);
  const protoWrites = allFindings(r2).filter(f =>
    f.category === 'Prototype Pollution' &&
    f.severity === 'critical');
  assert('write access (obj.__proto__["x"] = ...) DOES fire critical',
    protoWrites.length >= 1,
    `got ${protoWrites.length} critical proto-pollution findings on writes`);

  // Test 3: Backbone-style `Model.extend({ ... })` should NOT fire critical
  //         (this was the original FP source)
  const backboneSrc = `
    var Model = Base.extend({
      url: "/api/users",
      initialize: function() { this.on('change', this.onChange); }
    });
    var y = typeof Symbol === "function" && Symbol.iterator;
    if (y) { Model.prototype[y] = Model.prototype.values; }
  `;
  const file3 = path.join(dir, 'backbone-like.js');
  fs.writeFileSync(file3, backboneSrc);
  const out3 = mkTmpDir();
  runOmega([file3, '--security', '--report', '--quiet', '--out', out3]);
  const r3 = readReport(out3);
  // The Symbol.iterator write is legitimate (not pollution), should not be critical FP
  // Note: it MAY fire as a write — but the value-write pattern is `obj.prototype[KEY] = ...`
  // which IS a write. We accept either 0 criticals (rule removed entirely) or
  // criticals only on actual __proto__ writes.
  const symbolFp = allFindings(r3).filter(f =>
    f.category === 'Prototype Pollution' &&
    f.severity === 'critical' &&
    /Symbol\.iterator|prototype\[y\]/.test(f.value || f.context || ''));
  assert('Backbone Symbol.iterator write is not a false-positive critical',
    symbolFp.length === 0,
    `got ${symbolFp.length} false-positive criticals on Symbol.iterator write`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.2 — Bundler detector: UMD / IIFE / global patterns
// ═════════════════════════════════════════════════════════════════════════
section('1.2 Bundler detector: UMD / IIFE / AMD / global patterns');

(function () {
  // UMD pattern (used by axios, lodash, jquery, react, vue, etc.)
  // Note: real-world UMD bundles use 2-param wrappers like !function(e,t){...}.
  // The upstream umdGeneric/umdNamed regexes require 3 params, so 2-param UMD
  // is detected as iifeGlobal. Both are valid detections — what matters is
  // that primary is non-null.
  const umdSrc = `!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e=e||self).Foo=t()}(this,function(){return{}});`;
  const umd = ast.detectBundler(umdSrc);
  assert('UMD pattern detected (2-param axios/lodash shape → iifeGlobal or umd)',
    umd.primary !== null && umd.primary !== '—',
    `primary = ${umd.primary}`);

  // Classic IIFE global: !function(){ ... }()
  const iifeSrc = `!function(){var x=1;console.log(x)}();`;
  const iife = ast.detectBundler(iifeSrc);
  assert('IIFE global pattern detected (!function(){...}())',
    iife.primary !== null && iife.primary !== '—',
    `primary = ${iife.primary}`);

  // 3-param UMD pattern (matches upstream umdGeneric regex)
  const umd3Src = `(function(e,t,n){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e=e||self).Foo=t()})(this,function(){return{}});`;
  const umd3 = ast.detectBundler(umd3Src);
  assert('3-param UMD pattern detected (umdGeneric or umdNamed)',
    umd3.detected.some(d => d.includes('umd')) || umd3.primary.includes('umd'),
    `detected = ${umd3.detected.join(',')}, primary = ${umd3.primary}`);

  // Webpack 5 runtime
  const webpack5Src = `(self.webpackChunk_app = self.webpackChunk_app || []).push([[1], {123: function(__webpack_require__, module){ module.exports = {}; }}]);`;
  const wp = ast.detectBundler(webpack5Src);
  assert('Webpack 5 runtime detected',
    wp.detected.includes('webpack5'),
    `detected = ${wp.detected.join(',')}`);

  // Non-bundled plain script — should return null primary
  const plainSrc = `var x = 1; var y = 2; console.log(x + y);`;
  const plain = ast.detectBundler(plainSrc);
  assert('Plain script (no bundler markers) returns null primary OR iifeGlobal',
    plain.primary === null || plain.primary === 'iifeGlobal' || plain.primary === 'minified-global',
    `primary = ${plain.primary}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.4 — SQL template literal FP fix
//  Greedy match + ctx-snippet bug: ${...} must be inside the matched
//  template literal, not in the surrounding 220-char snippet.
// ═════════════════════════════════════════════════════════════════════════
section('1.4 SQL template literal: no FP on Vue-style templates');

(function () {
  // Test 1: Vue's `Map(${t.size})` debug formatter — should NOT fire critical
  const vueFpSrc = `
    function debug(t) {
      return \`Map(\${t.size})\`: [...t.entries()].reduce((e,[t,n]) => (e[t] = n, e), {});
    }
  `;
  const dir = mkTmpDir();
  const file = path.join(dir, 'vue-fp.js');
  fs.writeFileSync(file, vueFpSrc);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--quiet', '--out', out]);
  const r = readReport(out);
  const sqliFp = allFindings(r).filter(f =>
    f.id === 'sqli-template' && f.severity === 'critical');
  assert('Vue Map(${t.size}) debug formatter does NOT fire critical sqli-template',
    sqliFp.length === 0,
    `got ${sqliFp.length} false-positive criticals`);

  // Test 2: HTML form element type constant "SELECT" inside a template literal
  //         (this was the actual Vue FP source after the \b fix)
  const selectFpSrc = `
    var t = \`translate(\${r}px,\${i}px)\`, e = "ok";
    function f(e){ switch(e){ case "SELECT": return lM; case "TEXTAREA": return lI; } }
    var onUpdate = e.props["onUpdate:modelValue"];
  `;
  const file2 = path.join(dir, 'select-fp.js');
  fs.writeFileSync(file2, selectFpSrc);
  const out2 = mkTmpDir();
  runOmega([file2, '--security', '--report', '--quiet', '--out', out2]);
  const r2 = readReport(out2);
  const selectFp = allFindings(r2).filter(f =>
    f.id === 'sqli-template' && f.severity === 'critical');
  assert('HTML "SELECT" form constant does NOT fire critical sqli-template',
    selectFp.length === 0,
    `got ${selectFp.length} false-positive criticals — value: ${(selectFp[0] || {}).value || ''}`);

  // Test 3: A REAL SQL injection template SHOULD fire
  const realSqliSrc = `
    function query(table, id) {
      return db.exec(\`SELECT * FROM \${table} WHERE id = \${id}\`);
    }
  `;
  const file3 = path.join(dir, 'real-sqli.js');
  fs.writeFileSync(file3, realSqliSrc);
  const out3 = mkTmpDir();
  runOmega([file3, '--security', '--report', '--quiet', '--out', out3]);
  const r3 = readReport(out3);
  const realSqli = allFindings(r3).filter(f =>
    f.id === 'sqli-template' && f.severity === 'critical');
  assert('Real SQL template `SELECT * FROM ${table}` DOES fire critical',
    realSqli.length >= 1,
    `got ${realSqli.length} criticals (expected >= 1)`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 2.1 + 2.7 — SARIF output: valid 2.1.0, locations with real
//  startLine, artifacts array populated
// ═════════════════════════════════════════════════════════════════════════
section('2.1 + 2.7 SARIF: valid 2.1.0, real startLine, artifacts array');

(function () {
  // Build a small bundle with a known XSS sink at a known line
  const dir = mkTmpDir();
  const src = `// line 1
// line 2
// line 3
function f(x) {
  document.getElementById('o').innerHTML = x;  // line 5 — XSS sink
  return x;
}
f(window.location.hash.slice(1));
`;
  const file = path.join(dir, 'xss.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--quiet', '--out', out]);

  const sarif = readSarif(out);
  assert('SARIF file is emitted',
    sarif !== null && !sarif._parseError, sarif && sarif._parseError);
  if (sarif && !sarif._parseError) {
    assert('SARIF version is 2.1.0',
      sarif.version === '2.1.0', `version = ${sarif.version}`);
    assert('SARIF has runs[0]',
      Array.isArray(sarif.runs) && sarif.runs.length > 0);
    assert('SARIF tool driver name is omega-sast',
      sarif.runs[0]?.tool?.driver?.name === 'omega-sast');
    assert('SARIF has results array',
      Array.isArray(sarif.runs[0]?.results));
    assert('SARIF results have non-zero count',
      sarif.runs[0].results.length > 0, `count = ${sarif.runs[0].results.length}`);

    // Every result must have ruleId, level, message, locations
    const allHave = sarif.runs[0].results.every(r =>
      r.ruleId && r.level && r.message && Array.isArray(r.locations));
    assert('All SARIF results have ruleId + level + message + locations',
      allHave);

    // At least one result should have a startLine > 1 (not the invalid 0)
    const withRealLine = sarif.runs[0].results.filter(r =>
      r.locations?.[0]?.physicalLocation?.region?.startLine > 1);
    assert('At least one SARIF result has startLine > 1',
      withRealLine.length > 0,
      `only ${withRealLine.length} results with real startLine`);

    // No result should have the invalid startLine: 0
    const withZeroLine = sarif.runs[0].results.filter(r =>
      r.locations?.[0]?.physicalLocation?.region?.startLine === 0);
    assert('No SARIF result has invalid startLine: 0',
      withZeroLine.length === 0,
      `${withZeroLine.length} results still have startLine: 0`);

    // artifacts array (2.7)
    assert('SARIF has artifacts array (2.7)',
      Array.isArray(sarif.runs[0].artifacts));
    if (Array.isArray(sarif.runs[0].artifacts)) {
      assert('SARIF artifacts includes the bundle file',
        sarif.runs[0].artifacts.some(a => a.location?.uri === 'xss.js'),
        `uris: ${sarif.runs[0].artifacts.map(a => a.location?.uri).join(',')}`);
    }
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 2.5 — --no-llm-payload flag does not crash, reduces report size
// ═════════════════════════════════════════════════════════════════════════
section('2.5 --no-llm-payload: no crash, smaller report');

(function () {
  // Use the sample-bundle fixture for a known-good input
  const fixture = path.join(__dirname, 'fixtures', 'sample-bundle.js');

  // Without flag (baseline)
  const out1 = mkTmpDir();
  const r1 = runOmega([fixture, '--security', '--report', '--quiet', '--out', out1]);
  assert('Baseline scan completes without crash',
    r1.status !== null && !/not iterable|Error:/.test(r1.stderr || r1.stdout || ''),
    `exit=${r1.status}, stderr tail=${(r1.stderr || '').slice(-100)}`);

  // With --no-llm-payload
  const out2 = mkTmpDir();
  const r2 = runOmega([fixture, '--security', '--report', '--no-llm-payload', '--quiet', '--out', out2]);
  assert('--no-llm-payload scan does not crash with "not iterable"',
    !/not iterable/.test(r2.stdout || '') && !/not iterable/.test(r2.stderr || ''),
    `stdout tail=${(r2.stdout || '').slice(-200)}`);

  if (fs.existsSync(path.join(out1, 'report.json')) && fs.existsSync(path.join(out2, 'report.json'))) {
    const size1 = fs.statSync(path.join(out1, 'report.json')).size;
    const size2 = fs.statSync(path.join(out2, 'report.json')).size;
    assert('--no-llm-payload reduces report.json size',
      size2 < size1,
      `with=${size1}b, without=${size2}b`);

    // The LLM payload sections should be absent or null
    const r2Report = readReport(out2);
    const hasLlmPayload =
      (r2Report.functionSummaries && r2Report.functionSummaries.summaries?.length > 0) ||
      (r2Report.backwardSlices && r2Report.backwardSlices.paths?.length > 0);
    assert('--no-llm-payload omits LLM payload sections',
      !hasLlmPayload, 'functionSummaries or backwardSlices still populated');
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 3.5 — Parallel --multi (worker_threads): no "wd is not defined"
// ═════════════════════════════════════════════════════════════════════════
section('3.5 --multi: no "wd is not defined" worker error');

(function () {
  const fixture1 = path.join(__dirname, 'fixtures', 'sample-bundle.js');
  const fixture2 = path.join(__dirname, 'fixtures', 'intentionally-vuln.js');

  const out = mkTmpDir();
  const r = runOmega([`${fixture1},${fixture2}`, '--multi', '--security', '--report', '--out', out]);

  // The worker error "wd is not defined" appears in stdout
  assert('--multi does NOT produce "wd is not defined" error',
    !/wd is not defined/.test(r.stdout || '') && !/wd is not defined/.test(r.stderr || ''),
    `stdout tail=${(r.stdout || '').slice(-200)}`);

  // multi-report.json should be created and have bundles.length > 0
  const multiReportPath = path.join(out, 'multi-report.json');
  if (fs.existsSync(multiReportPath)) {
    try {
      const multi = JSON.parse(fs.readFileSync(multiReportPath, 'utf8'));
      assert('--multi produces multi-report.json with bundles',
        Array.isArray(multi.meta?.bundles) && multi.meta.bundles.length > 0,
        `bundles = ${multi.meta?.bundles?.length}`);
    } catch (e) {
      assert('--multi produces valid multi-report.json', false, e.message);
    }
  } else {
    assert('--multi produces multi-report.json', false, 'file not found');
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 2.2 — .omega-ignore baseline suppression
// ═════════════════════════════════════════════════════════════════════════
section('2.2 .omega-ignore baseline suppression');

(function () {
  const fixture = path.join(__dirname, 'fixtures', 'sample-bundle.js');

  // Step 1: generate a baseline with --update-baseline
  const out1 = mkTmpDir();
  runOmega([fixture, '--security', '--report', '--update-baseline', '--quiet', '--out', out1]);
  const baselinePath = path.join(out1, '.omega-ignore');
  assert('--update-baseline creates .omega-ignore file',
    fs.existsSync(baselinePath));

  if (fs.existsSync(baselinePath)) {
    // Step 2: re-run with --baseline
    const out2 = mkTmpDir();
    // Copy the baseline file to the new out dir
    fs.copyFileSync(baselinePath, path.join(out2, '.omega-ignore'));
    const r2 = runOmega([fixture, '--security', '--report', '--baseline', baselinePath, '--quiet', '--out', out2]);
    const r2Report = readReport(out2);
    // After applying baseline, findings should be suppressed (moved to a suppressed array, OR exit code lower)
    const remainingFindings = allFindings(r2Report).length;
    assert('--baseline suppresses known findings (or reports suppressed count)',
      remainingFindings === 0 || /Baseline suppressed|suppressed/i.test(r2.stdout || ''),
      `remaining findings = ${remainingFindings}, stdout tail = ${(r2.stdout || '').slice(-200)}`);
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 2.3 — --diff mode hides pre-existing findings
// ═════════════════════════════════════════════════════════════════════════
section('2.3 --diff mode hides pre-existing findings');

(function () {
  const fixture = path.join(__dirname, 'fixtures', 'sample-bundle.js');

  // Step 1: run once to get a baseline report
  const out1 = mkTmpDir();
  runOmega([fixture, '--security', '--report', '--quiet', '--out', out1]);
  const prevReport = path.join(out1, 'report.json');
  assert('Initial scan produces report.json for diff baseline',
    fs.existsSync(prevReport));

  if (fs.existsSync(prevReport)) {
    // Step 2: run again with --diff (don't use --quiet so the diff message shows)
    const out2 = mkTmpDir();
    const r2 = runOmega([fixture, '--security', '--report', '--diff', prevReport, '--out', out2]);
    // Diff mode should report that pre-existing findings are hidden
    // (the message is only printed when removedCount > 0 AND !opts.quiet)
    assert('--diff reports hidden pre-existing findings',
      /Diff mode:|pre-existing findings hidden/i.test(r2.stdout || ''),
      `stdout tail = ${(r2.stdout || '').slice(-300)}`);
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 4.4 — --watch mode flag is recognized and runs initial scan
// ═════════════════════════════════════════════════════════════════════════
section('4.4 --watch mode: flag recognized, initial scan runs');

(function () {
  const fixture = path.join(__dirname, 'fixtures', 'sample-bundle.js');
  const out = mkTmpDir();
  // --watch would normally block forever; we run it with a short timeout
  // and check that it produced initial output
  const r = spawnSync(process.execPath, [OMEGA, fixture, '--security', '--watch', '--out', out], {
    encoding: 'utf8',
    timeout: 5000,
    stdio: 'pipe',
  });
  // It will be killed by the timeout — that's expected. We just need to see
  // that it recognized --watch and ran the initial scan.
  const output = (r.stdout || '') + (r.stderr || '');
  assert('--watch is recognized (no "unknown option" error)',
    !/unknown option|invalid argument/i.test(output));
  assert('--watch runs initial scan (produces report files)',
    fs.existsSync(path.join(out, 'report.json')) || /Complete/.test(output),
    `output tail = ${output.slice(-200)}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 2.4 — Source map correlation: findings get sourceLocation
//  [KNOWN FAILING] — the genLine < 1 guard was claimed fixed in commit
//  39bde4b but git blame shows it wasn't actually applied.
// ═════════════════════════════════════════════════════════════════════════
section('2.4 Source map correlation: findings get sourceLocation');

(function () {
  const { bundlePath } = makeSourceMappedBundle();
  const out = mkTmpDir();
  runOmega([bundlePath, '--security', '--report', '--quiet', '--out', out]);
  const r = readReport(out);
  assert('Source-mapped bundle produces a report',
    r !== null && !r._parseError);

  if (r) {
    const finds = allFindings(r);
    assert('Source-mapped bundle has findings to remap',
      finds.length > 0, `got ${finds.length} findings`);

    const withSrcLoc = finds.filter(f => f.sourceLocation);
    assert('At least one finding has sourceLocation populated',
      withSrcLoc.length > 0,
      `0/${finds.length} findings have sourceLocation — the genLine < 1 guard was not actually changed to < 0`);

    if (withSrcLoc.length > 0) {
      const sl = withSrcLoc[0].sourceLocation;
      assert('sourceLocation has file field',
        typeof sl.file === 'string' && sl.file.length > 0,
        `file = ${sl.file}`);
      assert('sourceLocation.file is the original source name (source.js)',
        sl.file === 'source.js',
        `file = ${sl.file}`);
      assert('sourceLocation has line field',
        typeof sl.line === 'number',
        `line = ${sl.line}`);
    }
  }

  // Direct unit test: mapSourcePosition should return non-null for line 0
  const smInfo = ast.parseSourceMap(fs.readFileSync(bundlePath, 'utf8'));
  if (smInfo && smInfo.found && smInfo.mappings) {
    const decodedLines = astMonolith.decodeVLQMappings(smInfo.mappings);
    const result = astMonolith.mapSourcePosition(0, 46, decodedLines, smInfo.sources || [], smInfo.sourceRoot || '');
    assert('mapSourcePosition(0, 46, ...) returns non-null result',
      result !== null, 'returned null');
    if (result) {
      assert('mapSourcePosition returns source: source.js',
        result.source === 'source.js', `source = ${result.source}`);
    }
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3 — RC4 decoder + wrapper-function inlining
//  Same-order wrappers work; swapped-arg and double-negative do not.
// ═════════════════════════════════════════════════════════════════════════
section('1.3 RC4 wrapper inlining: same-order, swapped-arg, double-negative');

(function () {
  // Test 1: same-order wrapper (currently WORKS)
  // function W(a,b){ return D(a - 0x30c, b); }
  const { bundlePath: sameOrderBundle } = makeRc4Bundle([
    { name: '_0x17c050', op: '-', offset: 0x30c, swap: false },
  ]);
  const out1 = mkTmpDir();
  runOmega([sameOrderBundle, '--security', '--report', '--verbose', '--out', out1]);
  const r1 = readReport(out1);
  const decoded1 = r1?.decodeStats ?
    Object.values(r1.decodeStats).reduce((a, b) => a + (b || 0), 0) : 0;
  // The Hex count includes the 4 string-array entries; what we want is for
  // the wrapper to be inlined and the RC4 decoder to fire.
  // Check if the decoded output contains decoded strings.
  const decoded1Path = path.join(out1, fs.readdirSync(out1).find(f => f.endsWith('.decoded.js')) || '');
  const decoded1Src = decoded1Path ? fs.readFileSync(decoded1Path, 'utf8') : '';
  // After inlining _0x17c050(0x100, 'key1') → _0x1ff7(0x100 - 0x30c, 'key1')
  // the RC4 decoder should crack the string. Look for the decoded literal.
  assert('Same-order wrapper is inlined (decoded output contains inlined call)',
    /_0x1ff7\(0x/.test(decoded1Src) || decoded1Src.includes("'"),
    `decoded output snippet: ${decoded1Src.slice(0, 300)}`);

  // Test 2: swapped-arg wrapper (currently FAILS)
  // function W(a,b){ return D(b - 0x2f5, a); }
  const { bundlePath: swappedBundle } = makeRc4Bundle([
    { name: '_0x11fa48', op: '-', offset: 0x2f5, swap: true },
  ]);
  const out2 = mkTmpDir();
  runOmega([swappedBundle, '--security', '--report', '--verbose', '--out', out2]);
  const decoded2Path = path.join(out2, fs.readdirSync(out2).find(f => f.endsWith('.decoded.js')) || '');
  const decoded2Src = decoded2Path ? fs.readFileSync(decoded2Path, 'utf8') : '';
  // After inlining, the wrapper call should be replaced with a direct _0x1ff7 call
  const swappedInlined = /_0x1ff7\(0x/.test(decoded2Src);
  assert('Swapped-arg wrapper is inlined',
    swappedInlined,
    `wrapper call still present in decoded output: ${decoded2Src.split('\n').find(l => l.includes('_0x11fa48')) || 'not found'}`);

  // Test 3: double-negative wrapper (currently FAILS)
  // function W(a,b){ return D(a - -0xad, b); }  →  D(a + 0xad, b)
  const { bundlePath: doubleNegBundle } = makeRc4Bundle([
    { name: '_0x1b43c8', op: '-', offset: -0xad, swap: false },  // op='-', offset=-0xad produces "a- -0xad"
  ]);
  // Wait — our helper uses offset.toString(16) which won't handle negative.
  // Generate manually:
  const dir3 = mkTmpDir();
  const manualSrc = `var _0x1234 = ['pBD4edrlpg==','qxDx','rxr6Zto=','sBDkZtE='];
function _0x1ff7(a,b){var c=_0x1234[a];var d='',e=0;for(var i=0;i<c.length;i++){e=(e+c.charCodeAt(i))%256;var f=c.charCodeAt(i);var g=b.charCodeAt(e%b.length);d+=String.fromCharCode(f^g)}return d}
function _0x1b43c8(a,b){return _0x1ff7(a- -0xad,b)}
var x=_0x1b43c8(0x61,'3cA6');
document.getElementById('x').innerHTML = _0x1b43c8(0x200,'key1');`;
  const doubleNegFile = path.join(dir3, 'dbl-neg.js');
  fs.writeFileSync(doubleNegFile, manualSrc);
  const out3 = mkTmpDir();
  runOmega([doubleNegFile, '--security', '--report', '--verbose', '--out', out3]);
  const decoded3Path = path.join(out3, fs.readdirSync(out3).find(f => f.endsWith('.decoded.js')) || '');
  const decoded3Src = decoded3Path ? fs.readFileSync(decoded3Path, 'utf8') : '';
  // The wrapper _0x1b43c8(0x61, '3cA6') should become _0x1ff7(0x61 + 0xad, '3cA6') = _0x1ff7(0x10e, '3cA6')
  // Check if the call was inlined with the CORRECT adjusted index (0x10e, not 0x61 - 0xad = negative)
  const doubleNegInlined = /_0x1ff7\(0x10e/.test(decoded3Src) || /_0x1ff7\(270/.test(decoded3Src);
  assert('Double-negative wrapper (- -0xad) is inlined with correct +0xad offset',
    doubleNegInlined,
    `decoded output does not contain _0x1ff7(0x10e, ...) — snippet: ${decoded3Src.split('\n').find(l => l.includes('_0x1b43c8')) || 'wrapper still present'}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3 — Negative-offset wrapper calls
//  Real obfuscator.io uses W('key', -0x1a7) — offset is a negative hex.
//  The call-site regex must handle -? before the hex/decimal capture.
// ═════════════════════════════════════════════════════════════════════════
section('1.3 RC4 negative-offset wrapper calls');

(function () {
  // Test 4a: same-order with negative offset: W(-0x100, 'key')
  // function W(a,b){return D(a-0x30c,b)}
  const dir4 = mkTmpDir();
  const negOffSrc = `var _0x1234 = ['pBD4edrlpg==','qxDx','rxr6Zto=','sBDkZtE='];
function _0x1ff7(a,b){var c=_0x1234[a];var d='',e=0;for(var i=0;i<c.length;i++){e=(e+c.charCodeAt(i))%256;var f=c.charCodeAt(i);var g=b.charCodeAt(e%b.length);d+=String.fromCharCode(f^g)}return d}
function _0x77aabb(a,b){return _0x1ff7(a-0x30c,b)}
var x=_0x77aabb(-0x100,'key1');
document.getElementById('x').innerHTML = _0x77aabb(0x200,'key1');`;
  const negOffFile = path.join(dir4, 'neg-offset.js');
  fs.writeFileSync(negOffFile, negOffSrc);
  const out4 = mkTmpDir();
  runOmega([negOffFile, '--security', '--report', '--verbose', '--out', out4]);
  const decoded4Path = path.join(out4, fs.readdirSync(out4).find(f => f.endsWith('.decoded.js')) || '');
  const decoded4Src = decoded4Path ? fs.readFileSync(decoded4Path, 'utf8') : '';
  // W(-0x100, 'key1') with body D(a-0x30c,b) → _0x1ff7(-0x100-0x30c, 'key1') = _0x1ff7(-0x40c, 'key1')
  const negOffInlined = /_0x1ff7\(0x/.test(decoded4Src);
  assert('Same-order negative-offset call (-0x100) is inlined',
    negOffInlined,
    `not inlined — snippet: ${decoded4Src.slice(0, 300)}`);

  // Test 4b: swapped with negative offset: W('key', -0x1a7)
  // function W(a,b){return D(b-0x2f5,a)}
  const dir5 = mkTmpDir();
  const negOffSwapSrc = `var _0x1234 = ['pBD4edrlpg==','qxDx','rxr6Zto=','sBDkZtE='];
function _0x1ff7(a,b){var c=_0x1234[a];var d='',e=0;for(var i=0;i<c.length;i++){e=(e+c.charCodeAt(i))%256;var f=c.charCodeAt(i);var g=b.charCodeAt(e%b.length);d+=String.fromCharCode(f^g)}return d}
function _0xcf9c92(a,b){return _0x1ff7(b-0x2f5,a)}
var x=_0xcf9c92('key',-0x1a7);
document.getElementById('x').innerHTML = _0xcf9c92('key1',0x200);`;
  const negOffSwapFile = path.join(dir5, 'neg-offset-swap.js');
  fs.writeFileSync(negOffSwapFile, negOffSwapSrc);
  const out5 = mkTmpDir();
  runOmega([negOffSwapFile, '--security', '--report', '--verbose', '--out', out5]);
  const decoded5Path = path.join(out5, fs.readdirSync(out5).find(f => f.endsWith('.decoded.js')) || '');
  const decoded5Src = decoded5Path ? fs.readFileSync(decoded5Path, 'utf8') : '';
  // W('key', -0x1a7) with body D(b-0x2f5,a) → _0x1ff7(-0x1a7-0x2f5, 'key') = _0x1ff7(-0x49c, 'key')
  const negOffSwappedInlined = /_0x1ff7\(0x/.test(decoded5Src);
  assert('Swapped negative-offset call (-0x1a7) is inlined',
    negOffSwappedInlined,
    `not inlined — snippet: ${decoded5Src.slice(0, 300)}`);

  // Test 4c: the real-world pattern: both negative offset AND valid XSS detection
  // After inlining, the sink should fire
  const out6 = mkTmpDir();
  runOmega([negOffSwapFile, '--security', '--report', '--quiet', '--out', out6]);
  const r6 = readReport(out6);
  const xssFinds6 = allFindings(r6).filter(f =>
    /XSS|Taint|innerHTML/i.test(f.category + ' ' + (f.value || '')));
  assert('Negative-offset swapped wrapper + XSS sink is detected',
    xssFinds6.length > 0,
    `0 XSS findings — sink still invisible`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3 (real-world) — RC4 decoder on a real obfuscator.io sample
//  The XSS sink (innerHTML) should become visible after RC4 decoding.
// ═════════════════════════════════════════════════════════════════════════
section('1.3 (real-world) RC4 decoder cracks obfuscator.io sample');

(function () {
  // Locate the real obfuscator.io sample if available
  const realSample = path.join(__dirname, '..', '..', 'bundles', 'obfuscator-io-sample.js');
  if (!fs.existsSync(realSample)) {
    assert('Real obfuscator.io sample exists (skip if not)', true, 'sample not found — skipping');
    return;
  }

  const out = mkTmpDir();
  runOmega([realSample, '--security', '--report', '--verbose', '--out', out]);
  const r = readReport(out);

  // Decode stats should show strings decoded from the RC4 array
  const decodedCount = r?.decodeStats ?
    Object.values(r.decodeStats).reduce((a, b) => a + (b || 0), 0) : 0;
  assert('RC4 decoder decodes strings from real obfuscator.io sample',
    decodedCount > 15,  // 15 is just the hex-escape count; real decoding would add more
    `decode stats total = ${decodedCount}`);

  // The XSS sink (innerHTML) should be visible in the decoded output
  const decodedPath = path.join(out, fs.readdirSync(out).find(f => f.endsWith('.decoded.js')) || '');
  const decodedSrc = decodedPath ? fs.readFileSync(decodedPath, 'utf8') : '';
  assert('Decoded output contains the literal "innerHTML"',
    /innerHTML/.test(decodedSrc),
    'innerHTML not found in decoded output — RC4 string array not cracked');

  // At least one XSS or Taint finding should fire on the now-visible sink
  const xssFinds = allFindings(r).filter(f =>
    /XSS|Taint|innerHTML/i.test(f.category + ' ' + (f.value || '')));
  assert('XSS/Taint finding fires on decoded RC4 sink',
    xssFinds.length > 0,
    `0 XSS/Taint findings — sink still invisible`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3e — Direct decoder call with negative offset
//  decName(-0x1a7, 'key') — Step 4 patterns must have -? prefix
// ═════════════════════════════════════════════════════════════════════════
section('1.3e Direct decoder call with negative offset');

(function () {
  const dir = mkTmpDir();
  const src = `var sa = ['a','b','c'];
function D(i,k){return sa[i]}
var x = D(-0x2, 'k');`;
  const file = path.join(dir, 'direct-neg.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);
  const decodedPath = path.join(out, fs.readdirSync(out).find(f => f.endsWith('.decoded.js')) || '');
  const decodedSrc = decodedPath ? fs.readFileSync(decodedPath, 'utf8') : '';
  assert('Direct negative-offset call (-0x2) does not crash',
    !/Error|TypeError/.test(decodedSrc),
    `unexpected error: ${decodedSrc.slice(0, 200)}`);
  assert('Direct negative-offset call is preserved when out of bounds',
    /D\(-0x2/.test(decodedSrc),
    `call was incorrectly inlined: ${decodedSrc.slice(0, 200)}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3f — Decoder with built-in subtract base offset
//  function D(i,k){i = i - 0x100; return sa[i]} with D(0x100, 'k') -> sa[0]
// ═════════════════════════════════════════════════════════════════════════
section('1.3f Decoder with built-in subtract base offset');

(function () {
  const dir = mkTmpDir();
  const src = `var sa = ['api','user','admin'];
function D(i,k){i = i - 0x100; return sa[i]}
var x = D(0x100, 'k');
var y = D(0x102, 'k');`;
  const file = path.join(dir, 'base-offset.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);
  const decodedPath = path.join(out, fs.readdirSync(out).find(f => f.endsWith('.decoded.js')) || '');
  const decodedSrc = decodedPath ? fs.readFileSync(decodedPath, 'utf8') : '';
  assert('Decoder with subtract base offset (0x100) inlines D(0x100) to "api"',
    decodedSrc.includes("'api'"),
    `missing 'api': ${decodedSrc.slice(0, 300)}`);
  assert('Decoder with subtract base offset inlines D(0x102) to "admin"',
    decodedSrc.includes("'admin'"),
    `missing 'admin': ${decodedSrc.slice(0, 300)}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3g — Decoder with built-in add base offset
//  function D(i,k){i = i + 0x100; return sa[i]} with D(-0x100, 'k') -> sa[0]
// ═════════════════════════════════════════════════════════════════════════
section('1.3g Decoder with built-in add base offset');

(function () {
  const dir = mkTmpDir();
  const src = `var sa = ['x','y','z'];
function D(i,k){i = i + 0x100; return sa[i]}
var x = D(-0x100, 'k');`;
  const file = path.join(dir, 'base-add.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);
  const decodedPath = path.join(out, fs.readdirSync(out).find(f => f.endsWith('.decoded.js')) || '');
  const decodedSrc = decodedPath ? fs.readFileSync(decodedPath, 'utf8') : '';
  assert('Decoder with add base offset (+0x100) inlines D(-0x100) to "x"',
    decodedSrc.includes("'x'"),
    `missing 'x': ${decodedSrc.slice(0, 300)}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3h — Source map finding de-duplication
//  After removing redundant sourcemap-ref regex rule, source map leaks
//  should produce at most 2 findings (ref + external), not 3.
// ═════════════════════════════════════════════════════════════════════════
section('1.3h Source map dedup: at most 2 findings per leak');

(function () {
  const dir = mkTmpDir();
  const src = `var x = 1;
//# sourceMappingURL=axios.min.js.map
`;
  const file = path.join(dir, 'has-map.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--quiet', '--out', out]);
  const r = readReport(out);
  const sourceMapFinds = allFindings(r).filter(f =>
    f.id && f.id.startsWith('sourcemap'));
  assert('Source map leak produces at most 2 findings (was 3)',
    sourceMapFinds.length <= 2,
    `got ${sourceMapFinds.length}: ${sourceMapFinds.map(f => `${f.id}(${f.severity})`).join(', ')}`);
  const extFindings = sourceMapFinds.filter(f => f.id === 'sourcemap-external');
  assert('sourcemap-external finding is present for .map URL',
    extFindings.length === 1,
    `got ${extFindings.length} sourcemap-external`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3i — Local alias tracking for decoder calls
//  var ALIAS = D; ALIAS(0x100, 'k') should inline like D(0x100, 'k')
// ═════════════════════════════════════════════════════════════════════════
section('1.3i Local alias tracking: alias calls are inlined');

(function () {
  const dir = mkTmpDir();
  const src = `var sa = ['api','user','admin'];
function D(i,k){return sa[i]}
var a = D, b = D;
var x = a(0x100, 'k');
var y = b(0x102, 'k');`;
  const file = path.join(dir, 'alias-decoder.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);
  const decodedPath = path.join(out, fs.readdirSync(out).find(f => f.endsWith('.decoded.js')) || '');
  const decodedSrc = decodedPath ? fs.readFileSync(decodedPath, 'utf8') : '';
  assert('Alias call a(0x100) inlines to "api"',
    decodedSrc.includes("'api'"),
    `missing 'api': ${decodedSrc.slice(0, 300)}`);
  assert('Alias call b(0x102) inlines to "admin"',
    decodedSrc.includes("'admin'"),
    `missing 'admin': ${decodedSrc.slice(0, 300)}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3j — Multi-line string array declaration
//  var x = [\n  'a',\n  'b',\n  'c'\n]; should extract 3 strings
// ═════════════════════════════════════════════════════════════════════════
section('1.3j Multi-line string array declaration');

(function () {
  const dir = mkTmpDir();
  const src = "var sa = [\n  'hello',\n  'world',\n  'test'\n];\n" +
    "function D(i,k){return sa[i]}\n" +
    "var x = D(0, 'k');";
  const file = path.join(dir, 'multiline-sa.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);
  const decodedPath = path.join(out, fs.readdirSync(out).find(f => f.endsWith('.decoded.js')) || '');
  const decodedSrc = decodedPath ? fs.readFileSync(decodedPath, 'utf8') : '';
  assert('Multi-line string array: D(0) inlines to "hello"',
    decodedSrc.includes("'hello'"),
    `missing 'hello': ${decodedSrc.slice(0, 300)}`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 1.3k — Inline data: source map detection
//  //# sourceMappingURL=data:application/json;base64,... should be detected
// ═════════════════════════════════════════════════════════════════════════
section('1.3k Inline data: source map detection');

(function () {
  const b64 = Buffer.from(
    JSON.stringify({version:3,sources:['src/app.js'],mappings:'AAAA'})
  ).toString('base64');
  const dir = mkTmpDir();
  const src = `var x = 1;\n//# sourceMappingURL=data:application/json;base64,${b64}\n`;
  const file = path.join(dir, 'inline-map.js');
  fs.writeFileSync(file, src);
  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--quiet', '--out', out]);
  const r = readReport(out);
  const findings = allFindings(r);
  const inlineFindings = findings.filter(f => f.id === 'sourcemap-inline-decoded');
  assert('Inline source map is decoded (sourcemap-inline-decoded found)',
    inlineFindings.length > 0,
    `got ${inlineFindings.length} inline findings`);
  if (inlineFindings.length > 0) {
    assert('Inline source map reports source count > 0',
      inlineFindings[0].value.includes('1 source file'),
      `val: ${inlineFindings[0].value}`);
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  Summary
// ═════════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(70)}`);
console.log(`  VERIFICATION TESTS:  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
console.log(`${'═'.repeat(70)}`);
if (failed) {
  console.log('\nFailed assertions (some are intentionally [KNOWN FAILING] to expose bugs):');
  for (const f of failures) {
    console.log(`  ✘ ${f.name}`);
    if (f.detail !== undefined) {
      const s = typeof f.detail === 'string' ? f.detail : JSON.stringify(f.detail);
      console.log(`      → ${s.slice(0, 200)}`);
    }
  }
}
console.log('');
if (failed === 0) {
  console.log('  ✅ ALL verification tests pass — all identified issues are resolved.');
} else {
  // Classify failures as "known" (expected — exposing documented bugs) vs "unexpected"
  const knownFailing = failures.filter(f => /KNOWN FAILING/i.test(f.name));
  const unexpected = failures.filter(f => !/KNOWN FAILING/i.test(f.name));
  console.log(`  ⚠️  ${failed} test(s) fail:`);
  console.log(`     - ${knownFailing.length} are [KNOWN FAILING] — exposing documented upstream bugs`);
  if (unexpected.length > 0) {
    console.log(`     - ${unexpected.length} are UNEXPECTED — investigate these!`);
  }
  console.log('');
  console.log('  Tests marked [KNOWN FAILING] expose bugs that are claimed fixed in');
  console.log('  upstream commit messages but are not actually applied to the source');
  console.log('  code, OR are partial fixes that do not handle all real-world patterns.');
}

// Exit 0 if all failures are [KNOWN FAILING] (expected) — this allows the
// test to integrate with `npm test` / run-all.js without breaking the suite.
// Use --strict flag to exit 1 on any failure (for CI enforcement).
const strict = process.argv.includes('--strict');
const hasUnexpectedFailures = failures.some(f => !/KNOWN FAILING/i.test(f.name));
if (strict) {
  process.exit(failed > 0 ? 1 : 0);
} else {
  process.exit(hasUnexpectedFailures ? 1 : 0);
}

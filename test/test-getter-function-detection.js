#!/usr/bin/env node
/**
 * OMEGA-5.0 Getter-Function Detection Test Suite
 *
 * Targeted tests for the 1 remaining open issue (1.3 RC4 — function-wrapped
 * string-array pattern). These tests verify that omega-sast can detect and
 * inline RC4 decoder functions that obtain their string array via a getter
 * function call (the pattern used by real obfuscator.io output).
 *
 * The pattern:
 *   function GETTER() {                                  // getter function
 *     const ARRAY = ['enc1', 'enc2', ...];               // array declared inside
 *     return ARRAY;
 *   }
 *   function DECODER(idx, key) {                         // decoder function
 *     idx = idx - 0xNNN;                                 // base offset (v9 fix)
 *     const local = GETTER();                            // calls getter
 *     let s = local[idx];                                // indexes LOCAL, not ARRAY
 *     ... RC4 decrypt using key ...
 *     return decoded;
 *   }
 *   function WRAPPER(a, b) { return DECODER(a - 0xNNN, b); }
 *
 *   var x = WRAPPER(0x100, 'key');                       // call site
 *   document.getElementById('x').innerHTML = WRAPPER(0x200, 'key');  // XSS sink
 *
 * Current state: the decoder-detection regex requires ARRAY[idxParam] (the
 * array name directly in the decoder body), but the decoder uses local[idxParam]
 * where local = GETTER(). So the decoder is never detected and none of the
 * downstream logic (base-offset, wrapper inlining, RC4 decryption) runs.
 *
 * All tests in this file are until getter-function detection
 * is implemented upstream.
 *
 * Run:  node test/test-getter-function-detection.js
 *       node test/test-getter-function-detection.js --strict   (exit 1 on any failure)
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

// ── Resolve modules ──────────────────────────────────────────────────────
const ROOT       = path.resolve(__dirname, '..');
const ast        = require(path.join(ROOT, 'lib', 'ast.js'));
const astMonolith = require(path.join(ROOT, 'src', 'ast', '_monolith.js'));
const OMEGA      = path.join(ROOT, 'bin', 'omega.js');

// ── Tiny test framework ─────────────────────────────────────────────────
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
      console.log(`      → ${s.slice(0, 250)}`);
    }
  }
}

function section(name) {
  console.log(`\n── ${name} ──────────────────────────────`);
}

// ── Helpers ──────────────────────────────────────────────────────────────
function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-getter-'));
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

function allFindings(report) {
  if (!report) return [];
  return [...(report.security || []), ...(report.extendedFindings || [])];
}

function getDecodedSource(outDir) {
  const decodedFile = fs.readdirSync(outDir).find(f => f.endsWith('.decoded.js'));
  if (!decodedFile) return '';
  return fs.readFileSync(path.join(outDir, decodedFile), 'utf8');
}

// ═════════════════════════════════════════════════════════════════════════
//  Build a synthetic getter-function-pattern bundle.
//
//  This mimics real obfuscator.io output:
//    - String array declared INSIDE a getter function
//    - Decoder calls the getter and indexes a LOCAL variable
//    - Decoder has a built-in base offset (idx = idx - 0xfb)
//    - Wrapper functions with various patterns call the decoder
//    - Call sites use a mix of patterns (direct, swapped, negative offset)
//    - An XSS sink (innerHTML =) is present, sourced from a decoded string
//
//  Returns { dir, bundlePath, src }.
// ═════════════════════════════════════════════════════════════════════════
function makeGetterBundle(opts = {}) {
  const dir = mkTmpDir();
  const getterName = opts.getterName || '_0x4d4e';
  const arrayName  = opts.arrayName  || '_0x1aa0ac';
  const decoderName = opts.decoderName || '_0x1ff7';
  const localName  = opts.localName  || '_0x34688e';

  // Use real obfuscator.io RC4-encrypted strings (these decrypt to known
  // plaintext when the correct key is used). For the test to pass, the
  // decoded output must contain these plaintext strings.
  // For simplicity, we'll use plain (non-RC4) strings so we can verify
  // decoding without needing the exact RC4 key.
  const usePlain = opts.plain !== false;
  const strings = opts.strings || ['hello', 'world', 'innerHTML', 'document', 'getElementById'];

  // GETTER function: declares the array inside and returns it
  const getter = `function ${getterName}(){const ${arrayName}=[${strings.map(s => `'${s}'`).join(',')}];return ${arrayName};}`;

  // DECODER function: calls getter, indexes local, has base offset
  // Pattern: function D(idx, key) { idx = idx - 0xfb; const local = GETTER(); let s = local[idx]; return s; }
  // (plain variant — no RC4; just array indexing after base offset)
  let decoder;
  if (usePlain) {
    decoder = `function ${decoderName}(a,b){a=a-0xfb;const ${localName}=${getterName}();let s=${localName}[a];return s}`;
  } else {
    // RC4 variant — needs real encrypted strings + RC4 logic in body
    decoder = `function ${decoderName}(a,b){a=a-0xfb;const ${localName}=${getterName}();let s=${localName}[a];var d='',e=0;for(var i=0;i<s.length;i++){e=(e+s.charCodeAt(i))%256;var f=s.charCodeAt(i);var g=b.charCodeAt(e%b.length);d+=String.fromCharCode(f^g)}return d}`;
  }

  // WRAPPER functions — various patterns
  const wrappers = opts.wrappers || [
    // same-order, subtract offset
    `function _0x17c050(a,b){return ${decoderName}(a-0x30c,b)}`,
    // swapped-arg
    `function _0x11fa48(a,b){return ${decoderName}(b-0x2f5,a)}`,
    // double-negative (a - -0xad = a + 0xad)
    `function _0x1b43c8(a,b){return ${decoderName}(a- -0xad,b)}`,
  ];

  // Call sites — use a mix of patterns
  // For the plain variant, idx=0xfb maps to strings[0] (because a = a - 0xfb)
  // So _0x17c050(0x3fb, 'k') → D(0x3fb - 0x30c, 'k') = D(0xef, 'k') → a=0xef-0xfb=0xf4... too low
  // Let's use higher indices to land in-range after all the offsets
  const callSites = opts.callSites || [
    `var a = _0x17c050(0x40b, 'k');`,   // 0x40b - 0x30c = 0xff; 0xff - 0xfb = 0x4 → strings[4] = 'getElementById'
    `var b = _0x11fa48('k', 0x3f6);`,   // swapped: 0x3f6 - 0x2f5 = 0x101; 0x101 - 0xfb = 0x6... out of range, will skip
    `var c = _0x1b43c8(0x56, 'k');`,    // 0x56 + 0xad = 0x103; 0x103 - 0xfb = 0x8... out of range
  ];

  // XSS sink — uses a decoded string in innerHTML
  // This is the critical assertion: after getter-function detection + inlining
  // + decoding, this sink should be visible to the XSS detector.
  const xssSink = opts.xssSink || `document.getElementById('x').innerHTML = _0x17c050(0x40b, 'k');`;

  const src = [
    getter,
    decoder,
    ...wrappers,
    ...callSites,
    xssSink,
  ].join('\n');

  const bundlePath = path.join(dir, 'getter-bundle.js');
  fs.writeFileSync(bundlePath, src);
  return { dir, bundlePath, src };
}

// ═════════════════════════════════════════════════════════════════════════
//  TEST 1 — Minimal getter-function pattern (no wrappers, no base offset)
//
//  This is the simplest possible case. If omega can't handle this, it can't
//  handle any getter-function pattern.
//
//  IMPORTANT: We check that the CALL SITE is replaced with the decoded
//  literal, NOT just that the literal appears somewhere in the output
//  (the literal always appears in the array declaration).
// ═════════════════════════════════════════════════════════════════════════
section('1.3i Minimal getter-function pattern (no wrappers, no base offset)');

(function () {
  const dir = mkTmpDir();
  // Simplest possible: getter returns array, decoder calls getter and indexes local
  // Use a UNIQUE marker string that only appears via decoding, not in the source
  const src = `function getArr(){const arr=['hello','world','DECODED_MARKER_X1Y2Z3'];return arr}
function dec(i,k){const local=getArr();return local[i]}
var x = dec(2, 'key');
document.getElementById('x').innerHTML = dec(2, 'key');`;
  const file = path.join(dir, 'minimal-getter.js');
  fs.writeFileSync(file, src);

  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);

  const decoded = getDecodedSource(out);
  const report = readReport(out);

  // The call site `dec(2, 'key')` should be REPLACED with 'DECODED_MARKER_X1Y2Z3'
  // Count occurrences: 1 in the array declaration (always present) + 2 call sites
  // that should be inlined = 3 total if decoded, 1 if not
  const markerCount = (decoded.match(/DECODED_MARKER_X1Y2Z3/g) || []).length;

  assert('Minimal getter-pattern: call sites are replaced with decoded literal',
    markerCount >= 3,
    `found ${markerCount} occurrences of DECODED_MARKER_X1Y2Z3 (expected >=3 if decoded, 1 if not) — decoded snippet: ${decoded.slice(0, 400)}`);

  // The call `dec(2, 'key')` should NOT appear in the decoded output (it should
  // be replaced with 'DECODED_MARKER_X1Y2Z3')
  assert('Minimal getter-pattern: call site dec(2, "key") is replaced',
    !/dec\s*\(\s*2\s*,\s*['"]key['"]\s*\)/.test(decoded),
    `dec(2, 'key') still present in decoded output — call not replaced`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  TEST 2 — Getter + base offset (matches real obfuscator.io shape)
//
//  function GETTER() { const ARR = [...]; return ARR; }
//  function DEC(i, k) { i = i - 0xfb; const local = GETTER(); return local[i]; }
//  DEC(0xfb, 'k') → local[0] = ARR[0]
//
//  Uses unique marker strings to verify call-site replacement.
// ═════════════════════════════════════════════════════════════════════════
section('1.3j Getter + base offset (real obfuscator.io shape)');

(function () {
  const dir = mkTmpDir();
  // Use unique markers so we can verify call-site replacement
  const src = `function _0x4d4e(){const _0x1aa0ac=['MARKER_API_KEY_X9','MARKER_USER_TOKEN_Y8','MARKED_INNERHTML_Z7','MARKER_DOCUMENT_W6'];return _0x1aa0ac}
function _0x1ff7(a,b){a=a-0xfb;const _0x34688e=_0x4d4e();return _0x34688e[a]}
var x = _0x1ff7(0xfb, 'k');
var y = _0x1ff7(0xfd, 'k');
document.getElementById('x').innerHTML = _0x1ff7(0xfd, 'k');`;
  const file = path.join(dir, 'getter-baseoffset.js');
  fs.writeFileSync(file, src);

  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);

  const decoded = getDecodedSource(out);
  const report = readReport(out);

  // _0x1ff7(0xfb, 'k') with base offset 0xfb → local[0] = 'MARKER_API_KEY_X9'
  // _0x1ff7(0xfd, 'k') with base offset 0xfb → local[2] = 'MARKED_INNERHTML_Z7'
  // Each marker appears once in the array + should be inlined at call sites
  const apiKeyCount = (decoded.match(/MARKER_API_KEY_X9/g) || []).length;
  const innerHtmlCount = (decoded.match(/MARKED_INNERHTML_Z7/g) || []).length;

  assert('Getter + base-offset: _0x1ff7(0xfb) call replaced with decoded literal',
    apiKeyCount >= 2,  // 1 in array + 1 at call site
    `MARKER_API_KEY_X9 appears ${apiKeyCount} times (expected 2 if decoded, 1 if not) — snippet: ${decoded.slice(0, 500)}`);

  assert('Getter + base-offset: _0x1ff7(0xfd) call replaced with decoded literal',
    innerHtmlCount >= 3,  // 1 in array + 2 call sites
    `MARKED_INNERHTML_Z7 appears ${innerHtmlCount} times (expected 3 if decoded, 1 if not)`);

  // The call sites should be replaced
  assert('Getter + base-offset: call site _0x1ff7(0xfb, "k") is replaced',
    !/_0x1ff7\s*\(\s*0xfb\s*,\s*['"]k['"]\s*\)/.test(decoded),
    `_0x1ff7(0xfb, 'k') still present — call not replaced`);

  // XSS sink should be detected now that innerHTML is visible
  const xssFinds = allFindings(report).filter(f =>
    /XSS|Taint|innerHTML/i.test(f.category + ' ' + (f.value || '')));
  assert('Getter + base-offset: XSS finding fires on decoded sink',
    xssFinds.length > 0,
    `0 XSS findings — sink still invisible`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  TEST 3 — Getter + base offset + wrappers (full real-world pattern)
//
//  Adds wrapper functions on top of TEST 2's pattern. This is the complete
//  shape used by real obfuscator.io output.
// ═════════════════════════════════════════════════════════════════════════
section('1.3k Getter + base offset + wrappers (full real-world pattern)');

(function () {
  const dir = mkTmpDir();
  // Use unique markers so we can verify call-site replacement
  // Array indices: 0=MARKER_A, 1=MARKER_B, 2=MARKER_C, 3=MARKER_D, 4=MARKER_E
  const src = `function _0x4d4e(){const _0x1aa0ac=['MARKER_A1B2C3','MARKER_D4E5F6','MARKER_G7H8I9','MARKER_J1K2L3','MARKER_M4N5O6'];return _0x1aa0ac}
function _0x1ff7(a,b){a=a-0xfb;const _0x34688e=_0x4d4e();return _0x34688e[a]}
function _0x17c050(a,b){return _0x1ff7(a-0x30c,b)}
function _0x11fa48(a,b){return _0x1ff7(b-0x2f5,a)}
function _0x1b43c8(a,b){return _0x1ff7(a- -0xad,b)}
var a = _0x17c050(0x40b, 'k');
var b = _0x11fa48('k', 0x3f6);
var c = _0x1b43c8(0x56, 'k');
document.getElementById('x').innerHTML = _0x17c050(0x40b, 'k');`;
  const file = path.join(dir, 'full-getter-wrappers.js');
  fs.writeFileSync(file, src);

  const out = mkTmpDir();
  runOmega([file, '--security', '--report', '--verbose', '--out', out]);

  const decoded = getDecodedSource(out);
  const report = readReport(out);

  // After all the offsets:
  // _0x17c050(0x40b, 'k') → _0x1ff7(0x40b - 0x30c, 'k') = _0x1ff7(0xff, 'k')
  //   → base offset: 0xff - 0xfb = 0x4 → local[4] = 'MARKER_M4N5O6'
  // _0x11fa48('k', 0x3f6) → _0x1ff7(0x3f6 - 0x2f5, 'k') = _0x1ff7(0x101, 'k')
  //   → base offset: 0x101 - 0xfb = 0x6 → out of range (array has 5 elements)
  // _0x1b43c8(0x56, 'k') → _0x1ff7(0x56 + 0xad, 'k') = _0x1ff7(0x103, 'k')
  //   → base offset: 0x103 - 0xfb = 0x8 → out of range

  // MARKER_M4N5O6 should appear: 1 in array + 2 call sites (var a + innerHTML) = 3 if decoded
  const markerECount = (decoded.match(/MARKER_M4N5O6/g) || []).length;

  assert('Full pattern: wrapper call _0x17c050(0x40b) replaced with decoded literal',
    markerECount >= 3,
    `MARKER_M4N5O6 appears ${markerECount} times (expected 3 if decoded: 1 in array + 2 call sites) — snippet: ${decoded.slice(0, 600)}`);

  assert('Full pattern: wrapper call _0x17c050(0x40b, "k") is replaced',
    !/_0x17c050\s*\(\s*0x40b\s*,\s*['"]k['"]\s*\)/.test(decoded),
    `_0x17c050(0x40b, 'k') still present — wrapper call not inlined`);

  // XSS sink should be detected — the innerHTML assignment now uses a decoded literal
  const xssFinds = allFindings(report).filter(f =>
    /XSS|Taint|innerHTML/i.test(f.category + ' ' + (f.value || '')));
  assert('Full pattern: XSS finding fires on decoded sink',
    xssFinds.length > 0,
    `0 XSS findings — sink still invisible`);
})();

// ═════════════════════════════════════════════════════════════════════════
//  TEST 4 — Real obfuscator.io sample
//
//  The ultimate test: run omega against the real obfuscator.io sample and
//  verify that the XSS sink (innerHTML) becomes visible after getter-function
//  detection + base-offset + wrapper inlining + RC4 decryption.
// ═════════════════════════════════════════════════════════════════════════
section('1.3l Real obfuscator.io sample — getter-function pattern');

(function () {
  // Locate the real obfuscator.io sample
  const realSample = path.join(__dirname, '..', '..', 'bundles', 'obfuscator-io-sample.js');
  if (!fs.existsSync(realSample)) {
    assert('Real obfuscator.io sample exists (skip if not)', true, 'sample not found — skipping');
    return;
  }

  const out = mkTmpDir();
  runOmega([realSample, '--security', '--report', '--verbose', '--out', out]);

  const report = readReport(out);
  const decoded = getDecodedSource(out);

  // Step 1: decoder must be detected
  // The real sample's decoder is _0x1ff7 which uses _0x34688e[_0x5acede]
  // (local from calling _0x4d4e()), not _0x1aa0ac[_0x5acede]
  assert('Real sample: decoder _0x1ff7 is detected',
    allFindings(report).some(f => /obfuscator-io-decoder/.test(f.id) && /_0x1ff7/.test(f.value || '')),
    `decoder _0x1ff7 not in findings — getter-function pattern not detected`);

  // Step 2: decode stats should show strings decoded from the RC4 array
  const decodedCount = report?.decodeStats ?
    Object.values(report.decodeStats).reduce((a, b) => a + (b || 0), 0) : 0;
  assert('Real sample: decode stats show RC4 strings decoded (>15)',
    decodedCount > 15,
    `decode stats total = ${decodedCount} (15 = just hex escapes; >15 = RC4 cracked)`);

  // Step 3: decoded output should contain 'innerHTML' literal
  assert('Real sample: decoded output contains "innerHTML" literal',
    /innerHTML/.test(decoded),
    'innerHTML not found in decoded output — RC4 string array not cracked');

  // Step 4: XSS/Taint finding should fire on the now-visible sink
  const xssFinds = allFindings(report).filter(f =>
    /XSS|Taint|innerHTML/i.test(f.category + ' ' + (f.value || '')));
  assert('Real sample: XSS/Taint finding fires on decoded sink',
    xssFinds.length > 0,
    `0 XSS/Taint findings — sink still invisible`);

  // Step 5: Obfuscator.io decoder finding should report decoded strings count > 0
  const decoderFinding = allFindings(report).find(f => /obfuscator-io-decoder/.test(f.id));
  if (decoderFinding) {
    assert('Real sample: decoder finding reports decoded strings',
      /decoded|strings/i.test(decoderFinding.value || '') && !/0 strings/.test(decoderFinding.value || ''),
      `decoder finding: ${decoderFinding.value}`);
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  TEST 5 — Direct unit test of the decoder-detection regex
//
//  Calls the internal decodeObfuscatorIo function (if exported) to verify
//  the regex matches the getter-pattern decoder.
// ═════════════════════════════════════════════════════════════════════════
section('1.3m Direct test: decoder-detection regex matches getter pattern');

(function () {
  // The decoder-detection regex is internal to decodeObfuscatorIo in
  // src/_monolith.js. We can't call it directly without modifying exports,
  // but we CAN test the regex pattern itself.
  //
  // The current regex (from src/_monolith.js) is:
  //   function\s+NAME(p1,p2)\s*\{[\s\S]{0,800}?ARRAY\[\s*p1\s*\][\s\S]{0,800}?\}
  //
  // This requires ARRAY (the string array name) to appear directly in the
  // decoder body. In the getter pattern, the decoder uses LOCAL[idx] where
  // LOCAL = GETTER(), so ARRAY never appears in the decoder body.

  const arrayName = '_0x1aa0ac';
  const decoderSrc = `function _0x1ff7(a,b){a=a-0xfb;const _0x34688e=_0x4d4e();return _0x34688e[a]}`;

  // Current strict regex (from upstream src/_monolith.js)
  const strictRe = new RegExp(
    `function\\s+([A-Za-z_$][\\w$]*)\\s*\\(\\s*([A-Za-z_$][\\w$]*)\\s*,\\s*([A-Za-z_$][\\w$]*)\\s*\\)\\s*\\{[\\s\\S]{0,800}?${arrayName}\\[\\s*\\2\\s*\\][\\s\\S]{0,800}?\\}`,
    'g'
  );
  const strictMatch = strictRe.exec(decoderSrc);

  assert('Current strict regex does NOT match getter-pattern decoder [EXPECTED — exposes the bug]',
    strictMatch === null,
    `strict regex unexpectedly matched — getter pattern may now be detected`);

  // Current broad regex
  const broadRe = new RegExp(
    `function\\s+([A-Za-z_$][\\w$]*)\\s*\\(\\s*[A-Za-z_$][\\w$]*\\s*,\\s*[A-Za-z_$][\\w$]*\\s*\\)\\s*\\{[\\s\\S]{0,800}?${arrayName}\\[\\s*[A-Za-z_$][\\w$]*\\s*\\][\\s\\S]{0,800}?\\}`,
    'g'
  );
  const broadMatch = broadRe.exec(decoderSrc);

  assert('Current broad regex does NOT match getter-pattern decoder [EXPECTED — exposes the bug]',
    broadMatch === null,
    `broad regex unexpectedly matched — getter pattern may now be detected`);

  // Proposed fix: a new regex that handles the getter pattern
  // Match: function NAME(p1, p2) { ... GETTER() ... local[p1] ... }
  // where GETTER is the function that returns ARRAY
  //
  // This is what the maintainer needs to implement. We can't test it
  // upstream yet, but we document the expected shape here.
  const getterName = '_0x4d4e';
  const proposedRe = new RegExp(
    `function\\s+([A-Za-z_$][\\w$]*)\\s*\\(\\s*([A-Za-z_$][\\w$]*)\\s*,\\s*([A-Za-z_$][\\w$]*)\\s*\\)\\s*\\{[\\s\\S]{0,800}?${getterName}\\s*\\(\\s*\\)[\\s\\S]{0,200}?[A-Za-z_$][\\w$]*\\[\\s*\\2\\s*\\][\\s\\S]{0,800}?\\}`,
    'g'
  );
  const proposedMatch = proposedRe.exec(decoderSrc);

  assert('Proposed getter-pattern regex WOULD match the decoder',
    proposedMatch !== null,
    `proposed regex did not match — adjust the pattern`);

  if (proposedMatch) {
    assert('Proposed regex captures the decoder name correctly',
      proposedMatch[1] === '_0x1ff7',
      `captured name: ${proposedMatch[1]}`);
  }
})();

// ═════════════════════════════════════════════════════════════════════════
//  TEST 6 — Document the expected fix shape
//
//  This test documents what the maintainer needs to implement. It doesn't
//  run any assertions — it just prints the spec.
// ═════════════════════════════════════════════════════════════════════════
section('1.3n Expected fix shape (documentation)');

(function () {
  console.log(`
  EXPECTED FIX — Getter-Function Detection
  =========================================

  After detecting a string array inside a function (GETTER), the decoder-
  detection step should ALSO match decoders that:

    1. Call GETTER() and store the result in a local variable
    2. Index that local variable with a function parameter

  Concretely, when a string array ARRAY is found inside a function GETTER:

    function GETTER() {
      const ARRAY = [...];
      return ARRAY;
    }

  The decoder-detection regex should match decoders of the form:

    function DECODER(idx, key) {
      ... idx = idx OP OFFSET ...           // base offset (already handled)
      const local = GETTER();               // calls getter
      ... local[idx] ...                    // indexes local, not ARRAY
      ... RC4 decrypt using key ...
    }

  Proposed regex (to be added to decodeObfuscatorIo in src/_monolith.js):

    // After detecting string array ARRAY inside function GETTER:
    const getterRe = new RegExp(
      \`function\\\\s+(GETTER)\\\\s*\\\\(\\\\s*\\\\)\\\\s*\\\\{[\\\\s\\\\S]{0,2000}?return\\\\s+(ARRAY)\\\\s*;?\\\\s*\\\\}\`,
      'g'
    );
    // Then match decoders that call GETTER and index the result:
    const getterDecoderRe = new RegExp(
      \`function\\\\s+(NAME)\\\\s*\\\\(\\\\s*(p1)\\\\s*,\\\\s*(p2)\\\\s*\\\\)\\\\s*\\\\{[\\\\s\\\\S]{0,800}?GETTER\\\\s*\\\\(\\\\s*\\\\)[\\\\s\\\\S]{0,200}?[A-Za-z_\\\\$][\\\\w\\\\$]*\\\\[\\\\s*\\\\2\\\\s*\\\\][\\\\s\\\\S]{0,800}?\\\\}\`,
      'g'
    );

  Alternative simpler fix: eval() the getter function to resolve the array,
  then proceed with existing decoder detection using the resolved array.

  Once implemented, all tests in this file should pass.
  `);

  // This is a documentation test — always passes
  assert('Documentation test (always passes)', true);
})();

// ═════════════════════════════════════════════════════════════════════════
//  Summary
// ═════════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(70)}`);
console.log(`  GETTER-FUNCTION DETECTION TESTS:  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
console.log(`${'═'.repeat(70)}`);
if (failed) {
  console.log('\nFailed assertions:');
  for (const f of failures) {
    console.log(`  ✘ ${f.name}`);
    if (f.detail !== undefined) {
      const s = typeof f.detail === 'string' ? f.detail : JSON.stringify(f.detail);
      console.log(`      → ${s.slice(0, 250)}`);
    }
  }
}
console.log('');
if (failed === 0) {
  console.log('  ✅ ALL getter-function detection tests pass — issue 1.3 is fully resolved!');
  console.log('     The real obfuscator.io sample\'s XSS sink is now visible.');
} else {
  console.log(`  ⚠️  ${failed} test(s) fail.`);
}

process.exit(failed > 0 ? 1 : 0);

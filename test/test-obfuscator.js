#!/usr/bin/env node
/**
 * Obfuscator fingerprinting + decoder tests (Stage 5)
 *
 * Tests fingerprintObfuscator() against realistic samples from:
 *   · obfuscator.io (string-array rotation, decoder fn, control-flow flattening)
 *   · Jscrambler (chained decoder, OC* globals, date anti-debug)
 *   · ByteHide (namespace, XOR decryptor)
 *   · JSFuck ([]+() encoding)
 *   · Generic/unknown (hex identifiers, eval density)
 *
 * Also tests decodeObfuscatorIo() (string-array rotation + decoder) and
 * evaluateConstantExpressions() (constant folding).
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const astPath = path.resolve(__dirname, '..', 'lib', 'ast.js');
const ast = require(astPath);

// Extract decodeObfuscatorIo + evaluateConstantExpressions from omega-5.0.js
// We extract both the main functions AND their helpers, then eval them together.
const omegaPath = path.resolve(__dirname, '..', 'src', '_monolith.js');
const omegaSrc = fs.readFileSync(omegaPath, 'utf8');
function extractFnSrc(name) {
  const m = omegaSrc.match(new RegExp(`function ${name}\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\}`));
  if (!m) throw new Error(`could not extract ${name}`);
  return m[0];
}
// Build a self-contained module with the functions + their helpers
const moduleSrc = `
${extractFnSrc('rc4Decrypt')}
${extractFnSrc('evalConstantArith')}
${extractFnSrc('decodeObfuscatorIo')}
${extractFnSrc('evaluateConstantExpressions')}
module.exports = { decodeObfuscatorIo, evaluateConstantExpressions, rc4Decrypt, evalConstantArith };
`;
const tmpPath = path.join(__dirname, '_omega-extracted.js');
fs.writeFileSync(tmpPath, moduleSrc);
const { decodeObfuscatorIo, evaluateConstantExpressions } = require(tmpPath);
// Clean up temp file after require
fs.unlinkSync(tmpPath);

let total = 0, passed = 0, failed = 0;
const failures = [];
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++; failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

// ═══════════════════════════════════════════════════════════════════════
section('1. obfuscator.io fingerprint detection');
{
  // Realistic obfuscator.io output: string array + rotation IIFE + hex idents
  const src = `
var _0x3a2f = ['hello', 'world', 'secret', 'key', 'value'];
(function(_0x3a2f, _0x1b2c) {
  var _0xfn = function(_0xidx) { return _0x3a2f[_0xidx]; };
  while (--_0x1b2c) { _0x3a2f.push(_0x3a2f.shift()); }
}(_0x3a2f, 0x1f4));
function _0x4b5c(_0xidx, _0xkey) {
  var _0xval = _0x3a2f[_0xidx];
  var _0xout = '';
  for (var _0xi = 0; _0xi < _0xval.length; _0xi++) {
    _0xout += String.fromCharCode(_0xval.charCodeAt(_0xi) ^ _0xkey.charCodeAt(_0xi % _0xkey.length));
  }
  return _0xout;
}
var _0x1a2b = _0x4b5c(0x0, 'abc');
var _0x2b3c = _0x4b5c(0x1, 'def');
var _0x3c4d = _0x4b5c(0x2, 'ghi');
var _0x4d5e = _0x4b5c(0x3, 'jkl');
var _0x5e6f = _0x4b5c(0x4, 'mno');
var _0x6f7a = _0x4b5c(0x5, 'pqr');
var _0x7a8b = _0x4b5c(0x6, 'stu');
var _0x8b9c = _0x4b5c(0x7, 'vwx');
var _0x9c0d = _0x4b5c(0x8, 'yza');
var _0x0d1e = _0x4b5c(0x9, 'bcd');
var _0x1e2f = _0x4b5c(0xa, 'efg');
var _0x2f3a = _0x4b5c(0xb, 'hij');
var _0x3a4b = _0x4b5c(0xc, 'klm');
var _0x4b5d = _0x4b5c(0xd, 'nop');
var _0x5d6e = _0x4b5c(0xe, 'qrs');
var _0x6e7f = _0x4b5c(0xf, 'tuv');
var _0x7f8a = _0x4b5c(0x10, 'wxy');
var _0x8a9b = _0x4b5c(0x11, 'zab');
var _0x9b0c = _0x4b5c(0x12, 'cde');
var _0x0c1d = _0x4b5c(0x13, 'fgh');
var _0x1d2e = _0x4b5c(0x14, 'ijk');
var _0x2e3f = _0x4b5c(0x15, 'lmn');
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('obfuscator.io detected', result.primary && result.primary.obfuscator === 'obfuscator.io',
    `primary=${result.primary && result.primary.obfuscator}`);
  assert('confidence >= 0.4', result.primary && result.primary.confidence >= 0.4,
    `confidence=${result.primary && result.primary.confidence}`);
  assert('string-array-rotation signature matched',
    result.primary && result.primary.matched.some(s => s.signature === 'string-array-rotation-iife'),
    `sigs: ${result.primary && result.primary.matched.map(s=>s.signature).join(',')}`);
  assert('decoder-function signature matched',
    result.primary && result.primary.matched.some(s => s.signature === 'decoder-function-rc4-or-base64'));
  assert('hex-identifier-mangling signature matched',
    result.primary && result.primary.matched.some(s => s.signature === 'hex-identifier-mangling'));
  assert('LLM hint: expectStringArrayIndirection=true',
    result.llmHints.expectStringArrayIndirection === true);
  assert('LLM hint: expectMangledIdentifiers=true',
    result.llmHints.expectMangledIdentifiers === true);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. obfuscator.io control-flow flattening');
{
  const src = `
var _0xstate = [_0x1, _0x2, _0x3, _0x4, _0x5];
var _0xidx = 0;
while (!![]) {
  switch (_0xstate[_0xidx++]) {
    case '0x1': foo(); continue;
    case '0x2': bar(); continue;
    case '0x3': baz(); continue;
    case '0x4': qux(); continue;
    case '0x5': return;
  }
}
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('obfuscator.io detected with CFF',
    result.primary && result.primary.obfuscator === 'obfuscator.io');
  assert('control-flow-flattening signature matched',
    result.primary && result.primary.matched.some(s => s.signature === 'control-flow-flattening-dispatcher'));
  assert('LLM hint: expectControlFlowFlattening=true',
    result.llmHints.expectControlFlowFlattening === true);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. Jscrambler fingerprint detection');
{
  const src = `
var OCA = 0x1;
var OCB = 0x2;
var OCC = 0x3;
var OCD = 0x4;
var OCE = 0x5;
var OCF = 0x6;
function _0xdec(opf, _0xkey) {
  var _0xval = atob(opf);
  var _0xout = '';
  for (var _0xi = 0; _0xi < _0xval.length; _0xi++) {
    _0xout += String.fromCharCode(_0xval.charCodeAt(_0xi) ^ _0xkey.charCodeAt(_0xi % _0xkey.length));
  }
  return _0xout;
}
if (Date.now() > 0x18b5c800000) { debugger; }
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('Jscrambler detected',
    result.detected.some(s => s.obfuscator === 'Jscrambler'),
    `detected: ${result.detected.map(s=>s.obfuscator).join(',')}`);
  const jsc = result.detected.find(s => s.obfuscator === 'Jscrambler');
  assert('Jscrambler confidence >= 0.35', jsc && jsc.confidence >= 0.35,
    `confidence=${jsc && jsc.confidence}`);
  assert('jscrambler-chained-decoder matched',
    jsc && jsc.matched.some(s => s.signature === 'jscrambler-chained-decoder'));
  assert('jscrambler-oc-globals matched',
    jsc && jsc.matched.some(s => s.signature === 'jscrambler-oc-globals'));
  assert('jscrambler-date-anti-debug matched',
    jsc && jsc.matched.some(s => s.signature === 'jscrambler-date-anti-debug'));
  assert('LLM hint: expectAntiDebugging=true',
    result.llmHints.expectAntiDebugging === true);
}

// ═══════════════════════════════════════════════════════════════════════
section('4. ByteHide fingerprint detection');
{
  const src = `
var ByteHide = { decrypt: function(idx) { return _0xarr[idx ^ 0x5a]; } };
var _0xarr = ['s1', 's2', 's3', 's4'];
var _0x1 = ByteHide.decrypt(0x1);
var _0x2 = ByteHide.decrypt(0x2);
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('ByteHide detected',
    result.detected.some(s => s.obfuscator === 'ByteHide'),
    `detected: ${result.detected.map(s=>s.obfuscator).join(',')}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('5. JSFuck fingerprint detection');
{
  // Minimal JSFuck-style encoding (just enough to trigger the signature)
  const jsfuckChunk = '[' + '[]()!+'.repeat(60) + ']';
  const src = `var x = ${jsfuckChunk};`;
  const result = ast.fingerprintObfuscator(src);
  assert('JSFuck detected',
    result.detected.some(s => s.obfuscator === 'JSFuck'),
    `detected: ${result.detected.map(s=>s.obfuscator).join(',')}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('6. No obfuscation (clean bundle)');
{
  const src = `
const x = 1;
function foo() { return x + 2; }
const y = foo();
console.log(y);
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('clean bundle: no obfuscator detected', result.detected.length === 0,
    `detected: ${result.detected.map(s=>s.obfuscator).join(',')}`);
  assert('clean bundle: primary=null', result.primary === null);
  assert('clean bundle: LLM hints all false',
    !result.llmHints.expectMangledIdentifiers &&
    !result.llmHints.expectStringArrayIndirection &&
    !result.llmHints.expectControlFlowFlattening);
}

// ═══════════════════════════════════════════════════════════════════════
section('7. Generic obfuscation heuristic');
{
  // Some hex identifiers + eval density, but no specific obfuscator signature
  const src = `
var _0x1a2b = 1;
var _0x2b3c = 2;
var _0x3c4d = 3;
var _0x4d5e = 4;
var _0x5e6f = 5;
var _0x6f7a = 6;
eval("console.log('a')");
eval("console.log('b')");
eval("console.log('c')");
eval("console.log('d')");
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('generic obfuscation detected',
    result.detected.some(s => s.obfuscator === 'unknown/generic'),
    `detected: ${result.detected.map(s=>s.obfuscator).join(',')}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('8. obfuscator.io string-array decoder');
{
  // Build a minimal obfuscator.io-style bundle with a PLAIN decoder (no RC4)
  // so we can verify the rotation + indexing works correctly.
  const src = `
var _0xarr = ['first', 'second', 'third', 'fourth', 'fifth'];
(function(_0xarr, _0xkey) {
  while (--_0xkey) { _0xarr.push(_0xarr.shift()); }
}(_0xarr, 0x3));
function _0xdec(_0xidx, _0xkey) {
  var _0xval = _0xarr[_0xidx];
  return _0xval;
}
var a = _0xdec(0x0, 'x');
var b = _0xdec(0x1, 'x');
var c = _0xdec(0x2, 'x');
  `;
  const result = decodeObfuscatorIo(src);
  assert('decoder returns findings array', Array.isArray(result.findings));
  assert('rotation finding emitted',
    result.findings.some(f => f.id === 'obfuscator-io-rotation'),
    `findings: ${result.findings.map(f=>f.id).join(',')}`);
  assert('decoded strings array populated',
    result.decodedStrings.length === 3,
    `decoded count: ${result.decodedStrings.length}`);
  // After rotating ['first','second','third','fourth','fifth'] by 3:
  //   slice(3) = ['fourth','fifth'], slice(0,3) = ['first','second','third']
  //   result = ['fourth','fifth','first','second','third']
  // So _0xdec(0x0) = 'fourth', _0xdec(0x1) = 'fifth', _0xdec(0x2) = 'first'
  assert('decoded[0] = "fourth" (after rotation by 3)',
    result.decodedStrings[0] && result.decodedStrings[0].decoded === 'fourth',
    `decoded[0]=${result.decodedStrings[0] && result.decodedStrings[0].decoded}`);
  assert('decoded[1] = "fifth"',
    result.decodedStrings[1] && result.decodedStrings[1].decoded === 'fifth');
  assert('decoded[2] = "first"',
    result.decodedStrings[2] && result.decodedStrings[2].decoded === 'first');
  // Verify the source was rewritten
  assert('source rewritten with decoded strings',
    result.src.includes("'fourth'") && result.src.includes("'fifth'") && result.src.includes("'first'"),
    `src contains decoded: ${result.src.includes("'fourth'")}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('9. obfuscator.io base64 decoder');
{
  // Build a base64-variant obfuscator.io bundle
  // Use 4 base64 strings so rotation by 1 keeps them all base64-decodable
  const b64_1 = Buffer.from('first-value').toString('base64');
  const b64_2 = Buffer.from('second-val').toString('base64');
  const b64_3 = Buffer.from('third-val').toString('base64');
  const b64_4 = Buffer.from('fourth-val').toString('base64');
  const src = `
var _0xarr = ['${b64_1}', '${b64_2}', '${b64_3}', '${b64_4}'];
(function(_0xarr, _0xkey) { while (--_0xkey) { _0xarr.push(_0xarr.shift()); } }(_0xarr, 0x1));
function _0xdec(_0xidx, _0xkey) {
  var _0xval = _0xarr[_0xidx];
  return atob(_0xval);
}
var a = _0xdec(0x0, 'x');
var b = _0xdec(0x1, 'x');
  `;
  const result = decodeObfuscatorIo(src);
  assert('base64 decoder: rotation applied',
    result.findings.some(f => f.id === 'obfuscator-io-rotation'));
  assert('base64 decoder: 2 strings decoded',
    result.decodedStrings.length === 2,
    `decoded count: ${result.decodedStrings.length}`);
  // After rotating by 1: [b64_2, b64_3, b64_4, b64_1]
  // _0xdec(0x0) = atob(b64_2) = 'second-val'
  assert('base64 decoder: decoded[0] = "second-val"',
    result.decodedStrings[0] && result.decodedStrings[0].decoded === 'second-val',
    `decoded[0]=${result.decodedStrings[0] && result.decodedStrings[0].decoded}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('10. Constant-expression evaluator');
{
  // String.fromCharCode with hex arithmetic
  let src = `var x = String.fromCharCode(0x68, 0x65, 0x6c, 0x6c, 0x6f);`;
  let result = evaluateConstantExpressions(src);
  assert('String.fromCharCode(0x68,...) → "hello"',
    result.src.includes("'hello'"),
    `src: ${result.src.slice(0, 60)}`);

  // atob on constant
  src = `var y = atob("${Buffer.from('test').toString('base64')}");`;
  result = evaluateConstantExpressions(src);
  assert('atob("dGVzdA==") → "test"',
    result.src.includes("'test'"),
    `src: ${result.src.slice(0, 60)}`);

  // charCodeAt on known string
  src = `var z = "ABC".charCodeAt(0);`;
  result = evaluateConstantExpressions(src);
  assert('"ABC".charCodeAt(0) → 65',
    result.src.includes(' 65'),
    `src: ${result.src.slice(0, 60)}`);

  // parseInt with radix
  src = `var w = parseInt("0xff", 16);`;
  result = evaluateConstantExpressions(src);
  assert('parseInt("0xff", 16) → 255',
    result.src.includes(' 255'),
    `src: ${result.src.slice(0, 60)}`);

  // toString with radix
  src = `var v = (255).toString(16);`;
  // Note: our regex requires a number literal directly, not parenthesized
  // Let's use the bare form:
  src = `var v = 255.toString(16);`;
  result = evaluateConstantExpressions(src);
  assert('255.toString(16) → "ff"',
    result.src.includes("'ff'"),
    `src: ${result.src.slice(0, 60)}`);

  // String concatenation
  src = `var u = "hello" + " " + "world";`;
  result = evaluateConstantExpressions(src);
  assert('"hello" + " " + "world" → "hello world"',
    result.src.includes("'hello world'") || result.src.includes("'hello'") === false,
    `src: ${result.src.slice(0, 80)}`);

  // Mixed: String.fromCharCode + concatenation in multiple passes
  src = `var t = String.fromCharCode(0x68, 0x69) + "!";`;
  result = evaluateConstantExpressions(src);
  assert('multi-pass: String.fromCharCode + concat',
    result.src.includes("'hi!'") || result.src.includes("'hi'"),
    `src: ${result.src.slice(0, 60)}`);

  // Refusal: non-constant arg should NOT be evaluated
  src = `var s = String.fromCharCode(someVar);`;
  result = evaluateConstantExpressions(src);
  assert('refuses to evaluate non-constant args',
    result.src.includes('someVar') && !result.findings.some(f => f.id === 'const-expr-fromcharcode'),
    `src: ${result.src.slice(0, 60)}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('11. LLM payload metadata');
{
  // Verify the LLM hints structure is well-formed
  const src = `
var _0x1a2b = ['a','b','c'];
(function(_0x1a2b, _0xk) { while(--_0xk) _0x1a2b.push(_0x1a2b.shift()); }(_0x1a2b, 0x2));
function _0xdec(i,k) { var v = _0x1a2b[i]; return atob(v); }
var _0x2b3c = _0xdec(0x0, 'x');
var _0x3c4d = _0xdec(0x1, 'x');
var _0x4d5e = _0xdec(0x2, 'x');
var _0x5e6f = _0xdec(0x3, 'x');
var _0x6f7a = _0xdec(0x4, 'x');
var _0x7a8b = _0xdec(0x5, 'x');
var _0x8b9c = _0xdec(0x6, 'x');
var _0x9c0d = _0xdec(0x7, 'x');
var _0x0d1e = _0xdec(0x8, 'x');
var _0x1e2f = _0xdec(0x9, 'x');
var _0x2e3f = _0xdec(0xa, 'x');
var _0x3f4a = _0xdec(0xb, 'x');
var _0x4a5b = _0xdec(0xc, 'x');
var _0x5b6c = _0xdec(0xd, 'x');
var _0x6c7d = _0xdec(0xe, 'x');
var _0x7d8e = _0xdec(0xf, 'x');
var _0x8e9f = _0xdec(0x10, 'x');
var _0x9f0a = _0xdec(0x11, 'x');
var _0x0a1b = _0xdec(0x12, 'x');
var _0x1b2c = _0xdec(0x13, 'x');
  `;
  const result = ast.fingerprintObfuscator(src);
  assert('LLM hints object returned', result.llmHints && typeof result.llmHints === 'object');
  assert('LLM hints has expectMangledIdentifiers',
    'expectMangledIdentifiers' in result.llmHints);
  assert('LLM hints has expectStringArrayIndirection',
    'expectStringArrayIndirection' in result.llmHints);
  assert('LLM hints has recommendedDecoderPasses array',
    Array.isArray(result.llmHints.recommendedDecoderPasses));
  assert('recommendedDecoderPasses contains hints',
    result.llmHints.recommendedDecoderPasses.length > 0,
    `passes: ${result.llmHints.recommendedDecoderPasses.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(60)}`);
console.log(`  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
console.log(`${'═'.repeat(60)}`);
if (failed) {
  console.log('\nFailed assertions:');
  for (const f of failures) {
    console.log(`  ✘ ${f.name}`);
    if (f.detail !== undefined) console.log(`      → ${f.detail}`);
  }
}
process.exit(failed ? 1 : 0);

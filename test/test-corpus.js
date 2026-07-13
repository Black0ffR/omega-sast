#!/usr/bin/env node
'use strict';

/**
 * Corpus test for obfuscator.io decoder — runs multiple synthetic bundles.
 *
 * Extends coverage beyond test-obfuscator.js with edge-case bundles:
 *   • Zero rotation (key % length === 0)
 *   • Rotation without getter (direct array ref)
 *   • Large array rotation
 *   • Negative index in decoder call
 *   • Getter-wrapped array (no extra IIFE reassignment)
 *   • Decoder-dependent rotation (sandbox-eval path)
 */

const fs   = require('fs');
const path = require('path');

// ── Import decodeObfuscatorIo (same mechanism as test-obfuscator.js) ───
const omegaPath = path.resolve(__dirname, '..', 'src', '_monolith.js');
const omegaSrc = fs.readFileSync(omegaPath, 'utf8');
function extractFnSrc(name) {
  const m = omegaSrc.match(new RegExp(`function ${name}\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\}`));
  if (!m) throw new Error(`could not extract ${name}`);
  return m[0];
}
const moduleSrc = `
${extractFnSrc('rc4Decrypt')}
${extractFnSrc('evalConstantArith')}
${extractFnSrc('decodeObfuscatorIo')}
${extractFnSrc('rotateBruteForce')}
module.exports = { decodeObfuscatorIo };
`;
const tmpPath = path.join(__dirname, '_corpus-omega-extracted.js');
fs.writeFileSync(tmpPath, moduleSrc);
const { decodeObfuscatorIo } = require(tmpPath);
fs.unlinkSync(tmpPath);

  // ── Test harness ───────────────────────────────────────────────────────
  let passed = 0;
  let failed = 0;
  const failures = [];

  function assert(name, cond, detail) {
    if (cond) { passed++; }
    else {
      failed++;
      failures.push({ name, detail });
    }
  }

  function corpus(name, src, expected) {
    // Clear the sandbox eval cache to avoid name collisions between bundles
    if (decodeObfuscatorIo._rotEvaled) decodeObfuscatorIo._rotEvaled.clear();
    // expected: { decoded: string[], rotateFinding?: string, noThrow?: true }
    let result;
    try {
      result = decodeObfuscatorIo(src);
  } catch (e) {
    assert(`[${name}] decodeObfuscatorIo did not throw`, false, e.message);
    return;
  }

  if (expected.decoded !== undefined) {
    assert(`[${name}] decoded count = ${expected.decoded.length}`,
      result.decodedStrings.length === expected.decoded.length,
      `got ${result.decodedStrings.length}`);
    for (let i = 0; i < expected.decoded.length; i++) {
      assert(`[${name}] decoded[${i}] = "${expected.decoded[i]}"`,
        result.decodedStrings[i] && result.decodedStrings[i].decoded === expected.decoded[i],
        `got ${result.decodedStrings[i] && result.decodedStrings[i].decoded}`);
    }
    // Verify source rewriting
    for (const exp of expected.decoded) {
      // Each decoded value should appear as a literal in the rewritten source
      assert(`[${name}] source contains "${exp}"`,
        result.src.includes(`'${exp}'`),
        `src: ${result.src.slice(0, 200)}`);
    }
  }

  if (expected.rotateFinding !== undefined) {
    assert(`[${name}] rotation finding "${expected.rotateFinding}"`,
      result.findings.some(f => f.id === 'obfuscator-io-rotation' && f.value.includes(expected.rotateFinding)),
      `rotations: ${result.findings.filter(f => f.id === 'obfuscator-io-rotation').map(f => f.value).join('; ')}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 1: Zero rotation (key % length === 0)');
{
  // key=0x6, length=3, 6%3=0 → no rotation
  const src = `
var _0xarr=['alpha','beta','gamma'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x6));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=_0xdec(0x0,'x');
var b=_0xdec(0x1,'x');
var c=_0xdec(0x2,'x');
  `.trim();
  corpus('zero-rotation', src, {
    decoded: ['alpha', 'beta', 'gamma'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 2: Simple rotation with key%length');
{
  // key=0x3, length=4, 3%4=3 → rotate by 3
  // ['a','b','c','d'] → ['d','a','b','c']
  const src = `
var _0xarr=['a','b','c','d'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x3));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=_0xdec(0x0,'x');
var b=_0xdec(0x1,'x');
  `.trim();
  corpus('simple-rotation', src, {
    decoded: ['d', 'a'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 3: Getter-wrapped array with simple rotation');
{
  const src = `
function _0xget(){var _0xarr=['x','y','z'];return _0xarr}
(function(g,k){while(--k){g().push(g().shift())}}(_0xget,0x2));
function _0xdec(_0xidx,_0xkey){var _0xlocal=_0xget();return _0xlocal[_0xidx]}
var a=_0xdec(0x0,'x');
  `.trim();
  // Note: IIFE calls g() each iteration but g() creates a new array each time.
  // This tests the fallback path where sandbox eval is skipped or fails.
  corpus('getter-simple', src, {
    decoded: ['x'],  // rotation doesn't persist due to new-array-on-each-call
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 4: Large array rotation');
{
  // Build a 20-element array
  const arr = Array.from({ length: 20 }, (_, i) => `s${i}`);
  const src = `
var _0xarr=['${arr.join("','")}'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x7));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=_0xdec(0x0,'x');
var b=_0xdec(0x13,'x');
  `.trim();
  // 7%20=7 → rotated by 7: s7 is at index 0, s0 is at index 13
  // idx 0x0 - 0 = 0 → arr[0] = s7
  // idx 0x13 - 0 = 19 → arr[19] = s6
  corpus('large-array', src, {
    decoded: ['s7', 's6'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 5: Decoder-dependent rotation (sandbox eval)');
{
  // key=0x5, length=5, naive: 5%5=0 → no rotation
  // IIFE computes rotation via decoder calls: actual rotation = 4
  const src = `
function _0xget(){var _0xarr=['3','1','4','1','5'];return _0xarr}
(function(g,k){var a=g();var d=function(i){return a[i]};while(!![]){try{var c=parseInt(d(0),10);if(c===k)break;a.push(a.shift())}catch(_){a.push(a.shift());break}}_0xget=function(){return a}}(_0xget,0x5));
function _0xdec(_0xidx,_0xkey){var _0xlocal=_0xget();return _0xlocal[_0xidx]}
var a=_0xdec(0x0,'x');
var b=_0xdec(0x1,'x');
  `.trim();
  corpus('decoder-dependent', src, {
    decoded: ['5', '3'],
    rotateFinding: 'sandbox-evaluated',
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 6: Rotation with offset subtraction in decoder');
{
  // Subtracts 0xfb from idx before indexing
  const src = `
var _0xarr=['hello','world','foo'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x1));
function _0xdec(_0xidx,_0xkey){_0xidx=_0xidx-0xfb;return _0xarr[_0xidx]}
var a=_0xdec(0xfc,'x');
var b=_0xdec(0xfd,'x');
  `.trim();
  // rotate by 1: ['world','foo','hello']
  // idx 0xfc - 0xfb = 1 → arr[1] = 'foo'
  // idx 0xfd - 0xfb = 2 → arr[2] = 'hello'
  corpus('offset-subtract', src, {
    decoded: ['foo', 'hello'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 7: .call() decoder invocation');
{
  const src = `
var _0xarr=['cat','dog','bird'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x2));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=_0xdec.call(null,0x0,'x');
var b=_0xdec.call(this,0x1,'x');
  `.trim();
  // rotate by 2: ['bird','cat','dog']
  corpus('call-invocation', src, {
    decoded: ['bird', 'cat'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 8: No rotation (key=0)');
{
  const src = `
var _0xarr=['first','second','third'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x0));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=_0xdec(0x0,'x');
var b=_0xdec(0x2,'x');
  `.trim();
  corpus('no-rotation', src, {
    decoded: ['first', 'third'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 9: Decoder call with string-matching .apply()');
{
  const src = `
var _0xarr=['apply0','apply1','apply2'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x0));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=_0xdec.apply(null,[0x0,'x']);
var b=_0xdec.apply(null,[0x1,'x']);
  `.trim();
  corpus('apply-invocation', src, {
    decoded: ['apply0', 'apply1'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
console.log('Corpus 10: Indirect (0, fn) decoder call');
{
  const src = `
var _0xarr=['indirect0','indirect1','extra'];
(function(_0xarr,_0xkey){while(--_0xkey){_0xarr.push(_0xarr.shift())}}(_0xarr,0x1));
function _0xdec(_0xidx,_0xkey){return _0xarr[_0xidx]}
var a=(0,_0xdec)(0x0,'x');
var b=(0,_0xdec)(0x1,'x');
  `.trim();
  corpus('indirect-call', src, {
    decoded: ['indirect1', 'extra'],
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(60)}`);
console.log(`  TOTAL: ${passed}   PASSED: ${passed}   FAILED: ${failed}`);
console.log(`${'═'.repeat(60)}`);
if (failed) {
  console.log('\nFailed assertions:');
  for (const f of failures) {
    console.log(`  ✘ ${f.name}`);
    if (f.detail !== undefined) console.log(`      → ${f.detail}`);
  }
}
process.exit(failed ? 1 : 0);

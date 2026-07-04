#!/usr/bin/env node
/**
 * Phase 2b — CharCode obfuscation decoder tests
 *
 * Verifies the decodeCharCodeObfuscation() function in omega-5.0.js correctly
 * decodes the pattern:
 *   function(...args){ r=Array.slice(args); e=r.shift();
 *     return r.reverse().map((o,a)=>String.fromCharCode(o-e-OFFSET-a)).join("") }(seed,...bytes)
 *
 * Pattern is from Juice Shop's token/route obfuscation. Two offset variants
 * are tested: o-e-45-a and o-e-24-a.
 *
 * Since decodeCharCodeObfuscation lives inside omega-5.0.js (which auto-runs
 * main()), we extract it via eval to test in isolation.
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const omegaPath = path.resolve(__dirname, '..', 'src', '_monolith.js');
const src = fs.readFileSync(omegaPath, 'utf8');

// Extract decodeCharCodeObfuscation function source
const m = src.match(/function decodeCharCodeObfuscation\(src\)\s*\{[\s\S]*?\n\}\n/);
if (!m) {
  console.error('✘ could not extract decodeCharCodeObfuscation');
  process.exit(1);
}
// Convert "function decodeCharCodeObfuscation(src) { ... }" to "(src) => { ... }" via eval
// Use the function-declaration form wrapped in parens
const fnSrc = m[0].replace(/^function decodeCharCodeObfuscation/, 'function');
const decodeCharCodeObfuscation = eval(`(${fnSrc})`);

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

// ── Helper: encode a string in the CharCode obfuscation pattern ────────
// Decoder does: [...bytes].reverse().map((o, a) => String.fromCharCode(o - seed - offset - a))
// where `a` is the index in the REVERSED array (0..N-1).
// So if reversed_bytes[a] = charCode(S[a]) + seed + offset + a,
// then bytes (before reverse) at position i = reversed_bytes[N-1-i]
//                                          = charCode(S[N-1-i]) + seed + offset + (N-1-i)
function encode(str, seed, offset) {
  const chars = [...str];
  const N = chars.length;
  // Build reversed_bytes first: reversed_bytes[a] = charCode(S[a]) + seed + offset + a
  const reversedBytes = chars.map((c, a) => c.charCodeAt(0) + seed + offset + a);
  // bytes (args) = reversedBytes reversed
  const bytes = [...reversedBytes].reverse();
  return `reverse().map(function(o,a){return String.fromCharCode(o-e-${offset}-a)}).join("")}(${seed},${bytes.join(',')})`;
}

// ═══════════════════════════════════════════════════════════════════════
section('1. Single string decoding (offset 45)');
{
  const original = 'hidden-route';
  const seed = 100;
  const offset = 45;
  const encoded = encode(original, seed, offset);
  const result = decodeCharCodeObfuscation(encoded);
  assert('decoder returns findings array', Array.isArray(result.findings));
  assert('decoder finds 1 finding', result.findings.length === 1,
    `findings=${result.findings.length}`);
  assert('decoded string matches original',
    result.findings[0] && result.findings[0].decoded === original,
    `decoded=${result.findings[0] && result.findings[0].decoded}`);
  assert('seed is captured', result.findings[0] && result.findings[0].seed === seed,
    `seed=${result.findings[0] && result.findings[0].seed}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. Single string decoding (offset 24)');
{
  const original = 'coupon-code';
  const seed = 50;
  const offset = 24;
  const encoded = encode(original, seed, offset);
  const result = decodeCharCodeObfuscation(encoded);
  assert('offset-24 variant: 1 finding', result.findings.length === 1);
  assert('offset-24 variant: decoded matches',
    result.findings[0] && result.findings[0].decoded === original,
    `decoded=${result.findings[0] && result.findings[0].decoded}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. Multiple encoded strings in same input');
{
  const e1 = encode('route-a', 100, 45);
  const e2 = encode('route-b', 200, 45);
  const combined = `var x = ${e1}; var y = ${e2};`;
  const result = decodeCharCodeObfuscation(combined);
  assert('multiple: finds 2 findings', result.findings.length === 2,
    `findings=${result.findings.length}`);
  const decoded = result.findings.map(f => f.decoded).sort();
  assert('multiple: both strings decoded', decoded[0] === 'route-a' && decoded[1] === 'route-b',
    `decoded=${decoded.join(',')}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('4. No encoded strings in input');
{
  const result = decodeCharCodeObfuscation('var x = "normal string";');
  assert('no encoded input: 0 findings', result.findings.length === 0);
  assert('no encoded input: src unchanged', result.src === 'var x = "normal string";');
}

// ═══════════════════════════════════════════════════════════════════════
section('5. Comment injection');
{
  const original = 'secret-route';
  const encoded = encode(original, 100, 45);
  const result = decodeCharCodeObfuscation(encoded);
  assert('comment injected into output',
    result.src.includes('OMEGA-decoded'),
    `src contains OMEGA-decoded: ${result.src.includes('OMEGA-decoded')}`);
  assert('comment contains decoded string',
    result.src.includes(`"${original}"`),
    `src contains "${original}": ${result.src.includes(`"${original}"`)}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('6. Printable string filter');
{
  // Encode a string with non-printable chars — should be filtered out
  const nonPrintable = String.fromCharCode(1, 2, 3, 4, 5);
  const seed = 10;
  const offset = 45;
  const bytes = [...nonPrintable].map((c, i) => c.charCodeAt(0) + seed + offset + i);
  const encoded = `reverse().map(function(o,a){return String.fromCharCode(o-e-${offset}-a)}).join("")}(${seed},${bytes.join(',')})`;
  const result = decodeCharCodeObfuscation(encoded);
  assert('non-printable output filtered out', result.findings.length === 0,
    `findings=${result.findings.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('7. Edge cases');
{
  // Too few args (need at least 3: seed + 2 bytes)
  const short = `reverse().map(function(o,a){return String.fromCharCode(o-e-45-a)}).join("")}(100,200)`;
  const r1 = decodeCharCodeObfuscation(short);
  assert('too few args: filtered out', r1.findings.length === 0);

  // Too many args (>32)
  const longArgs = Array(35).fill(150).join(',');
  const long = `reverse().map(function(o,a){return String.fromCharCode(o-e-45-a)}).join("")}(100,${longArgs})`;
  const r2 = decodeCharCodeObfuscation(long);
  assert('too many args: filtered out', r2.findings.length === 0);
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

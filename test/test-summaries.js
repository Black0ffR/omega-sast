#!/usr/bin/env node
/**
 * Function summary emitter + backward slicer tests (Stage 6)
 *
 * Tests computeFunctionSummaries() and buildBackwardSlices() against
 * realistic inter-procedural taint flows:
 *   · Direct source→sink in same function
 *   · Source→local var→sink (indirect within function)
 *   · Source→param→sink (inter-procedural via params)
 *   · Sanitizer detection on path
 *   · Return value classification
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const astPath = path.resolve(__dirname, '..', 'lib', 'ast.js');
const ast = require(astPath);

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

function summarize(src) {
  const idx = ast.buildStructuralIndex(src);
  const summaries = ast.computeFunctionSummaries(src, idx);
  const cg = ast.buildCallGraph(idx, null);
  const slices = ast.buildBackwardSlices(src, idx, summaries, cg, 3);
  return { idx, summaries, slices };
}

// ═══════════════════════════════════════════════════════════════════════
section('1. Basic function summary structure');
{
  const src = `function foo(a, b) { return a + b; }`;
  const { summaries } = summarize(src);
  const foo = summaries.find(s => s.name === 'foo');
  assert('foo summary exists', !!foo);
  assert('foo has 2 params', foo && foo.params.length === 2, `params=${foo && foo.params}`);
  assert('foo params are [a, b]', foo && foo.params[0] === 'a' && foo.params[1] === 'b');
  assert('foo has 0 sinks', foo && foo.sinks.length === 0);
  assert('foo has 0 sources', foo && foo.sources.length === 0);
  assert('foo has 1 return', foo && foo.returns.length === 1);
  assert('foo return kind is "param" (a is a param, starts the expression)',
    foo && foo.returns[0].kind === 'param',
    `kind=${foo && foo.returns[0].kind}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. Direct source→sink detection');
{
  const src = `
function leakDirect() {
  document.body.innerHTML = location.hash;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakDirect');
  assert('leakDirect summary exists', !!fn);
  assert('leakDirect has 1 source (location.*)',
    fn && fn.sources.length >= 1 && fn.sources.some(s => s.name === 'location.*'),
    `sources=${fn && fn.sources.map(s=>s.name).join(',')}`);
  assert('leakDirect has 1 sink (innerHTML)',
    fn && fn.sinks.length === 1 && fn.sinks[0].name === 'innerHTML',
    `sinks=${fn && fn.sinks.map(s=>s.name).join(',')}`);
  assert('leakDirect sink via = "location.*" (direct flow)',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. Indirect source→sink via local variable (mini-SSA)');
{
  const src = `
function leakIndirect() {
  const h = location.hash;
  document.body.innerHTML = h;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakIndirect');
  assert('leakIndirect has 1 source', fn && fn.sources.length >= 1);
  assert('leakIndirect has 1 sink (innerHTML)',
    fn && fn.sinks.length === 1 && fn.sinks[0].name === 'innerHTML');
  assert('leakIndirect sink via = "location.*" (via tainted local h)',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('4. Multi-hop tainted local propagation');
{
  const src = `
function leakMultiHop() {
  const a = location.search;
  const b = a;
  const c = b;
  document.getElementById("out").innerHTML = c;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakMultiHop');
  assert('leakMultiHop has 1 sink',
    fn && fn.sinks.length === 1 && fn.sinks[0].name === 'innerHTML');
  assert('leakMultiHop sink via = "location.*" (3-hop propagation)',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('5. Sanitizer detection');
{
  const src = `
function safeRender() {
  const h = location.hash;
  document.body.innerHTML = DOMPurify.sanitize(h);
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'safeRender');
  assert('safeRender has 1 sanitizer (DOMPurify.sanitize)',
    fn && fn.sanitizers.length >= 1 && fn.sanitizers.some(s => s.name === 'DOMPurify.sanitize'),
    `sanitizers=${fn && fn.sanitizers.map(s=>s.name).join(',')}`);
  assert('safeRender has 1 sink (innerHTML)',
    fn && fn.sinks.length === 1 && fn.sinks[0].name === 'innerHTML');
  // The sink should still be detected (we record the sanitizer, the LLM judges effectiveness)
  assert('safeRender sink via = "location.*" (sanitizer present but flow still recorded)',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('6. Return value classification');
{
  // Returns a parameter directly
  const src1 = `function passthrough(x) { return x; }`;
  const s1 = summarize(src1);
  const f1 = s1.summaries.find(s => s.name === 'passthrough');
  assert('return param: kind=param, value=args[0]',
    f1 && f1.returns[0].kind === 'param' && f1.returns[0].value === 'args[0]');

  // Returns a tainted value
  const src2 = `function getSource() { return location.search; }`;
  const s2 = summarize(src2);
  const f2 = s2.summaries.find(s => s.name === 'getSource');
  assert('return tainted: kind=tainted',
    f2 && f2.returns[0].kind === 'tainted',
    `kind=${f2 && f2.returns[0].kind}`);

  // Returns a literal
  const src3 = `function getConst() { return "hello"; }`;
  const s3 = summarize(src3);
  const f3 = s3.summaries.find(s => s.name === 'getConst');
  assert('return literal: kind=literal',
    f3 && f3.returns[0].kind === 'literal',
    `kind=${f3 && f3.returns[0].kind}`);

  // Returns a function call
  const src4 = `function wrapper() { return compute(); }`;
  const s4 = summarize(src4);
  const f4 = s4.summaries.find(s => s.name === 'wrapper');
  assert('return call: kind=call, value=call:compute',
    f4 && f4.returns[0].kind === 'call' && f4.returns[0].value === 'call:compute',
    `kind=${f4 && f4.returns[0].kind}, value=${f4 && f4.returns[0].value}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('7. Backward slicer — direct source→sink');
{
  const src = `
function leak() {
  document.body.innerHTML = location.hash;
}`;
  const { slices } = summarize(src);
  assert('1 slice produced', slices.length === 1, `slices=${slices.length}`);
  const p = slices[0];
  assert('slice reaches source', p.reachesSource === true);
  assert('slice sourceChain includes location.*',
    p.sourceChain.includes('location.*'),
    `chain=${p.sourceChain.join(',')}`);
  assert('slice sink = innerHTML',
    p.sink.name === 'innerHTML');
  assert('slice sinkFn = leak',
    p.sinkFn.name === 'leak');
  assert('slice totalHops = 0 (direct, no callers)',
    p.totalHops === 0);
}

// ═══════════════════════════════════════════════════════════════════════
section('8. Backward slicer — inter-procedural via params');
{
  const src = `
function sink(input) {
  document.body.innerHTML = input;
}
function caller() {
  const h = location.hash;
  sink(h);
}`;
  const { slices } = summarize(src);
  assert('≥1 slice produced', slices.length >= 1);
  // Find the slice for the innerHTML sink in `sink`
  const p = slices.find(s => s.sink.name === 'innerHTML' && s.sinkFn.name === 'sink');
  assert('slice for sink(input)→innerHTML exists', !!p);
  if (p) {
    assert('slice via = args[0] (param input flows to sink)',
      p.sink.via === 'args[0]', `via=${p.sink.via}`);
    assert('slice has ≥1 hop (caller found)',
      p.totalHops >= 1, `hops=${p.totalHops}`);
    assert('slice reaches source (location.* via caller)',
      p.reachesSource === true, `reachesSource=${p.reachesSource}`);
    assert('slice sourceChain includes location.*',
      p.sourceChain.includes('location.*'),
      `chain=${p.sourceChain.join(',')}`);
    assert('slice hop[0] fn = caller',
      p.hops[0] && p.hops[0].fnName === 'caller',
      `hop0=${p.hops[0] && p.hops[0].fnName}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════
section('9. Backward slicer — sanitizer on path');
{
  const src = `
function safeSink(input) {
  document.body.innerHTML = DOMPurify.sanitize(input);
}
function caller() {
  const h = location.hash;
  safeSink(h);
}`;
  const { slices } = summarize(src);
  const p = slices.find(s => s.sink.name === 'innerHTML' && s.sinkFn.name === 'safeSink');
  assert('safeSink slice exists', !!p);
  if (p) {
    assert('slice has sanitizer on path (DOMPurify.sanitize)',
      p.sanitizersOnPath.some(s => s.name === 'DOMPurify.sanitize'),
      `sanitizers=${p.sanitizersOnPath.map(s=>s.name).join(',')}`);
    assert('slice is marked as sanitized (suppressed for effective DOMPurify)',
      p.sanitized === true, `sanitized=${p.sanitized}`);
    assert('slice does NOT reach source (sanitizer neutralized taint)',
      p.reachesSource === false);
  }
}

// ═══════════════════════════════════════════════════════════════════════
section('10. Arrow function summaries');
{
  const src = `const handler = (event) => { document.body.innerHTML = event.data; };`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'handler');
  assert('arrow function summary exists', !!fn);
  assert('arrow function isArrow=true',
    fn && fn.isArrow === true, `isArrow=${fn && fn.isArrow}`);
  assert('arrow function has 1 param (event)',
    fn && fn.params.length === 1 && fn.params[0] === 'event');
  assert('arrow function has 1 sink (innerHTML)',
    fn && fn.sinks.length === 1 && fn.sinks[0].name === 'innerHTML');
  assert('arrow function sink via = args[0] (event.data flows to sink)',
    fn && fn.sinks[0].via === 'args[0]' || fn && fn.sinks[0].via === 'event.data',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('11. Function call tracking (for reachability)');
{
  const src = `
function foo() { bar(); }
function bar() { baz(); }
function baz() { return 1; }
`;
  const { summaries } = summarize(src);
  const foo = summaries.find(s => s.name === 'foo');
  const bar = summaries.find(s => s.name === 'bar');
  assert('foo calls bar', foo && foo.calls.includes('bar'),
    `calls=${foo && foo.calls.join(',')}`);
  assert('bar calls baz', bar && bar.calls.includes('baz'));
}

// ═══════════════════════════════════════════════════════════════════════
section('12. No sinks → no slices');
{
  const src = `function safe() { return 42; }`;
  const { slices } = summarize(src);
  assert('no sinks → 0 slices', slices.length === 0);
}

// ═══════════════════════════════════════════════════════════════════════
section('13. Sample bundle end-to-end');
{
  const bundleSrc = fs.readFileSync(path.resolve(__dirname, 'fixtures', 'sample-bundle.js'), 'utf8');
  const { summaries, slices } = summarize(bundleSrc);
  assert('sample bundle: summaries produced', summaries.length > 0);
  assert('sample bundle: has functions with sinks',
    summaries.some(s => s.sinks.length > 0));
  assert('sample bundle: has functions with sources',
    summaries.some(s => s.sources.length > 0));
  assert('sample bundle: slices produced', slices.length > 0);
  assert('sample bundle: some slices reach source',
    slices.some(p => p.reachesSource),
    `reachable=${slices.filter(p=>p.reachesSource).length}/${slices.length}`);
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

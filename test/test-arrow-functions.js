#!/usr/bin/env node
/**
 * Arrow function detection tests for OMEGA-5.0 AST module.
 * Verifies that buildStructuralIndex now tracks arrow functions
 * (previously only `function`-keyword functions were tracked).
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
    failed++;
    failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

function getFunctions(src) {
  const idx = ast.buildStructuralIndex(src);
  return idx.functions;
}

// ═══════════════════════════════════════════════════════════════════════
section('1. Basic arrow function forms');
{
  // Block body, parenthesised params
  const fns = getFunctions('const f = (a, b) => { return a + b; };');
  const arrows = fns.filter(f => f.isArrow);
  assert('parenthesised params + block body: arrow detected', arrows.length >= 1,
    `arrows=${arrows.length}, all fns: ${fns.map(f=>`${f.name}(arrow=${f.isArrow})`).join(',')}`);
  assert('arrow has isArrow=true', arrows[0] && arrows[0].isArrow === true);
  assert('arrow has body span', arrows[0] && arrows[0].bodyTokStart >= 0 && arrows[0].bodyTokEnd > arrows[0].bodyTokStart);
}

{
  // Expression body
  const fns = getFunctions('const f = (a, b) => a + b;');
  const arrows = fns.filter(f => f.isArrow);
  assert('expression body: arrow detected', arrows.length >= 1, `arrows=${arrows.length}`);
  assert('expression body: isExprBody flag set', arrows[0] && arrows[0].isExprBody === true);
}

{
  // Single param without parens, block body
  const fns = getFunctions('const f = x => { return x * 2; };');
  const arrows = fns.filter(f => f.isArrow);
  assert('single-param (no parens) + block body: arrow detected', arrows.length >= 1,
    `arrows=${arrows.length}`);
}

{
  // Single param without parens, expression body
  const fns = getFunctions('const f = x => x * 2;');
  const arrows = fns.filter(f => f.isArrow);
  assert('single-param (no parens) + expr body: arrow detected', arrows.length >= 1);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. async arrows');
{
  const fns = getFunctions('const f = async (a) => { return await a; };');
  const arrows = fns.filter(f => f.isArrow);
  assert('async arrow detected', arrows.length >= 1, `arrows=${arrows.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. Arrow name inference');
{
  const fns = getFunctions('const myHandler = (e) => { console.log(e); };');
  const arrow = fns.find(f => f.isArrow);
  assert('arrow name inferred from `const NAME = ...`', arrow && arrow.name === 'myHandler',
    `name=${arrow && arrow.name}`);
}

{
  // Anonymous arrow (callback, no assignment)
  const fns = getFunctions('arr.map((x) => x + 1);');
  const arrow = fns.find(f => f.isArrow);
  assert('anonymous arrow has name <anonymous>', arrow && arrow.name === '<anonymous>',
    `name=${arrow && arrow.name}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('4. Mixed function forms');
{
  const src = `
    function declared() { return 1; }
    const arrow1 = (a) => { return a; };
    const arrow2 = a => a + 1;
    const arrow3 = async (x) => x * 2;
    class Foo { method() { return 3; } }
  `;
  const fns = getFunctions(src);
  const arrows = fns.filter(f => f.isArrow);
  const regular = fns.filter(f => !f.isArrow);

  assert('mixed: detects 3 arrow functions', arrows.length === 3,
    `arrows=${arrows.length}, names: ${arrows.map(f=>f.name).join(',')}`);
  assert('mixed: detects ≥1 regular function (declared)', regular.length >= 1);
  assert('mixed: arrow1 name inferred', arrows.some(f => f.name === 'arrow1'));
  assert('mixed: arrow2 name inferred', arrows.some(f => f.name === 'arrow2'));
  assert('mixed: arrow3 name inferred', arrows.some(f => f.name === 'arrow3'));
}

// ═══════════════════════════════════════════════════════════════════════
section('5. Arrow body span accuracy');
{
  const src = 'const f = (a) => { console.log(a); return a; };';
  const fns = getFunctions(src);
  const arrow = fns.find(f => f.isArrow);
  assert('arrow start is at or before `const`', arrow && arrow.start <= src.indexOf('const') + 5);
  assert('arrow end is after the closing brace', arrow && arrow.end > src.indexOf('};'));
  assert('arrow body span covers the block', arrow && arrow.bodyTokEnd > arrow.bodyTokStart);
}

// ═══════════════════════════════════════════════════════════════════════
section('6. Webpack-style arrow modules');
{
  // The webpack 5 module pattern uses arrow functions
  const src = '101: (Q, H, d) => { class X {} Q.X = X; };';
  const fns = getFunctions(src);
  const arrows = fns.filter(f => f.isArrow);
  assert('webpack module arrow detected', arrows.length >= 1, `arrows=${arrows.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(60)}`);
console.log(`  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
console.log(`${'═'.repeat(60)}`);
if (failed) {
  console.log('\nFailed assertions:');
  for (const f of failures || []) console.log(`  ✘ ${f.name}`);
}
process.exit(failed ? 1 : 0);

#!/usr/bin/env node
/**
 * Regression test — regex taint single-letter-var noise (Patch 03, proper).
 *
 * Root causes fixed in src/_monolith.js scanTaintFlow + main() dedup block:
 *  (1) `after.includes(v)` substring match: tainted var `n` matched every
 *      120-char sink window containing the letter "n" (19 critical FPs on
 *      echarts.min.js). Now identifier-boundary matched.
 *  (2) Same-name/different-scope collision in minified bundles
 *      (`var n=e.data` chart-domain data vs `n=t.top-s` SVG coordinates):
 *      uncorroborated single-letter regex findings are demoted to medium
 *      instead of critical. Direct named sources never demoted.
 *
 * Reference corpus numbers (05-raw-bundles/echarts.min.js, --all):
 *   pre-fix:  19 taint-flow critical (n/s → innerHTML/Function/document.write/...)
 *   boundary:  9 (7 crit + 1 high + 1 med)
 *   +demote:   1 high (URL parameter → location navigation, legit) + 8 medium
 *   score: 82 → 69 → 62. No finding dropped, only re-severitized.
 *
 * Run: node test/test-taint-single-letter.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const bin = path.join(repoRoot, 'bin', 'omega.js');

let total = 0, passed = 0, failed = 0;
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++;
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

function scan(src) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-t3-'));
  fs.writeFileSync(path.join(tmp, 'f.js'), src);
  try {
    execFileSync('node', [bin, path.join(tmp, 'f.js'), '--all', '--out', path.join(tmp, 'out')], { stdio: 'pipe' });
  } catch (e) { /* non-zero exit on findings is fine */ }
  const r = JSON.parse(fs.readFileSync(path.join(tmp, 'out', 'report.json'), 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return [...(r.extendedFindings || []), ...(r.security || [])]
    .filter(f => /taint/i.test(f.id || '') || f.category === 'Taint Flow');
}

// ── 1. Scope-collision FP is demoted, not critical ──────────────────────
section('1. Minified scope collision (echarts shape)');
{
  const t = scan('var n = e.data;\nfunction render(){ var n = compute(); document.body.innerHTML = n; }\nrender();');
  const regex = t.filter(f => f.id === 'taint-flow');
  assert('collision finding still emitted (not dropped)',
    regex.length >= 1, JSON.stringify(regex.map(f => f.value)));
  assert('collision finding demoted below critical',
    regex.every(f => f.severity !== 'critical'),
    JSON.stringify(regex.map(f => f.severity + ':' + f.value)));
}

// ── 2. True positives still fire at full severity (AST path) ────────────
section('2. True positives unaffected');
{
  const t1 = scan('var n=location.hash;document.body.innerHTML=n;');
  assert('single-letter true positive still critical',
    t1.some(f => (f.severity === 'critical' || f.severity === 'high') && /innerHTML/.test(f.value || '')),
    JSON.stringify(t1.map(f => f.severity + ':' + f.value)));
  const t2 = scan('var q=location.hash;document.body.innerHTML=q;');
  assert('normal-name true positive still critical',
    t2.some(f => (f.severity === 'critical' || f.severity === 'high') && /innerHTML/.test(f.value || '')),
    JSON.stringify(t2.map(f => f.severity + ':' + f.value)));
}

// ── 3. Clean code stays silent ──────────────────────────────────────────
section('3. No false positives on clean code');
{
  const t = scan('function f(){var n=1;document.body.innerHTML=n;}');
  assert('untainted single-letter local stays silent',
    t.length === 0, JSON.stringify(t.map(f => f.value)));
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

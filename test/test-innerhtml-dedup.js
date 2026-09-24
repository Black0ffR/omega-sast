#!/usr/bin/env node
/**
 * Regression test — innerHTML dedup by enclosing function (Patch 05, proper).
 *
 * Large libraries reuse `.innerHTML=` per render function (apexcharts:
 * 27 high → 16 collapsed: 12 singles + 3x2 + 1x9, all positions kept in
 * mergedPositions; score 56 HIGH → 45 MEDIUM). Collapse rule lives in
 * collapseInnerHtmlByFunction (src/_monolith.js, end of analyseSecurity):
 *  - only xss-innerhtml/high participates (benign info + other rules untouched)
 *  - grouping key = innermost AST function (name+start) from
 *    buildStructuralIndex on the SAME buffer; top-level falls back to
 *    4K position buckets (never merges across distant sites)
 *  - kept finding gains repeatCount + mergedPositions + description note;
 *    severity kept at max. Fail-open: any error → no collapse.
 *
 * Run: node test/test-innerhtml-dedup.js
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

function innerHtml(src) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-i5-'));
  fs.writeFileSync(path.join(tmp, 'f.js'), src);
  try {
    execFileSync('node', [bin, path.join(tmp, 'f.js'), '--security', '--report', '--out', path.join(tmp, 'out')], { stdio: 'pipe' });
  } catch (e) { /* non-zero exit on findings is fine */ }
  const r = JSON.parse(fs.readFileSync(path.join(tmp, 'out', 'report.json'), 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return [...(r.extendedFindings || []), ...(r.security || [])]
    .filter(f => f.id === 'xss-innerhtml');
}

// ── 1. Same-function repeats collapse, no data loss ─────────────────────
section('1. Same-function collapse');
{
  const t = innerHtml('function tip(a,b){ el1.innerHTML=a; el2.innerHTML=b; } tip(x,y);');
  assert('two assignments in one function collapse to one finding',
    t.length === 1, JSON.stringify(t.map(f => f.pos)));
  assert('repeatCount covers both sites',
    t.length === 1 && t[0].repeatCount === 2, JSON.stringify(t.map(f => f.repeatCount)));
  assert('mergedPositions preserves every site',
    t.length === 1 && Array.isArray(t[0].mergedPositions) && t[0].mergedPositions.length === 2,
    JSON.stringify(t.map(f => f.mergedPositions)));
  assert('severity kept at max (high)',
    t.length === 1 && t[0].severity === 'high', JSON.stringify(t.map(f => f.severity)));
}

// ── 2. Different functions stay separate ────────────────────────────────
section('2. Cross-function separation');
{
  const t = innerHtml('function a(x){ e1.innerHTML=x; } function b(y){ e2.innerHTML=y; } a(1);b(2);');
  assert('one finding per function (no merge)',
    t.length === 2, JSON.stringify(t.map(f => f.pos)));
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

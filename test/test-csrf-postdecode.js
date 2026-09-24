#!/usr/bin/env node
/**
 * Regression test — CSRF findings on decoded buffers (Gap 1).
 *
 * scanCsrf ran only on the raw buffer, where verbs/URLs hide behind
 * decoder calls. Phase 12s now re-runs it on the decoded buffer and
 * merges findings + recomputes posture. The jQuery inventory also
 * accepts bracket heads ($['ajax']) and url-first key order, since
 * decoders emit both.
 *
 * Run: node test/test-csrf-postdecode.js
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-csrfpd-'));
  fs.writeFileSync(path.join(tmp, 'f.js'), src);
  try {
    execFileSync('node', [bin, path.join(tmp, 'f.js'), '--all', '--out', path.join(tmp, 'out')], { stdio: 'pipe' });
  } catch (e) { /* findings exit codes are fine */ }
  const r = JSON.parse(fs.readFileSync(path.join(tmp, 'out', 'report.json'), 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return r;
}

// ── 1. Bracket-head, url-first jQuery POST is inventoried ───────────────
section('1. Decoded-shape jQuery POST');
{
  const r = scan(`$['ajax']( {\n  'url':'/api/prefs', 'method':'POST', 'data':x\n});`);
  const c = r.csrf || {};
  const hits = (c.findings || []).filter(f => f.id === 'csrf-state-change-no-token');
  assert('bracket-head url-first POST surfaces',
    hits.some(f => /POST \/api\/prefs/.test(f.value || '')),
    JSON.stringify((c.findings || []).map(f => f.value)));
  assert('posture counts the surface (1 state-changing, 1 at-risk)',
    c.posture && c.posture.stateChangingRequests === 1 && c.posture.atRiskRequests === 1,
    JSON.stringify(c.posture));
}

// ── 2. Plain-shape jQuery POST still works (no regression) ──────────────
section('2. Classic dot-notation shape');
{
  const r = scan(`$.ajax({url: '/api/save', method: 'POST', data: y});`);
  const hits = ((r.csrf || {}).findings || []).filter(f => f.id === 'csrf-state-change-no-token');
  assert('dot-notation method-first POST still surfaces',
    hits.some(f => /POST \/api\/save/.test(f.value || '')),
    JSON.stringify(hits.map(f => f.value)));
}

// ── 3. GET-only bundle stays silent ─────────────────────────────────────
section('3. No false positives on reads');
{
  const r = scan(`$.ajax({url: '/api/list', method: 'GET'}); fetch('/api/other');`);
  const hits = ((r.csrf || {}).findings || []).filter(f => f.id === 'csrf-state-change-no-token');
  assert('no state-change findings for GET-only code', hits.length === 0,
    JSON.stringify(hits.map(f => f.value)));
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

#!/usr/bin/env node
/**
 * Regression test — crypto key material written to web storage (Gap 3)
 * and hardcoded Bearer-token linkage (Gap 4).
 *
 * Gap 3 (`crypto-storage-key-exfil`, medium): localStorage/sessionStorage
 * .setItem fires when the key name is crypto-flavoured OR the value
 * carries key-material shapes. Plain prefs writes stay silent. Dot and
 * bracket spellings both match (decoders emit brackets).
 *
 * Gap 4 (`Hardcoded Bearer Token`, high): `var V = <secret>` linked to a
 * Bearer-containing statement referencing V. Plumbing without a literal
 * secret stays silent.
 *
 * Run: node test/test-storage-bearer.js
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-sb-'));
  fs.writeFileSync(path.join(tmp, 'f.js'), src);
  try {
    execFileSync('node', [bin, path.join(tmp, 'f.js'), '--all', '--out', path.join(tmp, 'out')], { stdio: 'pipe' });
  } catch (e) { /* findings exit codes are fine */ }
  const r = JSON.parse(fs.readFileSync(path.join(tmp, 'out', 'report.json'), 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return [...(r.extendedFindings || []), ...(r.security || []), ...(r.credentials || [])];
}

// ── Gap 3 ───────────────────────────────────────────────────────────────
section('1. Storage key-exfil rule');
{
  let t = scan(`localStorage.setItem('theme','light');`);
  assert('benign prefs write stays silent',
    !t.some(f => f.id === 'crypto-storage-key-exfil'), JSON.stringify(t.map(f => f.id)));

  t = scan(`sessionStorage.setItem('authToken', t);`);
  assert('crypto-named key fires',
    t.some(f => f.id === 'crypto-storage-key-exfil'), JSON.stringify(t.map(f => f.id)));

  t = scan(`localStorage['setItem']('exported', btoa(String['fromCharCode']['apply'](null, new Uint8Array(k))));`);
  assert('bracket spelling + key bytes fires',
    t.some(f => f.id === 'crypto-storage-key-exfil'), JSON.stringify(t.map(f => f.id)));
}

// ── Gap 4 ───────────────────────────────────────────────────────────────
section('2. Bearer-token linkage');
{
  const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  let t = scan(`var JWT = "${JWT}";\nfunction h(){return "Bearer " + JWT;}\nh();`);
  assert('live JWT in Bearer header fires high',
    t.some(f => f.name === 'Hardcoded Bearer Token' && f.severity === 'high'),
    JSON.stringify(t.filter(f => /earer/.test(f.name || '')).map(f => f.name + ':' + f.severity)));

  t = scan(`function h(){return 'Bearer ' + getToken();}\nh();`);
  assert('plumbing without a literal secret stays silent',
    !t.some(f => f.name === 'Hardcoded Bearer Token'), JSON.stringify(t.map(f => f.name)));
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

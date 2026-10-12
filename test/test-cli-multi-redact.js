#!/usr/bin/env node
/**
 * Regression test — v14 follow-ups: --multi forms, --redact/--no-redact.
 *
 * --multi: flag-first form crashed on null.split; bare --multi crashed the
 * same way; help showed only the positional form.
 * --redact/--no-redact: redaction is default-on (JWT values masked);
 * --no-redact restores raw values for revocation workflows.
 *
 * Run: node test/test-cli-multi-redact.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const OMEGA = path.join(ROOT, 'bin', 'omega.js');

let total = 0, passed = 0, failed = 0;
function ok(name, cond, extra) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++;
    console.log(`  ✘ ${name}`);
    if (extra !== undefined) console.log(`      → ${String(extra).slice(0, 200)}`);
  }
}

const F1 = path.join(ROOT, 'test', 'fixtures', 'sample-bundle.js');
const F2 = path.join(ROOT, 'test', 'fixtures', 'intentionally-vuln.js');
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

console.log('\n── --multi forms ──────────────────────');
{
  const o1 = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-mf1-'));
  const r1 = spawnSync(process.execPath, [OMEGA, `${F1},${F2}`, '--multi', '--out', o1, '--no-color', '--quiet'], { encoding: 'utf8', timeout: 90000 });
  ok('files-first succeeds', r1.status === 0, `status=${r1.status}`);
  ok('files-first writes multi-report.json', fs.existsSync(path.join(o1, 'multi-report.json')));
  fs.rmSync(o1, { recursive: true, force: true });

  const o2 = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-mf2-'));
  const r2 = spawnSync(process.execPath, [OMEGA, '--multi', `${F1},${F2}`, '--out', o2, '--no-color', '--quiet'], { encoding: 'utf8', timeout: 90000 });
  ok('flag-first succeeds (was null.split crash)', r2.status === 0, `status=${r2.status} ${(r2.stderr || '').slice(0, 150)}`);
  ok('flag-first is true multi mode', fs.existsSync(path.join(o2, 'multi-report.json')));
  fs.rmSync(o2, { recursive: true, force: true });

  const o3 = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-mf3-'));
  const r3 = spawnSync(process.execPath, [OMEGA, '--multi', '--out', o3, '--no-color'], { encoding: 'utf8', timeout: 30000 });
  const c3 = (r3.stdout || '') + (r3.stderr || '');
  ok('bare --multi exits 1 with a message (not a crash)', r3.status === 1 && /comma-separated list/i.test(c3), `status=${r3.status}`);
  fs.rmSync(o3, { recursive: true, force: true });
}

console.log('\n── --redact / --no-redact ──────────────────────');
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-rj-'));
  const src = path.join(dir, 'jwt-t.js');
  fs.writeFileSync(src, `var t = '${JWT}';\n`);
  const jwtVals = (out) => {
    const r = JSON.parse(fs.readFileSync(path.join(out, 'report.json'), 'utf8'));
    return [...(r.credentials || []), ...(r.security || []), ...(r.extendedFindings || [])]
      .filter(f => /jwt/i.test(f.id || ''));
  };
  const o1 = path.join(dir, 'o1');
  spawnSync(process.execPath, [OMEGA, src, '--security', '--report', '--out', o1, '--quiet'], { encoding: 'utf8', timeout: 90000 });
  const v1 = jwtVals(o1);
  ok('default redacts JWT values', v1.length > 0 && v1.every(f => !String(f.value || '').includes('eyJhbGci')),
    JSON.stringify(v1.map(f => String(f.value).slice(0, 40))));

  const o2 = path.join(dir, 'o2');
  spawnSync(process.execPath, [OMEGA, src, '--security', '--report', '--out', o2, '--quiet', '--no-redact'], { encoding: 'utf8', timeout: 90000 });
  const v2 = jwtVals(o2);
  ok('--no-redact preserves raw JWT', v2.some(f => String(f.value || '').includes('eyJhbGci')),
    JSON.stringify(v2.map(f => String(f.value).slice(0, 40))));
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

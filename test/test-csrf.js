#!/usr/bin/env node
/**
 * CSRF analyzer tests (Phase 12n)
 *
 * Tests scanCsrf() — hybrid regex/context analyzer:
 *   · auth-context classifier (cookie vs bearer vs unknown)
 *   · class 1: state-changing requests without CSRF token
 *   · class 2: cookie attribute weaknesses (SameSite / Secure)
 *   · class 3: JSONP legacy patterns
 *   · class 4: token mishandling (token in URL, localStorage-only, client compare)
 *   · class 5: positive protections → suppression + posture 'protected'
 *   · CSRF Posture object shape
 *   · CLI: report.json carries csrf section; report-only (no exit-code impact)
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const ROOT  = path.resolve(__dirname, '..');
const OMEGA = path.join(ROOT, 'bin', 'omega.js');

// ── Extract scanCsrf from the monolith (same pattern as test-obfuscator.js)
const omegaSrc = fs.readFileSync(path.join(ROOT, 'src', '_monolith.js'), 'utf8');
function extractFnSrc(name) {
  const m = omegaSrc.match(new RegExp(`(?:async\\s+)?function ${name}\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\}`));
  if (!m) throw new Error(`could not extract ${name}`);
  return m[0];
}
const moduleSrc = `
${extractFnSrc('scanCsrf')}
module.exports = { scanCsrf };
`;
const tmpPath = path.join(__dirname, '_omega-csrf-extracted.js');
fs.writeFileSync(tmpPath, moduleSrc);
const { scanCsrf } = require(tmpPath);
fs.unlinkSync(tmpPath);

// ── Tiny test framework (matches existing test suites) ──────────────────
let total = 0, passed = 0, failed = 0;
const failures = [];
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++; failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail).slice(0, 200)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }
function byId(res, id) { return (res.findings || []).filter(f => f.id === id); }
function mkTmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-csrf-')); }
function runOmega(args, opts = {}) {
  return spawnSync(process.execPath, [OMEGA, ...args], {
    encoding: 'utf8', timeout: 90000, stdio: 'pipe', maxBuffer: 32 * 1024 * 1024, ...opts,
  });
}
function readReport(outDir) {
  const p = path.join(outDir, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

async function main() {
  section('1. auth-context classifier + class 1 (state-changing w/o token)');
  {
    // Cookie-auth bundle: document.cookie read + bare POST fetch
    const cookieBundle = `
const csrfToken = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
function saveAccount(data) {
  fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
}`;
    const r1 = scanCsrf(cookieBundle);
    assert('cookieAuth = true', r1.posture.cookieAuth === true, JSON.stringify(r1.posture));
    const c1 = byId(r1, 'csrf-state-change-no-token');
    assert('class 1 finding fires', c1.length === 1, JSON.stringify(c1));
    assert('class 1 severity = medium (cookie auth)', c1.length && c1[0].severity === 'medium', c1.length && c1[0].severity);
    assert('class 1 surface = /api/account', c1.length && c1[0].csrfSurface === '/api/account', c1.length && c1[0].csrfSurface);

    // Same bundle but with X-CSRF-TOKEN header attached → suppressed
    const protectedBundle = `
const csrfToken = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
function saveAccount(data) {
  fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrfToken[1] }, body: JSON.stringify(data) });
}`;
    const r2 = scanCsrf(protectedBundle);
    assert('token header attach → suppressed', byId(r2, 'csrf-state-change-no-token').length === 0,
      JSON.stringify(r2.findings));
    assert('surface marked protected', r2.posture.protectedRequests >= 1,
      JSON.stringify(r2.posture.surfaces));
    assert('tokenMechanism detected', r2.posture.tokenMechanism && r2.posture.tokenMechanism.length > 0,
      JSON.stringify(r2.posture.tokenMechanism));

    // axios with xsrf config → suppressed
    const axiosBundle = `
axios.defaults.xsrfCookieName = 'XSRF-TOKEN';
axios.defaults.xsrfHeaderName = 'X-XSRF-TOKEN';
axios.post('/api/order', { qty: 1 });`;
    const r3 = scanCsrf(axiosBundle);
    assert('axios xsrf config → suppressed', byId(r3, 'csrf-state-change-no-token').length === 0,
      JSON.stringify(r3.findings));
    assert('axios surface protected', r3.posture.protectedRequests >= 1,
      JSON.stringify(r3.posture.surfaces));

    // Bearer-only bundle → immune context → info
    const bearerBundle = `
function api(data) {
  fetch('/api/account', { method: 'POST', headers: { 'Authorization': 'Bearer ' + getToken() }, body: JSON.stringify(data) });
}`;
    const r4 = scanCsrf(bearerBundle);
    assert('bearerAuth = true', r4.posture.bearerAuth === true, JSON.stringify(r4.posture));
    const c4 = byId(r4, 'csrf-state-change-no-token');
    assert('class 1 fires in bearer context', c4.length === 1, JSON.stringify(c4));
    assert('class 1 severity = info (bearer immune)', c4.length && c4[0].severity === 'info', c4.length && c4[0].severity);

    // meta csrf-token + header attach → suppressed
    const metaBundle = `
const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
fetch('/api/delete', { method: 'DELETE', headers: { 'X-CSRF-Token': token } });`;
    const r5 = scanCsrf(metaBundle);
    assert('meta csrf-token → suppressed', byId(r5, 'csrf-state-change-no-token').length === 0,
      JSON.stringify(r5.findings));

    // Fetch with method as variable (unknown) → no finding, not classified
    const varMethodBundle = `document.cookie; fetch('/api/x', { method: someMethod, body: '1' });`;
    const r6 = scanCsrf(varMethodBundle);
    assert('variable method → no class 1 finding', byId(r6, 'csrf-state-change-no-token').length === 0,
      JSON.stringify(r6.findings));
  }

  section('2. class 2 — cookie attribute weaknesses');
  {
    const noSameSite = `document.cookie = 'sessionid=abc123; path=/';`;
    const r1 = scanCsrf(noSameSite);
    const c1 = byId(r1, 'csrf-cookie-samesite-missing');
    assert('auth cookie without SameSite → finding', c1.length === 1, JSON.stringify(c1));
    assert('severity = medium (auth-named cookie)', c1.length && c1[0].severity === 'medium', c1.length && c1[0].severity);

    const withSameSite = `document.cookie = 'sessionid=abc123; path=/; SameSite=Lax';`;
    assert('SameSite=Lax present → no finding', byId(scanCsrf(withSameSite), 'csrf-cookie-samesite-missing').length === 0);

    const noneInsecure = `document.cookie = 'auth=xyz; path=/; SameSite=None';`;
    const r3 = scanCsrf(noneInsecure);
    const c3 = byId(r3, 'csrf-cookie-samesite-none-insecure');
    assert('SameSite=None without Secure → finding', c3.length === 1, JSON.stringify(c3));
    assert('severity = medium', c3.length && c3[0].severity === 'medium', c3.length && c3[0].severity);

    const jsCookieLax = `Cookies.set('session', 'v', { sameSite: 'lax', secure: true });`;
    assert('js-cookie with sameSite → no finding', byId(scanCsrf(jsCookieLax), 'csrf-cookie-samesite-missing').length === 0);

    const jsCookieBare = `Cookies.set('session', 'v');`;
    assert('js-cookie without sameSite → finding', byId(scanCsrf(jsCookieBare), 'csrf-cookie-samesite-missing').length === 1);
  }

  section('3. class 3 — JSONP legacy patterns');
  {
    const jsonp1 = `
document.cookie;
const s = document.createElement('script');
s.src = 'https://api.example.com/data?callback=handleResp';
document.head.appendChild(s);`;
    const r1 = scanCsrf(jsonp1);
    const c1 = byId(r1, 'csrf-jsonp');
    assert('callback= script src → finding', c1.length === 1, JSON.stringify(c1));
    assert('severity = medium (cookie auth)', c1.length && c1[0].severity === 'medium', c1.length && c1[0].severity);

    const jsonp2 = `$.ajax({ url: '/search', dataType: 'jsonp' });`;
    const c2 = byId(scanCsrf(jsonp2), 'csrf-jsonp');
    assert('dataType jsonp → finding', c2.length === 1, JSON.stringify(c2));
  }

  section('4. class 4 — token mishandling');
  {
    const urlToken = `fetch('/api/pay?token=7f3a9c21e8d4b6f0', { method: 'POST' });`;
    const c1 = byId(scanCsrf(urlToken), 'csrf-token-in-url');
    assert('token in URL query → finding', c1.length === 1, JSON.stringify(c1));
    assert('severity = low', c1.length && c1[0].severity === 'low', c1.length && c1[0].severity);

    const lsOnly = `const t = localStorage.getItem('csrf_token');`;
    const c2 = byId(scanCsrf(lsOnly), 'csrf-token-localstorage-only');
    assert('localStorage csrf token never attached → finding', c2.length === 1, JSON.stringify(c2));

    const lsAttached = `
const t = localStorage.getItem('csrf_token');
fetch('/api/x', { method: 'POST', headers: { 'X-CSRF-Token': t } });`;
    assert('localStorage token attached → no finding',
      byId(scanCsrf(lsAttached), 'csrf-token-localstorage-only').length === 0);

    const compare = `if (token === csrfToken) { proceed(); }`;
    const c4 = byId(scanCsrf(compare), 'csrf-client-side-compare');
    assert('client-side token comparison → finding', c4.length === 1, JSON.stringify(c4));
  }

  section('5. CSRF Posture shape + empty bundle');
  {
    const r1 = scanCsrf(`document.cookie; fetch('/api/account', { method: 'POST' });`);
    const p = r1.posture;
    assert('posture has all keys', typeof p.cookieAuth === 'boolean' && typeof p.bearerAuth === 'boolean' &&
      p.stateChangingRequests === 1 && p.protectedRequests === 0 && p.atRiskRequests === 1 &&
      Array.isArray(p.surfaces) && p.surfaces.length === 1,
      JSON.stringify(p));
    assert('surface entry has surface/method/protected',
      p.surfaces[0].surface === '/api/account' && p.surfaces[0].method === 'POST' && p.surfaces[0].protected === false,
      JSON.stringify(p.surfaces));

    const r2 = scanCsrf(`const a = 1; const b = 2;`);
    assert('no API calls → zero findings', r2.findings.length === 0, JSON.stringify(r2.findings));
    assert('no API calls → atRiskRequests 0', r2.posture.atRiskRequests === 0, JSON.stringify(r2.posture));
  }

  section('6. CLI — csrf section in report.json + report-only exit codes');
  {
    // Only a medium CSRF finding would push exit to 4 if it fed the gates;
    // the storage-cookie low finding keeps it at 5 → proves report-only.
    const f1 = path.join(mkTmpDir(), 'csrf-at-risk.js');
    fs.writeFileSync(f1, `const t = document.cookie.match(/XSRF-TOKEN=([^;]+)/);\n` +
      `fetch('/api/account', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });\n`);
    const out1 = mkTmpDir();
    const run1 = runOmega([f1, '--security', '--report', '--quiet', '--out', out1]);
    const rep1 = readReport(out1);
    assert('exit 5 (low findings only — csrf excluded from gates)',
      run1.status === 5, `status=${run1.status} stderr=${(run1.stderr || '').slice(0, 120)}`);
    assert('report.json carries csrf section', rep1 && rep1.csrf && Array.isArray(rep1.csrf.findings),
      JSON.stringify(rep1 && rep1.csrf && rep1.csrf.findings));
    assert('csrf finding present in report', rep1 && rep1.csrf.findings.some(f => f.id === 'csrf-state-change-no-token'),
      JSON.stringify(rep1 && rep1.csrf.findings));
    assert('posture.cookieAuth true in report', rep1 && rep1.csrf.posture && rep1.csrf.posture.cookieAuth === true,
      JSON.stringify(rep1 && rep1.csrf && rep1.csrf.posture));

    // Protected fixture → zero csrf findings
    const f2 = path.join(mkTmpDir(), 'csrf-protected.js');
    fs.writeFileSync(f2, `const t = document.cookie.match(/XSRF-TOKEN=([^;]+)/);\n` +
      `fetch('/api/account', { method: 'POST', headers: { 'X-CSRF-TOKEN': t[1] } });\n`);
    const out2 = mkTmpDir();
    const run2 = runOmega([f2, '--security', '--report', '--quiet', '--out', out2]);
    const rep2 = readReport(out2);
    assert('protected fixture: zero csrf findings', rep2 && rep2.csrf && rep2.csrf.findings.length === 0,
      JSON.stringify(rep2 && rep2.csrf && rep2.csrf.findings));
    assert('protected fixture: tokenMechanism detected', rep2 && rep2.csrf.posture.tokenMechanism &&
      rep2.csrf.posture.tokenMechanism.length > 0, JSON.stringify(rep2 && rep2.csrf && rep2.csrf.posture.tokenMechanism));

    // Clean fixture → exit 0, csrf section present with zero findings
    const f3 = path.join(mkTmpDir(), 'csrf-clean.js');
    fs.writeFileSync(f3, `const a = 1 + 2;\nconsole.log(a);\n`);
    const out3 = mkTmpDir();
    const run3 = runOmega([f3, '--security', '--report', '--quiet', '--out', out3]);
    const rep3 = readReport(out3);
    assert('clean fixture: exit 0', run3.status === 0, `status=${run3.status}`);
    assert('clean fixture: csrf section present, 0 findings',
      rep3 && rep3.csrf && rep3.csrf.findings.length === 0 && rep3.csrf.posture.atRiskRequests === 0,
      JSON.stringify(rep3 && rep3.csrf));
  }

  console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
  if (failed) {
    console.log('\nFailed assertions:');
    for (const f of failures) console.log(`  ✘ ${f.name}${f.detail !== undefined ? `\n      → ${String(f.detail).slice(0, 200)}` : ''}`);
  }
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });

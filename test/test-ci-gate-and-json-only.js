#!/usr/bin/env node
'use strict';

/**
 * test-ci-gate-and-json-only.js
 *
 * Regression tests for the CI exit gate and the --json-only report mode.
 *
 * ── Exit gate ────────────────────────────────────────────────────────────
 * The severity comparison was inverted (`failRank <= RANK[x]` instead of
 * `RANK[x] <= failRank`). Because the comparison holds for every severity
 * whenever the threshold is stricter than the finding, the documented default
 * `OMEGA_FAIL_ON=critical` failed the build on ANY finding at all — including
 * info — and exit 2 was unreachable unless the scan found nothing else.
 *
 * The logic also existed in two places: inside the `require.main === module`
 * block and inside the exported `runCLI()`. `bin/omega.js` calls `runCLI()`,
 * so the copy that governed every real CLI invocation was the second one —
 * meaning a fix applied to the first is invisible. These tests exercise the
 * binary, which is the only path that proves the live copy was fixed.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const OMEGA = path.join(ROOT, 'bin', 'omega.js');
const tmp = (n) => fs.mkdtempSync(path.join(os.tmpdir(), `cigate-${n}-`));

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail) {
  if (cond) pass++;
  else { fail++; failures.push(name + (detail ? `  — ${detail}` : '')); }
}

console.log('\n── CI exit gate: OMEGA_FAIL_ON threshold ──');

/**
 * Run the real binary and return its exit code.
 * spawnSync (not execSync) because omega exits non-zero BY DESIGN when it
 * finds things; execSync would throw and mask the very code under test.
 */
function scan(file, { env = {}, args = [] } = {}) {
  const out = tmp('out');
  const r = spawnSync(process.execPath,
    [OMEGA, file, '--security', '--no-color', '--out', out, ...args],
    { encoding: 'utf8', timeout: 120000, env: { ...process.env, ...env } });
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '', out };
}

function writeTmp(src) {
  const f = path.join(tmp('src'), 'input.js');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, src);
  return f;
}

// ── Fixtures with known severity profiles ─────────────────────────────────
// unserialize → critical (CWE-502)
// yaml.load    → high     (CWE-502)
//
// These MUST feed the sink from a request source. The node-surface rules
// downgrade severity when no untrusted input is demonstrably reaching the
// sink (critical→medium, high→info), so a sink with a neutral argument would
// assert the wrong thing: the test would pass for the wrong reason.
const CRIT = writeTmp(
  'const s = require("node-serialize");\n' +
  'app.post("/x", (req) => { s.unserialize(req.body); });');
const HIGH = writeTmp(
  'const yaml = require("yaml");\n' +
  'app.post("/x", (req) => { yaml.load(req.body); });');
const CLEAN = writeTmp('var total = 1 + 2; module.exports = total;');

// ── 1. Exit 2 must be reachable, and only for real criticals ─────────────
ok('critical fixture exits 2 on default threshold', scan(CRIT).code === 2,
   `got ${scan(CRIT).code}`);
ok('high-only fixture does NOT trip the default critical threshold',
   scan(HIGH).code === 0, `got ${scan(HIGH).code} — the inversion is back`);
ok('clean file exits 0', scan(CLEAN).code === 0);

// ── 2. Monotonicity: raising the threshold can only raise the exit code ───
// Before the fix this was non-monotonic — `medium` scored HIGHER than `high`.
{
  const codes = ['critical', 'high', 'medium', 'low'].map(l =>
    scan(HIGH, { env: { OMEGA_FAIL_ON: l } }).code);
  const rank = { 0: 0, 2: 1, 3: 2, 4: 3, 5: 4 };
  ok('thresholds are monotonic for a high-severity finding',
     rank[codes[0]] <= rank[codes[1]] && rank[codes[1]] <= rank[codes[2]] && rank[codes[2]] <= rank[codes[3]],
     `critical=${codes[0]} high=${codes[1]} medium=${codes[2]} low=${codes[3]}`);
  ok('high finding trips the high/medium/low thresholds',
     codes[1] === 3 && codes[2] === 3 && codes[3] === 3,
     `expected 3,3,3 got ${codes.slice(1).join(',')}`);
}

// ── 3. Widening the threshold must never lower the exit code ─────────────
{
  const codes = ['critical', 'high', 'medium', 'low'].map(l =>
    scan(CRIT, { env: { OMEGA_FAIL_ON: l } }).code);
  ok('a critical finding trips every real threshold',
     codes.every(c => c === 2), `got ${codes.join(',')}`);
}

// ── 4. none disables the gate; garbage does not silently pass ────────────
ok('OMEGA_FAIL_ON=none always exits 0', scan(CRIT, { env: { OMEGA_FAIL_ON: 'none' } }).code === 0);
{
  const r = scan(CRIT, { env: { OMEGA_FAIL_ON: 'totally-bogus' } });
  ok('invalid OMEGA_FAIL_ON does not fail the build', r.code === 0, `got ${r.code}`);
  ok('invalid OMEGA_FAIL_ON is reported on stderr',
     /Invalid OMEGA_FAIL_ON/.test(r.stderr),
     'a typo in a CI gate must not silently disable the gate');
}

console.log('\n── --json-only report mode ──');

{
  const b = path.join(ROOT, 'test', 'fixtures', 'sample-bundle.js');
  if (!fs.existsSync(b)) { console.log('  (sample-bundle.js absent — skipping)'); }
  else {
    const plain = tmp('plain');
    const jsonOnly = tmp('jsononly');

    spawnSync(process.execPath, [OMEGA, b, '--all', '--report', '--no-color', '--out', plain],
      { encoding: 'utf8', timeout: 180000 });
    const r2 = spawnSync(process.execPath,
      [OMEGA, b, '--all', '--report', '--no-color', '--json-only', '--out', jsonOnly],
      { encoding: 'utf8', timeout: 180000 });

    ok('default mode writes all four reports',
       ['report.json', 'report.html', 'report.md', 'report.sarif']
         .every(f => fs.existsSync(path.join(plain, f))));

    ok('--json-only writes report.json',
       fs.existsSync(path.join(jsonOnly, 'report.json')));

    ok('--json-only omits html', !fs.existsSync(path.join(jsonOnly, 'report.html')));
    ok('--json-only omits markdown', !fs.existsSync(path.join(jsonOnly, 'report.md')));
    ok('--json-only omits sarif', !fs.existsSync(path.join(jsonOnly, 'report.sarif')));

    ok('--json-only prints only the JSON line in the REPORTS block',
       /JSON report:/.test(r2.stdout) && !/HTML report:|SARIF report:|MD report:/.test(r2.stdout),
       r2.stdout.split('\n').filter(l => /report:/.test(l)).join(' | '));

    // The whole point of the flag is that the payload is unchanged.
    if (fs.existsSync(path.join(plain, 'report.json')) && fs.existsSync(path.join(jsonOnly, 'report.json'))) {
      const a = JSON.parse(fs.readFileSync(path.join(plain, 'report.json'), 'utf8'));
      const j = JSON.parse(fs.readFileSync(path.join(jsonOnly, 'report.json'), 'utf8'));
      for (const d of [a, j]) if (d.meta) delete d.meta.date;   // wall-clock, not payload
      ok('--json-only JSON is identical to the default run', JSON.stringify(a) === JSON.stringify(j));
    } else {
      ok('--json-only JSON is identical to the default run', false, 'a report.json was not produced');
    }
  }
}

console.log('\n' + '═'.repeat(62));
console.log(`  PASSED: ${pass}`);
if (fail) {
  console.log(`  FAILED: ${fail}`);
  console.log('\n  Failure detail:');
  for (const f of failures) console.log(`    ✗ ${f}`);
}
process.exit(fail === 0 ? 0 : 1);

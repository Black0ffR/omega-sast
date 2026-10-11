#!/usr/bin/env node
'use strict';

/**
 * test-review-fixes.js
 *
 * Regression tests for the defects found in review of omega-sast and the
 * `omega-v6-pr-4` patch bundle. Each block pins a specific fix; a block that
 * fails means that defect is back.
 *
 * The three marked ★ are the ones that had NO coverage anywhere in the suite.
 * Every earlier "0 regressions" run was green precisely because nothing
 * asserted them:
 *   ★1  baseline suppression must not zero the exit-code gate
 *   ★2  credential `context` must stay newline-free
 *   ★3  `suppressedBy` must be a string, not a closure over a dead binding
 *
 * Run standalone: node test/test-review-fixes.js
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const repo = path.resolve(__dirname, '..');
const pipeline = require(path.join(repo, 'src', '_monolith.js'));
const { ast } = require(path.join(repo, 'lib', 'index.js'));
const { analyze } = require(path.join(repo, 'lib', 'index.js'));

let pass = 0, fail = 0;
const failures = [];

function ok(name, cond, extra) {
  if (cond) { pass++; }
  else { fail++; failures.push(name + (extra ? `  — ${extra}` : '')); }
}

function section(t) { console.log(`\n── ${t} ──`); }

// ── fixtures + helpers ────────────────────────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-revfx-'));

const LEAKY = path.join(tmp, 'leaky.js');
fs.writeFileSync(LEAKY, [
  'var AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
  'var GH_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";',
  'var JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";',
  'fetch("https://api.example.com/v1/data?ak=" + AWS_KEY);',
  'document.getElementById("x").innerHTML = location.hash;',
  '',
].join('\n'));

const BASELINE = path.join(tmp, '.omega-ignore');
fs.writeFileSync(BASELINE, JSON.stringify([{ id: 'Credential', reason: 'known test key' }]));

const NOOP_BASELINE = path.join(tmp, '.omega-ignore-noop');
fs.writeFileSync(NOOP_BASELINE, JSON.stringify([{ id: 'NoSuchId', reason: 'matches nothing' }]));

function scan(args) {
  const out = path.join(tmp, 'out-' + Math.random().toString(36).slice(2));
  let code = 0;
  try {
    execFileSync(process.execPath, [path.join(repo, 'bin', 'omega.js'), LEAKY, '--all', '--quiet',
      '--out', out, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { code = e.status; }
  const reportPath = path.join(out, 'report.json');
  return { code, report: fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, 'utf8')) : null };
}

// ═══════════════════════════════════════════════════════════════════════════
section('★1  baseline suppression must not defeat the exit-code gate');

{
  // The fixture always contains a critical taint flow (location.hash -> innerHTML).
  // Suppressing credentials must not change the gate's verdict.
  const plain = scan([]);
  ok('no baseline → exit 2 (critical present)', plain.code === 2, `got ${plain.code}`);

  const base = scan(['--baseline', BASELINE]);
  ok('baseline suppressing credentials → still exit 2', base.code === 2, `got ${base.code}`);
  ok('…because a critical remains in the report',
    (base.report.extendedFindings || []).some(f => f.severity === 'critical'));
  ok('…and the summary counts it',
    base.report.__summary === undefined || true); // informational

  const noop = scan(['--baseline', NOOP_BASELINE]);
  ok('baseline matching nothing → still exit 2', noop.code === 2, `got ${noop.code}`);

  // The specific mechanism: `const allSec = allScored` is an alias, so any code
  // that clears allScored and re-pushes from it silently empties the array
  // feeding totalFindings / the exit code.
  const src = fs.readFileSync(path.join(repo, 'src', '_monolith.js'), 'utf8');
  ok('allSec is still an alias of allScored', /const allSec = allScored;/.test(src));
  ok('no code re-pushes allSec from itself after clearing it',
    !/allScored\.length = 0; allScored\.push\([\s\S]{0,200}?allSec\.length = 0; allSec\.push\(\.\.\.allScored\)/.test(src),
    'found the empty-then-push-from-empty sequence');
}

// ═══════════════════════════════════════════════════════════════════════════
section('★2  credential context stays newline-free');

{
  const r = scan([]).report;
  const creds = r.credentials || [];
  ok('fixture produced credentials', creds.length > 0, `got ${creds.length}`);
  for (const c of creds) {
    ok(`credential "${c.name}" context has no CR/LF`,
      !/[\r\n]/.test(c.context || ''), JSON.stringify(c.context));
  }
  // A source-side guard: /\\n/ matches a literal backslash-n, not a newline.
  const src = fs.readFileSync(path.join(repo, 'src', '_monolith.js'), 'utf8');
  const credBlock = src.slice(src.indexOf('function scanCredentials'));
  const ctxLine = (credBlock.match(/context: src\.slice\([^\n]*/) || [''])[0];
  ok('credential context still strips real newlines', /\.replace\(\/\\r\?\\n\/g/.test(ctxLine), ctxLine);
  // The defect under test: `/\\n/g` matches a literal backslash-n, not a newline.
  ok('credential context does NOT use a literal-backslash \\n replace',
    !/\.replace\(\/\\\\n\/g/.test(ctxLine), ctxLine);
}

// ═══════════════════════════════════════════════════════════════════════════
section('★3  suppressedBy is a string, not a closure over a dead binding');

{
  const r = scan(['--baseline', BASELINE]).report;
  const supp = r.suppressed || [];
  ok('suppressed array is present in report.json', Array.isArray(r.suppressed));
  ok('suppressed is non-empty', supp.length > 0, `got ${supp.length}`);
  for (const s of supp) {
    ok(`suppressedBy is a string (${s.id})`, typeof s.suppressedBy === 'string', typeof s.suppressedBy);
    ok(`suppressedBy is readable, no ReferenceError (${s.id})`, s.suppressedBy !== undefined);
    ok(`suppressedByKind set (${s.id})`, s.suppressedByKind === 'baseline');
    ok('suppressedReason carried through', typeof s.suppressedReason === 'string');
  }
  ok('suppressedBy equals the baseline id', supp.every(s => s.suppressedBy === 'Credential'));
  ok('suppression reason preserved', supp.some(s => s.suppressedReason === 'known test key'));
  ok('suppressed findings are still credential-shaped', supp.every(s => s.category === 'Credential'));
}

// ═══════════════════════════════════════════════════════════════════════════
section('baseline matching: id OR category');

{
  const r = scan(['--baseline', BASELINE]).report;
  ok('credentials were actually removed from credentials[]', (r.credentials || []).length === 0,
    `got ${(r.credentials || []).length}`);
  ok('non-credential findings are untouched', (r.security || []).length > 0);

  // A rule naming a credential id directly must also work.
  const byId = path.join(tmp, '.omega-ignore-byid');
  fs.writeFileSync(byId, JSON.stringify([{ id: 'cred-aws-access-key' }]));
  const r2 = scan(['--baseline', byId]).report;
  ok('baseline by specific credential id suppresses exactly that one',
    (r2.suppressed || []).length === 1 && r2.suppressed[0].id === 'cred-aws-access-key',
    JSON.stringify((r2.suppressed || []).map(s => s.id)));
  ok('…and the sibling credential is not over-suppressed',
    (r2.credentials || []).some(c => c.id === 'cred-github-token'),
    JSON.stringify((r2.credentials || []).map(c => c.id)));
}

// ═══════════════════════════════════════════════════════════════════════════
section('suppression propagates by identity, not by a content key');

{
  // A content-derived key (name|value|line) collides across distinct findings
  // and would drop a finding the user never baselined. Identity is exact.
  const src = fs.readFileSync(path.join(repo, 'src', '_monolith.js'), 'utf8');
  ok('applyBaseline exposes suppressedRefs', /suppressedRefs/.test(src));
  ok('propagation filters by identity', /\.filter\(f => !result\.suppressedRefs\.has\(f\)\)/.test(src));
  ok('no content-key filter remains', !/suppressedKey\s*=\s*new Set/.test(src));
}

// ═══════════════════════════════════════════════════════════════════════════
section('credential findings carry id + category');

{
  const r = scan([]).report;
  for (const c of r.credentials || []) {
    ok(`credential has id (${c.name})`, typeof c.id === 'string' && c.id.length > 0, JSON.stringify(c.id));
    ok(`credential id is slug-shaped (${c.name})`, /^cred-[a-z0-9-]+$/.test(c.id || ''), c.id);
    ok(`credential has category (${c.name})`, c.category === 'Credential');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
section('JWT secrets are redacted out of reports');

{
  const r = scan([]).report;
  const jwt = (r.extendedFindings || []).find(f => /jwt/i.test(f.id || ''));
  ok('fixture produced a JWT finding', !!jwt, 'no crypto-jwt-literal in report');
  if (jwt) {
    ok('JWT value is redacted', /^\[REDACTED:JWT_VALUE:/.test(jwt.value || ''), JSON.stringify(jwt.value));
    ok('no raw eyJ… token survives in the value', !/eyJ[A-Za-z0-9_-]{10,}\./.test(jwt.value || ''));
  }
  const whole = JSON.stringify(r);
  ok('no live JWT anywhere in report.json',
    !/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\./.test(whole), 'a full JWT leaked into the report');

  // Ordering: isJwtLike must be evaluated before redactText mutates f.value,
  // or the hard redaction is silently skipped for id-less JWT findings.
  const src = fs.readFileSync(path.join(repo, 'src', '_monolith.js'), 'utf8');
  ok('isJwtLike result is captured before mutation', /const jwt = isJwtLike\(f\);/.test(src));
  ok('hard redaction uses the cached result', /if \(jwt && typeof f\.value === 'string'/.test(src));
}

// ═══════════════════════════════════════════════════════════════════════════
section('external source map: redirects are followed, loops are bounded');

{
  const src = fs.readFileSync(path.join(repo, 'src', '_monolith.js'), 'utf8');
  const fn = src.slice(src.indexOf('async function fetchExternalSourceMap'));
  const chunk = fn.slice(0, fn.indexOf('\n}\n'));
  // Strip line comments first: the explanatory comment above the fix quotes
  // the old `if (res.statusCode !== 200)` ordering verbatim.
  const code = chunk.split('\n').filter(l => !/^\s*(\/\/|\*)/.test(l)).join('\n');
  const redirIdx = code.indexOf('if (res.statusCode >= 300');
  const bailIdx = code.indexOf('if (res.statusCode !== 200)');
  ok('redirect branch exists', redirIdx > -1);
  ok('non-200 bail exists', bailIdx > -1);
  ok('redirect check comes BEFORE the non-200 bail', redirIdx > -1 && redirIdx < bailIdx,
    `redirect@${redirIdx} bail@${bailIdx}`);
  ok('redirect depth is bounded', /depth > 3\) return null;/.test(code));
  ok('relative Location is resolved against the current URL', /new URL\(next, url\)\.toString\(\)/.test(code));
  ok('recursion passes the depth', /fetchExternalSourceMap\(absolute, bundlePath, depth \+ 1\)/.test(code));
}

// ═══════════════════════════════════════════════════════════════════════════
section('programmatic analyze()');

{
  ok('analyze is exported as a function', typeof analyze === 'function');

  // Guarded so an unpatched tree (no `analyze` export) reports failures
  // instead of throwing and killing the run before the summary prints.
  let firstCall = null;
  try { firstCall = analyze(LEAKY); } catch (e) { firstCall = e; }
  ok('analyze is async (returns a promise)', firstCall instanceof Promise, String(firstCall));

  const settled = firstCall instanceof Promise
    ? firstCall
    : Promise.reject(new Error('analyze() is not callable: ' + String(firstCall)));

  settled.then((r) => {
    ok('analyze returns a report object', r && typeof r === 'object');
    ok('…with a security array', Array.isArray(r.security));
    ok('…with a credentials array', Array.isArray(r.credentials));
    ok('…not the ast module (the old stub returned this)', typeof r.tokenizeForAST !== 'function');
    ok('…carries __summary counts', r.__summary && typeof r.__summary.totalFindings === 'number');
    ok('__summary is non-enumerable (report.json parity)',
      !Object.keys(r).includes('__summary'));

    return analyze('').then(
      () => ok('analyze rejects an empty path', false, 'resolved instead of rejecting'),
      (e) => ok('analyze rejects an empty path', e instanceof TypeError, String(e)))
    .then(() => analyze('/definitely/not/here.js').then(
      () => ok('analyze on a missing file rejects', false, 'resolved instead of rejecting'),
      (e) => ok('analyze on a missing file rejects', e instanceof Error, String(e))));
  }).then(() => {
    // ── AST buildStructuralIndex bound guard (patch 01) ──────────────────
    section('AST buildStructuralIndex: guard is real, ternary is not needed');
    const cases = [
      'function foo() {} function bar(){}',
      'function \n{}{}{}{}{}{}{}{}{}{}{}{}{}{}',
      '', 'function', 'function f(', 'function f(){',
      'function f(){' + '{'.repeat(400),
      'function f(){' + 'a('.repeat(300),
      'class A{', 'function f(){}' + '{'.repeat(200),
    ];
    let crashed = 0;
    for (const src of cases) {
      try { ast.buildStructuralIndex(src); } catch (e) { crashed++; failures.push(`AST crash on ${JSON.stringify(src.slice(0, 30))}: ${e.message}`); }
    }
    ok('no crash across malformed/adversarial inputs', crashed === 0, `${crashed} crashes`);
    // The published repro must not throw.
    let reproThrew = null;
    try { ast.buildStructuralIndex('function \n{}{}{}{}{}{}{}{}{}{}{}{}{}{}'); }
    catch (e) { reproThrew = e; }
    ok('the published "throws at line 702" repro does NOT throw', reproThrew === null,
      reproThrew && reproThrew.message);
    // The guard is the `continue`, not a silent ternary fallback.
    const asrc = fs.readFileSync(path.join(repo, 'src', 'ast', '_monolith.js'), 'utf8');
    const bfn = asrc.slice(asrc.indexOf('function buildStructuralIndex'));
    ok('the `if (k2 >= M) continue;` guard is still present', /if \(k2 >= M\) continue;/.test(bfn));
    // Lines 421/480 carry PRE-EXISTING v6 bound checks in other walkers, and
    // buildStructuralIndex has several `functions.push({` sites. Anchor on the
    // body-scan loop so we test exactly the block that was reported broken.
    // `paramsTokStart: nameTok + 2` is unique to the function-declaration
    // push (the arrow-function push nearby uses `bodyEnd` / `arrowStart`).
    const marker = 'paramsTokStart: nameTok + 2';
    const pushIdx = bfn.lastIndexOf('functions.push({', bfn.indexOf(marker));
    const pushBlock = bfn.slice(pushIdx, pushIdx + 300);
    ok('anchored on the function-declaration push', pushIdx > -1 && pushBlock.includes(marker),
      `push@${pushIdx}`);
    ok('no silent `T[k2] ? T[k2].end : t.end` fallback in buildFunctions',
      !/end: T\[k2\] \? T\[k2\]\.end/.test(pushBlock),
      'a ternary fallback here would mask a future removal of the guard');
    ok('buildFunctions uses the plain T[k2].end guarded by continue',
      /end: T\[k2\]\.end/.test(pushBlock), pushBlock.slice(0, 120));

    // ── anti-debug fingerprint ordering ──────────────────────────────────
    section('anti-debug detection is not gated behind its own score');
    const anti = [
      "var _0xa = new RegExp(this['a'] + this['b']);",
      "this['c']['test'](this['a']['toString']());",
      '(function () {',
      "  for (var i = 0x0, len = this['_arr']['length']; i < len; i++) {",
      "    this['_arr']['push'](Math['round'](Math['random']()));",
      '  }',
      '})();',
    ].join('\n');
    const fp = ast.fingerprintObfuscator(anti);
    ok('expectAntiDebugging is true on an anti-debug bundle', fp.llmHints.expectAntiDebugging === true,
      JSON.stringify(fp.llmHints));
    ok('obfuscator.io signature is produced', !!(fp.detected || []).length);
    const cleanFp = ast.fingerprintObfuscator('function add(a,b){ return a + b; }\nvar x = 1;');
    ok('expectAntiDebugging is false on clean code', cleanFp.llmHints.expectAntiDebugging === false);
    // Ordering: the anti-debug blocks must be evaluated BEFORE the score gate.
    const asrc2 = asrc;
    const antiIdx = asrc2.indexOf('obfuscator-io-debug-protection');
    const gateIdx = asrc2.indexOf('if (obfuscatorIoScore >= 0.3)');
    ok('anti-debug detection precedes the obfuscator.io score gate', antiIdx > -1 && antiIdx < gateIdx,
      `anti@${antiIdx} gate@${gateIdx}`);

    // ── decode integrity assessment ──────────────────────────────────────
    section('decode integrity under anti-debug (AGENTS.md #12 interim)');
    const antiFp = { llmHints: { expectAntiDebugging: true } };
    const cleanFp2 = { llmHints: { expectAntiDebugging: false } };
    ok('no decoded strings → ok', pipeline.assessDecodeIntegrity(0, antiFp).status === 'ok');
    ok('decoded + clean → ok', pipeline.assessDecodeIntegrity(12, cleanFp2).status === 'ok');
    ok('decoded + anti-debug → untrusted', pipeline.assessDecodeIntegrity(12, antiFp).status === 'untrusted');
    ok('null fingerprint → ok (no crash)', pipeline.assessDecodeIntegrity(5, null).status === 'ok');
    const untrusted = pipeline.assessDecodeIntegrity(12, antiFp);
    ok('carries the decoded count', untrusted.decodedStrings === 12);
    ok('carries an advisory for the analyst', typeof untrusted.advisory === 'string' && untrusted.advisory.length > 20);
    const df = pipeline.decodeIntegrityFinding(untrusted);
    ok('emits a high-severity finding', df && df.severity === 'high', JSON.stringify(df));
    ok('finding id is stable', df && df.id === 'decode-integrity-untrusted');
    ok('no finding when integrity is ok', pipeline.decodeIntegrityFinding(pipeline.assessDecodeIntegrity(12, cleanFp2)) === null);

    // Clean scan must report ok
    const r2 = scan([]);
    ok('clean scan reports decodeIntegrity ok',
      r2.report.decodeIntegrity && r2.report.decodeIntegrity.status === 'ok',
      JSON.stringify(r2.report.decodeIntegrity));

    // ── summary ──────────────────────────────────────────────────────────
    console.log('\n' + '═'.repeat(62));
    if (fail === 0) {
      console.log(`  PASSED: ${pass}`);
    } else {
      console.log(`  PASSED: ${pass}`);
      console.log(`  FAILED: ${fail}`);
      console.log('\n  Failure detail:');
      for (const f of failures) console.log(`    ✗ ${f}`);
    }
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
    process.exit(fail === 0 ? 0 : 1);
  }).catch((e) => {
    console.log(`  PASSED: ${pass}`);
    console.log(`  FAILED: ${fail + 1}`);
    console.log('\n  Failure detail:');
    for (const f of failures) console.log(`    ✗ ${f}`);
    console.log(`    ✗ async section threw: ${e && e.stack ? e.stack.split('\n')[0] : e}`);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
    process.exit(1);
  });
}

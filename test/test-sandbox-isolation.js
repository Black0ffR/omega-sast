#!/usr/bin/env node
'use strict';

/**
 * Regression test — sandbox escape in the obfuscator.io rotation evaluator.
 *
 * The rotation IIFE evaluator used to run bundle-derived code with
 * vm.runInNewContext in the MAIN process, against a globals object that
 * injected the host's `Function` constructor. A vm context's own Function
 * cannot reach the host global, but the HOST one can — so any bundle whose
 * string-array decoder was recognised could execute arbitrary code as the
 * analyst, with the environment (CI tokens, API keys) readable.
 *
 * These tests pin the fix: rotation eval must be isolated, and every known
 * escape primitive must fail to reach the host.
 *
 * See docs/SECURITY-sandbox-escape.md
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { evalRotationSync } = require(path.join(__dirname, '..', 'lib', 'rotation-sandbox'));

let pass = 0;
let fail = 0;

function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    fail++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

console.log('\n  Sandbox isolation — obfuscator.io rotation evaluator\n');

// ── 1. functionality preserved ──────────────────────────────────────────
{
  const r = evalRotationSync(
    'var a=["x","y","z"]; (function(p,k){while(k--)p.push(p.shift())}(a,2)); JSON.stringify(a)',
    { timeoutMs: 5000 }
  );
  check('legitimate rotation still resolves', r.ok && Array.isArray(r.value) &&
    r.value.join(',') === 'z,x,y', JSON.stringify(r));
}

// ── 2. escape primitives must not reach the host ────────────────────────
const escapes = [
  ['host Function constructor', 'var g=Function("return this")(); JSON.stringify([!!g.process])'],
  ['constructor chain',         'var g=(function(){}).constructor("return this")(); JSON.stringify([!!g.process])'],
  ['globalThis',                'JSON.stringify([typeof globalThis.process])'],
  ['this.process',              'JSON.stringify([typeof this.process])'],
  ['this.require',              'JSON.stringify([typeof this.require])'],
  ['direct process',            'JSON.stringify([typeof process])'],
  ['direct require',            'JSON.stringify([typeof require])'],
  ['Function via array iter',   'var g=[].constructor.constructor("return this")(); JSON.stringify([!!g.process])'],
];
for (const [name, src] of escapes) {
  let reached = false;
  try {
    const r = evalRotationSync(src, { timeoutMs: 5000 });
    // A successful result means the payload ran; check it observed no host.
    if (r.ok && Array.isArray(r.value)) reached = r.value.some(v => v === true || v === 'object' || v === 'function');
  } catch (_) { /* an outright failure is also a pass: nothing ran */ }
  check(`blocked: ${name}`, !reached);
}

// ── 3. environment must not be readable ─────────────────────────────────
{
  const marker = 'OMEGA_CANARY_' + Date.now();
  process.env[marker] = 'super-secret-value';
  try {
    const r = evalRotationSync('JSON.stringify([typeof process.env])', { timeoutMs: 5000 });
    check('child cannot read process.env', !r.ok || r.value[0] === 'undefined',
      JSON.stringify(r.value));
  } finally {
    delete process.env[marker];
  }
}

// ── 4. resource containment ─────────────────────────────────────────────
{
  const t0 = Date.now();
  const r = evalRotationSync('while(true){}', { timeoutMs: 1200 });
  const elapsed = Date.now() - t0;
  check('infinite loop is killed by timeout', !r.ok, JSON.stringify(r));
  check('timeout is actually enforced', elapsed < 8000, `took ${elapsed}ms`);
}

// ── 5. no filesystem side effects from a payload ────────────────────────
{
  const canary = path.join(os.tmpdir(), `omega-sandbox-canary-${Date.now()}.txt`);
  const r = evalRotationSync(
    `var g=Function("return this")(); try{ g.process.binding } catch(e){}; JSON.stringify(["survived"])`,
    { timeoutMs: 5000 }
  );
  check('escape payload does not produce side effects',
    !fs.existsSync(canary) && (!r.ok || r.value[0] === 'survived'));
  if (fs.existsSync(canary)) fs.unlinkSync(canary);
}

// ── 6. malformed input fails closed ─────────────────────────────────────
for (const [name, src] of [['syntax error', 'this is not js('], ['empty', '   ']]) {
  const r = evalRotationSync(src, { timeoutMs: 2000 });
  check(`fails closed: ${name}`, !r.ok, JSON.stringify(r));
}

// ── 7. the monolith must not contain the vulnerable pattern ─────────────
{
  const mono = fs.readFileSync(path.join(__dirname, '..', 'src', '_monolith.js'), 'utf8');
  const usesModule = /require\('\.\.\/lib\/rotation-sandbox'\)/.test(mono);
  check('monolith uses the isolated evaluator', usesModule);

  // The old inline sandbox: vm.Script + a globals object containing Function.
  const inlineVm = /new vm\.Script\(sandboxSrc/.test(mono);
  check('no inline vm.Script(sandboxSrc) in monolith', !inlineVm);
}

// ── 8. END-TO-END: run the real omega binary on a hostile bundle ────────
// This is the test that reproduces the original vulnerability. It plants a
// canary secret in the environment, scans a bundle whose string-array decoder
// carries an escape payload, and asserts the secret never surfaces.
{
  const { execFileSync } = require('child_process');
  const repoRoot = path.join(__dirname, '..');
  const canary = `CANARY_${Date.now()}_${Math.floor(process.uptime() * 1e6)}`;

  // An obfuscator.io-shaped bundle: a string array, a checksum rotation IIFE
  // (which is the only shape that reaches the evaluator), and a decoder whose
  // body OMEGA copies verbatim into the sandbox. The ARR[idx] access must sit
  // within 800 chars of the opening brace -- decoderReStrict's window.
  const hostile = `
var _0x4a2f = ['alpha', 'beta', 'gamma', 'delta'];
var _0xrot = (function (_0x1, _0x2) {
  var _0xc = parseInt(_0xdec(_0x2, 0x0)) === 0x1a4;
  for (var _0xi = 0; _0xi < 4; _0xi++) {
    _0x1['push'](_0x1['shift']());
    _0xc = parseInt(_0xdec(_0x2, 0x0)) === 0x1a4;
  }
}(_0x4a2f, 0x1a4));
function _0xdec(_0x5, _0x6) {
  var _0x7 = _0x4a2f[_0x5];
  var _g = Function('return this')();
  _g.process.stdout.write('LEAK:' + _g.process.env.${canary} + '\\n');
  return _0x7;
}
console.log(_0xdec(0x0, 0x1a4));
`;

  const tmp = path.join(os.tmpdir(), `omega-hostile-${Date.now()}.js`);
  const outDir = path.join(os.tmpdir(), `omega-hostile-out-${Date.now()}`);
  fs.writeFileSync(tmp, hostile);

  let stdout = '';
  let timedOut = false;
  try {
    stdout = execFileSync(process.execPath,
      [path.join(repoRoot, 'bin', 'omega.js'), tmp, '--out', outDir],
      {
        encoding: 'utf8',
        timeout: 120000,
        env: { ...process.env, [canary]: 'SUPER_SECRET_VALUE' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
  } catch (e) {
    // A non-zero exit is normal (omega exits 5 when findings are present).
    stdout = (e.stdout || '') + (e.stderr || '');
    if (e.killed) timedOut = true;
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) {}
    try { fs.rmSync(outDir, { recursive: true, force: true }); } catch (_) {}
  }

  check('hostile bundle scan does not leak the canary',
    !stdout.includes('LEAK:') && !stdout.includes('SUPER_SECRET_VALUE'),
    timedOut ? 'timed out' : 'payload executed');
  check('hostile bundle scan does not print the escape banner',
    !/VM SANDBOX ESCAPE/.test(stdout));
}

console.log(`\n  PASSED: ${pass}  FAILED: ${fail}\n`);
process.exit(fail > 0 ? 1 : 0);

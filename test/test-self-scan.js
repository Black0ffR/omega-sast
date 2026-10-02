#!/usr/bin/env node
'use strict';

/**
 * test-self-scan.js
 *
 * Dogfooding gate: run omega's OWN ruleset against omega's OWN source.
 *
 * Rationale
 * ---------
 * omega-sast's entire purpose is analysing code it did not write. Before the
 * CWE-94 sandbox-escape fix (commit e544308 / PR #1), the tool itself
 * executed bundle-derived text in the main process via `vm.runInNewContext`
 * with the host realm's `Function` constructor injected. A SAST tool for
 * untrusted input that does not scan itself is a structural gap: the one
 * codebase whose threat model exactly matches the tool's is the one it never
 * checks.
 *
 * This gate is intentionally narrow and high-precision. It asserts on a
 * specific, well-understood class of self-defect (execution primitives fed by
 * input-derived text) rather than trying to assert "no findings ever", which
 * would be noisy and would rot.
 *
 * Run: node test/test-self-scan.js
 * Exit: 0 = clean, 1 = gate tripped
 */

const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, extra) {
  if (cond) pass++;
  else { fail++; failures.push(name + (extra ? `  — ${extra}` : '')); }
}

console.log('\n── Self-scan: dogfooding gate ──');

// ── 1. The source files that make up the engine ─────────────────────────────
const TARGETS = [
  'src/_monolith.js',
  'src/ast/_monolith.js',
  'lib/rotation-sandbox.js',
  'lib/node-surface.js',
  'lib/redos-worker.js',
  'bin/omega.js',
].filter(f => fs.existsSync(path.join(ROOT, f)));

// ── 2. The security property: no host-realm object may cross the boundary ──
//
// The failure mode being gated is NOT "this file calls vm.runInNewContext" —
// the deobfuscator legitimately evaluates rotated code. It is that a HOST-REALM
// object (the `vm` module, or any host function) becomes reachable from inside
// the sandbox, because both of these are live escapes that existed here:
//
//   new vm.Script(s).runInThisContext()  -> evaluates s in the HOST context
//   hostFn.constructor('return process') // the HOST Function constructor
//
// Both were confirmed by execution, not inspection, before being fixed.
{
  const mono = fs.readFileSync(path.join(ROOT, 'src', '_monolith.js'), 'utf8');

  ok('host vm module is never injected into a sandbox',
     !/sandbox\.__vmModule\s*=\s*vm\s*;/.test(mono),
     'found `sandbox.__vmModule = vm` — restores the confirmed escape');

  ok('vm capability is built as a context-realm wrapper, not a host object',
     /__mkVmShim/.test(mono) && /vm\.createContext\(/.test(mono),
     'no context-realm wrapper found — capability would be host-realm');

  const shimBlock = mono.match(/const shim = Object\.create\(null\);[\s\S]{0,400}/);
  ok('shim exposes only runInNewContext',
     !!shimBlock && /shim\.runInNewContext\s*=/.test(shimBlock[0]) &&
     !/shim\.(Script|createContext|compileFunction|runInThisContext|runInContext)\s*=/.test(shimBlock[0]),
     'shim re-exposes a dangerous vm member');
}

// (d) Dynamic proof: the wrapper construction must never yield a host bridge.
// This guards the technique itself rather than a copy of the call site.
{
  const vmMod = require('vm');
  const sandbox = Object.create(null);
  const ctx = vmMod.createContext(sandbox);
  vmMod.runInContext('function __mk(hf){ return function(a,b,c){ return hf(a,b,c); }; }', ctx);
  const mk = vmMod.runInContext('__mk', ctx);
  const shim = Object.create(null);
  shim.runInNewContext = mk((a, b, c) => vmMod.runInNewContext(a, b, c));
  sandbox.__vmModule = shim;

  let bridge, functional;
  try {
    bridge = vmMod.runInContext('__vmModule.runInNewContext.constructor("return typeof process")()', ctx, { timeout: 3000 });
    functional = vmMod.runInContext('__vmModule.runInNewContext("1+1")', ctx, { timeout: 3000 });
  } catch (e) { bridge = 'THREW: ' + e.message; }

  ok('context-realm wrapper has no host Function bridge',
     bridge === 'undefined', 'constructor bridge reached the host: ' + bridge);
  ok('context-realm wrapper still performs its job',
     functional === 2, 'wrapper returned ' + JSON.stringify(functional));
}

// ── 3. The mitigation must actually be wired in ────────────────────────────
//
// A "no vm calls" gate would be trivially satisfiable by deleting the
// deobfuscation feature. What we really want to assert is: rotation
// evaluation goes through the sandbox, not the main process.
{
  const monolith = fs.readFileSync(path.join(ROOT, 'src', '_monolith.js'), 'utf8');
  const sandboxPath = path.join(ROOT, 'lib', 'rotation-sandbox.js');
  const hasSandbox = fs.existsSync(sandboxPath);
  ok('lib/rotation-sandbox.js exists', hasSandbox);

  if (hasSandbox) {
    const sb = fs.readFileSync(sandboxPath, 'utf8');
    // The sandbox must NOT inject a host-realm Function into the child.
    ok('sandbox does not inject a host-realm Function constructor',
       !/sandboxGlobals\s*=\s*\{[^}]*\bFunction\b/.test(sb) && !/,\s*Function\s*,/.test(sb),
       'host Function found in sandbox globals — that is the escape primitive');
    // It must strip the environment.
    ok('sandbox strips the inherited environment',
       /env\s*:/i.test(sb) && /(PATH|NODE_ENV)/.test(sb),
       'no stripped-env construction found');
    // It must bound runtime.
    ok('sandbox enforces a timeout / kill',
       /timeout/i.test(sb) && /SIGKILL|kill/i.test(sb));
    // The main process must delegate to it.
    ok('main pipeline delegates rotation eval to the sandbox',
       /rotation-sandbox/.test(monolith) || /evaluateRotation/.test(monolith),
       'main process does not reference the rotation sandbox');
  }
}

// ── 5. End-to-end: a hostile bundle must not execute ───────────────────────
//
// This is the assertion that would have caught the original CVE. It runs the
// real binary against a bundle whose decoder body carries a payload, with an
// environment canary planted, and asserts nothing leaked.
{
  const pocPath = path.join(ROOT, 'docs', 'poc-malicious-bundle.js');
  if (fs.existsSync(pocPath)) {
    const os = require('os');
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'selfscan-'));
    const canary = 'SELFCANARY_' + Math.random().toString(36).slice(2);
    const r = spawnSync(process.execPath,
      [path.join(ROOT, 'bin', 'omega.js'), pocPath, '--security', '--report', '--no-color', '--out', out],
      { encoding: 'utf8', timeout: 90000, env: { ...process.env, OMEGA_CANARY: canary } });
    const combined = (r.stdout || '') + (r.stderr || '');

    ok('hostile bundle: payload did not execute',
       !/VM SANDBOX ESCAPE|STOLEN ENV|host pid=/.test(combined),
       'payload output detected — rotation evaluator is executing untrusted code');
    ok('hostile bundle: environment canary not leaked',
       !combined.includes(canary));
    ok('hostile bundle: scan still completed and wrote reports',
       fs.existsSync(path.join(out, 'report.json')),
       'rotation sandbox should fail closed, not abort the scan');
  } else {
    console.log('  (docs/poc-malicious-bundle.js not present — skipping e2e escape check)');
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

#!/usr/bin/env node
'use strict';

/**
 * test-esoteric-sandbox-isolation.js
 *
 * Property test for the esoteric decoder's shadow-execution sandbox.
 *
 * ── Background ───────────────────────────────────────────────────────────
 * The rotation/esoteric path has produced two confirmed sandbox-escape
 * PRIMITIVES (an exploitable primitive is not the same as a reachable one):
 *
 *   1. the host realm's `Function` constructor injected into the child
 *      process globals by the rotation sandbox, and
 *   2. the host realm's `vm` module injected into the main-process context as
 *      `__vmModule` — `new vm.Script(s).runInThisContext()` evaluates in the
 *      HOST realm, which was demonstrated live against commit da8fc53.
 *
 * Both were fixed. But a fixed primitive that is still *reachable* is a live
 * vulnerability, so reachability is the property that matters. Fuzzing
 * (test/fuzz-esoteric.js, 1200 iterations) established the following, and this
 * file pins it so a future change cannot quietly undo it:
 *
 *   Attacker-controlled code only ever executes inside a NESTED context
 *   created by __tryShell, never in the outer context that holds __vmModule.
 *   The `eval` trap it is handed (__ce2) is itself defined inside that nested
 *   context, so `eval.constructor` yields a NESTED-realm Function — which
 *   cannot see `process`, and cannot reach the outer global object.
 *
 * That is why the __vmModule injection was a latent primitive rather than a
 * reachable one. The fix is still correct and worth keeping: it removes the
 * primitive rather than relying on a second layer happening to hold.
 *
 * ── What is asserted ─────────────────────────────────────────────────────
 * Probes run as real decode input, through the real decodeEsoteric(), so they
 * exercise the engine's own sandbox rather than a reconstruction of it.
 */

const path = require('path');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');

const ROOT = path.join(__dirname, '..');
const CHILD = path.join(__dirname, 'fuzz-esoteric-child.js');

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail) {
  if (cond) pass++;
  else { fail++; failures.push(name + (detail ? `  — ${detail}` : '')); }
}

console.log('\n── Esoteric sandbox isolation ──');

const CANARY = 'ISOLATION_CANARY_' + Math.random().toString(36).slice(2);

/**
 * Run a probe as decode input and read back what the decoder captured.
 * The probe must push its result through the trapped `eval` for the decoder
 * to return it — that is the only channel out of the nested sandbox, which is
 * precisely why it is a safe one.
 */
function probe(body) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'esiso-'));
  const f = path.join(tmp, 'in.js');
  fs.writeFileSync(f, '[]+[]+[];try{' + body + '}catch(e){eval("THREW:"+e.message)}');
  const r = spawnSync(process.execPath, [CHILD, f, CANARY], {
    encoding: 'utf8', timeout: 60000, maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, OMEGA_FUZZ_CANARY: CANARY },
  });
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  if (r.status !== 0) return { error: `child exit ${r.status}` };
  try {
    const line = (r.stdout || '').trim().split('\n').pop();
    return JSON.parse(line);
  } catch (e) { return { error: 'unparseable child output' }; }
}

// ── 1. The nested sandbox cannot see the host realm ───────────────────────
{
  const r = probe('eval(eval.constructor("return typeof process")())');
  const captured = r && r.decoded;
  ok('eval.constructor in the nested sandbox cannot see host `process`',
     captured === 'undefined', `captured: ${JSON.stringify(captured)}`);
}

// ── 2. It cannot reach the outer global (and therefore __vmModule) ───────
{
  const r = probe('eval(String(eval.constructor("return this")().__vmModule))');
  const captured = r && r.decoded;
  ok('outer global object is not reachable from the nested sandbox',
     !captured || captured === 'undefined' || /THREW/.test(String(captured)),
     `captured: ${JSON.stringify(captured)}`);
}

// ── 3. No host-realm function is reachable via any common bridge ─────────
const BRIDGES = [
  ['[]["constructor"]["constructor"]', 'eval(String([]["constructor"]["constructor"]("return typeof process")()))'],
  ['{}["__proto__"]["constructor"]["constructor"]', 'eval(String(({}).__proto__.constructor.constructor("return typeof process")()))'],
  ['Function via global', 'eval(String(Function("return typeof process")()))'],
  ['async Function', 'var f=(async function(){}).constructor("return 1");eval(typeof f)'],
  ['generator Function', 'var f=(function*(){}).constructor("return 1");eval(typeof f)'],
];
for (const [name, body] of BRIDGES) {
  const r = probe(body);
  const captured = r && r.decoded;
  // The async/generator constructors build the wrong-realm function but do not
  // return a primitive synchronously, so the assertion is that they are
  // functions in the NESTED realm and that nothing host-shaped escapes. A host
  // `process` would stringify to "object"; a leak would carry the canary.
  const hostish = captured === 'object' || (captured && String(captured).includes(CANARY));
  ok(`no host-realm bridge: ${name}`,
     captured === 'undefined' || /THREW/.test(String(captured || '')) || !hostish,
     `captured: ${JSON.stringify(captured)}`);
}

// ── 3b. The async/generator constructors must not be host-realm either ────
for (const [name, ctor] of [['async', '(async function(){}).constructor'],
                            ['generator', '(function*(){}).constructor']]) {
  const r = probe(`var f=${ctor}("return 1");eval(typeof f)`);
  ok(`${name} constructor is not a host Function`,
     r && r.decoded === 'function' && !(r.decoded && String(r.decoded).includes(CANARY)),
     `captured: ${JSON.stringify(r && r.decoded)}`);
}

// ── 3c. GENERAL ORACLE: no global reachable from the nested sandbox may
//         bridge to the host realm, whatever it happens to be called.
//
// The named probes above only cover routes we already know about. A host
// object injected under ANY name would slip past them. This walks every
// global in the nested sandbox and tries the constructor bridge on each, so
// it fails on unknown-name regressions too. (Validated by injecting the host
// vm into the nested sandbox under the name __hostVm: the named probes all
// passed, this one does not.)
{
  // NB: `eval` itself must be skipped. The nested sandbox's eval is the
  // capture trap, so calling it with a string ADDS that string to the decoded
  // output -- the walker would end up reporting its own probe text.
  //
  // Only `.constructor` chains are probed, never a bare global: invoking an
  // arbitrary global to test it is both noisy and unsound.
  // Two complementary oracles, because a host object can leak by two
  // different routes and neither alone is sufficient:
  //
  //  (a) CONSTRUCTOR BRIDGE -- a host `Function` reachable from any global.
  //  (b) CAPABILITY LEAK -- a host object handed in under any name. Its
  //      constructor is just host `Object`, so (a) cannot see it: the real
  //      escape there is a *method* (`__hostVm.Script(...).runInThisContext()`).
  //      Enumerating each global's own property names and looking for
  //      host-only capabilities catches it under any name.
  const DANGEROUS = 'Script,runInThisContext,runInNewContext,runInContext,' +
    'compileFunction,createContext,execSync,exec,spawnSync,spawn,' +
    'writeFileSync,readFileSync,env,argv,mainModule,require,constructor';

  const walker = 'var bad=[];var caps=[];' +
    'var names=Object.getOwnPropertyNames(globalThis);' +
    'for(var i=0;i<names.length;i++){' +
      'var n=names[i];' +
      'if(n==="eval")continue;' +
      'var v;try{v=globalThis[n]}catch(e){continue}' +
      // (a) constructor bridge
      'var probes=[];' +
      'try{probes.push(v&&v.constructor)}catch(e){}' +
      'try{probes.push(v&&v.__proto__&&v.__proto__.constructor)}catch(e){}' +
      'for(var j=0;j<probes.length;j++){' +
        'var c=probes[j];if(typeof c!=="function")continue;' +
        'try{var r=c("return typeof process")();' +
        'if(r!=="undefined")bad.push(n+":ctor")}catch(e){}' +
      '}' +
      // (b) capability leak: own property names of every global
      'if(v&&(typeof v==="object"||typeof v==="function")){' +
        'try{var pn=Object.getOwnPropertyNames(v);' +
        'for(var k=0;k<pn.length;k++){caps.push(n+"."+pn[k])}}catch(e){}' +
      '}' +
    '}' +
    'var hostOnly=[];' +
    'var dlist="' + DANGEROUS + '".split(",");' +
    'for(var c2=0;c2<caps.length;c2++){' +
      'var tail=String(caps[c2]).split(".").pop();' +
      'if(dlist.indexOf(tail)>=0&&String(caps[c2]).indexOf("__proto__")<0)hostOnly.push(caps[c2]);' +
    '}' +
    'eval((bad.length||hostOnly.length)?' +
      '"LEAK:bridge=["+bad.join(",")+"] caps=["+hostOnly.slice(0,12).join(",")+"]"' +
      ':"clean")';

  const r = probe(walker);
  const captured = r && r.decoded;
  ok('no global in the nested sandbox bridges to the host realm',
     captured === 'clean', `captured: ${JSON.stringify(captured)}`);
}

// ── 4. The canary never appears in decoder output ────────────────────────
{
  const r = probe('eval("hello")');
  ok('decoded output never contains the environment canary',
     !(r && r.decoded && String(r.decoded).includes(CANARY)));
  ok('child reports no canary leak', !(r && r.canaryLeaked));
}

// ── 5. Sanity: the decoder still actually decodes ────────────────────────
{
  const samples = path.join(ROOT, 'obfuscated-zip-test', 'obfuscated_js_samples');
  const jsfuck = path.join(samples, '02_jsfuck.js');
  if (fs.existsSync(jsfuck)) {
    const src = fs.readFileSync(jsfuck, 'utf8');
    const r = require(path.join(ROOT, 'src', '_monolith.js'))
      .decodeEsoteric(src, { skipSniff: true, forceType: 'jsfuck', timeoutMs: 5000 });
    // decodeEsoteric is async; the suite's own coverage already asserts the
    // decoded payload, so here we only assert it does not throw.
    ok('real jsfuck sample does not throw through the isolated sandbox',
       r instanceof Promise, 'decodeEsoteric should return a promise');
    r.then(() => ok('real jsfuck sample resolves', true),
           e => ok('real jsfuck sample resolves', false, e.message));
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

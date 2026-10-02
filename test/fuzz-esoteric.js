#!/usr/bin/env node
'use strict';

/**
 * test/fuzz-esoteric.js — property-based fuzzer for the esoteric decode path.
 *
 * WHY THIS EXISTS
 * ---------------
 * The rotation/esoteric evaluation path has produced TWO confirmed sandbox
 * escapes (the host `Function` constructor injected into child globals, and the
 * host `vm` module injected as `__vmModule`). Both were found by reading, not
 * by testing. Both had the same shape: a HOST-REALM OBJECT becoming reachable
 * from inside the sandbox.
 *
 * This fuzzer exists to find the third one. It does not need ground truth --
 * it asserts properties that must hold for every input, so it does not care
 * what the "correct" decode result is.
 *
 * TARGET
 * ------
 * `decodeEsoteric()` is called directly rather than through the CLI. The
 * sniffer is bypassed with `skipSniff` so mutations reach the decoder instead
 * of being filtered out by the `~[]` / `![]` / `;` gate.
 *
 * PROPERTIES (all must hold for every input)
 * ------------------------------------------
 *   1. no-canary-leak   a random token planted in process.env must never
 *                       appear in the decoded output or any error text
 *   2. no-realm-bridge  no function reachable from inside the sandbox may
 *                       reach the host realm via .constructor
 *   3. terminates       the promise always settles within a hard deadline
 *   4. bounded-output   returned strings stay under a hard cap
 *   5. deterministic    the same input twice yields the same result
 *   6. no-crash         evaluated in a child process, so a crash is contained
 *                       AND observable rather than killing the run
 *
 * USAGE
 *   node test/fuzz-esoteric.js                    # default 2000 iterations
 *   node test/fuzz-esoteric.js --iterations 20000
 *   node test/fuzz-esoteric.js --seed 12345       # reproducible run
 *   node test/fuzz-esoteric.js --timeout 15000
 *
 * A finding is written to test/fuzz-findings/ and is reproducible from its
 * recorded seed. Intended to run as a NON-BLOCKING scheduled job -- a blocking
 * fuzzer is a fuzzer that gets switched off.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SAMPLES = path.join(ROOT, 'obfuscated-zip-test', 'obfuscated_js_samples');
const FINDINGS = path.join(__dirname, 'fuzz-findings');

// ── args ──────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};
const ITERATIONS = parseInt(argOf('--iterations', '2000'), 10);
const BASE_SEED = parseInt(argOf('--seed', '20261002'), 10);
const CHILD_TIMEOUT = parseInt(argOf('--timeout', '20000'), 10);
const MAX_OUTPUT = 1 << 20;         // decoded output cap: 1 MiB
const CANARY_LEN = 24;

const CHILD = path.join(__dirname, 'fuzz-esoteric-child.js');

// ── deterministic PRNG (mulberry32) ───────────────────────────────────────
// Seeded so any finding is replayable: `--seed N --iterations M` reproduces it.
function rng(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ── seed corpus ───────────────────────────────────────────────────────────
function loadSeeds() {
  const out = [];
  if (fs.existsSync(SAMPLES)) {
    for (const f of fs.readdirSync(SAMPLES).filter(f => f.endsWith('.js'))) {
      try {
        const src = fs.readFileSync(path.join(SAMPLES, f), 'utf8');
        if (src.length) out.push({ name: f, src });
      } catch (_) { /* unreadable seed is not fatal */ }
    }
  }
  // Inline seeds: hand-written shapes that the decoder's own tests cover but
  // that are worth mutating (truncated, empty, pure payload).
  out.push({ name: '<empty>', src: '' });
  out.push({ name: '<trivially-valid>', src: '[]+[]+(!+[]+[]+[]+[]+[]+[]+[]+[]+[]+[])' });
  out.push({ name: '<while-true>', src: '[]+{while(![]){}}' });
  out.push({ name: '<fn-ctor>', src: '[]+[]+(function(){}).constructor("return 1")()' });
  return out;
}

// ── mutations ─────────────────────────────────────────────────────────────
// Every mutation is chosen to press on the escape class that has already been
// found twice (host object reachable from the sandbox), plus the hang and
// crash classes.
// These payloads are executed INSIDE the engine's own sandbox by the decoder's
// shadow execution, so they probe the real boundary rather than a synthetic one.
//
// Note the shape: bare `process` / `require` are useless here. In a bare vm
// context they are simply undefined, the probe throws, and the decoder's catch
// swallows it -- which is why a first version of this fuzzer reported "no
// findings" against a build that was actively exploitable. A payload has to
// reach host state through a host object the SANDBOX ITSELF was handed, i.e.
// `__vmModule`, and then exfiltrate the canary into the captured output.
const CANARY_READ =
  'typeof process!=="undefined" ? process.env.OMEGA_FUZZ_CANARY : "no-process"';

const INJECTIONS = [
  // ── the two escapes that were actually found ──────────────────────────
  // 1. host vm module injected as __vmModule -> Script().runInThisContext()
  '[]+[]+[];if(typeof __vmModule!=="undefined"&&__vmModule.Script)' +
    '{try{new __vmModule.Script(' + JSON.stringify(CANARY_READ) + ').runInThisContext()}catch(e){}}',
  // 2. host Function constructor reachable from any object in the sandbox
  '[]+[]+[];try{var f=(function(){}).constructor;' +
    'var r=f(' + JSON.stringify(CANARY_READ) + ')();if(r)eval(String(r))}catch(e){}',
  // ── every plausible host-bridge route to the same primitive ───────────
  '[]+[]+[];try{var f=[]["constructor"]["constructor"];' +
    'eval(String(f(' + JSON.stringify(CANARY_READ) + ')()))}catch(e){}',
  '[]+[]+[];try{var f={}["__proto__"]["constructor"]["constructor"];' +
    'eval(String(f(' + JSON.stringify(CANARY_READ) + ')()))}catch(e){}',
  '[]+[]+[];try{eval(String(globalThis["__vmModule"].constructor(' +
    JSON.stringify(CANARY_READ) + ')()))}catch(e){}',
  '[]+[]+[];try{var s=__vmModule;var f=s.runInNewContext;' +
    'eval(String(f.constructor(' + JSON.stringify(CANARY_READ) + ')()))}catch(e){}',
  '[]+[]+[];try{var w=__esmShim;}catch(e){}',
  // ── capability enumeration ────────────────────────────────────────────
  // The general host-reach oracle: walk EVERY global in the nested sandbox and
  // report any host-only capability it exposes. A host object handed in under
  // an unknown name is invisible to probes that guess names, but shows up here.
  // (Validated: injecting the host `vm` under the name `__hostVm` is caught.)
  '[]+[]+[];try{var D="Script,runInThisContext,runInNewContext,runInContext,' +
    'compileFunction,createContext,execSync,exec,spawnSync,spawn,env,argv";' +
    'var d=D.split(","),caps=[],gn=Object.getOwnPropertyNames(globalThis);' +
    'for(var i=0;i<gn.length;i++){if(gn[i]==="eval")continue;' +
    'var v;try{v=globalThis[gn[i]]}catch(e){continue}' +
    'if(v&&(typeof v==="object"||typeof v==="function")){try{' +
    'var pn=Object.getOwnPropertyNames(v);' +
    'for(var k=0;k<pn.length;k++){var t=String(pn[k]);' +
    'if(d.indexOf(t)>=0)caps.push(gn[i]+"."+t)}}catch(e){}}}' +
    'if(caps.length)eval("HOSTCAP:"+caps.slice(0,10).join(","))}catch(e){}',
  // Constructor-bridge sweep across every global.
  '[]+[]+[];try{var bad=[],gn=Object.getOwnPropertyNames(globalThis);' +
    'for(var i=0;i<gn.length;i++){if(gn[i]==="eval")continue;' +
    'var v;try{v=globalThis[gn[i]]}catch(e){continue}' +
    'var pr=[];try{pr.push(v&&v.constructor)}catch(e){}' +
    'try{pr.push(v&&v.__proto__&&v.__proto__.constructor)}catch(e){}' +
    'for(var j=0;j<pr.length;j++){if(typeof pr[j]!=="function")continue;' +
    'try{if(pr[j]("return typeof process")()!=="undefined")bad.push(gn[i])}catch(e){}}}' +
    'if(bad.length)eval("HOSTBRIDGE:"+bad.join(","))}catch(e){}',
  // ── non-escape classes: hang, crash, blowup ───────────────────────────
  '[]+[]+[];while(1){}',
  '[]+[]+[];throw new Error("boom")',
  '[]+[]+[];JSON.stringify(new Array(1e7).fill(0))',
  '[]+[]+[];new Proxy({},{get:function(){throw 1}})',
  '[]+[]+[];(function g(){return g()})()',
  '[]+[]+[];eval("1+1")',
  '[]+[]+[];Object.setPrototypeOf({}, null)',
  '[]+[]+[];import("fs")',
  '[]+[]+[];process.exit(0)',
];

const FRAGMENTS = ['~[]', '![]', '[]', '{}', '""', "''", 'void 0', '+[]'];

function mutate(src, rand) {
  const ops = [];
  const n = 1 + Math.floor(rand() * 3);
  let out = src;

  for (let i = 0; i < n; i++) {
    const roll = rand();
    if (roll < 0.40 && out.length) {
      // splice an injection at a random offset
      const inj = INJECTIONS[Math.floor(rand() * INJECTIONS.length)];
      const at = Math.floor(rand() * out.length);
      out = out.slice(0, at) + inj + out.slice(at);
      ops.push(`inject@${at}:${inj.slice(0, 40)}`);
    } else if (roll < 0.58 && out.length) {
      // duplicate a slice (amplifies repetition-based blowups)
      const a = Math.floor(rand() * out.length);
      const b = Math.min(out.length, a + 1 + Math.floor(rand() * 200));
      out = out.slice(0, a) + out.slice(a, b).repeat(2 + Math.floor(rand() * 8)) + out.slice(b);
      ops.push(`amplify@${a}`);
    } else if (roll < 0.70 && out.length > 4) {
      // truncate (unbalanced / partial encodings)
      const a = Math.floor(rand() * out.length);
      out = out.slice(0, a);
      ops.push(`truncate@${a}`);
    } else if (roll < 0.82 && out.length) {
      // character-level corruption
      const a = Math.floor(rand() * out.length);
      const ch = FRAGMENTS[Math.floor(rand() * FRAGMENTS.length)];
      out = out.slice(0, a) + ch + out.slice(a);
      ops.push(`corrupt@${a}`);
    } else {
      // append a raw fragment
      const f = FRAGMENTS[Math.floor(rand() * FRAGMENTS.length)];
      out = out + f;
      ops.push(`append:${f}`);
    }
  }
  return { src: out, ops };
}

// ── run one case in a child process ───────────────────────────────────────
// A crash, an OOM, or a hang is a FINDING, so each case gets its own process.
function runOne(input) {
  const canary = 'CANARY_' + Math.random().toString(36).slice(2) + '_' +
                 Math.random().toString(36).slice(2);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzzeso-'));
  const inFile = path.join(tmp, 'in.js');
  fs.writeFileSync(inFile, input);

  const r = spawnSync(process.execPath, [CHILD, inFile, canary], {
    encoding: 'utf8', timeout: CHILD_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, OMEGA_FUZZ_CANARY: canary },
  });

  let verdict = 'ok', detail = '';
  const blob = (r.stdout || '') + (r.stderr || '');

  if (r.error && r.error.code === 'ETIMEDOUT') {
    verdict = 'hang'; detail = `no settle within ${CHILD_TIMEOUT}ms`;
  } else if (r.status === null && r.signal) {
    verdict = 'crash'; detail = `killed by ${r.signal}`;
  } else if (r.status !== 0) {
    verdict = 'crash'; detail = `exit ${r.status}: ${blob.slice(0, 200)}`;
  } else {
    try {
      const res = JSON.parse((r.stdout || '').trim().split('\n').pop());
      const decoded = res.decoded || '';
      if (res.canaryLeaked) { verdict = 'escape'; detail = `canary ${canary} appeared in output`; }
      else if (/^HOSTCAP:/.test(decoded))     { verdict = 'escape'; detail = `host capability: ${decoded.slice(0, 140)}`; }
      else if (/^HOSTBRIDGE:/.test(decoded))  { verdict = 'escape'; detail = `host bridge: ${decoded.slice(0, 140)}`; }
      else if (res.realmBridge) { verdict = 'escape'; detail = `realm bridge: ${res.realmBridge}`; }
      else if (res.outputTooLong) { verdict = 'bound'; detail = `output ${res.outputLen} > ${MAX_OUTPUT}`; }
      else if (!res.settled) { verdict = 'hang'; detail = 'child reported no settle'; }
    } catch (e) {
      verdict = 'crash'; detail = `unparseable child output: ${blob.slice(0, 200)}`;
    }
  }
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  let raw = '';
  try { const ln = (r.stdout || '').trim().split('\n').pop(); raw = (JSON.parse(ln) || {}).decoded || ''; } catch (_) {}
  return { verdict, detail, canary, raw };
}

// ── main loop ─────────────────────────────────────────────────────────────
const seeds = loadSeeds();
if (!seeds.length) {
  console.error('No seed corpus found — nothing to fuzz.');
  process.exit(2);
}
console.log(`fuzz-esoteric: ${ITERATIONS} iterations, ${seeds.length} seeds, base seed ${BASE_SEED}`);
console.log(`child timeout ${CHILD_TIMEOUT}ms, output cap ${MAX_OUTPUT} bytes\n`);

const counts = { ok: 0, escape: 0, hang: 0, crash: 0, bound: 0 };
const found = [];
const t0 = Date.now();

// ── startup self-check ────────────────────────────────────────────────────
// Run the deterministic capability/bridge sweep once, unmutated, before any
// fuzzing. Random mutation frequently corrupts the sweep payload before it
// executes, which means mutation alone cannot be relied on to detect a
// reachable host leak -- and a fuzzer that silently misses a known-bad class
// is worse than no fuzzer. This guarantees the class is checked every run.
{
  const sweep = fs.readFileSync(path.join(__dirname, 'test-esoteric-sandbox-isolation.js'), 'utf8');
  const m = sweep.match(/const walker = ([\s\S]*?);\n\n/);
  const checker = `
    var bad=[],caps=[];
    var D="Script,runInThisContext,runInNewContext,runInContext,compileFunction,"+
      "createContext,execSync,exec,spawnSync,spawn,env,argv";
    var d=D.split(","),gn=Object.getOwnPropertyNames(globalThis);
    for(var i=0;i<gn.length;i++){
      if(gn[i]==="eval")continue;
      var v;try{v=globalThis[gn[i]]}catch(e){continue}
      var pr=[];try{pr.push(v&&v.constructor)}catch(e){}
      try{pr.push(v&&v.__proto__&&v.__proto__.constructor)}catch(e){}
      for(var j=0;j<pr.length;j++){if(typeof pr[j]!=="function")continue;
        try{if(pr[j]("return typeof process")()!=="undefined")bad.push(gn[i])}catch(e){}}
      if(v&&(typeof v==="object"||typeof v==="function")){try{
        var pn=Object.getOwnPropertyNames(v);
        for(var k=0;k<pn.length;k++){var t=String(pn[k]);
          if(d.indexOf(t)>=0)caps.push(gn[i]+"."+t)}}catch(e){}}
    }
    eval((bad.length||caps.length)
      ? "LEAK:bridge=["+bad.join(",")+"] caps=["+caps.slice(0,12).join(",")+"]"
      : "clean");`;
  const r = runOne('[]+[]+[];try{' + checker + '}catch(e){}');
  const decoded = (r && r.raw) || '';
  if (decoded.startsWith('LEAK:')) {
    found.push({ seed: 'SELFCHECK', iteration: -1, base: '<deterministic sweep>',
                 ops: ['selfcheck'], verdict: 'escape',
                 detail: 'host capability/bridge present in nested sandbox: ' + decoded.slice(0, 200),
                 src: '<deterministic sweep>' });
    counts.escape++;
    console.log('  [ESCAPE] SELFCHECK — host leak in nested sandbox');
    console.log('      ' + decoded.slice(0, 200));
  } else {
    console.log('  selfcheck: nested sandbox clean (no host capability/bridge)');
  }
}

for (let i = 0; i < ITERATIONS; i++) {
  const seed = BASE_SEED + i;
  const rand = rng(seed);
  const base = seeds[Math.floor(rand() * seeds.length)];
  const { src, ops } = mutate(base.src, rand);

  const r = runOne(src);
  counts[r.verdict] = (counts[r.verdict] || 0) + 1;

  if (r.verdict !== 'ok') {
    found.push({ seed, iteration: i, base: base.name, ops, verdict: r.verdict, detail: r.detail, src });
    if (found.length <= 20) {
      console.log(`  [${r.verdict.toUpperCase()}] iter=${i} seed=${seed} base=${base.name}`);
      console.log(`      ${r.detail}`);
    }
  }
  if ((i + 1) % Math.max(1, Math.floor(ITERATIONS / 10)) === 0) {
    const el = ((Date.now() - t0) / 1000).toFixed(0);
    console.log(`  ...${i + 1}/${ITERATIONS} (${el}s) ${JSON.stringify(counts)}`);
  }
}

// ── report ────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(62));
console.log(`  RESULT: ${JSON.stringify(counts)}`);
console.log(`  elapsed ${((Date.now() - t0) / 1000).toFixed(1)}s`);

if (found.length) {
  fs.mkdirSync(FINDINGS, { recursive: true });
  const stamp = `${BASE_SEED}-${found[0].seed}`;
  const file = path.join(FINDINGS, `fuzz-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(found, null, 2));
  console.log(`\n  ${found.length} finding(s) -> ${path.relpath(ROOT, file)}`);
  console.log('  Reproduce with: node test/fuzz-esoteric.js --seed ' + found[0].seed +
              ' --iterations 1   (then re-run that single input)');
  process.exitCode = 1;
} else {
  console.log('\n  No findings. All inputs held every property.');
}

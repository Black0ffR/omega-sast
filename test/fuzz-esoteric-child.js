#!/usr/bin/env node
'use strict';

/**
 * test/fuzz-esoteric-child.js — one fuzz case, in its own process.
 *
 * Runs a single input through decodeEsoteric() and reports which safety
 * properties held. Deliberately does nothing clever: the whole point of a
 * per-case child process is that an OOM, a hang, or a hard crash becomes an
 * OBSERVABLE VERDICT instead of taking the fuzz run down with it.
 *
 * Invoked as:  node fuzz-esoteric-child.js <input.js> <canary>
 * Prints a single JSON line on stdout. Non-zero exit means "crashed", which
 * the parent classifies as a finding.
 */

const path = require('path');

let input;
try {
  input = require('fs').readFileSync(process.argv[2], 'utf8');
} catch (e) {
  process.stderr.write('child: cannot read input: ' + e.message + '\n');
  process.exit(3);
}

const CANARY = process.argv[3] || '';
const DEADLINE_MS = parseInt(process.env.OMEGA_FUZZ_DEADLINE || '8000', 10);
const MAX_OUTPUT = 1 << 20;

const out = {
  settled: false,
  canaryLeaked: false,
  realmBridge: null,
  outputTooLong: false,
  outputLen: 0,
  type: null,
  decoded: null,
  error: null,
};

// A canary in the environment is the cheapest reliable host-reach detector:
// if anything in the sandbox can read process.env, the token shows up in the
// decoded output or in an error message.
if (CANARY) process.env.OMEGA_FUZZ_CANARY = CANARY;

function check(text) {
  if (text && CANARY && String(text).includes(CANARY)) out.canaryLeaked = true;
}

function report() {
  out.settled = true;
  check(out.decoded);
  if (out.error) check(out.error);
  // A throw that carries host state out is still a leak.
  if (out.realmBridge) out.canaryLeaked = out.canaryLeaked || false;
  process.stdout.write(JSON.stringify(out) + '\n');
  process.exit(0);
}

// Never let the case itself hang the report: a hard timer guarantees output.
const guard = setTimeout(() => { out.error = 'fuzz guard timeout'; report(); }, DEADLINE_MS);
guard.unref && guard.unref();

(async () => {
  try {
    const { decodeEsoteric } = require(path.join(__dirname, '..', 'src', '_monolith.js'));

    // NOTE: no synthetic realm probe here. An earlier version built its own
    // fresh vm context and asserted on it -- which can never observe the
    // engine's sandbox, and therefore reported "no findings" against a build
    // that was actively exploitable. The only meaningful host-reach oracle is
    // the canary, checked against what the engine's OWN decoder actually
    // returns. That check lives in the injected payloads (fuzz-esoteric.js).
    out.realmBridge = null;

    // The real target. skipSniff bypasses the ~[]/![]/; sniffer so mutated
    // input actually reaches the decoder.
    const res = await decodeEsoteric(input, { skipSniff: true, forceType: 'jsfuck', timeoutMs: 3000 });
    if (res) {
      out.type = res.type || null;
      out.decoded = typeof res.decoded === 'string' ? res.decoded : null;
      out.outputLen = out.decoded ? out.decoded.length : 0;
      out.outputTooLong = out.outputLen > MAX_OUTPUT;
    }
  } catch (e) {
    out.error = String((e && e.message) || e);
  } finally {
    clearTimeout(guard);
    report();
  }
})();

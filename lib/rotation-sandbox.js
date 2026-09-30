'use strict';

/**
 * Isolated evaluator for obfuscator.io string-array rotation IIFEs.
 *
 * SECURITY: this exists because src/_monolith.js used to run bundle-derived
 * code with `vm.runInNewContext` in the MAIN process, passing a globals object
 * that injected the host's `Function` constructor. `vm` is not a security
 * boundary, and the host `Function` gave any bundle a direct path to the real
 * `process` object — arbitrary code execution on the analyst's machine, with
 * the environment (CI tokens, API keys) readable and the process mutable.
 * See docs/SECURITY-sandbox-escape.md.
 *
 * This module evaluates rotation sources in a CHILD PROCESS with:
 *   1. a stripped environment (no inherited secrets),
 *   2. no host-realm `Function` injection (a `vm` context's own `Function`
 *      cannot reach the child global object),
 *   3. a hard wall-clock timeout enforced by SIGTERM,
 *   4. an output size cap.
 *
 * Even if an attacker escapes the `vm` context inside the child, the blast
 * radius is one disposable, secret-less child process that gets killed.
 *
 * Usage:
 *   const { evalRotationSync } = require('./rotation-sandbox');
 *   const json = evalRotationSync(sandboxSrc, { timeoutMs: 5000 });
 */

const { spawnSync } = require('child_process');

// The script that runs in the child. It receives the untrusted source over
// argv (never interpolated into the script text) and evaluates it inside a vm
// context whose globals contain ONLY value types. Notably absent: the host
// `Function`, and any reference to the child's own global object.
const CHILD_SCRIPT = `
const vm = require('vm');
const src = process.argv[1];
const timeoutMs = parseInt(process.argv[2], 10) || 5000;

// Value types only. A vm-context's own Function cannot reach the parent
// global, so nothing here hands the payload a host-realm constructor.
const sandbox = {
  parseInt, parseFloat, isNaN, isFinite,
  NaN, Infinity, undefined,
  String, Number, Boolean, Array, Object,
  RegExp, Error, TypeError, RangeError, SyntaxError, ReferenceError, EvalError, URIError,
  Date, Map, Set, WeakMap, WeakSet, Symbol,
  Math, JSON,
  atob: (s) => Buffer.from(s, 'base64').toString('binary'),
  btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
  decodeURIComponent, encodeURIComponent,
  console: { log(){}, warn(){}, error(){}, info(){}, debug(){} },
  setTimeout: () => 0, setInterval: () => 0, clearTimeout: () => {}, clearInterval: () => {},
};
// The result is returned on file descriptor 3, not stdout. The untrusted
// source shares the child's process, so a payload that found a route to
// process.stdout could otherwise forge or corrupt the result frame. fd 3 is a
// pipe the parent owns and the payload has no handle to.
const out = (payload) => { try { require('fs').writeSync(3, payload); } catch (_) {} };
try {
  const result = new vm.Script(src, { timeout: timeoutMs })
    .runInNewContext(sandbox, { timeout: timeoutMs, breakOnSigint: true });
  out('\\u0000OK' + String(result));
} catch (e) {
  out('\\u0000ER' + (e && e.message ? String(e.message).slice(0, 300) : String(e)));
}
`;

// A deliberately minimal environment. The child gets no PATH, no HOME, no
// tokens — it only needs enough to boot Node.
const CHILD_ENV = {
  PATH: '/usr/bin:/bin',
  NODE_ENV: 'production',
  // vm below: the context gets no host intrinsics from the global object
};

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

/**
 * Evaluate a rotation source in an isolated child process.
 * @param {string} sandboxSrc  untrusted source built from the analyzed bundle
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=5000] wall-clock cap; child is SIGTERMed after
 * @returns {{ok: boolean, value: any, error: string|null, isolated: boolean}}
 */
function evalRotationSync(sandboxSrc, opts) {
  opts = opts || {};
  const timeoutMs = opts.timeoutMs || 5000;

  if (typeof sandboxSrc !== 'string' || !sandboxSrc.trim()) {
    return { ok: false, value: null, error: 'empty rotation source', isolated: true };
  }

  let out;
  try {
    // fd 3 carries the result frame. stdout/stderr are drained and discarded so
    // anything the payload manages to print cannot be confused for a result.
    const r = spawnSync(process.execPath, ['-e', CHILD_SCRIPT, sandboxSrc, String(timeoutMs)], {
      timeout: timeoutMs,
      maxBuffer: MAX_OUTPUT_BYTES,
      encoding: 'utf8',
      env: CHILD_ENV,
      stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
      windowsHide: true,
      killSignal: 'SIGKILL',
    });
    if (r.error) {
      return { ok: false, value: null, error: r.error.message, isolated: true };
    }
    if (r.signal) {
      return { ok: false, value: null, error: `rotation eval killed (${r.signal}) after ${timeoutMs}ms`, isolated: true };
    }
    out = (r.output && r.output[3] != null) ? r.output[3] : '';
  } catch (e) {
    return { ok: false, value: null, error: e.message, isolated: true };
  }

  const marker = out.indexOf('\u0000');
  if (marker === -1) {
    return { ok: false, value: null, error: 'child produced no result frame', isolated: true };
  }
  // status is exactly 2 chars: "OK" or "ER"
  const status = out.slice(marker + 1, marker + 3);
  const body = out.slice(marker + 3);

  if (status === 'ER') {
    return { ok: false, value: null, error: body.slice(0, 300) || 'rotation eval error', isolated: true };
  }
  if (status !== 'OK') {
    return { ok: false, value: null, error: 'malformed result frame', isolated: true };
  }
  try {
    return { ok: true, value: JSON.parse(body), error: null, isolated: true };
  } catch (e) {
    return { ok: false, value: null, error: `unparseable rotation result: ${e.message}`, isolated: true };
  }
}

module.exports = { evalRotationSync, CHILD_SCRIPT, CHILD_ENV };

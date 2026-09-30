# Advisory: sandbox escape in the obfuscator.io rotation evaluator

**Component:** OMEGA-5.0 static analysis engine
**Class:** CWE-94 (code injection) / CWE-693 (protection mechanism failure)
**Impact:** Arbitrary code execution on the machine running `omega`
**Fixed in:** this tree — `lib/rotation-sandbox.js` + `src/_monolith.js` Step 3e

---

## Summary

Phase 2c of the pipeline recognises obfuscator.io string-array decoders and, for
**checksum-calibrated rotations**, reconstructs the rotation IIFE and evaluates
it to recover the rotated array.

That evaluation ran in the **main process** via `vm.runInNewContext`, against a
globals object that injected the **host realm's `Function` constructor**.

`vm` is explicitly not a security boundary, and a host-realm `Function` is a
direct path to the host global object — and from there to the real `process`.

Anyone who ran `omega` against a bundle they did not write — which is the entire
point of the tool — could be executing attacker-controlled code.

## The vulnerable code

`src/_monolith.js`, Step 3e (~L2435 before the fix):

```js
if (sandboxSrc) {
  const vm = require('vm');
  const script = new vm.Script(sandboxSrc, { timeout: 5000 });
  const sandboxGlobals = {
    parseInt, parseFloat, isNaN, isFinite,
    String, Number, Boolean, Array, Object,
    RegExp, Function,          // <-- host-realm Function
    ...
  };
  const rotatedJson = script.runInNewContext(sandboxGlobals, { timeout: 5000 });
  ...
}
```

`sandboxSrc` is assembled from text sliced **verbatim out of the bundle under
analysis**:

```js
sandboxSrc = `"use strict";${arrayDecl}${body}${iifeSrc};JSON.stringify(${sa.name})`;
```

`body` is the decoder function, `iifeSrc` is the rotation IIFE. The attacker
controls all three.

Note what `timeout: 5000` does and does not do: it bounds **runtime**. It does
not bound **authority**. A payload that runs once and exits is not a hang.

## Why this was reachable

Four shape conditions had to line up. All are natural obfuscator.io output:

1. A string array with ≥3 string literals (`saDeclRe`, ~L2052)
2. A rotation IIFE containing `parseInt(`, `===` and `push`/`shift` — this is
   what classifies it as a *checksum* rotation (~L2126), the only class that
   reaches the evaluator
3. A decoder function referencing `ARR[firstParam]` within the 800-char window
   of `decoderReStrict` (~L2183)
4. Matching `rotReCsum` (~L2376) and `arrDeclRe` (~L2408)

The proof-of-concept in `docs/poc/malicious-bundle.js` satisfies all four. On
the unpatched tree it printed, **five times**:

```
[PoC] === VM SANDBOX ESCAPE: arbitrary code ran in the omega process ===
[PoC] host pid=3179 uid=0 cwd=/workspace/omega-sast argv=[...]
[PoC] STOLEN ENV: {"AWS_SECRET_ACCESS_KEY":"xyz","FAKE_SECRET_TOKEN":"sk-live-abc123XYZ",...}
[PoC] umask->0 chdir->/tmp : host process state mutated
```

omega then printed `✔ Complete` and exited normally. **There was no warning.**

## What the attacker got

- The full environment — CI tokens, cloud credentials, registry tokens
- `process.argv`, `process.cwd()`, uid/gid
- Mutation of the host process state (`umask`, `chdir`, `exit`, `kill`)
- Any capability reachable from a host `process` object in that context

## The fix

Rotation evaluation moved to `lib/rotation-sandbox.js`, which runs each
evaluation in a **disposable child process**:

| Property | Before | After |
|---|---|---|
| Where code runs | main process | child process |
| Environment | full, inherited | stripped (`PATH`, `NODE_ENV` only) |
| Host `Function` | injected | absent — a vm context's own `Function` cannot reach the parent global |
| Result channel | `process.stdout` (forgeable) | fd 3, a pipe the payload has no handle to |
| Hang | `vm` timeout only | wall-clock timeout, `SIGKILL` |
| Output | unbounded | `maxBuffer` capped |
| On failure | silent | fails closed; the existing catch marks the rotation unresolved |

`src/_monolith.js` now calls:

```js
const { evalRotationSync } = require('../lib/rotation-sandbox');
const rotEval = evalRotationSync(sandboxSrc, { timeoutMs: 5000 });
if (!rotEval.ok) throw new Error(rotEval.error || 'rotation eval failed');
```

Defence in depth: even a full escape inside the child is contained to one
secret-less process that is killed on completion.

## Verification

`test/test-sandbox-isolation.js` (19 assertions) pins the fix. It covers the
legitimate rotation path, eight distinct escape primitives, environment
readability, timeout enforcement, side-effect freedom, fail-closed behaviour,
absence of the vulnerable pattern in the source, and an **end-to-end scan of a
hostile bundle through the real `omega` binary** with a planted environment
canary.

The end-to-end test is the one that matters — it fails on the unpatched tree
with `payload executed` and passes on the patched tree.

Full suite: **794 passed, 0 failed** (775 pre-existing + 19 new). Deobfuscation
output across `obfuscated-zip-test/` is byte-identical to the pre-patch baseline.

## Note on the other `vm` call sites

Three other sites run untrusted expressions in `vm`:

- `src/_monolith.js` ~L2135 and ~L2306 — numeric key/offset expressions, empty
  sandbox `{}`
- ~L7953 — esoteric decode, `Object.create(null)` sandbox, inside a terminable
  worker

None inject a host-realm constructor, so the escape above does not apply. They
are not hardened to the same standard, and the rotation evaluator is the one
site where a full re-review is worth doing.

## Disclosure

Found by static reading plus dynamic proof during an independent review of
`Black0ffR/omega-sast`. No advisory or CVE had been assigned at the time of
writing. If you maintain this project, please treat the Step 3e evaluator as
compromised for all previously released versions and rotate any credential that
has been in the environment of a machine that scanned an untrusted bundle.

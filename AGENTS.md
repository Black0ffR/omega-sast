# AGENTS.md — omega-sast contributor guide

Project conventions, architecture map, and **the single known-work backlog**.

> This file previously existed only as a cross-reference target: four items in
> `obfuscated-zip-test/OBFUSCATED-SAMPLES-REPORT.md` pointed at "AGENTS.md
> known-work #1/#2/#2b/#8" while the file was absent from the repository and
> had zero commits. Those items were documented only by a dangling pointer.
> This is that file.

---

## Known work

Single source of truth. When you fix something here, move the row to **Done**
with the commit, and delete any "known-work #N" cross-references elsewhere that
point at it.

### Blocked — needs an input that does not exist in the repo yet

| # | item | blocked on | guard |
|---|------|-----------|-------|
| ~~1~~ | ~~RC4 decode fixture-validated only~~ **RESOLVED 2026-10-03.** Generated 16 samples with the real `javascript-obfuscator@5.8.1` engine and scanned them: the decoder is **correct on 15/16** (plain, base64, rc4, mixed, shuffle, wrappers fn+var, CFF, compact, callsTransform, splitStrings, VM all recover the original plaintext). Corpus committed at `test/fixtures/obfuscator-io-real/`, guarded by `test/test-obfuscator-io-real-corpus.js`. | — | test-obfuscator-io-real-corpus.js |
| 12 | **🔴 `selfDefending` + `debugProtection` silently produce WRONG strings.** The string-array rotation offset is sometimes resolved incorrectly, so the decoder emits plausible-but-incorrect values: `setRequestHeader('Content - Type')` for `'Content-Type'`, `.split`→`.load`, `.appendChild`→`.test`, `.value`→`['apply']`. Measured on 8 seeds of one config: **8/8 corrupt, 4/8 below 7/8 markers recovered.** Not garbage — wrong, which is worse for an analyst. Absent from all 15 non-anti-debug samples. | Fix needs the rotation solver to handle what the self-defending wrapper does to the offset. Interim options: decline to claim full recovery, or emit an integrity warning when anti-debug signatures are present. | test-obfuscator-io-real-corpus.js (detection only) |
| 11 | `modern-obf-strong.js` fixture is not representative. **Correction to an earlier note in this file:** real `identifierNamesGenerator: 'mangled'` output emits **single letters** (`a`, `b`, `g`, `j`), NOT `_0x` + hex — verified against the generated `09-rc4-mangled.js`. The fixture's `S` is representative; its `a1` is not. Either way the tool handles genuine mangled output correctly (0.85 confidence, 35 strings decoded), so the fixture's `expectStringArrayIndirection: false` is a fixture artefact. | Superseded by `test/fixtures/obfuscator-io-real/09-rc4-mangled.js`. Do not loosen the signature to satisfy the old fixture. | test-obfuscator-io-real-corpus.js |

### Open — real gaps, tractable

| # | item | notes |
|---|------|-------|
| 2 | **No pre-inline alias→sink correlation.** Sinks hidden behind `_0x33e4(...)` call chains are only detected *after* inlining. | String-array decode does feed later phases, so post-decode findings work. This is about the pre-inline representation. |
| 2b | **Non-constant array-mutation indexes unresolved.** `_0xarr[1] = x` folds (Step 4m); `_0xarr[i] = x` with variable `i` does not. | A mutation RHS whose decoder is defined later in the same round is handled on a subsequent fixpoint round — that part works. |
| 8 | **Multi-layer / obfuscator.io-style esoteric shells are out of scope.** Only single-payload shells are sniffed (charset density + bootstrap motifs, min 80 non-ws chars). | `test/fuzz-esoteric.js` covers the **single-layer** path only. Extending to multi-layer means extending the fuzzer's seed corpus too. |
| ~~9~~ | ~~0.85 confidence unreachable~~ **PARTLY RESOLVED 2026-10-03.** Against real output 0.85 **is** reachable — both `identifierNamesGenerator: 'mangled'` samples score 0.85; 0.6 is correct for `hexadecimal` names. The v7 note ("my hand-rolled strong fixture didn't match") was a fixture problem, not a ceiling. | — | test-obfuscator-io-real-corpus.js |
| 12 | `sourcemap-external` defaults to `info` for HTTP/CDN URLs. | **Deliberate**, with `--strict-sourcemaps` as the opt-in. Not a bug. If per-environment control is ever wanted, `--sourcemap-severity <s>` is cleaner than flipping the default. |
| 4.7 | **Statement-level unreachable code is preserved.** The pipeline prunes dead *branches* and folds opaque predicates, but a statement following a terminating statement is kept. | Must respect function hoisting and labels. |
| 4.8 | **Minified code gets no source expansion.** Tokenize/parse works (0 findings, no crash) but the rename-table / source-expander pass is skipped for small files. | Threshold-gated on size/complexity; would need revisiting for small-but-dense inputs. |
| 4.6 | **Bundler module splitting misses small bundles.** `--split-modules` and the Webpack 5 graph don't fire on a 1.4 KB educational sample. | Works on real-world-sized bundles (jQuery → `jqueryUmd`, Vue → `iifeGlobal`). Low priority. |

### Ideas floated, not yet justified

| # | idea | why it is not implemented |
|---|------|--------------------------|
| 10 | Add a 3rd obfuscator.io detection signal — the `function(){}.constructor("while (true) {}")` anti-debug counter pattern. | Would need to be validated against real output to show it improves precision rather than adding FPs. Sequence after #1. |

---

## Security architecture (read before touching the decode path)

The rotation/esoteric path has produced **two confirmed sandbox-escape
primitives**, both found by reading rather than testing:

1. The host realm's `Function` constructor injected into `rotation-sandbox`
   child-process globals.
2. The host realm's `vm` module injected into the main-process context as
   `__vmModule` — `new vm.Script(s).runInThisContext()` evaluates in the HOST
   realm.

Both are fixed. (2) is now a **latent primitive**: attacker-controlled code only
executes inside a *nested* context created by `__tryShell`, and the `eval` trap
handed to that nested context is defined inside it, so `eval.constructor` yields
a nested-realm `Function` that cannot see `process` or the outer global.

**Rules for anyone editing this path:**

- **Never hand a host-realm object to a sandbox.** Not the `vm` module, not a
  host function. A host object leaks the host `Function` via `.constructor`;
  a host module's real danger is usually a *method* (`Script`, `execSync`), so
  a constructor-bridge check alone will not catch it.
- If a sandbox needs any callable, construct the wrapper **inside the
  context** (`vm.createContext` + an in-context factory). A context-realm
  wrapper's `.constructor` resolves to the context's `Function`, not the host's.
- Watch the `delete` trap: `vm.runInContext('delete globalThis.X', ctx)` returns
  `false` on a contextified global and silently does nothing. Assign
  `undefined` instead.
- **Do not "fix" a test to make it pass.** Several tests here encoded real
  bugs; see the `OMEGA_FAIL_ON` and stage7 cases in git history for what
  happened when the gate was corrected and three assertions encoded the old
  behaviour.

**Guards — run these before claiming a decode-path change is safe:**

```bash
node test/test-self-scan.js                  # 13 — engine's own security properties
node test/test-esoteric-sandbox-isolation.js  # 13 — nested sandbox cannot reach host
node test/fuzz-esoteric.js --iterations 500  # property fuzz, non-blocking
npm test                                     # full suite
```

### Obfuscator.io anti-debug signatures

The anti-debug signature set was **Jscrambler-only** and matched zero real
obfuscator.io output — `expectAntiDebugging` was `false` on samples generated
with `selfDefending: true` and `debugProtection: true`. Two obfuscator.io
signatures are now included: the `RegExp` built by concatenating `this[...]`
properties and tested against another property's `toString()` (debugProtection),
and the self-bounded counter array grown with `Math.random()` (selfDefending).
Validated 3/3 true positives and 2/2 correct negatives on the real corpus.

That is *detection*, not correctness — the same family still decodes incorrectly
(see known-work #12).

The fuzzer's self-check walks **every** global in the nested sandbox and reports
host-only capabilities by capability-name, not object-name. It was validated
against a deliberately reachable break (host `vm` bridged in under the name
`__hostVm`) and correctly failed. Do not weaken it to a name-guessing probe.

---

## Conventions

- **Zero external dependencies.** Everything is hand-rolled and vendored. Keep
  it that way.
- **Tests:** `npm test` runs `test/run-all.js` over every `test-*.js` file.
  - `npm test` — **tolerates** `[KNOWN FAILING]`. This is the default and what
    CI should run: the markers exist to document real bugs *without* blocking,
    so enforcing them in CI would delete the concept.
  - `npm test -- --strict` — turns any marker into a hard failure. Use when
    verifying a specific fix, and in the nightly job so drift is visible.
  - The marker list is enforced in exactly one file (`test-verification-issues.js`);
    `run-all.js` uses an allowlist because other suites read positional argv
    (`test-harness.js` takes `argv[2]` as the AST module path).
  - `run-all.js` derives the suite verdict from each child's **exit code**, not
    from the printed `FAILED: N`. Counting the printed number made the tolerance
    a no-op — a file could print failures, exit 0, and still redden the build.
- **A new test file is picked up automatically** if named `test-*.js`. The fuzzer
  is deliberately named `fuzz-*.js` so it does **not** block CI; it runs on a
  nightly schedule (`.github/workflows/fuzz.yml`).
- **Findings carry metadata:** `confidence`, `ctxWindow`, `disambiguation`,
  `cwe`, remediation and evidence where a rule can supply them.
- **Runtime gating:** Node/Electron taint sources only activate when a Node or
  Electron marker is present, so ordinary browser bundles are never analysed
  under a server threat model. Unambiguous non-browser sinks (`yaml.load`,
  `unserialize`) run unconditionally.
- **Precision over coverage.** A rule that fires on minified production bundles
  without a real sink is worse than no rule. If you add one, prove it against
  the corpus in `../omega-sast-test/bundles/` and confirm 0 new findings there.

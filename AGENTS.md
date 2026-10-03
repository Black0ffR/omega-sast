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
| 1 | **RC4 / base64 string-array decoding is fixture-validated only.** `06_obfuscator_io_style.js` uses a *plain* string array; the `rc4Decrypt` path is exercised by a synthetic fixture but never against real output. | A production sample generated with `stringArrayEncoding: ['rc4']` from obfuscator.io. Drop it in `obfuscated-zip-test/obfuscated_js_samples/`. **This also unblocks #9 and #10** — the 0.85-confidence question cannot be answered without ground truth. | — |
| 11 | `modern-obf-strong.js` fixture is not representative. It uses `a1` / `S` identifiers; real obfuscator.io `identifierNamesGenerator: 'mangled'` emits `_0x` + hex (compare `modern-obf.js`, which uses `_0x4f2a` and is detected correctly). This makes `llmHints.expectStringArrayIndirection` report `false` for a shape the tool is right to expect. | **The fixture is wrong, not the tool.** Do not loosen the signature to satisfy it — that would trade real-world accuracy for a synthetic case. Re-derive from genuine output (same acquisition problem as #1). | — |

### Open — real gaps, tractable

| # | item | notes |
|---|------|-------|
| 2 | **No pre-inline alias→sink correlation.** Sinks hidden behind `_0x33e4(...)` call chains are only detected *after* inlining. | String-array decode does feed later phases, so post-decode findings work. This is about the pre-inline representation. |
| 2b | **Non-constant array-mutation indexes unresolved.** `_0xarr[1] = x` folds (Step 4m); `_0xarr[i] = x` with variable `i` does not. | A mutation RHS whose decoder is defined later in the same round is handled on a subsequent fixpoint round — that part works. |
| 8 | **Multi-layer / obfuscator.io-style esoteric shells are out of scope.** Only single-payload shells are sniffed (charset density + bootstrap motifs, min 80 non-ws chars). | `test/fuzz-esoteric.js` covers the **single-layer** path only. Extending to multi-layer means extending the fuzzer's seed corpus too. |
| 9 | **Modern obfuscator.io fingerprint tops out at 0.6 confidence.** The 0.85 path is not reachable. | Blocked by #1 — do not relax the Phase 2c RC4 regex without a real sample to measure against. |
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

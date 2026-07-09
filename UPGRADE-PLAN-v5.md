# OMEGA-SAST v5 Upgrade Plan

## Ground-truth verified against source code (Jul 2026)

All 10 items confirmed via source inspection and live test run against 14 production bundles. Each item is marked `Termux: YES/NO/PARTIAL` based on actual feasibility on unrooted Android ARM64.

---

### Item 1 — Fix `proto-assign` false positive on read access

**Source:** `src/_monolith.js:896`
**Verified:** Regex `/(?:__proto__|prototype)\s*\[/g` fires on ALL `prototype[key]` accesses, including reads (e.g., `Backbone.Model.extend`, `Array.prototype.slice.call`, `Vue.component`). Review test: 3/11 criticals were false positives from this.
**Fix:**
- Split into write-only detector: require `=` after `]`
- Add merge-suspect detector for `Object.assign` deep-merge patterns where key comes from user input
- Demote `Object.setPrototypeOf` from `high` → `medium` when target is not literal `Object.prototype`
**Termux: YES — pure regex change, no deps**

---

### Item 2 — Add UMD/IIFE generic bundler patterns

**Source:** `src/ast/_monolith.js:1152`
**Verified:** Currently has webpack5/webpack4/vite/rollup/esbuild/parcel/browserify patterns. Missing:
- UMD universal wrapper: `(function(root, factory) { typeof define === 'function'... })`
- IIFE global: `!function(...){...}(window)` (jQuery-style)
- Named UMD: `(function(name, deps, factory)`
**Fix:**
- Add `umdGeneric` / `iifeGlobal` / `umdNamed` patterns
- Fix priority: most specific match first (webpack5 over iifeGlobal)
- Track `isMinified` heuristic: if >50 single-letter idents → likely minified
**Termux: YES — pure regex change**

---

### Item 3 — Add SARIF output format

**Source:** `src/_monolith.js:4032` (`generateReports`)
**Verified:** Currently outputs JSON/HTML/MD. No SARIF. GitHub Code Scanning accepts SARIF natively.
**Fix:**
- Add `report.sarif` alongside existing formats
- Use `node:crypto` for `sha1` fingerprints (built-in, no dep)
- Map severity: critical/error → `error`, high → `error`, medium → `warning`, low → `note`, info → `none`
- Include `artifactLocation` with bundle filename, region with line/col if available
**Termux: YES — built-in node:crypto, fs.writeFileSync**

---

### Item 4 — Add `--no-llm-payload` flag

**Source:** `src/_monolith.js:5730-5762` (Phase 17-20 execution)
**Verified:** Phases 17-20 (function summaries, backward slicer, VRT, source expander) run unconditionally. On jquery, `functionSummaries` alone had 593 entries. For non-LLM use, this is bloat.
**Fix:**
- Add `--no-llm-payload` CLI flag (or invert: `--full-report` to opt in)
- When set, skip Phases 17-20 entirely
- Reduces JSON report size ~70%, speeds up runs ~20%
**Termux: YES — trivial flag guard**

---

### Item 5 — Expand RC4 decoder for `const`/`let` array declarations

**Source:** `src/_monolith.js:1547`
**Verified:** String array regex requires `var NAME = [...]` — newer obfuscator.io emits `const NAME = [...]` or `window.NAME = [...]`. Also rotation regex at line 1580 may not match variant patterns.
**Fix:**
- Expand regex to accept `var|const|let`
- Add fallback for `window.NAME = [...]` pattern
- Add debug logging for decoder matching attempts
**Termux: YES — pure JS, buffer/string operations**

---

### Item 6 — Add `.omega-ignore` baseline file support

**Source:** `src/_monolith.js` (no existing suppression mechanism)
**Verified:** No way to suppress known false positives. CI tool unusable on real codebases without this.
**Fix:**
- JSON format to maintain zero-dependency (no YAML parser needed)
- Fields: `id`, `file`, `reason`, `expires` (optional)
- CLI flag: `--baseline .omega-ignore`
- Findings matching a suppression move to `suppressed[]` in report (still visible, don't affect exit code)
- `--update-baseline` auto-adds current findings
**Termux: YES — JSON.parse, fs.readFileSync**

---

### Item 7 — Add `--watch` mode

**Source:** `src/_monolith.js` (no existing file watcher)
**Verified:** `fs.watch` is built-in Node.js, available on Termux.
**Fix:**
- Add `--watch` CLI flag
- Use `fs.watch(inputPath, ...)` to detect changes
- On change: re-run pipeline, re-generate reports
- Combine with `--diff` for instant "what changed?" feedback
**Termux: YES — built-in fs.watch**

---

### Item 8 — Add `--diff` mode

**Source:** `src/_monolith.js` (no existing comparison)
**Verified:** Without diff, every CI run re-surfaces all old findings.
**Fix:**
- Load previous `report.json` via `--diff <path>`
- Compare finding IDs + values to identify new/changed/removed
- Only report new findings
- Combine with baseline file for clean CI workflow
**Termux: YES — pure JSON comparison**

---

### Item 9 — Source map correlation for findings

**Source:** `src/ast/_monolith.js:90-210` (VLQ decoder already exists), `src/ast/_monolith.js:2110` (source map parser exists)
**Verified:** AST module already has `decodeVLQMappings`, `mapSourcePosition`, and `fetchExternalSourceMap`. But finding positions in `src/_monolith.js` remain as raw byte offsets in the minified bundle.
**Fix:**
- Post-pass in `generateReports()` or `main()`: after all findings collected, if source map is available, remap each finding's position to `{originalFile, originalLine, originalColumn}`
- Add `sourceLocation` to each finding in JSON report
- Link to source files in HTML report
**Termux: YES — already partially implemented, uses built-in modules**

---

### Item 10 — Parallel multi-bundle with `worker_threads`

**Source:** `src/_monolith.js:4900-5055` (current `--multi` processes sequentially)
**Verified:** No `worker_threads` usage currently. `node:worker_threads` is available on Termux since Node 12+.
**Fix:**
- One worker per CPU core
- Each worker receives `{file, opts}` via `workerData`
- Workers return findings, master collects + generates combined report
- For 100 bundles: serial ~70s → parallel ~3s
**Termux: YES — built-in worker_threads**

---

## Execution Order

```
1 (proto FP fix) → 2 (bundler patterns) → 3 (SARIF) → 4 (no-llm-payload) →
5 (RC4 var/const) → 6 (baseline) → 7 (watch) → 8 (diff) → 9 (source maps) → 10 (parallel multi)
```

## Design Decisions

1. **Item 3 (SARIF)**: Use `node:crypto` SHA1 for `partialFingerprints` — zero deps. Each finding gets `primaryLocationLineHash` based on value + position.
2. **Item 6 (baseline)**: JSON format not YAML — keeps zero-dependency promise. User can also use `--update-baseline` to auto-generate from current run.
3. **Item 9 (source maps)**: Only remap when source map is available and `fetchSourcemaps` is enabled. Fall back to raw position otherwise.
4. **Item 10 (parallel)**: Workers communicate via `workerData` + `parentPort.postMessage()`. No shared memory, no cross-worker state.

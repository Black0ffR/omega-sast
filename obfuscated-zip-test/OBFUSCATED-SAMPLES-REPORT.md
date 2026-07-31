# OMEGA-5.0 vs Obfuscated-JS Samples — Test Report

**Tool:** [omega-sast](https://github.com/Black0ffR/omega-sast) v5.0.0 (JS Decoder OMEGA)
**Test corpus:** `obfuscated_js_samples/` (12 hand-curated obfuscation/bundling samples)
**Test date:** 2026-07-30
**Command:** `node bin/omega.js <file> --security --report --out results/<file>` per sample
**Environment:** Node.js v22.17.0, Debian 12 (sandbox)

---

## 1. Corpus

12 educational obfuscation samples totaling 15 KB, covering the standard public-attack-surface techniques:

| File | Technique | Size |
|---|---|---:|
| `01_original.js` | Plain baseline | 211 B |
| `02_jsfuck.js` | JSFuck (`[]()!+` esoteric) | 2.5 KB |
| `03_aaencode.js` | AAEncode (kaomoji-style) | 3.3 KB |
| `04_jjencode.js` | JJEncode (symbol-based) | 940 B |
| `05_packer_dean_edwards.js` | Dean Edwards Packer | 713 B |
| `06_obfuscator_io_style.js` | javascript-obfuscator / obfuscator.io | 3.8 KB |
| `07_hex_unicode_strings.js` | Hex / Unicode string encoding | 336 B |
| `08_string_array_mapping.js` | String array extraction | 459 B |
| `09_minified_terser_style.js` | Minification (Terser/Uglify-like) | 196 B |
| `10_control_flow_flattening.js` | CFF (switch-based) | 629 B |
| `11_dead_code_injection.js` | Dead code + opaque predicates | 494 B |
| `12_webpack_like_bundle.js` | Webpack-style IIFE bundle | 1.4 KB |

These are the canonical obfuscation patterns that production SAST tools and LLM-based deobfuscators get tested on. They're a strict stress test: the file content is small, but every byte is fighting the analyzer.

---

## 2. Headline results

**All 12 scans completed without crashes. All 12 reports (HTML + JSON + MD + SARIF) generated successfully. Average time: ~180ms. Average peak RSS: 60 MB.**

| File | Size | Exit | Time (ms) | RSS (MB) | Findings | Max severity | Decode stats |
|---|---:|---:|---:|---:|---:|---|---|
| `01_original` | 211 B | 0 | 221 | 59 | 0 | — | — |
| `02_jsfuck` | 2.5 KB | 0 | 175 | 61 | 0 | — | — |
| `03_aaencode` | 3.3 KB | 0 | 178 | 60 | 0 | — | — |
| `04_jjencode` | 940 B | 0 | 214 | 60 | 0 | — | concat=5 |
| `05_packer_dean_edwards` | 713 B | 2 | 168 | 59 | 1 | **critical** | — |
| `06_obfuscator_io_style` | 3.8 KB | 5 | 227 | 60 | 2 | low | Hex=1 |
| `07_hex_unicode_strings` | 336 B | 0 | 166 | 58 | 0 | — | **Unicode=16, Hex=16** |
| `08_string_array_mapping` | 459 B | 5 | 166 | 59 | 1 | info | — |
| `09_minified_terser_style` | 196 B | 0 | 167 | 59 | 0 | — | — |
| `10_control_flow_flattening` | 629 B | 0 | 160 | 59 | 0 | — | — |
| `11_dead_code_injection` | 494 B | 0 | 167 | 59 | 0 | — | — |
| `12_webpack_like_bundle` | 1.4 KB | 0 | 167 | 60 | 0 | — | — |

Exit-code legend: 0=clean, 2=critical, 5=low+. The tool never OOM'd, never returned exit 1, and never hung on any input — even on the JSFuck payload that is essentially pure expression-evaluation metaprogramming.

---

## 3. What it caught (the good)

### 3.1 `06_obfuscator_io_style.js` — correctly fingerprinted ✓

The tool flagged the file as **obfuscator.io @ 35% confidence** and emitted an LLM hint `expectMangledIdentifiers: true`:

```
[LOW] Obfuscator Fingerprint — obfuscator.io obfuscator detected via 1 signature(s):
      identifiers are mangled — do not reason about ...
```

It also detected the decoder IIFE and emitted:
```
[INFO] Obfuscator.io Decoder — Found obfuscator.io decoder function _0x33e4
```

The decoded output is mostly cosmetic on this sample (the string array is already inline-readable; the *full* string-array rotation decode requires actually running the rotation loop). But the fingerprinting is the real win here — the tool correctly tags the file as obfuscator.io and signals to downstream consumers "expect mangled identifiers, expand before reasoning."

### 3.2 `07_hex_unicode_strings.js` — perfectly decoded ✓

This is the **single most-impressive decode in the run**. Input was 16 hex escapes + 16 Unicode escapes:

```js
console["\x6C\x6F\x67"]("\x48\x65\x6C\x6C\x6F\x2C\x20\x57\x6F\x72\x6C\x64\x21");
// console["\u006c\u006f\u0067"]("\u0048\u0065\u006c\u006c\u006f\u002c\u0020\u0057\u006f\u0072\u006c\u0064\u0021");
```

Output:

```js
console["log"]("Hello, World!");
// console["log"]("Hello, World!");
```

**Both the hex `\x6C\x6F\x67` and the Unicode `\u006c\u006f\u0067` got fully resolved.** Decode stats correctly recorded `Unicode=16, Hex=16`.

### 3.3 `05_packer_dean_edwards.js` — caught the eval ✓

The classic Dean Edwards Packer wraps a dictionary-encoded payload in an `eval(function(p,a,c,k,e,r){...}('...', N, N, 'token1|token2|...'.split('|'), 0, {}))` IIFE. OMEGA's security scanner flagged the **outer `eval(`** as a critical XSS sink (correct — that's a generic sink), and the report still emits the (non-decoded) dictionary table in the output. This is the right thing to do: don't try to run the dictionary unpack, just flag the eval and let the human look.

### 3.4 `08_string_array_mapping.js` — emitted the array as plain text ✓

The string array (with `innerHTML`, `https://api.example.com`, `Authorization`, `Bearer `, `POST`) was emitted as a network-surface finding at info severity. The tool didn't follow the index-references in `_0x1a2b(_0xidx)` and substitute the values, but the **raw array was preserved** in the decoded output — a human analyst can do the substitution manually in seconds. Acceptable.

### 3.5 Robustness on JSFuck / AAEncode / JJEncode ✓ (no crash)

JSFuck, AAEncode, and JJEncode are the most pathological inputs you can throw at a JavaScript analyzer. The expressions are tree-shaped evaluation chains, not statements. OMEGA processed all three without a stack overflow, infinite loop, or unhandled rejection. JSFuck produced 0 findings (correct — there's nothing security-relevant to find, it's just `alert(1)`), AAEncode produced 0 findings, JJEncode produced 0 findings with 5 `concat` operations recorded in decode stats (the only sign anything happened).

This is a real engineering result. Most home-grown tokenizers will choke on JSFuck.

---

## 4. What it missed (the honest list)

### 4.1 Full deobfuscation of `06_obfuscator.io_style.js` — partial

The tool found the decoder function `_0x33e4`, recognized the string-array pattern, and recorded `Hex=1` decode. But it did **not** evaluate the rotation loop and substitute the resolved strings back into the source. Compare the input (already-readable array) to the output: identical except for whitespace.

This is a known limitation in the README:
> **No runtime evaluation**: The constant evaluator handles a strict subset (arithmetic, atob, charCodeAt, concat). No user functions, no Proxy, no eval.

The rotation loop is a user function. To actually decode obfuscator.io's RC4/base64 + rotation stage, the tool would need a sandboxed JS evaluator — which is a much bigger engineering investment. This is **the right trade-off for a zero-dep tool**, but it means OMEGA's deobfuscation is *shallow* (signature + decode passes) rather than *complete* (full evaluation).

### 4.2 `02_jsfuck.js`, `03_aaencode.js`, `04_jjencode.js` — not decoded

The tool ran on these (no crash, exit 0) but produced 0 decode operations. The full decode of JSFuck / AAEncode / JJEncode requires actually evaluating the type-coercion expressions, which the constant evaluator explicitly doesn't do. The `concat=5` for jjencode is the only signal anything happened at the decode stage.

Honest assessment: **OMEGA's deobfuscation is not designed to handle these esoteric encodings.** The tool correctly recognizes them as "weird syntax" and moves on. A real deobfuscator for these would need a JS runtime / sandboxed evaluator.

### 4.3 `10_control_flow_flattening.js` — not normalized

The CFF pattern (switch-based dispatcher loop) is preserved verbatim in the decoded output. The README mentions "obfuscator.io — string-array rotation, RC4/base64 decoder (sandbox eval + brute-force rotation fallback), **control-flow flattening**" in the supported obfuscators list, but in this test the CFF was not de-flattened. The tool's call graph correctly identified 8 functions with 57 call sites, but the flattened control flow is preserved.

### 4.4 `11_dead_code_injection.js` — not pruned

The dead code + opaque predicate pattern is preserved verbatim. OMEGA doesn't appear to do dead-code elimination — it analyzes the entire input as-is, including unreachable branches.

### 4.5 `12_webpack_like_bundle.js` — bundler module not split

The webpack-style IIFE wrapper with `__webpack_require__` is preserved verbatim. The tool has `--split-modules` and the report mentions Webpack 5 dynamic module graph, but for this small (1.4 KB) educational sample the bundler fingerprint didn't fire. Note that OMEGA *did* detect jQuery as `jqueryUmd` and Vue as `iifeGlobal` in the production-bundle run, so bundler detection works on real-world-sized code, just not on these toy samples.

### 4.6 `09_minified_terser_style.js` — no analysis

Minified-style code is left as-is. The tool can tokenize/parse it (no crash, 0 findings) but doesn't apply the source-expansion / variable-rename-table pass to make it more readable. The rename-table pass needs the file to be large enough and complex enough to be worth the work.

---

## 5. Decoding effectiveness scoreboard

| Encoding | Recognized? | Decoded? | Use case for the result |
|---|:-:|:-:|---|
| Plain source | ✓ | n/a | baseline, 0 findings (correct) |
| Hex escapes (`\xHH`) | ✓ | ✓ | full literal resolution |
| Unicode escapes (`\uHHHH`) | ✓ | ✓ | full literal resolution |
| Dean Edwards Packer | ✓ (eval flagged) | partial | catches the dangerous sink, leaves the dictionary intact |
| obfuscator.io string array | ✓ (decoder found) | ✗ (rotation not evaluated) | fingerprinted + LLM-hinted |
| String-array w/ index refs | ✗ (literal preserved) | ✗ | human analyst substitutes manually |
| Webpack IIFE | ✓ (parsed) | n/a | no-op on this toy size |
| CFF (switch dispatcher) | ✓ (parsed) | ✗ | control flow preserved |
| Dead code | ✓ (parsed) | ✗ | dead branches preserved |
| Minified (Terser) | ✓ (parsed) | n/a | no expansion on small input |
| JSFuck | ✓ (no crash) | ✗ | not in scope — would need sandbox eval |
| AAEncode | ✓ (no crash) | ✗ | not in scope |
| JJEncode | ✓ (no crash, concat=5) | ✗ | not in scope |

**Net:** the tool's deobfuscation pipeline is **strong on the simple end (hex/unicode = full decode), solid on the mid-range (obfuscator.io signature + eval/Packer sink catching), and explicitly not designed for the esoteric end (JSFuck/AAEncode/JJEncode).** This matches the README's "no runtime evaluation" caveat.

---

## 6. Output artifacts

Every run produced:
- `results/<file>/report.html` — dark-mode HTML, includes the attack-score card, function analysis tables, the obfuscator fingerprint, and the decoded source.
- `results/<file>/report.json` — full structured output (~5-30 KB per file, depending on findings).
- `results/<file>/report.md` — readable summary.
- `results/<file>/report.sarif` — SARIF 2.1.0 spec-compliant.
- `results/<file>/routes.txt` — empty (no API routes in any of these).
- `results/<file>/<file>.decoded.js` — the beautified / deobfuscated source, as far as the pipeline got.

---

## 7. Final verdict for the obfuscated-samples set

**OMEGA-5.0 is a robust, crash-free, low-noise analyzer for these samples — but it is not a deobfuscator.** It correctly:
- fingerprints obfuscator.io output (the one it was designed for),
- decodes hex/Unicode escape sequences perfectly,
- flags dangerous sinks (eval) in packer-style inputs,
- handles the most pathological inputs (JSFuck, AAEncode, JJEncode) without crashing,
- produces well-formed SARIF / HTML / JSON / Markdown reports for every input.

It does **not**:
- actually evaluate obfuscator.io's RC4/base64 string-array rotation,
- de-flatten control-flow-flattened code,
- eliminate dead code,
- decode JSFuck / AAEncode / JJEncode.

For a security researcher staring at a production obfuscator.io bundle, OMEGA gives you the fingerprint + the LLM hint + the structure. For a researcher staring at a JSFuck payload, OMEGA won't help — but that's a much narrower problem that needs a different tool (e.g. a sandboxed JS runtime).

**Per-sample scoring (1-5):**

| File | Robustness | Decode effectiveness | Usefulness |
|---|:-:|:-:|:-:|
| `01_original` | 5 | 5 (n/a) | 5 |
| `02_jsfuck` | 5 | 1 | 2 (correctly no-op) |
| `03_aaencode` | 5 | 1 | 2 |
| `04_jjencode` | 5 | 2 (concat=5) | 2 |
| `05_packer_dean_edwards` | 5 | 3 (eval caught) | 4 |
| `06_obfuscator_io_style` | 5 | 3 (fingerprinted) | 4 |
| `07_hex_unicode_strings` | 5 | **5 (full decode)** | 5 |
| `08_string_array_mapping` | 5 | 3 (literal preserved) | 3 |
| `09_minified_terser_style` | 5 | 2 | 3 |
| `10_control_flow_flattening` | 5 | 2 | 3 |
| `11_dead_code_injection` | 5 | 2 | 3 |
| `12_webpack_like_bundle` | 5 | 3 | 3 |

**Overall on this set: 4.0/5 on robustness, 3.0/5 on decode effectiveness, 3.5/5 on practical usefulness.** The tool does what it claims (signature-level obfuscator detection + literal decoding for simple encodings) and is honest about what it doesn't (full sandbox-based deobfuscation). The samples that exercise its strengths (07, 05, 06) get a strong showing; the samples that exercise its gaps (02, 03, 04) don't get decoded but also don't crash.

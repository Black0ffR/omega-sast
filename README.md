# OMEGA-5.0 — Zero-Dependency JavaScript SAST Engine

[![Test Suite](https://img.shields.io/badge/tests-722%20passing-brightgreen)](test/)
[![Zero Deps](https://img.shields.io/badge/dependencies-0-success)](package.json)
[![Ongoing Fixes](https://img.shields.io/badge/fixes-P0--P3%20complete-blue)](OMEGA-SAST-FIX-PLAN-R3.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-green)](package.json)
A hand-rolled, zero-dependency static analysis engine for JavaScript bundles. Built for security researchers analyzing minified, framework-heavy production code. Combines structural AST analysis, inter-procedural taint tracking, obfuscator fingerprinting, and LLM-ready payload generation — all in a single Node.js package with no external dependencies.

## Quick Start

```bash
# Clone or unzip the package
cd omega-sast

# Run the demo scan
node bin/omega.js test/fixtures/sample-bundle.js --security --report --out ./demo-output

# Or install globally
npm link
omega test/fixtures/sample-bundle.js --all
```

## What It Does

OMEGA-5.0 analyzes a JavaScript bundle in 20 phases:

| Phase | Function | Description |
|-------|----------|-------------|
| 0a | TypeScript stripper | Removes TS annotations for `.ts`-as-`.js` analysis |
| 0 | Module alias resolver | Maps `d(N)` → npm package name |
| 1 | Escape decode | Unicode/hex/octal/HTML-entity |
| 2 | String decode | fromCharCode, atob, base64, hex arrays (10-pass) |
| 2b | CharCode decoder | Juice-Shop-style IIFE obfuscation |
| 2c | obfuscator.io decoder | String-array rotation + RC4/base64 + brute-force fallback; multi-layer pass-through + swapped-arg/double-neg wrapper inlining |
| 2d | Constant evaluator | Safe partial evaluator for runtime strings |
| 2e | Esoteric decode | Opt-in JSFuck/AAEncode/JJEncode payload recovery (`--decode-esoteric`, sandboxed, no execution) |
| 3-6 | Normalization | Booleans, webpack cleanup, Angular Ivy, RxJS |
| 7 | Beautifier | Token-based formatter (arrow-safe) |
| 8-8c | Code analysis | Cyclomatic complexity, storage keys, auth surface |
| 9-9b | Framework detection | Regex + AST-based (Angular/Vue/React/Svelte/Next) |
| 10-11 | Routes & credentials | API routes, 33+ credential patterns (generalized API key/secret regex with fpGuard) |
| 12 | Security patterns | XSS, injection, crypto, network, storage |
| 12b-m | Behavioral detectors | Dynamic code, business logic, WebSocket, IDOR, CVEs |
| 12n | CSRF analyzer | Report-only hybrid regex/context detector (state-changing calls, cookie attributes, JSONP, token mishandling) |
| 12o-p | Modern scanners | JWT/WebCrypto/Node crypto, network surface |
| 12r | ReDoS detection | In-source ReDoS vulnerable pattern scan |
| 12s | Pluggable custom rules | User-defined regex patterns from `.omega-rules.json` |
| 12q | Source map parser | Inline/external map detection |
| 13-14 | Webpack + call graph | Module resolution, dependency edges |
| 14c | AST taint tracker | SSA-based cross-statement taint |
| 2c2 | CFF de-flattener | Linearizes `while(1){switch(x){case…}}` patterns |
| 3b | Opaque predicate eliminator | Removes dead branches (`if(true){A}else{B}` → `A`) |
| 15 | Reports | HTML (dark-mode) + JSON + Markdown + SARIF |
| 16 | Obfuscator fingerprint | obfuscator.io, Jscrambler, ByteHide, JSFuck |
| 17 | Function summaries | Per-function taint contracts (LLM payload) |
| 18 | Backward slicer | Sink-anchored inter-procedural paths |
| 19 | Variable rename table | Canonical v0/v1/v2 names (token compression) |
| 20 | Source expander | On-demand function expansion (LLM tool-call) |

## Key Features

### Inter-Procedural Taint Tracking
Tracks data flow from taint sources (`location.hash`, `localStorage`, `event.data`) through function boundaries to dangerous sinks (`innerHTML`, `eval`, `exec`, `spawn`, `fork`). Uses per-function SSA-style variable tracking with destructuring support.

### CFF De-Flattener (Phase 2c.2)
Detects and linearizes control-flow flattening (`while(1) { switch(dispatcher) { case … } }`) produced by obfuscator.io, JScrambler, and similar tools. Uses brace-matched string parsing — no AST required. Handles multi-layer flattening via iterative passes (max 5).

### Chained String-Array Fixpoint (Phase 2c)
Multi-layer obfuscator.io string arrays — `var _0xb = ['x', _0xa[2], 'y']` — are resolved via a bounded fixpoint loop (max 4 rounds): each round extracts string arrays, decodes constant-index calls, then folds `KNOWNARR[CONST]` references inside array literals so the referencing array becomes extractable in the next round. Per-name idempotency prevents double-rotation on re-extraction; single-layer runs complete in one round with no behavior change.

### Constant Array Mutation Resolution (Phase 2c.3)
Obfuscator.io custom protectors rewrite string-array slots at runtime — `_0xarr[1] = _0xop ? 'innerHTML' : 'textContent'` — hiding sink property names behind opaque predicates. Step 4m folds constant-index mutations into the decoded array before call inlining: literal/numeric right-hand sides are applied unconditionally; decoder calls resolve through a cross-array decoder registry; ternary/`||` of literals become a **may-set** candidate list (the predicate is never evaluated) — the first candidate is inlined downstream while the full set is recorded in an `obfuscator-io-mutation` finding.

### Post-Decode Second Security Pass (Phase 12s)
When Phase 2c (string-array) or 2c.2 (CFF de-flattener) actually decoded code, OMEGA re-runs the decode → opaque-elimination → taint/security scans on the fully decoded buffer and merges only findings that did not already surface (dedup by id + value + position). Catches sinks that materialize only after full inlining — e.g. `document.body[...] = location.hash` where the property name is hidden in a string array. `decodeStats.secondPass` reports `{ ran, decodedStrings, merged }`.

### Obfuscator Fingerprinting + Confidence Corroboration
Fingerprints obfuscator.io, JSFuck, AAEncode, JJEncode, and packers from structural signatures. When Phase 2c inlines 10+ strings from an obfuscator.io string array, the fingerprint confidence is raised (≥ 0.6) with a `decoder-inlining-corroboration` signature, `llmHints` are synced with decoder evidence (`expectStringArrayIndirection`, `expectControlFlowFlattening`, `recommendedDecoderPasses`), and the fingerprint finding's text/severity are re-synced to the boosted confidence (no more "35%" text next to a 0.6 confidence).

### Interpreting findings on framework internals

- **`innerHTML`/DOM sinks inside framework internals** (Angular sanitizer-wrapped bindings, Vue `v-html`, DOMPurify, jQuery, preact) are *technically correct attack-surface call-outs* but usually sanitizer-wrapped: triage by checking whether user input can reach the sink un-sanitized, not by the flag alone. `bypassSecurityTrust*` findings are the real danger signals (they disable Angular's sanitizer).
- **Info Leakage on library error paths** (`console.error(e)`, `e.stack` in error formatting) is standard library practice; only the exposure-gated findings (console/alert/DOM/network) are reported (review R3).
- **Broken Crypto `Math.random().toString(36)`** fires only in security-token contexts (token/nonce/csrf/session/secret/password/otp/salt/hash/crypto/auth) (review R2) — internal ID generation is not flagged.
- **`new Function(` / `eval(`** in libraries is usually a real code-exec risk: underscore's `_.template()` and D3's compiled accessors are documented cases worth an explicit look.

### Opaque Predicate Eliminator (Phase 3b)
Removes dead code branches after constant folding:
- `if (true) { A } else { B }` → `A`
- `if (false) { A }` → removed
- `"str" === "str"` → `true`, `x !== x` → `false`
- `true ? A : B` → `A`, `false ? A : B` → `B`

### Esoteric Payload Decode (Phase 2e, `--decode-esoteric`)
Opt-in recovery of JSFuck / AAEncode / JJEncode payloads **without executing the payload**: an eval-shim strategy (context-global `eval` overwrite) recovers JSFuck, and a constructor-patch strategy captures `return "…"` bodies in a fresh empty realm for AAEncode/JJEncode. Runs inside a `worker_threads` Worker (terminated after) with an in-process vm fallback; hostile payloads (`return process`, `while(1){}`) fail safe. The decoded payload replaces the working source for downstream phases, and `decodeStats.esoteric` records the recovered character count.

### CSRF Analyzer (Phase 12n)
Report-only hybrid regex/context analyzer (findings **never** affect exit codes or the attack score — CI gates stay untouched). Classifies the bundle's auth context (cookie vs bearer) and checks:
- **State-changing requests without a CSRF token** — fetch/axios/jQuery/XHR/superagent `POST/PUT/PATCH/DELETE` calls with no `X-CSRF*`/`X-XSRF*` header (medium in cookie-auth bundles, info otherwise)
- **Cookie attribute weaknesses** — missing `SameSite` on auth-named cookies, `SameSite=None` without `Secure`
- **JSONP legacy patterns** — `callback=` script loads, `dataType: 'jsonp'`
- **Token mishandling** — token in URL query, localStorage-only token never attached, client-side token comparison
- **Positive protections** — axios `xsrf` defaults, `meta[name="csrf-token"]`, Angular `HttpXsrfInterceptor`, Django `csrf_token`, generic header attaches suppress findings and mark surfaces `PROTECTED`

Emits a **CSRF Posture** section in HTML/JSON/Markdown reports: auth context, token mechanism, protected vs at-risk request surfaces (`{surface, method, protected}`).

### TypeScript Stripper (Phase 0a)
Strips TypeScript type annotations so `.ts` files can be analyzed as plain `.js`:
- Removes `: Type`, `as Type`, `interface`, `type`, `enum`, `declare`, decorators, generics
- Does NOT require `tsc` or any TypeScript tooling

### Pluggable Custom Rules (Phase 12s)
Load user-defined regex patterns from `.omega-rules.json`:
```json
[
  { "id": "danger-fn", "name": "Dangerous Function",
    "severity": "high", "category": "custom",
    "pattern": "dangerousFunction\\s*\\(",
    "description": "Custom dangerous function pattern" }
]
```
Use with `--custom-rules <path>`.

### SARIF 2.1.0 Output
When `--report` is used, OMEGA emits `report.sarif` in SARIF v2.1.0 format, compatible with GitHub Code Scanning and other SARIF viewers. Includes artifact arrays, precise startLine locations, and baseline suppression tagging.

### Baseline Suppression (.omega-ignore)
Suppress known findings using a JSON baseline file:
```json
[{ "id": "hardcoded-credential", "file": "bundle.js", "reason": "Won't fix" }]
```
Use with `--baseline <file>`. Suppressed findings are tagged in SARIF output as `suppressed` (kind: `external`). Use `--update-baseline` to generate a baseline from current scan results.

### Obfuscator Fingerprinting
Detects 8 obfuscator types (obfuscator.io, Jscrambler, ByteHide, JSProtect, JSFuck, AAEncode, JJEncode, generic) with confidence scoring. Emits LLM-actionable metadata: "expect mangled identifiers", "expect control-flow flattening", etc.

### LLM-Ready Payload
Each function compresses to a ~40-80 token "taint contract" (params, sources, sinks, sanitizers, returns). The backward slicer produces inter-procedural paths ranked by severity. The Variable Rename Table cuts token count 30-50% on minified input.

### CI/CD Integration
Exit codes for CI pipelines: `0`=clean, `2`=critical (default), `3`=high+, `4`=medium+, `5`=low+. Configure via `OMEGA_FAIL_ON` env var. `--quiet` flag suppresses all non-essential output. Phase 12n CSRF findings are report-only and never affect exit codes.

### Runtime on large bundles (measured 2026-08-01, Node 26.1, Termux/ARM64, single pass)

| Bundle | Size | Time |
|---|---:|---:|
| angular-17.3.0.iife.js | 1.5 MB | ~16 s |
| three.min.js | 656 KB | ~21 s |
| d3-7.9.0.min.js | 276 KB | ~15 s |
| vue-3.4.21.global.prod.js | 148 KB | ~8 s |

Scaling is super-linear on multi-MB bundles (multiple full-source passes:
decode fixpoint, CFF, taint, security patterns). For regular scanning of
multi-MB assets, run with `OMEGA_PROFILE=1` to find the dominant phase,
or scan per-chunk. **Optimization landed:** Phase 5 Ivy annotation previously
ran 204 full-source regex passes (102 map entries × 2 patterns); now merged
into 2 alternation passes (`annotateAngularIvy`) — angular total dropped
~26 s → ~16 s with byte-identical findings (all 21 bundle scores unchanged,
717/717 tests). **R4.5:** the angular classifier signature now requires a word
boundary (`\bng\.`) so `objectToString.call` / `String.fromCharCode` ("…String.")
no longer match the `ng.` substring — lodash-debounce/backbone reclassify
ui-framework → utility, chart/marked → general (722/722 tests).

## CLI Usage

```bash
omega <file.js> [options]

Options:
  --out <dir>           Output directory (default: ./omega_output)
  --security            Full security scan (enables --ast)
  --report              Generate HTML + JSON + Markdown reports
  --all                 Enable everything
  --quiet               CI-friendly (suppress non-essential output)
  --module-map <f>      Load external webpack module-id → name map (JSON)
  --severity-floor <s>  Minimum severity (critical|high|medium|low|info)
  --no-ast              Disable AST pass (regex-only fallback)
  --treat-ts-as-js      Strip TypeScript annotations before analysis
  --custom-rules <f>    Path to .omega-rules.json for pluggable rule patterns
  --baseline <f>        Suppress known findings from a baseline JSON file
  --update-baseline     Write current findings to .omega-ignore baseline
  --decode-esoteric     Recover JSFuck/AAEncode/JJEncode payloads (sandboxed)
  --strict-sourcemaps   Keep CDN http(s) source-map findings at medium (default: info)
  --watch               Re-scan when the input file changes
  --max-hops <n>        Backward-slice hop limit (default: 5)

CI Exit Codes (OMEGA_FAIL_ON env var):
  0=clean, 1=error, 2=critical (default), 3=high+, 4=medium+, 5=low+
```

## Programmatic API

```javascript
const { ast } = require('omega-sast');

// Build structural index
const src = require('fs').readFileSync('bundle.js', 'utf8');
const idx = ast.buildStructuralIndex(src);

// Compute function summaries (LLM payload)
const summaries = ast.computeFunctionSummaries(src, idx);

// Build backward slices (inter-procedural taint paths)
const cg = ast.buildCallGraph(idx, null);
const slices = ast.buildBackwardSlices(src, idx, summaries, cg, 3);

// Fingerprint obfuscator
const fp = ast.fingerprintObfuscator(src);
console.log(fp.primary);  // { obfuscator: 'obfuscator.io', confidence: 0.85 }
console.log(fp.llmHints); // { expectMangledIdentifiers: true, ... }

// On-demand source expansion
const expander = ast.createSourceExpander(src, idx, summaries);
const expansion = expander.expand(42);  // Expand function #42
```

## Project Structure

```
omega-sast/
├── bin/
│   └── omega.js              # CLI entry point
├── lib/
│   ├── index.js              # Main library entry
│   ├── ast.js                # AST module aggregator
│   └── redos-worker.js       # Worker-thread ReDoS isolation
├── src/
│   ├── _monolith.js          # Full pipeline implementation
│   └── ast/
│       ├── _monolith.js      # AST module implementation
│       ├── tokenizer.js      # Tokenizer + structural index
│       ├── frameworks.js     # Framework detection
│       ├── bundler.js        # Webpack/bundler analysis
│       ├── call-graph.js     # Call graph builder
│       ├── taint.js          # SSA-based taint tracker
│       ├── crypto.js         # Modern crypto scanner
│       ├── network.js        # Network surface extractor
│       ├── sourcemap.js      # Source map parser
│       ├── obfuscator.js     # Obfuscator fingerprinting
│       ├── summaries.js      # Function summaries + backward slicer
│       ├── llm-payload.js    # VRT + source expander
│       └── helpers.js        # windowText, tokPos
├── test/
│   ├── run-all.js            # Test runner
│   ├── test-harness.js       # Core AST tests (89)
│   ├── test-tokenizer.js     # Tokenizer edge cases (73)
│   ├── test-beautifier.js    # Beautifier tests (11)
│   ├── test-summaries.js     # Function summary tests (52)
│   ├── test-obfuscator.js    # Obfuscator fingerprint tests (45)
│   ├── test-stage7.js        # Destructuring/VRT/expander tests (52)
│   ├── test-regex-audit.js   # Regex audit regression tests (20)
│   ├── test-sourcemap.js     # Source map parser tests (28)
│   ├── test-charcode.js      # CharCode decoder tests (15)
│   ├── test-redos.js         # ReDoS protection tests (10)
│   ├── test-arrow-functions.js # Arrow function tests (19)
│   ├── test-corpus.js          # Bundle corpus regression (51)
│   ├── test-getter-function-detection.js # Getter detection (15)
│   ├── test-verification-issues.js # FP-fix + RC4 + cmd-injection tests (73)
│   ├── test-esoteric.js           # Esoteric decode tests (30)
│   ├── test-csrf.js               # CSRF analyzer tests (41)
│   ├── test-sourcemap.js          # Source map parser tests (40)
│   ├── test-open-disambiguation.js # fs.open vs XHR vs window.open (9)
│   ├── test-math-random-context.js # rand-math-token security-context disambiguation (5)
│   ├── test-stack-trace-context.js # err-stacktrace exposure-context gate (5)
│   ├── test-obfio-recovery.js     # Decoder evidence: hints, boost sync, fixpoint, mutations, second pass (32)
│   ├── test-classify-library.js   # classifyLibrary: lodash-before-jQuery ordering (5)
│   ├── test-classify-angular.js   # classifyLibrary: angular word-boundary rule (\bng\.) (5)
│   └── fixtures/
│       └── sample-bundle.js  # Test fixture
├── bundles/                    # 21 real-world library bundles (regression corpus)
├── docs/
│   └── API.md                # API documentation
├── examples/
│   └── basic-scan.js         # Programmatic usage example
├── .github/workflows/
│   └── ci.yml                # GitHub Actions CI
├── package.json
├── LICENSE
└── README.md
```

## Test Suite

```bash
# Run all 722 tests (100% pass rate)
npm test

# Run individual suites
npm run test:ast
npm run test:tokenizer
npm run test:summaries
npm run test:obfuscator
```

## Supported Frameworks

- **Angular** (Ivy annotation, 110+ instruction maps, component/service/module/pipe/directive detection)
- **React** (hooks, DOM, fiber props, synthetic events, component counting)
- **Vue 3** (vnode, reactivity, router, lifecycle, directives)
- **Svelte** (runtime, store, transition, animation)
- **Next.js** (app-router, server-components, image, headers)
- **Webpack 5** (runtime, chunk, HMR, federation)
- **Vite** (HMR, SSR, preload)
- **Lodash-ES, date-fns, Zod, Zustand, Immer, core-js**

## Supported Obfuscators

- **obfuscator.io** — string-array rotation, RC4/base64 decoder (sandbox eval + brute-force rotation fallback), control-flow flattening
- **Jscrambler** — chained atob/charCode decoder, OC* globals, date anti-debug
- **ByteHide** — namespace detection, XOR decryptor
- **JSProtect** — eval(CryptoJS.decrypt(...))
- **JSFuck** — `[]()!+` encoding (fingerprinted + decodable via `--decode-esoteric`)
- **AAEncode** — `ﾟωﾟﾉ` bootstrap (fingerprinted + decodable via `--decode-esoteric`)
- **JJEncode** — `$=~[]` bootstrap (fingerprinted + decodable via `--decode-esoteric`)
- **Generic** — hex identifiers, eval density, string-concat chains

## Limitations

- **Intra-procedural taint**: The SSA tracker handles local variable propagation and destructuring, but cross-function flows rely on the backward slicer's hop-based traversal (max 3 hops by default).
- **No runtime evaluation**: The constant evaluator handles a strict subset (arithmetic, atob, charCodeAt, concat). No user functions, no Proxy, no eval.
- **Static CVE list**: The dependency scanner uses a curated snapshot (30 packages). For production use, pair with `npm audit` or OSV.dev.
- **Command injection**: Covered via both pattern matching (`child_process`, `cp`, `shell` prefixes and bare `exec`/`spawn`/`fork` with `require("child_process")` context guard) and taint tracking (sinks include `exec`, `spawn`, `fork`). Covers destructured imports and dynamic require patterns.
- **Bracket-notation sinks**: Security patterns and taint tracking cover bracket-notation invocations (`obj[method](arg)`, `obj["eval"](arg)`, `this[fn](arg)`, `window[name](arg)`) for eval, exec, spawn, fork, and other dangerous method names.
- **Indirect eval**: Detects non-literal `eval(expr)`, `Function(arg)`, `setTimeout(str)`, `setImmediate(str)` where the argument is stored in a variable, returned from a function, passed as parameter, or comes from user-controlled sources.
- **Prototype Pollution FP reduction**: `prototype["methodName"] = fn` (known-good library pattern) is no longer flagged; only `__proto__[key]` and dynamic-key `prototype[key]` assignments fire. `JSON.parse(JSON.stringify(x))` deep-clone pattern is excluded. **Open Redirect**: `window.location = X` pattern added. **Path traversal sinks**: `readFileSync`, `writeFileSync`, `unlinkSync`, `mkdirSync`, `rmSync`, `renameSync`, `existsSync`, `createWriteStream`, `createReadStream`, `appendFileSync`. **Credential patterns**: OpenAI `sk-…`, Anthropic `sk-ant-…`, npm `npm_…`, Heroku API key, Google `AIza…`.
- **bcrypt/argon2 recategorized**: These password hashing functions are no longer flagged as "Broken Crypto" — they are moved to "Hardcoded Credential" to reduce false positives on legitimate password hashing use.

## License

MIT — see [LICENSE](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

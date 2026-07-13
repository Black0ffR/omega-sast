# OMEGA-5.0 — Zero-Dependency JavaScript SAST Engine

[![Test Suite](https://img.shields.io/badge/tests-571%20passing-brightgreen)](test/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-green)](package.json)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)](package.json)

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
| 0 | Module alias resolver | Maps `d(N)` → npm package name |
| 1 | Escape decode | Unicode/hex/octal/HTML-entity |
| 2 | String decode | fromCharCode, atob, base64, hex arrays (10-pass) |
| 2b | CharCode decoder | Juice-Shop-style IIFE obfuscation |
| 2c | obfuscator.io decoder | String-array rotation + RC4/base64 + brute-force fallback |
| 2d | Constant evaluator | Safe partial evaluator for runtime strings |
| 3-6 | Normalization | Booleans, webpack cleanup, Angular Ivy, RxJS |
| 7 | Beautifier | Token-based formatter (arrow-safe) |
| 8-8c | Code analysis | Cyclomatic complexity, storage keys, auth surface |
| 9-9b | Framework detection | Regex + AST-based (Angular/Vue/React/Svelte/Next) |
| 10-11 | Routes & credentials | API routes, 32 credential patterns |
| 12 | Security patterns | XSS, injection, crypto, network, storage |
| 12b-m | Behavioral detectors | Dynamic code, business logic, WebSocket, IDOR, CVEs |
| 12o-p | Modern scanners | JWT/WebCrypto/Node crypto, network surface |
| 12r | ReDoS detection | In-source ReDoS vulnerable pattern scan |
| 12q | Source map parser | Inline/external map detection |
| 13-14 | Webpack + call graph | Module resolution, dependency edges |
| 14c | AST taint tracker | SSA-based cross-statement taint |
| 15 | Reports | HTML (dark-mode) + JSON + Markdown |
| 16 | Obfuscator fingerprint | obfuscator.io, Jscrambler, ByteHide, JSFuck |
| 17 | Function summaries | Per-function taint contracts (LLM payload) |
| 18 | Backward slicer | Sink-anchored inter-procedural paths |
| 19 | Variable rename table | Canonical v0/v1/v2 names (token compression) |
| 20 | Source expander | On-demand function expansion (LLM tool-call) |

## Key Features

### Inter-Procedural Taint Tracking
Tracks data flow from taint sources (`location.hash`, `localStorage`, `event.data`) through function boundaries to dangerous sinks (`innerHTML`, `eval`, `exec`, `spawn`, `fork`). Uses per-function SSA-style variable tracking with destructuring support.

### Obfuscator Fingerprinting
Detects 6 obfuscator types (obfuscator.io, Jscrambler, ByteHide, JSProtect, JSFuck, generic) with confidence scoring. Emits LLM-actionable metadata: "expect mangled identifiers", "expect control-flow flattening", etc.

### LLM-Ready Payload
Each function compresses to a ~40-80 token "taint contract" (params, sources, sinks, sanitizers, returns). The backward slicer produces inter-procedural paths ranked by severity. The Variable Rename Table cuts token count 30-50% on minified input.

### CI/CD Integration
Exit codes for CI pipelines: `0`=clean, `2`=critical (default), `3`=high+, `4`=medium+, `5`=low+. Configure via `OMEGA_FAIL_ON` env var. `--quiet` flag suppresses all non-essential output.

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
│   └── fixtures/
│       └── sample-bundle.js  # Test fixture
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
# Run all 571 tests
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
- **JSFuck** — `[]()!+` encoding
- **Generic** — hex identifiers, eval density, string-concat chains

## Limitations

- **Intra-procedural taint**: The SSA tracker handles local variable propagation and destructuring, but cross-function flows rely on the backward slicer's hop-based traversal (max 3 hops by default).
- **No runtime evaluation**: The constant evaluator handles a strict subset (arithmetic, atob, charCodeAt, concat). No user functions, no Proxy, no eval.
- **Static CVE list**: The dependency scanner uses a curated snapshot (30 packages). For production use, pair with `npm audit` or OSV.dev.
- **Command injection**: Covered via both pattern matching (`child_process`, `cp`, `shell` prefixes and bare `exec`/`spawn`/`fork` with `require("child_process")` context guard) and taint tracking (sinks include `exec`, `spawn`, `fork`). Covers destructured imports and dynamic require patterns.

## License

MIT — see [LICENSE](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

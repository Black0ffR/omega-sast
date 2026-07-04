# API Documentation

## Core Functions

### `tokenizeForAST(src)`
Tokenizes JavaScript source into a flat array of tokens.

**Returns:** `{ tokens, errors, lines }`

```javascript
const { tokenizeForAST } = require('omega-sast').ast;
const { tokens } = tokenizeForAST('var x = 42;');
// tokens: [{ type: 'keyword', value: 'var' }, { type: 'ident', value: 'x' }, ...]
```

### `buildStructuralIndex(src)`
Walks the token stream to produce a structural index of classes, functions, call sites, member access, identifiers, and assignments.

**Returns:** `{ classes, functions, callSites, memberAccess, identifiers, assignments, tokens, lex }`

### `detectFrameworksAST(src, structuralIndex)`
AST-based framework detection for Angular, Vue, and React.

**Returns:** `{ angular: { components, services, modules, pipes, directives, total }, vue: { components, total }, react: { components, total } }`

### `computeFunctionSummaries(src, structuralIndex)`
Computes per-function taint contracts (the LLM payload keystone).

**Returns:** Array of summaries:
```javascript
{
  id: 42,              // function index
  name: 'renderHash',
  start: 1024,         // source position
  end: 1152,
  isArrow: false,
  params: ['props'],
  sources: [{ expr: 'location.hash', name: 'location.*', pos: 1050 }],
  sinks: [{ name: 'innerHTML', pos: 1100, cwe: 'CWE-79', severity: 'critical', via: 'location.*' }],
  sanitizers: [],
  returns: [{ kind: 'unknown', value: 'unknown' }],
  calls: ['parseHash', 'render'],
}
```

### `buildBackwardSlices(src, structuralIndex, functionSummaries, callGraph, maxHops)`
Sink-anchored backward slicer. Starts from every sink, walks the call graph backward N hops.

**Returns:** Array of paths:
```javascript
{
  sink: { name: 'innerHTML', pos: 1100, cwe: 'CWE-79', severity: 'critical', via: 'args[0]' },
  sinkFn: { name: 'renderHash', id: 42 },
  hops: [{ fnName: 'caller', fnId: 41, via: 'args[0]', sources: ['location.*'], ... }],
  reachesSource: true,
  sourceChain: ['location.*'],
  totalHops: 1,
  sanitizersOnPath: [],
}
```

### `fingerprintObfuscator(src)`
Detects obfuscator type and emits LLM-useful metadata.

**Returns:**
```javascript
{
  detected: [{ obfuscator: 'obfuscator.io', confidence: 0.85, matched: [...] }],
  primary: { obfuscator: 'obfuscator.io', confidence: 0.85, ... },
  findings: [...],
  llmHints: {
    expectMangledIdentifiers: true,
    expectStringArrayIndirection: true,
    expectControlFlowFlattening: false,
    expectAntiDebugging: false,
    expectRuntimeStringConstruction: true,
    recommendedDecoderPasses: ['extract string array + apply rotation offset', ...],
  }
}
```

### `buildVariableRenameTable(structuralIndex, functionSummaries)`
Generates canonical v0/v1/v2 names for mangled identifiers.

**Returns:**
```javascript
{
  renameTable: Map { '_0x1a2b' => 'fn0', '_0x3c4d' => 'p0', ... },
  reverseTable: Map { 'fn0' => '_0x1a2b', 'p0' => '_0x3c4d', ... },
  stats: { renamed: 74, params: 4, locals: 66, functions: 4 }
}
```

### `createSourceExpander(src, structuralIndex, functionSummaries)`
Creates an on-demand source expansion interface for LLM tool calls.

**Returns:**
```javascript
{
  expand(fnId),           // → { id, name, source, tokenEstimate, params, sources, sinks, ... }
  expandMany(fnIds),      // → Array of expansions
  getSummary(fnId),       // → compact summary (no source)
  getAllSummaries(),      // → all function summaries
  getSinkSummaries(),     // → only functions with sinks
  cache: Map,
  stats: { expansions, cacheHits, cacheMisses, cacheSize },
}
```

### `parseSourceMap(src)`
Parses `//# sourceMappingURL=` references and decodes inline maps.

### `trackTaintAST(src, structuralIndex, callGraph)`
SSA-based cross-statement taint tracker.

### `scanModernCrypto(src, structuralIndex)`
JWT, WebCrypto, bcrypt/argon2, Node crypto scanner.

### `extractNetworkSurface(src)`
URL/host clustering, cloud metadata, RFC1918, public IP catalog.

### `resolveWebpack5Modules(src)`
Parses `webpackChunk_xxx` runtime, extracts module bodies and edges.

### `detectBundler(src)`
Detects webpack5/4, vite-legacy/modern, rollup, ESM build.

### `buildCallGraph(structuralIndex, webpackGraph)`
Function-level + module-level call graph builder.

## CLI

```bash
omega <file.js> [options]
```

Exit codes: `0`=clean, `1`=error, `2`=critical, `3`=high+, `4`=medium+, `5`=low+ (via `OMEGA_FAIL_ON` env var)

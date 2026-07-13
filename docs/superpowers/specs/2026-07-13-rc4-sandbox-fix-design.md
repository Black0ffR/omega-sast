# RC4 Sandbox Eval Fix — Design Spec

**Date:** 2026-07-13
**Status:** Approved design

## Problem

The sandbox eval in `decodeObfuscatorIo()` Step 3e (`src/_monolith.js:1741-1797`) fails on real obfuscator.io samples with `"Invalid or unexpected token"`, causing only 1 of 14 strings to decode. Two root causes:

1. **Missing sandbox globals**: Only `parseInt`, `String`, `Array`, `JSON` are passed to `vm.runInNewContext()`. Real decoder/rotation code references `Math`, `Object`, `RegExp`, `atob`, `isNaN`, `Number`, `Boolean`, `Map`, `Set`, `console`, etc., which throw ReferenceError.

2. **`_findMatchingBrace` ignores regex literals**: The helper walks source tracking `{`/`}` depth for string matching but does not skip regex literals (`/regex{1,3}/`). A `{` inside a regex increments depth, causing premature or incorrect body boundary detection.

## Design

Three changes, attempted in order:

1. **Fix `_findMatchingBrace`** — add regex literal skipping (always applied)
2. **Expand sandbox globals** — provide all commonly-used built-ins (sandbox-first attempt)
3. **Brute-force rotation fallback** — if sandbox eval fails, try all N offsets (catch-all)

---

### 1. Fix `_findMatchingBrace` — regex literal awareness

**File:** `src/_monolith.js`, function `_findMatchingBrace()` (line 1581)

**Change:** After the string-literal skip block, add a regex-literal skip block:

```
When ch === '/':
  Look ahead: if the next char is not a regex-start indicator (not '*', not '/'
  that starts a comment), skip until the closing '/' (handling '\/' escapes).
```

The key insight: regex literals start with `/` only when the preceding context is an operator, assignment, comma, colon, paren, or statement start — not when it's a division operator. For brace-matching purposes, we can safely assume any `/` that isn't a `//` comment or `/*` block comment is a regex literal (false positives for division only matter where `{` is unlikely, e.g. `x = a / b / c;` which is rare in obfuscated code).

**Implementation:**

```javascript
// In the while loop, before brace handling:
if (ch === '/') {
  const next = str[i + 1];
  if (next === '/' || next === '*') {
    // Comment — skip to line end or */
    if (next === '/') { i = str.indexOf('\n', i); if (i === -1) break; continue; }
    const end = str.indexOf('*/', i + 2);
    if (end !== -1) { i = end + 2; continue; } else break;
  }
  if (i === 0 || /[{(\[=,:!&|^?+\-*/%<>~\s;]/.test(str[i - 1])) {
    // Likely a regex literal — skip to closing /
    i++;
    while (i < len) {
      if (str[i] === '\\') { i += 2; continue; }
      if (str[i] === '/') break;
      i++;
    }
  }
}
```

---

### 2. Expand sandbox globals

**File:** `src/_monolith.js`, Step 3e (line 1768)

**Current:**
```javascript
const rotatedJson = script.runInNewContext(
  { parseInt: parseInt, String: String, Array: Array, JSON: JSON },
  { timeout: 5000 }
);
```

**New — comprehensive sandbox globals:**

```javascript
const vm = require('vm');
const _sandbox = {
  // Primitives
  parseInt, parseFloat, isNaN, isFinite,
  NaN, Infinity, undefined,
  // Constructors
  String, Number, Boolean, Array, Object,
  RegExp, Function, Error, TypeError,
  RangeError, SyntaxError, ReferenceError, EvalError, URIError,
  Date, Map, Set, WeakMap, WeakSet, Promise, Symbol,
  // Utilities
  Math, JSON,
  atob: typeof atob !== 'undefined' ? atob : (s) => Buffer.from(s, 'base64').toString('binary'),
  btoa: typeof btoa !== 'undefined' ? btoa : (s) => Buffer.from(s, 'binary').toString('base64'),
  escape, unescape,
  decodeURIComponent, encodeURIComponent,
  // Iteration helpers
  console: { log:()=>{}, warn:()=>{}, error:()=>{}, info:()=>{}, debug:()=>{} },
  setTimeout: (fn) => (typeof fn === 'function' ? fn() : null),
  setInterval: () => {},
  clearTimeout: () => {},
  clearInterval: () => {},
};
const script = new vm.Script(sandboxSrc, { timeout: 5000 });
const rotatedJson = script.runInNewContext(_sandbox, { timeout: 5000, breakOnSigint: true });
```

**Why these globals:**
- `Math` — used in many RC4 decoders for `Math.round`, etc.
- `Object` — used for `.keys()`, `.assign()` in some patterns
- `RegExp` — used in string transforms
- `atob`/`btoa`/`escape`/`unescape` — common in string decoders
- `Map`/`Set`/`WeakMap` — used by some obfuscator variants
- `console.{log,warn,error}` — prevents crashes when obfuscated code logs
- `setTimeout`/`setInterval` stubs — prevents infinite timer loops
- `breakOnSigint: true` — helps kill runaway scripts

**Non-goals:** We explicitly do NOT provide `process`, `Buffer`, `require`, `module`, `__dirname`, `__filename`, `global`, `globalThis`, `window`, `self`, `document`, or any I/O-capable globals. The sandbox remains read-only and memory-only.

---

### 3. Brute-force rotation fallback

**File:** `src/_monolith.js`, Step 3e catch block (line 1786)

**Current:** Catch block only updates the finding description with the error message.

**New:** After the catch block, if the sandbox eval failed, run brute-force rotation correction:

```javascript
// ── Step 3f: brute-force rotation if sandbox eval failed ──────────
if (!rotatedCorrected) {
  const bestOffset = bruteForceRotation(
    src, sa, decName, idxParam, keyParam,
    baseOffset, isRC4, isBase64, isPlain
  );
  if (bestOffset !== null && bestOffset !== initialEffective) {
    // Re-apply rotation with corrected offset
    sa.strings = originalSlice(bestOffset);
    correctedFinding(bestOffset);
  }
}
```

**Brute-force algorithm:**

```javascript
function bruteForceRotation(src, sa, decName, idxParam, keyParam,
                            baseOffset, isRC4, isBase64, isPlain) {
  // 1. Find ALL decoder calls in src (reuse Step 4 call patterns)
  const callSites = extractDecoderCalls(src, decName, aliases);
  if (callSites.length < 2) return null;

  // 2. For each offset 0..N-1:
  let bestOffset = null;
  let bestScore = -1;
  const N = sa.strings.length;

  for (let offset = 0; offset < N; offset++) {
    const rotated = sa.strings.slice(offset).concat(sa.strings.slice(0, offset));
    let score = 0;
    for (const cs of callSites) {
      const adjustedIdx = cs.idx - baseOffset;
      if (adjustedIdx < 0 || adjustedIdx >= N) continue;
      try {
        const raw = rotated[adjustedIdx];
        let decoded;
        if (isPlain) decoded = raw;
        else if (isBase64) decoded = Buffer.from(raw, 'base64').toString('utf8');
        else if (isRC4) decoded = rc4Decrypt(raw, cs.key);
        if (typeof decoded === 'string' && /^[\x20-\x7e\s]*$/.test(decoded)) {
          score++;
        }
      } catch (_) {}
    }
    if (score > bestScore) {
      bestScore = score;
      bestOffset = offset;
    }
  }

  // 3. Return best offset if it beats the initial estimate
  if (bestScore > callSites.length * 0.3) return bestOffset;
  return null;
}
```

**Key design decisions:**
- Uses the same validation function as Step 4 (`/^[\x20-\x7e\s]*$/`) so consistency is guaranteed
- Minimum 2 call sites to avoid single-match noise
- Requires at least 30% valid decoding rate to accept an offset (tunable)
- Falls back to initial estimate if no offset produces useful results
- Runs inside the existing catch block, so it only executes when sandbox fails
- Maximum runtime: `N × callSites` decodings, typically < 1ms even for 1000-element arrays

**Edge cases:**
- **Empty call sites**: If no decoder calls are found with constant args, skip brute-force (no data to score)
- **Tied scores**: First best wins (initial lower offsets are preferred for stability)
- **No offset beats 30% threshold**: Return null, keep initial estimate (the sample may not be obfuscatable)

---

### Test plan

| Test | What it verifies |
|------|-----------------|
| `_findMatchingBrace` with regex `{n,m}` | Brace matching correctly counts braces in regex literals |
| Sandbox with comprehensive globals | `runInNewContext` succeeds with all globals available |
| Brute-force exact match | Synthetic obfuscator.io sample: brute-force picks correct offset |
| Brute-force stability | No offset beats 30% → returns null, keeps initial estimate |
| Real obfuscator.io sample | All 14 strings decoded, `innerHTML` visible, XSS finding fires |

---

### Implementation order

1. `_findMatchingBrace` regex fix (5 lines)
2. Sandbox globals expansion (15 lines)
3. Brute-force function + Step 3e fallback (60 lines)
4. Verify: all corpus tests pass, real sample test passes

---

### Files changed

| File | Change |
|------|--------|
| `src/_monolith.js` | Fix `_findMatchingBrace`, expand sandbox globals, add brute-force function, add Step 3f fallback |
| `test/test-verification-issues.js` | Add regression tests for brute-force (synthetic) |

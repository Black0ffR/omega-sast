# Plan: Fix Remaining V7 Gaps

Based on `VERDICT-V7.md` — 3 remaining gaps in priority order.

---

## Gap 1: Local Alias Tracking for Decoder Calls

**Problem:** The rotation IIFE creates `var _0x357ed1 = a0_0x6ceb` and all subsequent call sites use `_0x357ed1(0x11b, 'Or1k')` instead of `a0_0x6ceb(0x11b, 'Or1k')`. The inlining regex `\\b${decName}\\s*\\(` at `src/_monolith.js:1788-1797` only matches the decoder's actual name, not aliases. Result: 0 strings decoded on real obfuscator.io CLI output even though the decoder and rotation are correctly identified.

**Fix location:** `src/_monolith.js` — after Step 3c (wrapper inlining) and before Step 4 (call-site inlining), around line ~1784.

**Approach (~30 lines):**
1. Scan the source for `var|const|let ALIAS = decName` patterns within function scopes
2. Build a `Set` of alias names for the current decoder
3. Before Step 4, for each alias, append additional `callPatterns` entries using the alias name instead of `decName`
4. The same 4 patterns (direct, .call, .apply, indirect) are generated per alias

```js
// Pre-pass: find aliases of this decoder
const aliasRe = new RegExp(
  `(?:var|const|let)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*${decName}\\b`,
  'g'
);
const aliases = new Set();
let am;
while ((am = aliasRe.exec(src)) !== null) {
  aliases.add(am[1]);
}
```

Then for each alias in `aliases`, push additional call patterns:
```js
for (const alias of aliases) {
  const aliasPatterns = [
    `\\b${alias}\\s*\\(\\s*(-?0x[0-9a-fA-F]+|-?\\d+)\\s*,\\s*["']([^"']*)["']\\s*\\)`,
    `\\b${alias}\\.call\\s*\\(\\s*(?:this|null|undefined)\\s*,\\s*(-?0x[0-9a-fA-F]+|-?\\d+)\\s*,\\s*["']([^"']*)["']\\s*\\)`,
    `\\b${alias}\\.apply\\s*\\(\\s*(?:this|null|undefined)\\s*,\\s*\\[(-?0x[0-9a-fA-F]+|-?\\d+)\\s*,\\s*["']([^"']*)["']\\s*\\]\\s*\\)`,
    `\\(\\s*0\\s*,\\s*${alias}\\s*\\)\\s*\\(\\s*(-?0x[0-9a-fA-F]+|-?\\d+)\\s*,\\s*["']([^"']*)["']\\s*\\)`,
  ];
  callPatterns.push(...aliasPatterns);
}
```

**Test fixture:** Create a test with `var ALIAS = DECODER; ALIAS(0x100, 'key')` and verify it decodes.

---

## Gap 2: Multi-Line String Array Declaration

**Problem:** The string array extraction regex at `src/_monolith.js:1581` requires `];` on the same logical line. Real prettified obfuscator.io output uses multi-line arrays:
```js
var _0x1234 = [
  'string1',
  'string2',
  'string3'
];
```

**Fix location:** `src/_monolith.js:1581` — replace the regex with a multi-line version.

**Approach (~2 lines):**
The current regex is:
```js
const saDeclRe = /(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*\[((?:["'][^"']*["']\s*,?\s*){3,})\]\s*;/g;
```

Replace with a brace-matched approach similar to the decoder body capture: match the opening `[...` on the same line, then walk forward counting `[`/`]` depth to find the closing `]`.

Or simpler: change the regex to use `[\s\S]` (match any char including newline) instead of `[^"']` for the inner content, and use a non-greedy quantifier.

Actually the simplest fix: the current regex's `\s*` already matches newlines. The issue might be more subtle. Let me verify the exact failure case:

Test: `var x = [\n  'a',\n  'b',\n  'c'\n];`
- `\s*` after `,` matches newline+spaces ✓
- `\]` matches `]` after `\s*` consumes newline+spaces before `]` ✓
- `\s*` after `\]` matches newline ✓
- `;` matches `;` ✓

This SHOULD work. If it doesn't, the issue might be:
1. The `{3,}` quantifier combined with backtracking causing catastrophic backtracking
2. The regex engine hitting limits

**Fix if regex fails:** Replace the regex with a minimal start-match + brace-walk:
```js
const saDeclStart = /(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*\[/g;
let sm;
while ((sm = saDeclStart.exec(src)) !== null) {
  let depth = 1;
  let end = sm.index + sm[0].length;
  for (let i = end; i < src.length && depth > 0; i++) {
    if (src[i] === '[') depth++;
    else if (src[i] === ']') depth--;
    end = i;
  }
  const fullDecl = src.slice(sm.index, end + 1);
  // Extract strings from fullDecl with a simpler regex that allows newlines
  const strRe = /["']([^"']*)["']/g;
  const strings = [];
  let sm2;
  while ((sm2 = strRe.exec(fullDecl)) !== null) {
    strings.push(sm2[1]);
  }
  if (strings.length >= 3) {
    // process string array
  }
}
```

**Test fixture:** Create a multi-line `var x = [\n  'a',\n  'b',\n  'c'\n];` and verify it extracts 3 strings.

---

## Gap 3: Inline `data:` Source Map Content Analysis

**Problem:** The `parseSourceMap` function at `src/ast/_monolith.js:2134` already handles inline `data:application/json;base64,...` URIs — it decodes the base64, parses the JSON, flags sensitive paths. But the inline map's decoded sources/mappings may not be fully propagated to the position remapping pipeline.

**Fix location:** `src/ast/_monolith.js:2134-2246` and `src/_monolith.js:5913-5954`.

**Investigation needed:**
1. Check if `parseSourceMap`'s inline path returns `mappings` correctly (line 2212: `mappings: map.mappings || ''`)
2. Check if the pipeline at line ~6080 correctly reads `sourceMapInfo.mappings` for inline maps
3. Check if the inline map findings (`sourcemap-inline-decoded`, `sourcemap-sensitive-path`) appear in the final report

**Likely minimal fix:** If the pipeline already handles inline maps, this gap may be a documentation/verification issue. If not, wire up the inline map's `mappings` and `sources` to the position remapping stage.

---

## Effort Estimates

| Gap | Effort | Complexity | Impact |
|-----|--------|-----------|--------|
| 1 — Local alias tracking | ~45 min | Medium | **HIGH** — unlocks real-world obfuscator.io deobfuscation |
| 2 — Multi-line string array | ~15 min | Low | **MEDIUM** — prettified bundle support |
| 3 — Inline source map | ~15 min (or 0) | Low | **LOW** — may already work |

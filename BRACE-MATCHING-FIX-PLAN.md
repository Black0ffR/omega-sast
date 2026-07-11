# Plan: Brace-Matching for Full Decoder Body Capture

## Root Cause

The getter decoder regex (`src/_monolith.js:1680-1681`) uses non-greedy `[\s\S]{0,800}?` and `[\s\S]{0,200}?` quantifiers. For the real obfuscator.io sample's decoder (3,263 chars), the regex captures only **373 chars** of the body — stopping at the first `}` after the array index expression. The RC4 indicators at positions 622-1797 are never seen:

```
function _0x1ff7(a,b){a=a-0xfb;const local=_0x4d4e();let s=local[a];  ← 373 chars captured
                                                                       ← nothing beyond here in dm[0]
... charCodeAt ... fromCharCode ...                                    ← at positions 622-1797
```

Result: `isRC4` check returns `false`, decoder classified as `plain`, raw ciphertexts inlined, `innerHTML` never recovered.

## Fix

Replace `const body = dm[0]` at line 1694 with brace-matched full function body:

```js
// ── decoder body ──────────────────────────────────────────
// Use brace-matching to capture the full function body
// (regex dm[0] may be truncated by non-greedy quantifiers)
const idx0 = dm[0].indexOf('{');
let fullBody = dm[0];
if (idx0 !== -1) {
  let depth = 1;
  let end = dm.index + idx0 + 1;
  for (let i = end; i < src.length && depth > 0; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') depth--;
    end = i;
  }
  fullBody = src.slice(dm.index, end + 1);
}
```

Then use `fullBody` everywhere `body` was used for detection logic:
- Base offset detection
- `isRC4` / `isBase64` / `isPlain` classification
- The `context` field (uses `body.slice(0, 100)` — fine to use fullBody or keep dm[0])

**Important:** `dm[0]` is fine for the regex's structural match verification — we only need the full body for content analysis.

## Files to modify

| File | Change | Lines |
|------|--------|-------|
| `src/_monolith.js` | Replace `const body = dm[0]` with brace-matching at line 1694 | ~10 lines |

## Estimated effort: ~10 minutes

## Verification

1. `node test/test-getter-function-detection.js` — all 19 tests pass (if real sample present)
2. `node test/test-verification-issues.js` — all 58 tests pass
3. Real obfuscator.io sample: decoder classified as `RC4`, 37 strings decrypted to plaintext, `innerHTML` visible, XSS findings fire

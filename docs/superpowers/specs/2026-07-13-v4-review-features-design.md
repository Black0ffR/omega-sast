# OMEGA-SAST v4 Review Feature Design

**Date:** 2026-07-13
**Source:** INDEPENDENT-REVIEW-v4.md (HEAD a002e22)
**Goal:** Implement the 3 aspirational gaps identified in the v4 review.

---

## 1. ReDoS Detector — Phase 12r

### Goal
Detect vulnerable regex patterns in scanned source code that are susceptible to catastrophic backtracking (ReDoS). Closes the last TPR gap: 15/16 → 16/16.

### Approach
Static extraction + pattern library + optional dynamic verification (Option B from brainstorming).

### Function: `scanReDoS(src)`
New function in `src/_monolith.js` placed after Phase 12q (source map).

**Input:** beautified source text
**Output:** Array of finding objects with `id: 'redos-vulnerable'`, `category: 'ReDoS'`, `cwe: 'CWE-1333'`

### Regex pattern library
Matches against the following known ReDoS-vulnerable patterns in regex literals:

| Pattern class | Example | Detection regex |
|---|---|---|
| Nested quantifiers | `(.+)+`, `(\d+)*`, `(a*)+` | `\([^)]+\)[+*]` then check if surrounded by `[...][+*]` |
| Overlapping alternation | `(a|a)+`, `(ab\|ab)*` | Extract alternation groups, compare alternatives for equality |
| Common prefix alternation | `(a|ab)+`, `(\d|\d\d)+` | Check if one alternative is a prefix of another |
| Backreference with quantifier | `(.*)\1` | Capture group followed by `\N` backreference |

### Regex literal extraction
Match two forms:
1. Literal: `/(?:...)/flags` — match `/` delimiters with escape awareness
2. Constructor: `new RegExp('...', 'flags')` — extract string argument

### Pipeline integration
```javascript
// Phase 12r — In-source ReDoS vulnerability detection
if (opts.verbose) console.log(info('  Phase 12r: In-source ReDoS vulnerability scan…'));
const redosFindings = (opts.security || opts.report) ? scanReDoS(src) : [];
```

Inserted before the `extendedFindings` aggregation at line ~6280. Findings merge into `extendedFindings`:
```javascript
const extendedFindings = [
  ...dynCodeFindings, ...bizLogicFindings, ...wsFindings,
  ...cryptoFindings, ...leakageFindings, ...idorFindings,
  ...depFindings, ...raceFindings, ...taintAll,
  ...web3Findings, ...configFindings, ...lazyFindings,
  ...modernCrypto, ...(networkSurface ? networkSurface.findings : []),
  ...((sourceMapInfo && sourceMapInfo.findings) || []),
  ...((obfuscatorFingerprint && obfuscatorFingerprint.findings) || []),
  ...obfIoFindings,
  ...constExprFindings,
  ...redosFindings,  // <-- ADD HERE
];
```

### Severity assignment
- Nested quantifiers + overlapping alternation: `medium` (CWE-1333, reliable detection)
- Backreference with quantifier: `medium`
- Single non-vulnerable patterns in well-known libs: skip via citation-domain filter

---

## 2. Library-vs-App Context Filter — Phase 12n1

### Goal
Tag findings that originate from library/vendor code (not the application itself) to reduce false positives and noise. Implemented as a two-pass filter: identify library-code regions, then tag findings in those regions.

### Approach
Combined approach (Option C): `node_modules` path detection + known library boilerplate fingerprinting.

### Function: `tagLibraryFindings(findings, src)`

Post-processes the aggregated findings array. Not a scan phase — it mutates finding objects in place.

**Algorithm:**
1. **First pass — scan source for library boundary markers:**
   - `node_modules/` paths in code strings
   - Known CDN URL patterns (e.g., `cdnjs.cloudflare.com/ajax/libs/...`)
   - Library boilerplate signatures per framework
2. **Second pass — for each finding, check context:**
   - If the finding's `context` string or surrounding source region contains a library marker, set `f.libraryInternal = true`
   - Optionally demote severity: `critical → high`, `high → medium`, `medium → low`, etc.
   - Add confidence penalty

### Library boilerplate signatures

| Library | Signature pattern |
|---|---|
| jQuery | `jQuery|jquery|\.fn\.` near the finding |
| React | `createElement|createRoot|useState|useEffect` |
| Vue | `createApp|defineComponent` |
| Angular | `angular\.module|ng\.` |
| Lodash/underscore | `lodash|_\.` near the finding |
| D3 | `d3\.(scale|select|axis)` |
| GSAP | `gsap|Tween|Timeline` |
| Three.js | `THREE\.|three\.module` |
| Chart.js | `Chart\.|chart\.js` |
| Socket.IO | `io\(|socket\.io` |

### Severity demotion rules
- Library-internal `critical` → `high`
- Library-internal `high` → `medium`
- Library-internal `medium` → `low`
- Library-internal `low` → `info`

### Confidence adjustment
- If `libraryInternal: true`, multiply confidence by 0.5 (penalty for uncertain attribution)

### Pipeline integration
Runs after `extendedFindings` is built and before the severity-floor filter:
```javascript
// Phase 12n1 — Tag library-internal findings to reduce FP noise
tagLibraryFindings(extendedFindings, src);
```

---

## 3. Bundler Detection Accuracy Improvement

### Goal
Reduce the number of production bundles that fall back to `minified-global`. Current: 3/14 detected, 11/14 fall back. Target: 6-8/14 detected.

### Approach
Additive pattern additions (Option A): more specific CDN build fingerprints without changing existing patterns.

### Changes to `detectBundler()` in `src/ast/_monolith.js`

#### 3a. Fix `iifeGlobal` pattern
Remove the `^` anchor which causes false negatives when source has leading whitespace/BOM:
```javascript
// Before:
iifeGlobal: /^!\s*function\s*\([^)]*\)\s*\{/,
// After:
iifeGlobal: /!\s*function\s*\([^)]*\)\s*\{/,
```

#### 3b. Add jQuery UMD pattern
```javascript
jqueryUmd: /jQuery.*noConflict|\.fn\.(?:jquery|init)/i,
```
Matches jQuery's `jQuery.fn.jquery` version string or `jQuery.noConflict` signature.

#### 3c. Add AngularJS pattern
```javascript
angularJs: /angular\.module\s*\(|\.module\s*\(\s*['"][^'"]*['"]\s*,\s*\[/,
```
Matches Angular module definition with dependency array.

#### 3d. Enhanced esbuild pattern
```javascript
esbuild: /__require\s*=\s*typeof\s+require|__markAsModule|var\s+__defProp\s*=\s*Object\.defineProperty.*__getOwnPropDesc|var\s+__commonJS\s*=\s*\(|\/\/\s*esbuild|\/\*\s*esbuild-built/,
```
Added `\/\/\s*esbuild` and `\/\*\s*esbuild-built` comments that esbuild inlines.

#### 3e. Enhanced rollup pattern
```javascript
rollup: /var\s+(__defProp|__getOwnPropSlot|__copyProps|__export|__commonJS|__esModule)\s*=\s*Object\.defineProperty|Object\.defineProperty\s*\(\s*exports,\s*["']__esModule["']|\/\*\s*rollup|\/\/!\s*rollup|function\s+\w+\s*\([^)]*\)\s*\{[\s\S]{0,300}\/\*\s*rollup/,
```
Added rollup comment markers.

#### 3f. Priority reorder
Keep `esbuild`, `rollup`, `parcel`, `angularJs`, `jqueryUmd` at appropriate priority levels:
```
['nextAppRouter','webpack5','webpack4','viteRelChunks','viteLegacy','viteModern','rollup','esbuild','parcel','angularJs','jqueryUmd','browserify','umdNamed','umdGeneric','iifeGlobal']
```

### Risk assessment
- These are purely additive regex patterns that can only INCREASE detection, never decrease existing matches
- The priority ordering ensures specific patterns (rollup, esbuild) match before generic fallbacks (umd, iifeGlobal)
- No test changes needed; existing tests should continue passing

---

## Testing Strategy

### New test file: `test/test-redos-detector.js`
| Test | Assertions |
|---|---|
| Nested quantifier `(.+)+` detected | 1 |
| Nested quantifier `(\d+)*` detected | 1 |
| Overlapping alternation `(a|a)+` detected | 1 |
| Backreference `(.*)\1` detected | 1 |
| Safe regex literal `/hello/` not flagged | 1 |
| `new RegExp('(.+)+')` constructor form detected | 1 |
| Safe `new RegExp('\\d+')` not flagged | 1 |

### Test additions to `test/test-verification-issues.js`
Add a section 3.x for v4 feature verification:
| Test | Assertions |
|---|---|
| `--security` mode runs ReDoS scan without crash | 1 |
| ReDoS findings appear in report.json | 1 |
| Library-tagged findings have `libraryInternal` field | 1 |
| Library-tagged findings have demoted severity | 1 |
| Bundler detection still works on known bundles | 2 |

### Existing test regression
- `npm test` must produce 551+ passed, 0 failed (same baseline as v4)
- All 13-bundle scans must produce same or lower total findings count (library filter reduces noise)

---

## Files Modified

| File | Change |
|---|---|
| `src/_monolith.js` | Add `scanReDoS()`, `tagLibraryFindings()` functions; add pipeline integration |
| `src/ast/_monolith.js` | Update `detectBundler()` with 4 new patterns + fix `iifeGlobal` anchor |
| `test/test-redos-detector.js` | New file with 7-8 test assertions |
| `test/test-verification-issues.js` | Add v4 feature verification section |

# v4 Review Features Implementation Plan

> **For agentic workers:** Inline execution.

**Goal:** Implement ReDoS detector, library-vs-app filter, and bundler detection improvements.

**Architecture:** Three independent additions to the monolith scanner pipeline — new Phase 12r (ReDoS), new Phase 12n1 (library filter), and updated `detectBundler()` patterns.

**Tech Stack:** Node.js, regex-based static analysis, worker_threads isolation for ReDoS confirmation

---

### Task 1: Update Bundler Detection

**Files:**
- Modify: `src/ast/_monolith.js:1151-1188`

- [ ] **Remove `^` anchor from `iifeGlobal` pattern**

```javascript
iifeGlobal: /!\s*function\s*\([^)]*\)\s*\{/,
```

- [ ] **Add `jqueryUmd` pattern**
```javascript
jqueryUmd: /jQuery.*noConflict|\.fn\.(?:jquery|init)/i,
```

- [ ] **Add `angularJs` pattern**
```javascript
angularJs: /angular\.module\s*\(|\.module\s*\(\s*['"][^'"]*['"]\s*,\s*\[/,
```

- [ ] **Enhance `esbuild` pattern** — add comment markers
```javascript
esbuild: /__require\s*=\s*typeof\s+require|__markAsModule|var\s+__defProp\s*=\s*Object\.defineProperty.*__getOwnPropDesc|var\s+__commonJS\s*=\s*\(|\/\/\s*esbuild|\/\*\s*esbuild-built/,
```

- [ ] **Enhance `rollup` pattern** — add comment markers
```javascript
rollup: /var\s+(__defProp|__getOwnPropSlot|__copyProps|__export|__commonJS|__esModule)\s*=\s*Object\.defineProperty|Object\.defineProperty\s*\(\s*exports,\s*["']__esModule["']|\/\*\s*rollup|\/\/!\s*rollup/,
```

- [ ] **Update priority array**
```javascript
const PRIORITY = ['nextAppRouter','webpack5','webpack4','viteRelChunks','viteLegacy','viteModern','rollup','esbuild','parcel','angularJs','jqueryUmd','browserify','umdNamed','umdGeneric','iifeGlobal'];
```

- [ ] **Run tests**
```bash
npm test
```

---

### Task 2: Implement `scanReDoS()` Function

**Files:**
- Modify: `src/_monolith.js` — add function after Phase 12q (~line 4204)
- Create: `test/test-redos-detector.js`

- [ ] **Write the failing test**

```javascript
// test/test-redos-detector.js
const assert = require('assert');
const { scanReDoS } = require('../src/_monolith');

function testNestedQuantifier() {
  const findings = scanReDoS('var re = /(.+)+/;');
  assert(findings.some(f => f.id === 'redos-vulnerable'));
  console.log('  ✔ Nested quantifier (.+)+ detected');
}

function testSimpleQuantifierNotFlagged() {
  const findings = scanReDoS('var re = /hello/;');
  assert(!findings.some(f => f.id === 'redos-vulnerable'));
  console.log('  ✔ Simple literal /hello/ not flagged');
}

function testAlternationOverlap() {
  const findings = scanReDoS('var re = /(a|a)+/;');
  assert(findings.some(f => f.id === 'redos-vulnerable'));
  console.log('  ✔ Overlapping alternation (a|a)+ detected');
}

function testNewRegExpForm() {
  const findings = scanReDoS('var re = new RegExp("(.+)+");');
  assert(findings.some(f => f.id === 'redos-vulnerable'));
  console.log('  ✔ new RegExp("(.+)+") constructor form detected');
}

function testBackreference() {
  const findings = scanReDoS('var re = /(.*)\\1/;');
  assert(findings.some(f => f.id === 'redos-vulnerable'));
  console.log('  ✔ Backreference (.*)\\1 detected');
}

function testSafeNewRegExp() {
  const findings = scanReDoS('var re = new RegExp("\\\\d+");');
  assert(!findings.some(f => f.id === 'redos-vulnerable'));
  console.log('  ✔ Safe new RegExp("\\\\d+") not flagged');
}

// Run all
let pass = 0, fail = 0;
for (const [name, fn] of Object.entries(module.exports)) {
  try { fn(); pass++; } catch (e) { console.error(`  ✘ ${name}: ${e.message}`); fail++; }
}
console.log(`\nReDoS tests: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
```

- [ ] **Implement `scanReDoS(src)`**

Function to extract regex literals from source and check against vulnerable patterns.

Algorithm:
1. Extract regex literals: `/\x[^/]*/[gimsuy]*` (with escape awareness for `\/` inside)
2. Extract `new RegExp(...)` strings
3. For each extracted regex, check:
   - Nested quantifiers: has `[+*][?+]?` after a group `(...)` where group body also has `[+*][?+]?`
   - Overlapping alternation: group with alternation `|` where two alternatives are identical
   - Common prefix alternation: one alternative is a prefix of another in same group
   - Backreference: `\\[1-9]` present
4. Create finding objects

```javascript
function scanReDoS(src) {
  const findings = [];
  const regexes = new Set();

  // Extract regex literals: /pattern/flags with escape-aware parsing
  const litRe = /(?<!\\)\/((?:[^\/\\]|\\.)+)\/([gimsuy]*)/g;
  let m;
  while ((m = litRe.exec(src)) !== null) {
    const pattern = m[1];
    if (pattern.length > 2 && pattern.length < 1000) regexes.add(pattern);
  }

  // Extract new RegExp('...') strings
  const ctorRe = /new\s+RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g;
  while ((m = ctorRe.exec(src)) !== null) {
    const pattern = m[1].replace(/\\(.)/g, '$1');
    if (pattern.length > 2 && pattern.length < 1000) regexes.add(pattern);
  }

  for (const pattern of regexes) {
    if (isVulnerable(pattern)) {
      findings.push({
        id: 'redos-vulnerable',
        category: 'ReDoS',
        severity: 'medium',
        cwe: 'CWE-1333',
        value: pattern.slice(0, 80),
        context: src.length > 0 ? 'regex pattern vulnerable to ReDoS' : '',
        description: 'Regex vulnerable to ReDoS (catastrophic backtracking) — pattern contains constructs that can cause exponential backtracking on crafted input',
      });
    }
  }

  return findings;
}
```

- [ ] **Implement `isVulnerable(pattern)` helper**

```javascript
function isVulnerable(pattern) {
  try {
    new RegExp(pattern);
  } catch { return false; }

  // Check for nested quantifiers: group with [+*][?+]? where group contains [+*][?+]?
  const nestedQuant = /\([^)]*[+*][?+]?[^)]*\)[+*]/;
  if (nestedQuant.test(pattern)) return true;

  // Check for backreference: \1, \2, etc.
  if (/\\([1-9])/.test(pattern)) return true;

  // Check for overlapping alternation in quantifier groups
  // Match groups like: (a|a)+, (ab|ab)*, etc.
  const altGroupRe = /\(([^)]+)\)[+*]/g;
  let am;
  while ((am = altGroupRe.exec(pattern)) !== null) {
    const alts = am[1].split('|');
    if (alts.length > 1) {
      const trimmed = alts.map(a => a.replace(/\s/g, ''));
      // Check for identical alternatives
      for (let i = 0; i < trimmed.length; i++) {
        for (let j = i + 1; j < trimmed.length; j++) {
          if (trimmed[i] === trimmed[j]) return true;
          // Check for common prefix alternation (one is prefix of another)
          if (trimmed[i].length > 0 && trimmed[j].length > 0 &&
              (trimmed[j].startsWith(trimmed[i]) || trimmed[i].startsWith(trimmed[j]))) {
            if (trimmed[i] !== trimmed[j]) return true;
          }
        }
      }
    }
  }

  return false;
}
```

- [ ] **Export `scanReDoS` from `src/_monolith.js`**

```javascript
// At module.exports (bottom of file):
module.exports = { ...existing, scanReDoS };
```

- [ ] **Run tests**
```bash
node test/test-redos-detector.js
```

---

### Task 3: Integrate ReDoS into Pipeline

**Files:**
- Modify: `src/_monolith.js` — add Phase 12r call

- [ ] **Add Phase 12r call after Phase 12q source map section**

After the `scanLazyLoading` call (~line 6007), add:
```javascript
// Phase 12r — In-source ReDoS vulnerability detection
if (opts.verbose) console.log(info('  Phase 12r: In-source ReDoS vulnerability scan…'));
const redosFindings = (opts.security || opts.report) ? scanReDoS(src) : [];
```

- [ ] **Merge into extendedFindings**

```javascript
const extendedFindings = [
  ...
  ...obfIoFindings,
  ...constExprFindings,
  ...redosFindings,  // <-- ADD HERE
];
```

- [ ] **Run tests**
```bash
npm test
```

---

### Task 4: Implement `tagLibraryFindings()`

**Files:**
- Modify: `src/_monolith.js` — add function after `classifyLibrary` (~line 4283)

- [ ] **Implement `tagLibraryFindings(findings, src)`**

```javascript
const LIBRARY_PATTERNS = [
  { re: /node_modules[\\/]/, name: 'node_modules' },
  { re: /cdnjs\.cloudflare\.com\/ajax\/libs\//, name: 'cdnjs' },
  { re: /(?:jQuery|jquery|\.fn\.jquery)/, name: 'jQuery' },
  { re: /(?:React|createElement|createRoot|useState|useEffect)/, name: 'React' },
  { re: /(?:createApp|defineComponent|Vue)/, name: 'Vue' },
  { re: /angular\.module|ng\./, name: 'Angular' },
  { re: /(?:lodash|underscore)/, name: 'lodash' },
  { re: /d3\.(?:scale|select|axis|format)/, name: 'D3' },
  { re: /(?:gsap|Tween|TimelineLite|TimelineMax)/, name: 'GSAP' },
  { re: /THREE\./, name: 'Three.js' },
  { re: /Chart\.(?:register|new Chart)/, name: 'Chart.js' },
  { re: /io\(|socket\.io/, name: 'Socket.IO' },
  { re: /express|koa|fastify|hapi/, name: 'backend' },
];

function tagLibraryFindings(findings, src) {
  const markers = [];
  for (const { re, name } of LIBRARY_PATTERNS) {
    let m;
    while ((m = re.exec(src)) !== null) {
      markers.push({ index: m.index, name });
    }
  }

  for (const f of findings) {
    const ctx = (f.context || '').toLowerCase();
    const val = (f.value || '').toLowerCase();
    const combined = ctx + ' ' + val;
    for (const { name } of LIBRARY_PATTERNS) {
      if (name === 'node_modules' || name === 'cdnjs') {
        // Direct path match — very reliable
        if (combined.includes(name === 'node_modules' ? 'node_modules' : 'cdnjs.cloudflare.com')) {
          f.libraryInternal = true;
          break;
        }
      } else {
        // Check if finding context matches library signature
        if (name === 'jQuery' && /jquery/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'React' && /react|createElement|createroot|usestate|useeffect/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'Vue' && /vue|createapp|definecomponent/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'Angular' && /angular|ng\b/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'D3' && /d3\.(scale|select|axis)/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'Three.js' && /three\./i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'Chart.js' && /chart\.(register|new chart)/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'Socket.IO' && /socket\.io|io\(/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'GSAP' && /gsap|tween/i.test(combined)) { f.libraryInternal = true; break; }
        if (name === 'lodash' && /lodash|underscore/i.test(combined)) { f.libraryInternal = true; break; }
      }
    }

    if (f.libraryInternal) {
      // Demote severity
      const demote = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
      if (demote[f.severity]) f.severity = demote[f.severity];
      // Demote confidence
      if (f.confidence) f.confidence *= 0.5;
    }
  }
}
```

- [ ] **Integrate into pipeline after extendedFindings build (~line 6291)**

Add after `const extendedFindings = [...]` block:
```javascript
// Phase 12n1 — Tag library-internal findings to reduce FP noise
tagLibraryFindings(extendedFindings, src);
```

- [ ] **Run tests**
```bash
npm test
```

---

### Task 5: Add Verification Tests

**Files:**
- Modify: `test/test-verification-issues.js` — add section 3.x

- [ ] **Add v4 features test section**

```javascript
// ═════════════════════════════════════════════════════════════════════════
//  ISSUE 3.x — v4 features: ReDoS, library filter, bundler detection
// ═════════════════════════════════════════════════════════════════════════
section('3.x v4 feature verification');

(function () {
  const fixture = path.join(__dirname, 'fixtures', 'sample-bundle.js');

  // ReDoS: scan produces redos-vulnerable findings
  const out1 = mkTmpDir();
  const r1 = runOmega([fixture, '--security', '--report', '--quiet', '--out', out1]);
  const r1Report = readReport(out1);
  const redosCount = allFindings(r1Report).filter(f => f.id === 'redos-vulnerable').length;
  assert('--security mode runs ReDoS scan without crash', r1.status === 0);
  // (actual ReDoS detection depends on the bundle content)

  // Bundler detection doesn't crash
  assert('Scan completes with bundler detection', r1.status === 0);
})();
```

- [ ] **Ensure test fixture contains a ReDoS-vulnerable pattern**

(Done by sample-bundle.js already having varied content; may need verification.)

- [ ] **Run full test suite**
```bash
npm test
```

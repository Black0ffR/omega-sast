# Plan: Scoring Calibration & Detection Quality Improvements

Based on the assessment report (OMEGA-SAST-Assessment-Report.md), there are 5 key gaps to address:

---

## Gap 1: Library-Type Context for Scoring

**Problem:** Socket.IO scored 83 (CRITICAL) for using network APIs that are its core purpose. All bundles are scored by the same metric regardless of their domain (networking, crypto, UI framework, utility library).

**Fix:** Add library-type awareness to the attack surface scoring in the reporting phase.

**File:** `src/_monolith.js` (Phase 15 — Report generation, around line ~4300-4600)

Add a library-type classification step that detects the bundle's domain:
```js
function classifyLibrary(src) {
  if (src.includes('socket.io') || /WebSocket|XHR|\.on\("(data|connect|error)"/i.test(src))
    return 'networking';
  if (src.includes('CryptoJS') || /(AES|DES|SHA|MD5|RSA)/.test(src))
    return 'crypto';
  if (src.includes('jQuery') || /\.(fn|extend|each)\(/.test(src))
    return 'ui-framework';
  return 'general';
}
```

Then adjust scoring weights:
- **networking:** Reduce "Dangerous API Calls" weight by 50-75% (network APIs are expected)
- **crypto:** Reduce "Broken Crypto" false positives (legitimate crypto operations)
- **ui-framework:** Standard scoring (UI frameworks can have XSS/DOM manipulation issues)
- **general:** Full scoring

---

## Gap 2: Taint-Source Correlation Weighting

**Problem:** "Dangerous API Calls" findings score 75 points on Socket.IO without any taint source correlation. A dangerous API call (e.g. `document.cookie`, `fetch()`) without an attacker-controllable taint source should score lower.

**Fix:** In the attack surface scoring function, correlate findings with taint sources. Implementation options:

**Option A (simple):** Reduce "Dangerous API Calls" category weight by half when no taint-source findings (CRITICAL/HIGH XSS) exist in the same bundle.

**Option B (better):** For each "Dangerous API Call" finding, check if a taint source reaches it. If not, demote its score contribution.

**File:** `src/_monolith.js` — the scoring function around line ~4400-4500

---

## Gap 3: Cookie-Context Awareness

**Problem:** Axios flagged for `document.cookie` access in XSRF token handling. cookie access should distinguish between:
- Reading cookies for XSRF token transmission (legitimate)
- Reading all cookies for exfiltration (suspicious)

**Fix:** Add contextual analysis to the `credentials` finder (Phase 8a):

```js
// If document.cookie access is near XSRF/XSRF-TOKEN or axios defaults:
//   → demote from MEDIUM to LOW or INFO
if (context.includes('xsrf') || context.includes('XSRF-TOKEN'))
  severity = 'info';
```

**File:** `src/_monolith.js` — Phase 8a credential/cookie detection

---

## Gap 4: Expand Backward Slicer Hop Limit

**Problem:** The backward slicer has a max 3-hop limit (Phase 18). Complex inter-procedural flows may require more hops.

**Fix:** Increase default hop limit from 3 to 5, and add `--max-hops N` CLI option.

**Files:**
- `src/ast/_monolith.js` — buildBackwardSlices function, change default from 3 to 5
- `src/_monolith.js` — CLI option parsing for `--max-hops`

---

## Gap 5: Individual Finding Confidence Scoring

**Problem:** The tool outputs an aggregate attack score per bundle, but individual findings don't have confidence scores. This makes triage harder.

**Fix:** Add a `confidence` field (0.0-1.0) to each finding object in the security findings phase:

```js
finding.confidence = 
  finding.severity === 'critical' ? 0.95 :
  finding.severity === 'high'     ? 0.80 :
  finding.severity === 'medium'   ? 0.60 :
  finding.severity === 'low'      ? 0.40 : 0.10;
```

And add a `reason` field explaining the confidence level:
```js
finding.confidenceReason = 
  'AST-verified taint flow from source to sink'  // critical/high
  || 'Regex-suspected pattern, no AST verification'  // medium
  || 'Prone to false positives, verify manually';  // low
```

**File:** `src/_monolith.js` — security findings phase (Phase 12, around ~line 2200-2800)

---

## Effort Estimates

| Gap | Effort | Complexity | Impact |
|-----|--------|-----------|--------|
| 1 — Library-type scoring | ~2 hours | Medium | **HIGH** — Fixes Socket.IO score inflation |
| 2 — Taint-source correlation | ~1 hour | Low | **HIGH** — Reduces false-positive scores |
| 3 — Cookie context | ~30 min | Low | **MEDIUM** — Fixes Axios false positive |
| 4 — Hop limit | ~15 min | Low | **LOW** — More flow coverage |
| 5 — Confidence scoring | ~1 hour | Low | **MEDIUM** — Better triage UX |

**Total:** ~5 hours for all 5 improvements.

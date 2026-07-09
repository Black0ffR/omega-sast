# OMEGA-SAST v4 Upgrade Plan

## 4 remaining architectural gaps from v3 verification (score 9/10 → target 10/10)

### Gap 1 — Taint tracking (intra-procedural + 3-hop limit)

**Sub-tasks:**
| # | Task | File(s) | Est. |
|---|------|---------|------|
| 1a | `--max-hops N` CLI option (default 5), remove hardcoded 3 | `src/_monolith.js` | 15m |
| 1b | Full inter-procedural return-value propagation through summaries | `src/ast/_monolith.js` | 3h |
| 1c | Module-export taint tracking (`module.exports = taintedVar` → cross-module flow) | `src/ast/_monolith.js`, `src/_monolith.js` | 2h |
| 1d | Sanitizer recognition — suppress findings that pass through `.replace(/</g…)` or `DOMPurify` | `src/ast/_monolith.js` | 1h |

### Gap 2 — Source-map recovery

| # | Task | File(s) | Est. |
|---|------|---------|------|
| 2a | `--fetch-sourcemaps` flag, Node built-in `http`/`https` to fetch external `.map` files | `src/ast/_monolith.js`, `src/_monolith.js` | 1.5h |
| 2b | VLQ base64 position decoding from `mappings` field | `src/ast/_monolith.js` | 2h |
| 2c | Remap findings to `{originalFile, originalLine, originalColumn}` when source map available | `src/_monolith.js` | 1h |

### Gap 3 — Cross-bundle analysis

| # | Task | File(s) | Est. |
|---|------|---------|------|
| 3a | `--multi` CLI mode, merged module graph, version-conflict detection | `src/_monolith.js` | 2h |
| 3b | Combined report with per-bundle breakout | `src/_monolith.js` | 1.5h |

### Gap 4 — CVE/CWE database

| # | Task | File(s) | Est. |
|---|------|---------|------|
| 4a | Expand curated list from 30→80+ packages, add 2025-2026 CVEs | `src/_monolith.js` | 1h |
| 4b | `package.json` dependency extraction from bundle comments/metadata | `src/_monolith.js` | 1h |
| 4c | `--fetch-cves` flag, OSV.dev API via Node built-in `https`, memory cache | `src/_monolith.js` | 2h |

### Execution order

```
4a (CVE expand) → 1a (maxHops) → 4b (package.json) → 4c (OSV.dev fetch) →
2a (fetch sourcemaps) → 2b+2c (VLQ decode + remap) →
1b (return propagation) → 1c (module-exports) → 1d (sanitizer) →
3a+3b (cross-bundle)
```

### Design decisions (per user)

1. **Gap 1b**: Full summary propagation — function summaries now say "if param X is tainted, return value is tainted at position Y". Heavier but correct dataflow.
2. **Gap 2a**: Node built-in `http`/`https` (keeps zero-dep, adds network I/O). Opt-in `--fetch-sourcemaps`.
3. **Gap 4c**: Both — expand static list to 80+ AND add `--fetch-cves` for OSV.dev API.
4. **Gap 3**: `--multi` flag on main `omega` CLI, not a separate binary.

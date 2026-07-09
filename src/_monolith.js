#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║          JS DECODER OMEGA  v5  —  Unified Multi-Framework Security Engine                       ║
 * ║                                                                                                   ║
 * ║  Synthesises and surpasses:                                                                      ║
 * ║    · js_decoder_omega.js             (OMEGA-1.0 — Angular/Webpack focus)                          ║
 * ║    · framework_symbol_maps.js        (OMEGA-2.0 — Multi-framework maps)                           ║
 * ║    · js_decoder_omega_v3.js          (OMEGA-3.0 — Storage/Auth surface)                           ║
 * ║    · js_decoder_omega_v4.js          (OMEGA-4.0 — Behavioral + business logic)                     ║
 * ║                                                                                                   ║
 * ║  OMEGA-5.0 IMPROVEMENTS — TIER 1 STRUCTURAL UPGRADE:                                              ║
 * ║    [5-AST]    Custom zero-dep JS tokenizer + structural walker (replaces pure regex detection)     ║
 * ║    [5-T1.1]   AST-based framework detection — Angular components, services, modules, pipes,        ║
 * ║               directives counted via class-body AST walk, not surface regex hits                 ║
 * ║    [5-T1.2]   Webpack 5 dynamic module resolver — parses `webpackChunk_xxx` runtime,              ║
 * ║               extracts real `(Q,H,d) => {...}` module bodies and weighted edges                  ║
 * ║    [5-T1.3]   Call-graph builder — (moduleId, functionName) → {imports, exports, calls} map,       ║
 * ║               entry-point + orphan-function analysis                                             ║
 * ║    [5-T1.4]   Cross-statement taint tracking on AST — propagates through assignment chains,        ║
 * ║               finds `location.search → innerHTML` flows that pure regex misses                   ║
 * ║    [5-T1.5]   Bundler detection + per-bundler Phase 13 — supports webpack5 / webpack4 /            ║
 * ║               vite-legacy / vite-modern ESM / rollup IIFE                                        ║
 * ║    [5-T1.6]   Modern crypto pattern scanner — JWT literal payload decoding, WebCrypto             ║
 * ║               subtle.{encrypt,decrypt,importKey,exportKey}, Node `createHash`/`createHmac`        ║
 * ║               with weak algorithms, bcrypt/argon2 literal hashes, hardcoded bearer tokens        ║
 * ║    [5-T1.10]  Network surface extractor — host clustering, RFC1918 IP audit, cloud metadata       ║
 * ║               (169.254.169.254, metadata.google.internal), public-IP cataloging                  ║
 * ║                                                                                                   ║
 * ║  Plus the full OMEGA-4.0 surface preserved:                                                       ║
 * ║    [A1] Hierarchical framework detection with confidence scoring                                  ║
 * ║    [A2] Route-guard ↔ API-endpoint authorization correlation                                     ║
 * ║    [B1] Dynamic code execution: setTimeout/setInterval/Function()/Wasm                            ║
 * ║    [B2] Complete DOM-XSS sink catalog (outerHTML/insertAdjacentHTML/srcdoc…)                      ║
 * ║    [B3] Angular template injection / $compile detection                                            ║
 * ║    [B4] Prototype pollution + gadget detection                                                   ║
 * ║    [B5] PostMessage wildcard origin / missing validation                                          ║
 * ║    [B6] Insufficient randomness in security contexts                                              ║
 * ║    [B7] bypassSecurityTrust* full family (Style/Url/ResourceUrl/Script)                          ║
 * ║    [B8] Error-handling information leakage                                                        ║
 * ║    [B9] Source-map artifact detection                                                             ║
 * ║    [B10] Web Workers / importScripts security                                                    ║
 * ║    [B11] Client-side file upload validation                                                       ║
 * ║    [B14] Attack surface prioritisation scorer                                                     ║
 * ║    [C1] Business logic: rate-limit/balance/coupon/role bypass vectors                             ║
 * ║    [C2] WebSocket message content → DOM sink taint tracing                                       ║
 * ║    [C3] Socket.io event → side-effect + sensitive payload mapping                                ║
 * ║    [C4] Cryptographic context: privkey/static-IV/ECB/subtle misuse                                ║
 * ║    [C5] Information leakage: stack trace/debug/path/enumeration                                  ║
 * ║    [C6] IDOR: user-ID in URL/localStorage without ownership check                                ║
 * ║    [C7] Static dependency CVE correlation (10 known-vuln packages)                              ║
 * ║    [C8] Race conditions in async localStorage read-modify-write                                  ║
 * ║    [D1] Heuristic taint-flow: URL/postMessage/storage → innerHTML/eval                            ║
 * ║    [D2] Web3/blockchain: privkey/sendTx/sig-replay/reentrancy                                   ║
 * ║    [D3] Config-driven behaviour: disabled auth/CORS wildcard/debug flags                          ║
 * ║    [D4] Lazy-loading: unguarded chunks + user-controlled dynamic import()                         ║
 * ║                                                                                                   ║
 * ║                                                                                                   ║
 * ║  PHASE  0  Module alias resolver (d(N) → known npm package name)                                  ║
 * ║  PHASE  1  Escape decode  (Unicode / ES6 / Hex / Octal / HTML-entity)                             ║
 * ║  PHASE  2  String decode  (fromCharCode · atob · base64 · hex-array ·                             ║
 * ║              unicode-array · concat-folding — 10-pass iterative)                                   ║
 * ║  PHASE 2b  CharCode obfuscation decoder                                                             ║
 * ║              · r.reverse().map(fromCharCode(o-e-offset-a)) decoder                              ║
 * ║              · Recovers hidden routes, embedded strings, coupon codes                             ║
 * ║  PHASE  3  Boolean/undefined normalise  (!0 !1 void 0 !![] ![] +[])                              ║
 * ║  PHASE  4  Webpack 5 cleanup  (IIFE · require rename · export helpers)                          ║
 * ║  PHASE  5  Angular Ivy annotation  (110+ instructions, namespace-aware,                            ║
 * ║              human-readable comment headers for ɵfac/ɵcmp/ɵprov)                                  ║
 * ║  PHASE 5b  Multi-framework symbol annotation                                                       ║
 * ║              · Vue 3 vnode/reactivity/router/lifecycle/directives                                 ║
 * ║              · React hooks/DOM/fiber-props/synthetic-events                                       ║
 * ║              · Svelte runtime/store/transition/animation                                          ║
 * ║              · Next.js app-router/server-components/image/headers                                  ║
 * ║              · Webpack 5 runtime/chunk/HMR/federation comment tags                                ║
 * ║              · Vite HMR/SSR/preload comment tags                                                   ║
 * ║              · Lodash-ES tree-shaken symbol map                                                   ║
 * ║              · date-fns v3 symbol map                                                              ║
 * ║              · Zod schema symbol map                                                               ║
 * ║              · Zustand store symbol map                                                            ║
 * ║              · Immer produce/draft symbol map                                                      ║
 * ║              · core-js polyfill shim recognition                                                   ║
 * ║  PHASE  6  RxJS operator annotation  (map · catchError · switchMap …)                             ║
 * ║  PHASE  7  Token-based beautifier  (full lexer — O(n) formatter)                                  ║
 * ║  PHASE  8  Code analysis  (cyclomatic complexity · Halstead metrics …)                            ║
 * ║  PHASE 8b  Storage key audit                                                                        ║
 * ║              · localStorage / sessionStorage key→op-type map                                       ║
 * ║              · cookieService key audit (get/put/remove)                                            ║
 * ║  PHASE 8c  Auth surface mapper                                                                      ║
 * ║              · Guard→route mapping (canActivate resolved to paths)                                 ║
 * ║              · Unguarded high-value route detection                                                ║
 * ║  PHASE  9  Framework detection  (FP-safe — merged heuristics, regex fallback)                       ║
 * ║  PHASE 9b  AST foundation  (OMEGA-5.0 NEW)                                                         ║
 * ║              · Custom zero-dep tokenizer + walker                                                  ║
 * ║              · Classes, functions, call sites, member access, identifiers                          ║
 * ║  PHASE 9b-T1  AST framework detection  (OMEGA-5.0 NEW — replaces Tier 1.1)                          ║
 * ║  PHASE 10  Route extraction  (/rest /api /graphql /vN · wss:// ·                                    ║
 * ║              child routes · CharCode-obfuscated hidden routes)                                     ║
 * ║  PHASE 11  Credential scanner  (32 patterns · dedup · FP-suppressed)                                ║
 * ║  PHASE 12  Security analysis  (XSS · injection · crypto · network …)                              ║
 * ║  PHASE 12b-m  OMEGA-4.0 behavioral detectors (dynamic code, business logic, WebSocket,             ║
 * ║              IDOR, dependency CVEs, race conditions, etc.)                                         ║
 * ║  PHASE 12o  Modern crypto scanner  (OMEGA-5.0 NEW — Tier 1.6)                                       ║
 * ║              · JWT literal + payload decode                                                        ║
 * ║              · WebCrypto subtle.{encrypt,decrypt,import,export}                                    ║
 * ║              · Node `createHash`/`createHmac`/`createCipheriv` weak-algo audit                    ║
 * ║              · bcrypt/argon2 literal hashes, hardcoded bearer tokens                                ║
 * ║  PHASE 12p  Network surface extractor  (OMEGA-5.0 NEW — Tier 1.10)                                  ║
 * ║              · URL/host clustering, RFC1918 + cloud metadata + public IP catalog                  ║
 * ║  PHASE 13  Webpack module splitter                                                                  ║
 * ║  PHASE 13b  Webpack 5 dynamic module resolver  (OMEGA-5.0 NEW — Tier 1.2)                           ║
 * ║  PHASE 13c  ESM bundler detection  (OMEGA-5.0 NEW — Tier 1.5)                                      ║
 * ║  PHASE 14  Dependency graph  (d(N) call-graph reconstruction, regex fallback)                       ║
 * ║  PHASE 14b  Call graph builder  (OMEGA-5.0 NEW — Tier 1.3)                                          ║
 * ║  PHASE 14c  Cross-statement AST taint tracker  (OMEGA-5.0 NEW — Tier 1.4)                           ║
 * ║  PHASE 15  Reports  (HTML dark-mode · JSON · Markdown)                                             ║
 * ║                                                                                                   ║
 * ║  Usage:  node omega-5.0.js <file.js> [options]                                                    ║
 * ║    --out <dir>          Output directory (default: ./omega_output)                                ║
 * ║    --split-modules      Write each webpack module to its own file                                  ║
 * ║    --no-beautify        Skip formatting pass                                                       ║
 * ║    --secrets            Run credential scanner                                                     ║
 * ║    --routes             Extract API routes & endpoints                                             ║
 * ║    --security           Run behavioural security scan                                              ║
 * ║    --ast                Run AST-powered structural analyzer (default: true with --security)        ║
 * ║    --no-ast             Disable AST pass for legacy fallback                                       ║
 * ║    --graph              Build module dependency graph                                              ║
 * ║    --report             Generate HTML + JSON + Markdown reports                                    ║
 * ║    --all                Enable every feature                                                       ║
 * ║    --verbose            Verbose progress                                                            ║
 * ║    --no-color           Plain output (for pipes/CI)                                                 ║
 * ╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝
 *
 * Implementation note on dependencies:
 *   The OMEGA-5.0 AST foundation lives in `omega-5.0-ast.js` (auto-loaded
 *   from the same directory). All other phases are zero-dep and live in
 *   this single file. The split is intentional — keeps the main pipeline
 *   self-contained while allowing the AST module to evolve independently.
 *
 * Zero external dependencies — Node.js core only.
 */

'use strict';

const fs     = require('fs');
const path   = require('path');

// ═══════════════════════════════════════════════════════════════════════════
//  OMEGA-5.0 AST FOUNDATION — auto-loaded from the same directory
//  Provides: buildStructuralIndex, detectFrameworksAST, resolveWebpack5Modules,
//            detectBundler, buildCallGraph, trackTaintAST, scanModernCrypto,
//            extractNetworkSurface.
// ═══════════════════════════════════════════════════════════════════════════
const OMEGA_AST = (() => {
  const candidates = [
    path.join(__dirname, 'ast', '_monolith.js'),
    path.join(__dirname, 'ast', '_monolith.js'),
    path.join(__dirname, 'ast', '_monolith.js'),
    path.join(__dirname, 'ast', '_monolith.js'),
  ];
  for (const p of candidates) {
    try { return require(p); } catch (_) { /* try next */ }
  }
  console.error('\x1b[31m✘\x1b[0m OMEGA-5.0: AST foundation module not found.');
  console.error('   Expected one of:', candidates.join(', '));
  process.exit(1);
})();
const ast = OMEGA_AST;
const crypto = require('crypto');
const os = require('os');

// ═══════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════
const VERSION     = 'OMEGA-5.0';
const MAX_FILE_MB = 200;
const INDENT      = '  ';
// Maximum number of regex match iterations per pattern before we abort and
// treat the input as hostile. Protects against pathological inputs that
// trigger catastrophic backtracking in patterns like CREDENTIAL_PATTERNS.
const MAX_REGEX_MATCHES = 5000;
// Wall-clock budget (ms) for any single regex-execution loop. If exceeded,
// we abort the loop and emit a warning. Node's regex engine itself is not
// preemptible, but the per-match cost is bounded; the loop budget catches
// patterns that match too many times on hostile input.
const REGEX_LOOP_BUDGET_MS = 5000;

// ─── ReDoS-safe regex iterator ───────────────────────────────────────────
// Wraps the common `while ((m = re.exec(src)) !== null)` pattern with two
// guards:
//   1. Match-count cap (MAX_REGEX_MATCHES) — aborts if a pattern matches
//      too many times, indicating either a hostile input or a too-loose
//      pattern.
//   2. Wall-clock budget (REGEX_LOOP_BUDGET_MS) — aborts if the loop has
//      been running too long.
// On abort, calls `onAbort(reason)` (if provided) and returns the matches
// collected so far. The regex's `lastIndex` is reset to 0 on abort to
// avoid leaving it in a partial state.
function safeRegexIter(re, src, onMatch, onAbort) {
  const startedAt = Date.now();
  let count = 0;
  let m;
  // Ensure global flag — without it, re.exec returns the same match forever.
  if (!re.global) {
    re = new RegExp(re.source, re.flags + 'g');
  }
  while ((m = re.exec(src)) !== null) {
    onMatch(m);
    count++;
    if (count >= MAX_REGEX_MATCHES) {
      if (onAbort) onAbort(`match cap exceeded (${MAX_REGEX_MATCHES})`);
      re.lastIndex = 0;
      return;
    }
    if ((count & 0xFF) === 0 && Date.now() - startedAt > REGEX_LOOP_BUDGET_MS) {
      if (onAbort) onAbort(`time budget exceeded (${REGEX_LOOP_BUDGET_MS}ms)`);
      re.lastIndex = 0;
      return;
    }
    // Guard against zero-length matches (which would loop forever)
    if (m.index === re.lastIndex) re.lastIndex++;
  }
}

// ─── ANSI ──────────────────────────────────────────────────────────────────
// FIX: previously `useColor` was a mutable module-level `let` mutated from
// inside parseArgs(). Now it lives in a single state object so the dependency
// is explicit and the value is set via a setter function. The Proxy reads the
// current value via closure, so all helpers (ok/info/warn/fail/head) pick up
// the change automatically.
const uiState = { useColor: process.stdout.isTTY };
function setColorEnabled(v) { uiState.useColor = !!v; }
const C = new Proxy({
  reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m',
  red:'\x1b[31m', green:'\x1b[32m', yellow:'\x1b[33m',
  blue:'\x1b[34m', magenta:'\x1b[35m', cyan:'\x1b[36m', white:'\x1b[37m',
  gray:'\x1b[90m', bgRed:'\x1b[41m', bgGreen:'\x1b[42m', bgBlue:'\x1b[44m',
}, {
  get(t, k) { return uiState.useColor ? (t[k] || '') : ''; },
});
const ok   = s => `${C.green}✔${C.reset} ${s}`;
const info = s => `${C.cyan}ℹ${C.reset} ${s}`;
const warn = s => `${C.yellow}⚠${C.reset} ${s}`;
const fail = s => `${C.red}✘${C.reset} ${s}`;
const head = s => `\n${C.bold}${C.blue}══ ${s} ══${C.reset}`;

// ═══════════════════════════════════════════════════════════════════════════
//  ANGULAR IVY MAP — 110+ entries  (unchanged from OMEGA-1.0)
// ═══════════════════════════════════════════════════════════════════════════
const ANGULAR_IVY_MAP = {
  // ── Element lifecycle ─────────────────────────────────────────────────
  j41:'ɵɵelementStart',   k0s:'ɵɵelementEnd',     nrm:'ɵɵelement',
  Hgh:'ɵɵelementContainer', Hqn:'ɵɵelementContainerEnd',
  ncO:'ɵɵprojectionDef',  aNF:'ɵɵprojection',     SdG:'ɵɵprojectionImpl',
  NAR:'ɵɵdeclareProjDef', rj2:'ɵɵelementStartNS', eux:'ɵɵnamespacedElementEnd',
  qSk:'ɵɵnamespaceSVG',   joV:'ɵɵnamespaceHTML',
  // ── Events / listeners ────────────────────────────────────────────────
  bIt:'ɵɵlistener',       mxI:'ɵɵtwoWayListener',
  tSv:'ɵɵsyntheticHostListener', Z7z:'ɵɵrepeaterTrackBy',
  // ── Text / interpolation ──────────────────────────────────────────────
  EFF:'ɵɵtext',           JRh:'ɵɵtextInterpolate1',
  SpI:'ɵɵtextInterpolate2', Lme:'ɵɵtextInterpolate4',
  LHq:'ɵɵtextInterpolate8', ai1:'ɵɵtextInterpolateV',
  DH7:'ɵɵtextInterpolateV',
  // ── Property & attribute bindings ─────────────────────────────────────
  Y8G:'ɵɵproperty',       R50:'ɵɵtwoWayProperty',
  BMQ:'ɵɵattribute',      MHs:'ɵɵattribute',
  MHn:'ɵɵattributeInterpolate', THe:'ɵɵpropertyInterpolate',
  jOp:'ɵɵhostProperty',   xc7:'ɵɵstylePropInterpolate1',
  // ── Class & style bindings ────────────────────────────────────────────
  AVh:'ɵɵclassProp',      HbH:'ɵɵclassMap',        KoU:'ɵɵclassMap',
  sMw:'ɵɵclassMapInterpolate1', sbH:'ɵɵstyleProp',
  d8G:'ɵɵstyleMap',        VkB:'ɵɵstyleMapInterpolate1',
  Udp:'ɵɵupdateBinding',
  // ── Template / structural / control flow ──────────────────────────────
  nVh:'ɵɵtemplate',       vxM:'ɵɵconditional',     vZN:'ɵɵconditionalWithMemo',
  Dyx:'ɵɵrepeaterApply',  BUC:'ɵɵrepeaterCreate',
  // ── Defer blocks (Angular 17+) ────────────────────────────────────────
  qex:'ɵɵdeferredBlockStart', bVm:'ɵɵdeferredBlockEnd',
  DNE:'ɵɵdeferredBlockSlot',
  // ── Advance / view traversal ──────────────────────────────────────────
  'R7$':'ɵɵadvance',
  // ── View references ───────────────────────────────────────────────────
  RV6:'ɵɵgetCurrentView', XpG:'ɵɵnextContext',
  eBV:'ɵɵrestoreView',    Njj:'ɵɵresetView',
  sdS:'ɵɵgetDirectives',  fX1:'ɵɵtemplateRefExtractor',
  wD4:'ɵɵtemplateContext',
  // ── Pipes ─────────────────────────────────────────────────────────────
  nI1:'ɵɵpipe',           bMT:'ɵɵpipeBind2',       Xts:'ɵɵpipeBind',
  x7i:'ɵɵpipeBindV',      mI1:'ɵɵpipeBindV',
  i5U:'ɵɵpipeBind4',      l_i:'ɵɵpipeBind3',       lJ4:'ɵɵpipeBindV',
  eq3:'ɵɵi18nExp',
  // ── Query ─────────────────────────────────────────────────────────────
  GBs:'ɵɵviewQuery',      lsd:'ɵɵloadQueryList',   mGM:'ɵɵqueryRefresh',
  // ── Sanitization / trust ──────────────────────────────────────────────
  npT:'ɵɵsanitizeHtml',   mNQ:'ɵɵsanitizeHtml2',
  P7a:'ɵɵsanitizeUrl',    scb:'ɵɵsanitizeResourceUrl',
  yYe:'ɵɵsanitizeScript', nln:'ɵɵsanitizeStyle',
  B4B:'ɵɵtrustHtml',      GfV:'ɵɵtrustResourceUrl',
  ZxD:'ɵɵtrustScript',    KVd:'ɵɵtrustUrl',
  // ── i18n ──────────────────────────────────────────────────────────────
  lnJ:'ɵɵi18n',           f6r:'ɵɵi18nApply',       mI1x:'ɵɵi18nAttributes',
  // ── Definition ────────────────────────────────────────────────────────
  VBU:'ɵɵdefineComponent', 'VB$':'ɵɵdefineComponent2',
  jDH:'ɵɵdefineInjectable', tiK:'ɵɵdefineNgModule',
  hqG:'ɵɵsetNgModuleScope', bmF:'ɵɵdefineDirective',
  jtY:'ɵɵdefinePipe',      EJ8:'ɵɵdefinePipe',
  // ── Injection ─────────────────────────────────────────────────────────
  WQX:'ɵɵinject',          Mgp:'ɵɵinjectAttribute',
  lFW:'ɵɵinjectImplementation', wRn:'ɵɵrunInInjectionContext',
  rCR:'ɵɵresetCompiledComponents', xGo:'ɵɵgetFactory',
  oKB:'ɵɵimportProvidersFrom', 'Jv_':'ɵɵproviders',
  Rfq:'ɵɵforwardRef',      SKi:'NgZone',
  // ── Host binding ──────────────────────────────────────────────────────
  OA$:'ɵɵNgOnChangesFeature', Vt3:'ɵɵInheritDefinitionFeature',
  'kB':'ɵɵCopyDefinitionFeature',
};

// Angular unicode static property names (ɵ prefix = \u0275)
const ANGULAR_UNICODE_PROPS = {
  '\\u0275fac':'ɵfac', '\\u0275cmp':'ɵcmp', '\\u0275dir':'ɵdir',
  '\\u0275pipe':'ɵpipe', '\\u0275prov':'ɵprov',
  '\\u0275mod':'ɵmod',  '\\u0275inj':'ɵinj',
};

// Angular static annotations → human-readable comment prefix
const ANGULAR_STATIC_MAP = {
  'static ɵfac':  '/* Angular Factory   */ static ɵfac',
  'static ɵcmp':  '/* Angular Component */ static ɵcmp',
  'static ɵprov': '/* Angular Provider  */ static ɵprov',
  'static ɵmod':  '/* Angular NgModule  */ static ɵmod',
  'static ɵinj':  '/* Angular Injector  */ static ɵinj',
  'static ɵdir':  '/* Angular Directive */ static ɵdir',
};

// ── RxJS operator annotation ───────────────────────────────────────────────
const RXJS_OPERATORS = {
  'b.T':'/*rxjs:map*/',      'b.t':'/*rxjs:mapTo*/',
  'g.W':'/*rxjs:catchError*/','g.w':'/*rxjs:catchError*/',
  'g.M':'/*rxjs:mergeMap*/', 'g.S':'/*rxjs:switchMap*/',
  'g.E':'/*rxjs:exhaustMap*/','g.F':'/*rxjs:flatMap*/',
  'g.c':'/*rxjs:concatMap*/','g.f':'/*rxjs:filter*/',
  'g.d':'/*rxjs:debounceTime*/','g.t':'/*rxjs:tap*/',
  'g.D':'/*rxjs:distinctUntilChanged*/','g.T':'/*rxjs:take*/',
  'xt.p':'/*rxjs:combineLatest*/','xt.A':'/*rxjs:forkJoin*/',
  'rd.z':'/*rxjs:zip*/','yt.of':'/*rxjs:of*/',
  'gm.H':'/*rxjs:from*/','Vc.c':'/*rxjs:Observable*/',
  'St.w':'/*rxjs:EMPTY*/','Zt.B':'/*rxjs:BehaviorSubject*/',
};

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 5b MAPS — Multi-framework symbol deobfuscation
//  Integrated from: framework_symbol_maps.js
//  Confidence: 82% — short mangled keys are heuristic; verify against
//  your bundle's source map or export list when precision matters.
// ═══════════════════════════════════════════════════════════════════════════

// ── 1. VUE 3 ─────────────────────────────────────────────────────────────
const VUE3_VNODE_MAP = {
  cEV:'createElementVNode',   cTV:'createTextVNode',
  cCV:'createCommentVNode',   cSV:'createStaticVNode',
  cVN:'createVNode',          clV:'cloneVNode',
  cEB:'createElementBlock',   oB: 'openBlock',
  cB: 'createBlock',          kS: 'KeepAlive',
  sS: 'Suspense',             tP: 'Teleport',
  // Render helpers
  rL: 'renderList',           rS: 'renderSlot',
  wC: 'withCtx',              wD: 'withDirectives',
  rD: 'resolveDirective',     rC: 'resolveComponent',
  rDC:'resolveDynamicComponent',
  mP: 'mergeProps',           nC: 'normalizeClass',
  nSt:'normalizeStyle',       nP: 'normalizeProps',
  tDS:'toDisplayString',      gSS:'guardReactiveProps',
  cSS:'createSlots',          wSK:'withScopeId',
  pSV:'pushScopeId',          pSP:'popScopeId',
  // Reactivity
  sR: 'shallowRef',           tR: 'triggerRef',
  cR: 'customRef',            rct:'reactive',
  sRc:'shallowReactive',      ro: 'readonly',
  sRo:'shallowReadonly',      wE: 'watchEffect',
  wPS:'watchPostEffect',      wSE:'watchSyncEffect',
  eR: 'effectScope',          gCS:'getCurrentScope',
  oCS:'onScopeDispose',       iR: 'isRef',
  uR: 'unref',                tRw:'toRef',
  tRws:'toRefs',              iRP:'isReactive',
  iRO:'isReadonly',           iP: 'isProxy',
  iSR:'isShallow',            tRW:'toRaw',
  mkR:'markRaw',              prx:'proxyRefs',
  // Lifecycle hooks
  oMt:'onMounted',            oUM:'onUnmounted',
  oBM:'onBeforeMount',        oBU:'onBeforeUnmount',
  oU: 'onUpdated',            oBUp:'onBeforeUpdate',
  oAc:'onActivated',          oDa:'onDeactivated',
  oEH:'onErrorCaptured',      oRt:'onRenderTracked',
  oRT:'onRenderTriggered',    oSC:'onServerPrefetch',
  // Component API
  dC: 'defineComponent',      dAs:'defineAsyncComponent',
  dPr:'defineProps',          dEm:'defineEmits',
  dEx:'defineExpose',         dOp:'defineOptions',
  dSl:'defineSlots',          dMd:'defineModel',
  wMd:'withDefaults',         sSU:'setupStatefulComponent',
  gCI:'getCurrentInstance',   gPB:'getPublicInstance',
  // DI
  prv:'provide',              inj:'inject',
  hIj:'hasInjectionContext',
  // Template refs
  uAt:'useAttrs',             uSl:'useSlots',
  uTR:'useTemplateRef',       uID:'useId',
  // Misc
  nxt:'nextTick',             mXP:'mergeDefaults',
  tSS:'toHandlers',           vSh:'vShow',
  vMd:'vModelText',           vMC:'vModelCheckbox',
  vMR:'vModelRadio',          vMS:'vModelSelect',
  vMDy:'vModelDynamic',       usA:'useSSRContext',
};

const VUE3_INTERNAL_PROPS = {
  '__vccOpts':   '/* Vue: component options */__vccOpts',
  '__hmrId':     '/* Vue: HMR ID */__hmrId',
  '__file':      '/* Vue: source file */__file',
  '__scopeId':   '/* Vue: scoped CSS ID */__scopeId',
  '__cssModules':'/* Vue: CSS modules */__cssModules',
  '_component':  '/* Vue: component ref */_component',
  '_ctx':        '/* Vue: component ctx */_ctx',
  '_cache':      '/* Vue: template cache */_cache',
};

const VUE_ROUTER_MAP = {
  cRt: 'createRouter',        cWH:'createWebHistory',
  cWHH:'createWebHashHistory',cMH:'createMemoryHistory',
  uRt: 'useRouter',           uRte:'useRoute',
  rVw: 'RouterView',          rLk:'RouterLink',
  nVI: 'NavigationFailureType',iNF:'isNavigationFailure',
  oBC: 'onBeforeRouteLeave',  oBRC:'onBeforeRouteUpdate',
  stRt:'START_LOCATION',
};

// ── 2. REACT ─────────────────────────────────────────────────────────────
const REACT_HOOKS_MAP = {
  uSt:'useState',             uEf:'useEffect',
  uLEf:'useLayoutEffect',     uIEf:'useInsertionEffect',
  uCb:'useCallback',          uMm:'useMemo',
  uRf:'useRef',               uCx:'useContext',
  uRd:'useReducer',           uId:'useId',
  uDV:'useDeferredValue',     uTr:'useTransition',
  uSI:'useSyncExternalStore', uIS:'useImperativeHandle',
  uDL:'useDebugValue',        uAt:'useActionState',
  uOm:'useOptimistic',
  // Element / component creation
  cEL:'createElementWithValidation',
  jsx:'jsx',                  jsxs:'jsxs',
  jsxD:'jsxDEV',              jsxsD:'jsxsDEV',
  clE:'cloneElement',         isVE:'isValidElement',
  cRef:'createRef',           fwd:'forwardRef',
  memo:'memo',                lazy:'lazy',
  frag:'Fragment',            stn:'StrictMode',
  pro:'Profiler',             sus:'Suspense',
  // Context
  cCx:'createContext',
  // Children
  chM:'Children.map',         chFe:'Children.forEach',
  chC:'Children.count',       chO:'Children.only',
  chTa:'Children.toArray',
  // Concurrent
  stTr:'startTransition',     act:'act',
  cch:'cache',
};

const REACT_DOM_MAP = {
  cRt:'createRoot',           hSR:'hydrateRoot',
  rnd:'render',               umt:'unmountComponentAtNode',
  cPt:'createPortal',         flS:'flushSync',
  rTS:'renderToString',       rTSt:'renderToStaticMarkup',
  rNS:'renderToNodeStream',   rSS:'renderToStaticNodeStream',
  rTP:'renderToPipeableStream',rTRS:'renderToReadableStream',
};

const REACT_FIBER_PROPS = {
  '__reactFiber\\$':     '/* React: fiber node */__reactFiber',
  '__reactProps\\$':     '/* React: props cache */__reactProps',
  '__reactEvents\\$':    '/* React: delegated events */__reactEvents',
  '__reactListeners\\$': '/* React: listeners */__reactListeners',
  '__reactContext':      '/* React: context value */__reactContext',
  '_reactRootContainer': '/* React: root container */_reactRootContainer',
  '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED':
                         '/* React: internal dispatcher */__REACT_INTERNALS',
};

const REACT_EVENTS_MAP = {
  oCp:'onClickCapture',  oCh:'onChange',      oI: 'onInput',
  oSb:'onSubmit',        oKD:'onKeyDown',      oKU:'onKeyUp',
  oKP:'onKeyPress',      oFc:'onFocus',        oBl:'onBlur',
  oME:'onMouseEnter',    oML:'onMouseLeave',   oMM:'onMouseMove',
  oMD:'onMouseDown',     oMU:'onMouseUp',      oMO:'onMouseOver',
  oTO:'onTouchStart',    oTE:'onTouchEnd',     oTM:'onTouchMove',
  oDR:'onDragOver',      oDp:'onDrop',         oSl:'onScroll',
  oWhl:'onWheel',        oCx:'onContextMenu',
  oAP:'onAnimationStart',oAE:'onAnimationEnd', oTP:'onTransitionEnd',
  oPS:'onPointerDown',
};

// ── 3. SVELTE ─────────────────────────────────────────────────────────────
const SVELTE_RUNTIME_MAP = {
  // DOM helpers
  apH:'append_hydration',     ins:'insert',         insH:'insert_hydration',
  nod:'noop',                 elIs:'element_is',    svgE:'svg_element',
  clT:'claim_text',           clSp:'claim_space',   atNS:'attr_dev',
  sAt:'set_attributes',       xLk:'xlink_attr',     sSD:'set_svg_attributes',
  sIC:'set_input_value',      sDat:'set_data',       sDtD:'set_data_dev',
  sSt:'set_style',            tgl:'toggle_class',    rmAt:'remove_attribute',
  // Event listeners
  lnrD:'listen_dev',          prD:'prevent_default', stP:'stop_propagation',
  stIP:'stop_immediate_propagation', slf:'self',     trsted:'trusted',
  // Lifecycle / utils
  sfd:'safe_not_equal',       nEql:'not_equal',
  vrEl:'validate_each_argument', vrCm:'validate_component',
  vrSt:'validate_store',      sbc:'subscribe',       cmPN:'component_subscribe',
  cr8:'create_component',     mntC:'mount_component', dstC:'destroy_component',
  trIn:'transition_in',       trOt:'transition_out',  gSpC:'get_spread_object',
  gSpU:'get_spread_update',   upF:'update_keyed_each',
  oWk:'outro_and_destroy_block', cEch:'create_each_block',
  cIfB:'create_if_block',     cElB:'create_else_block',
  cSlB:'create_slot',         gSlC:'get_slot_context',
  gSlS:'get_slot_spread_changes', uSlC:'update_slot_base',
  cMtB:'create_mount_block',  bfUd:'before_update',  afUd:'after_update',
  // Stores
  wrt:'writable',             rdd:'readable',        drv:'derived',
  rdbl:'readable',
  // Transitions / animations
  slid:'slide',               scl:'scale',           drw:'draw',
  crst:'crossfade',           twn:'tweened',         spr:'spring',
};

// ── 4. NEXT.JS ───────────────────────────────────────────────────────────
const NEXTJS_RUNTIME_MAP = {
  uPN:'usePathname',          uSP:'useSearchParams',
  uPrm:'useParams',           uSI:'useSelectedLayoutSegment',
  uSIS:'useSelectedLayoutSegments',
  rdr:'redirect',             prRdr:'permanentRedirect',
  nNA:'notFound',             usEF:'useFormStatus',
  usEA:'useFormState',
  wRtr:'withRouter',
  cSA:'createServerAction$',  rSC:'registerServerReference',
  cSR:'createServerReference',encA:'encodeReply',
  decRp:'decodeReply',        decAc:'decodeAction',
  decFm:'decodeFormState',    cRq:'createRequest',
  rPth:'revalidatePath',      rTag:'revalidateTag',
  uns:'unstable_cache',       unNo:'unstable_noStore',
  hds:'headers',              cks:'cookies',
  nImg:'Image',               gImP:'getImageProps',
  gStP:'generateStaticParams',gMtd:'generateMetadata',
  gVP:'generateViewport',     nLnk:'Link',
  ntFt:'localFont',
};

// Next.js long-key annotations (applied as literal string replacement)
const NEXTJS_LITERAL_MAP = {
  '__N_SSP':           '/* Next.js: SSP marker */__N_SSP',
  '__N_SSG':           '/* Next.js: SSG marker */__N_SSG',
  '__NEXT_DATA__':     '/* Next.js: page data */__NEXT_DATA__',
  '__nextRouterBasePath':'/* Next.js: base path */__nextRouterBasePath',
};

// ── 5. WEBPACK 5 RUNTIME ─────────────────────────────────────────────────
// Applied as literal string comments; single-char keys intentionally omitted
// to avoid false positives (e.g. the variable 'e', 'f', etc.)
const WEBPACK_RUNTIME_COMMENTS = {
  '__webpack_require__':    '/* webpack: require */__webpack_require__',
  '__webpack_module__':     '/* webpack: module */__webpack_module__',
  '__webpack_exports__':    '/* webpack: exports */__webpack_exports__',
  '__webpack_modules__':    '/* webpack: module registry */__webpack_modules__',
  '__webpack_chunk_load__': '/* webpack: chunk loader */__webpack_chunk_load__',
  '__webpack_base_uri__':   '/* webpack: public path */__webpack_base_uri__',
  '__webpack_nonce__':      '/* webpack: CSP nonce */__webpack_nonce__',
  '__webpack_share_scopes__':'/* webpack: federation shares */__webpack_share_scopes__',
  '__webpack_init_sharing__':'/* webpack: federation init */__webpack_init_sharing__',
  'webpackJsonp':            '/* webpack: jsonp (legacy) */webpackJsonp',
};

// ── 6. VITE ──────────────────────────────────────────────────────────────
const VITE_RUNTIME_COMMENTS = {
  '__vite__mapDeps':    '/* Vite: dep map for preload */__vite__mapDeps',
  '__vitePreload':      '/* Vite: asset preload */__vitePreload',
  '__vite_ssr_import__':'/* Vite SSR: import */__vite_ssr_import__',
  '__vite_ssr_exports__':'/* Vite SSR: exports */__vite_ssr_exports__',
  '__vite_ssr_exportAll__':'/* Vite SSR: exportAll */__vite_ssr_exportAll__',
};

// ── 7a. LODASH-ES ─────────────────────────────────────────────────────────
const LODASH_ES_MAP = {
  // Collection
  fnd:'_.find',      fI: '_.findIndex', evr:'_.every',
  grB:'_.groupBy',   kBy:'_.keyBy',     cntB:'_.countBy',
  srtB:'_.sortBy',   orB:'_.orderBy',   fltD:'_.flattenDeep',
  fltM:'_.flatMap',
  // Object
  pkB:'_.pickBy',    omB:'_.omitBy',    asn:'_.assign',
  dfD:'_.defaults',  dfDp:'_.defaultsDeep',
  kys:'_.keys',      vls:'_.values',    ens:'_.entries',
  unst:'_.unset',    clnD:'_.cloneDeep',
  // Array
  chk:'_.chunk',     dff:'_.difference',
  drp:'_.drop',      drpR:'_.dropRight',tke:'_.take',
  tkeR:'_.takeRight',nth:'_.nth',       inp:'_.intersection',
  unqB:'_.uniqBy',   zpO:'_.zipObject',
  // String
  cml:'_.camelCase', kbb:'_.kebabCase', snk:'_.snakeCase',
  stC:'_.startCase', trnc:'_.truncate', tpl:'_.template',
  // Function
  dbc:'_.debounce',  thrt:'_.throttle', miz:'_.memoize',
  crO:'_.curry',     prt:'_.partial',   nce:'_.once',
  flp:'_.flip',      neg:'_.negate',
  // Lang / Type
  isA:'_.isArray',   isO:'_.isObject',  isS:'_.isString',
  isN:'_.isNumber',  isB:'_.isBoolean', isFn:'_.isFunction',
  isNl:'_.isNull',   isUd:'_.isUndefined', isNE:'_.isNil',
  isEq:'_.isEqual',  isEm:'_.isEmpty',  isIn:'_.isInteger',
  isNaN:'_.isNaN',
  // Utility
  nop:'_.noop',      idn:'_.identity',  cnst:'_.constant',
  tms:'_.times',     uid:'_.uniqueId',
};

// ── 7b. DATE-FNS v3 ──────────────────────────────────────────────────────
const DATE_FNS_MAP = {
  prsI:'parseISO',           fmtI:'formatISO',
  fmtRl:'formatRelative',    fmtDst:'formatDistance',
  fmtDstTNow:'formatDistanceToNow',
  isVld:'isValid',           isBf:'isBefore',        isAf:'isAfter',
  addD:'addDays',            addH:'addHours',         addM:'addMinutes',
  addMo:'addMonths',         addYr:'addYears',        addWk:'addWeeks',
  subD:'subDays',            subMo:'subMonths',       subYr:'subYears',
  subWk:'subWeeks',
  dffD:'differenceInDays',   dffH:'differenceInHours',dffMn:'differenceInMinutes',
  dffMo:'differenceInMonths',dffYr:'differenceInYears',dffCd:'differenceInCalendarDays',
  strtD:'startOfDay',        endD:'endOfDay',
  strtMo:'startOfMonth',     endMo:'endOfMonth',
  strtWk:'startOfWeek',      endWk:'endOfWeek',
  strtYr:'startOfYear',      endYr:'endOfYear',
  gtDy:'getDay',             gtDt:'getDate',          gtMo:'getMonth',
  gtYr:'getYear',            gtHr:'getHours',         gtMin:'getMinutes',
  gtSec:'getSeconds',        gtMs:'getMilliseconds',
  setDy:'setDay',            setDt:'setDate',          setMo:'setMonth',
  setYr:'setYear',           toD:'toDate',             frUnx:'fromUnixTime',
  gtUnx:'getUnixTime',
};

// ── 7c. ZOD ──────────────────────────────────────────────────────────────
const ZOD_MAP = {
  zO:'z.object',    zS:'z.string',    zN:'z.number',    zB:'z.boolean',
  zA:'z.array',     zU:'z.union',     zI:'z.intersection',zE:'z.enum',
  zNE:'z.nativeEnum',zL:'z.literal', zTp:'z.tuple',    zRc:'z.record',
  zMp:'z.map',      zSt:'z.set',     zFn:'z.function', zLz:'z.lazy',
  zPm:'z.promise',  zVd:'z.void',    zAn:'z.any',      zUk:'z.unknown',
  zNv:'z.never',    zNl:'z.null',    zUd:'z.undefined',
  zDc:'z.discriminatedUnion',
  prsA:'schema.parseAsync',   sprA:'schema.safeParseAsync',
};

// ── 7d. ZUSTAND ──────────────────────────────────────────────────────────
const ZUSTAND_MAP = {
  crtSt:'createStore',  uSt:'useStore',    sbscr:'subscribeWithSelector',
  imr:'immer',          prst:'persist',    dvtl:'devtools',
  cmbn:'combine',       cmpS:'computed',   stlS:'shallow',
};

// ── 7e. IMMER ─────────────────────────────────────────────────────────────
const IMMER_MAP = {
  prdWR:'produceWithPatches',  cDft:'createDraft',  fnDft:'finishDraft',
  apPt:'applyPatches',         gnPt:'generatePatches',
  enAS:'enableAllPlugins',     enMP:'enableMapSet',  enPS:'enablePatches',
  isDft:'isDraft',             isDtb:'isDraftable',  crnt:'current',
  orgnl:'original',            cstm:'setAutoFreeze',
};

// ── 8. CORE-JS SHIMS ─────────────────────────────────────────────────────
// Applied as literal string comments to tag polyfill boilerplate
const COREJS_SHIMS_COMMENTS = {
  '__core-js_shared__':  '/* core-js: shared state */',
  'IS_PURE':             '/* core-js: pure mode flag */',
  'NATIVE_WEAK_MAP':     '/* core-js: WeakMap native check */',
  'nativeBind':          '/* core-js: Function.bind shim */',
  'nativeCreate':        '/* core-js: Object.create shim */',
  'nativeGetPrototype':  '/* core-js: getPrototypeOf shim */',
  'nativeObjectCreate':  '/* core-js: Object.create */',
  'nativeFreeze':        '/* core-js: Object.freeze */',
  'nativeKeys':          '/* core-js: Object.keys */',
  '$export':             '/* core-js: export helper */',
  '$iterCreate':         '/* core-js: iterator factory */',
  '$iterDefine':         '/* core-js: iterator define */',
  'DESCRIPTORS':         '/* core-js: descriptor support flag */',
  'arraySpeciesCreate':  '/* core-js: array species */',
  'arrayFromIterable':   '/* core-js: from iterable */',
};

// ═══════════════════════════════════════════════════════════════════════════
//  CREDENTIAL PATTERNS — 32 entries (unchanged from OMEGA-1.0)
// ═══════════════════════════════════════════════════════════════════════════
const CREDENTIAL_PATTERNS = [
  { name:'Hardcoded Password',   severity:'critical',
    re:/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,64})["']/gi,
    fpGuard: v => /^(?:password|placeholder|\*+|your.password)$/i.test(v) },
  { name:'Hardcoded Credential', severity:'critical',
    re:/(?:testingUsername|testingPassword|TESTING_CRED)\s*=\s*["']([^"']+)["']/gi,
    fpGuard: null },
  { name:'Hardcoded API Key',    severity:'critical',
    re:/(?:api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,64})["']/gi,
    fpGuard: null },
  { name:'JWT Secret',           severity:'critical',
    re:/(?:jwt[_-]?secret|jwtSecret)\s*[:=]\s*["']([^"']{8,})["']/gi,
    fpGuard: null },
  { name:'JWT Token Literal',    severity:'critical',
    re:/["'](ey[Jt][A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']/g,
    fpGuard: v => v.length < 40 || /^(?:eyJ|eyJ0|example|test|placeholder)/i.test(v) },
  { name:'Google OAuth Client ID', severity:'high',
    re:/\d{12,}-[a-z0-9]{32}\.apps\.googleusercontent\.com/g,
    fpGuard: null },
  { name:'OAuth Client ID',      severity:'high',
    re:/client[_-]?id\s*[:=]\s*["']([^"']{8,128})["']/gi,
    fpGuard: v => /placeholder|example|test/i.test(v) },
  { name:'localStorage token',   severity:'high',
    re:/localStorage\.(?:getItem|setItem)\s*\(\s*["']token["']/g,
    fpGuard: null },
  { name:'Cookie token',         severity:'medium',
    re:/cookieService\.(?:put|get)\s*\(\s*["']token["']/g,
    fpGuard: null },
  { name:'Broken Crypto — btoa(reverse)', severity:'critical',
    re:/btoa\s*\(\s*\w+\.split\s*\(\s*["']["']\s*\)\.reverse\s*\(\s*\)\.join\s*\(\s*["']["']\s*\)\s*\)/g,
    fpGuard: null },
  { name:'Broken Crypto — btoa(field.split.reverse)', severity:'critical',
    re:/btoa\s*\(\s*[\w.]+(?:email|password|user)\s*(?:\?\.|\.)\s*split\s*\(["']["']\s*\)\s*\.reverse/gi,
    fpGuard: null },
  { name:'Cookie token storage', severity:'medium',
    re:/cookieService\.put\s*\(\s*["']token["']/g,
    fpGuard: null },
  { name:'Weak Entropy — Math.random password', severity:'high',
    re:/Math\.random\s*\(\s*\).*?password/gi, fpGuard: null },
  { name:'Private Key',          severity:'critical',
    re:/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    fpGuard: null },
  { name:'Bearer Token',         severity:'high',
    re:/Bearer\s+[A-Za-z0-9\-_\.]{20,}/g,
    fpGuard: null },
  { name:'AWS Access Key',       severity:'critical',
    re:/AKIA[0-9A-Z]{16}/g, fpGuard: null },
  { name:'AWS Secret Key',       severity:'critical',
    re:/aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*["']([^"']{40})["']/gi,
    fpGuard: null },
  { name:'Stripe Key',           severity:'critical',
    re:/sk_(?:live|test)_[0-9a-zA-Z]{24}/g, fpGuard: null },
  { name:'SendGrid API Key',     severity:'critical',
    re:/SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, fpGuard: null },
  { name:'GitHub Token',         severity:'critical',
    re:/gh[pousr]_[A-Za-z0-9]{36}/g, fpGuard: null },
  { name:'Hardcoded Email',      severity:'medium',
    re:/["'][a-zA-Z0-9._%+\-]+@(?!example\.com|test\.com)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}["']/g,
    fpGuard: v => v.length > 80 },
  { name:'Internal IP',          severity:'low',
    re:/["'](?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+["']/g,
    fpGuard: null },
  { name:'US SSN',               severity:'critical',
    re:/\b\d{3}-\d{2}-\d{4}\b/g,
    fpGuard: v => /entry\.\d+/.test(v) },
  { name:'Hardcoded Coupon Code', severity:'high',
    re:/\b([A-Z]{4,10}\d{4})\s*:/g,
    fpGuard: v => v.length > 20 },
  { name:'Time-Gated Discount',  severity:'medium',
    re:/validOn\s*:\s*(\d{10,13})/g, fpGuard: null },
  { name:'MongoDB URI',          severity:'critical',
    re:/mongodb(?:\+srv)?:\/\/[^"'\s]+/gi, fpGuard: null },
  { name:'Database password',    severity:'critical',
    re:/db[_-]?pass(?:word)?\s*[:=]\s*["']([^"']+)["']/gi, fpGuard: null },
  { name:'SMTP credentials',     severity:'high',
    re:/smtp[_-]?(?:pass|password|user|username)\s*[:=]\s*["']([^"']+)["']/gi,
    fpGuard: null },
  { name:'Slack Token',          severity:'critical',
    re:/xox[baprs]-[0-9a-zA-Z]{10,48}/g, fpGuard: null },
  { name:'Base64 secret candidate', severity:'low',
    re:/["'][A-Za-z0-9+/]{40,}={0,2}["']/g,
    fpGuard: v => v.length > 200 || !/[+/]/.test(v) },
  { name:'Hex secret candidate', severity:'low',
    re:/["'][0-9a-fA-F]{40,}["']/g,
    fpGuard: v => v.length > 80 || /^(?:[0-9a-f]{6,8})+$/.test(v) || !/[A-Z]/.test(v) || !/[a-z]/.test(v) },
];

// ═══════════════════════════════════════════════════════════════════════════
//  SECURITY PATTERNS (unchanged from OMEGA-1.0)
// ═══════════════════════════════════════════════════════════════════════════
const SECURITY_PATTERNS = [
  { id:'xss-write',      cat:'XSS',        sev:'critical',
    re:/document\.write\s*\(/g,
    ctx: m => !m.includes('// test') },
  { id:'xss-innerhtml',  cat:'XSS',        sev:'high',
    re:/\.innerHTML\s*=/g,
    ctx: m => !/sanitize|DomSanitizer|bypassSecurityTrust/.test(m.slice(-200)) },
  { id:'xss-eval',       cat:'XSS',        sev:'critical',
    re:/\beval\s*\(/g,        ctx: null },
  { id:'xss-new-func',   cat:'XSS',        sev:'critical',
    re:/new\s+Function\s*\(/g,
    ctx: (snippet, src) => {
      // Fast path: check context window for Vue template compiler markers
      if (/openBlock|createElementVNode|_createBlock|withDirectives|createVNode|_ hoisted|renderList|renderSlot|resolveComponent/.test(snippet)) return false;
      // Slow path: check if the ENTIRE source contains Vue compile markers.
      // Catches cases like `u = new Function(a)()` where the compiled template
      // function body (containing openBlock etc.) is in variable `a`, defined
      // far from the new Function call site.
      if (/openBlock|createElementVNode|_createBlock|resolveComponent/.test(src)) return false;
      return true;
    } },
  { id:'sqli-concat',    cat:'Injection',  sev:'high',
    re:/(?:query|sql|exec)\s*=\s*["'][^"']*["']\s*\+/gi,
    ctx: m => !/placeholder|label|aria/.test(m) },
  { id:'cmd-injection',  cat:'Injection',  sev:'critical',
    re:/(?:child_process|cp|shell(?:js)?)\s*["']?\s*\)?\s*\.\s*(?:exec(?:Sync)?|spawn(?:Sync)?|fork)\s*\(/g, ctx: null },
  { id:'crypto-broken-entropy', cat:'Broken Crypto', sev:'critical',
    re:/btoa\s*\([^)]*\.split\s*\(\s*["']["']\s*\)\.reverse/g, ctx: null },
  { id:'crypto-weak-hash', cat:'Broken Crypto', sev:'high',
    re:/(?:MD5|sha1|SHA1)\s*\(/gi,
    ctx: m => !/comment|hmac/.test(m.toLowerCase()) },
  { id:'crypto-math-random', cat:'Broken Crypto', sev:'medium',
    re:/Math\.random\s*\(\s*\)/g,
    ctx: m => /password|secret|token|key|nonce/i.test(m.slice(-100,100)) },
  { id:'network-socket', cat:'Network',    sev:'info',
    re:/socket\.io|\.on\s*\(\s*["'](?:connect|message|data)/g, ctx: null },
  { id:'network-socket-emit', cat:'Network Surface', sev:'medium',
    re:/(?:socket|ws|webSocket|client|provider|conn)\s*\.\s*(?:emit|send|post)\s*\(\s*["']([^"']+)["']/g,
    ctx: m => /\.(?:emit|send|post)\s*\(\s*["'](?:message|data|event|request|response|ping|pong|auth|frame|payload)["']/i.test(m) },
  { id:'network-http-open', cat:'Network', sev:'info',
    re:/https?:\/\/[^\s"']+/g,
    ctx: m => {
      // Skip known documentation / CDN / package-homepage / citation URLs
      const skipDomains = /(?:accounts\.google|cdnjs\.cloudflare|openstreetmap|github\.com|developer\.mozilla\.org|w3\.org|npmjs\.com|angular\.io|vuejs\.org|reactjs\.org|typescriptlang\.org|babeljs\.io|webpack\.js|nodejs\.org|mit\.edu|apache\.org|opensource\.org|creativecommons\.org|unlicense\.org|jquery\.com|lodash\.com|d3js\.org|chartjs\.org|threejs\.org|greensock\.com|gsap\.com|preactjs\.com|axios\.http|cryptojs\.git|momentjs\.com|day\.js|eastus\.data\.tables\.net|paas[0-9]+\.southeastasia\.project|yarnpkg\.com|jsdelivr\.net|unpkg\.com|bundlephobia\.com|stackoverflow\.com|stackexchange\.com|wikipedia\.org|arxiv\.org|ieee\.org|acm\.org|springer\.com|linkedin\.com|twitter\.com|facebook\.com|youtube\.com|medium\.com|sitepoint\.com|smashingmagazine\.com|css-tricks\.com|hackernews\.com|reddit\.com|stackblitz\.com|codesandbox\.io|replit\.com)/;
      if (skipDomains.test(m)) return false;
      // Skip URLs that look like license/copyright headers in comments
      if (/license|licence|copyright|\(c\)|released under|MIT|Apache|BSD|CC BY|CC0/i.test(m) && m.length < 120) return false;
      // Skip URLs in obvious citation contexts (wikipedia / arxiv / doi.org)
      if (/doi\.org|ieee\.org|acm\.org|arxiv\.org/.test(m)) return false;
      return true;
    } },
  { id:'storage-local',  cat:'Storage',    sev:'medium',
    re:/localStorage\./g,      ctx: null },
  { id:'storage-session',cat:'Storage',    sev:'medium',
    re:/sessionStorage\./g,    ctx: null },
  { id:'storage-cookie', cat:'Storage',    sev:'low',
    re:/document\.cookie/g,    ctx: null },
  { id:'pii-email-field',cat:'PII',        sev:'low',
    re:/\.email\s*=|email\s*:/g,
    ctx: m => !/placeholder|label|aria/.test(m) },
  { id:'angular-guard',  cat:'Auth Surface', sev:'info',
    re:/canActivate\s*:\s*\[([^\]]+)\]/g, ctx: null },
  { id:'angular-bypass', cat:'Angular Security', sev:'high',
    re:/bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)/g, ctx: null },

  // ── B2: DOM XSS Sinks ──────────────────────────────────────────────────
  { id:'xss-outerhtml',  cat:'XSS',        sev:'critical',
    re:/\.outerHTML\s*=/g, ctx: null },
  { id:'xss-insertadj',  cat:'XSS',        sev:'critical',
    re:/\.insertAdjacentHTML\s*\(/g, ctx: null },
  { id:'xss-srcdoc',     cat:'XSS',        sev:'critical',
    re:/\.srcdoc\s*=/g,
    ctx: m => !/ɵɵ|@angular\/|trustedHTML/.test(m) },
  { id:'xss-createfrag', cat:'XSS',        sev:'high',
    re:/createContextualFragment\s*\(/g, ctx: null },
  { id:'xss-jquery-html',cat:'XSS',        sev:'critical',
    re:/(?:jQuery|\$)\s*\([^)]*\)\.html\s*\([^)]+\)/g, ctx: null },
  { id:'xss-jquery-dom', cat:'XSS',        sev:'high',
    re:/(?:jQuery|\$)\([^)]*\)\.(?:append|prepend|after|before|wrap)\s*\([^)]+\)/g, ctx: null },
  { id:'xss-set-attr-on',cat:'XSS',        sev:'critical',
    re:/\.setAttribute\s*\(\s*['"]on\w+['"]\s*,/g, ctx: null },
  { id:'redirect-location-href',cat:'Open Redirect', sev:'high', cwe:'CWE-601',
    re:/(?:location|window\.location)\.href\s*=/g,
    ctx: m => !/https?:\/\//.test(m) },
  { id:'redirect-loc-replace', cat:'Open Redirect',  sev:'high', cwe:'CWE-601',
    re:/location\.(?:replace|assign)\s*\(/g, ctx: null },
  { id:'xss-window-open', cat:'XSS',       sev:'medium',
    re:/window\.open\s*\(/g, ctx: null },

  // ── B2.5: SQL Injection — string concat/template with SQL keywords ──────
  { id:'sqli-concat',     cat:'Injection', sev:'critical', cwe:'CWE-89',
    re:/(?:\$|string)?\s*SELECT\s.+?\bFROM\b/g,
    ctx: m => {
      const c = m.slice(0, 500);
      // Must contain both SQL keyword AND a variable reference (+ or ${})
      return /\+|`\$\{|\.concat|\.join/.test(c);
    } },
  { id:'sqli-template',   cat:'Injection', sev:'critical', cwe:'CWE-89',
    re:/`.*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*`/g,
    ctx: m => /\$\{[^}]+\}/.test(m) },

  // ── B3: Angular Template Injection ──────────────────────────────────────
  { id:'ng-tmpl-inject',  cat:'Angular Security', sev:'high',
    re:/DomSanitizer.*bypassSecurityTrustHtml\s*\(\s*[`'"]/g, ctx: null },
  { id:'ng-compile',      cat:'Angular Security', sev:'critical',
    re:/\$compile\s*\(\s*(?!['"])/g, ctx: null },

  // ── B4: Prototype Pollution ─────────────────────────────────────────────
  // Write-only: only flag actual ASSIGNMENT to prototype[key], not read access
  { id:'proto-write',     cat:'Prototype Pollution', sev:'critical',
    re:/(?:__proto__|prototype)\s*\[\s*['"][^'"]+['"]\s*\]\s*=/g, ctx: null },
  // Merge suspect: Object.assign with user-controlled source — potential pollution
  { id:'proto-merge-suspect', cat:'Prototype Pollution', sev:'medium',
    re:/Object\.(?:assign|merge)\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)/g,
    ctx: m => /user|request|input|body|data|param|query/i.test(m.slice(-200)) },
  // Deprecated: old read-access pattern (too many FPs on .extend/.slice.call)
  { id:'proto-assign',    cat:'Prototype Pollution', sev:'critical',
    re:/(?:__proto__|prototype)\s*\[/g, ctx: m => /=\s*[^;]+$/.test(m) || /=/.test(m.slice(0,400)) },
  { id:'proto-setproto',  cat:'Prototype Pollution', sev:'medium',
    re:/Object\.setPrototypeOf\s*\(/g, ctx: m => /Object\.prototype/.test(m) },
  { id:'proto-jsonparse',  cat:'Prototype Pollution', sev:'medium',
    re:/JSON\.parse\s*\([^)]+\)/g,
    ctx: m => /user|request|input|param|__proto__|constructor/i.test(m) },

  // ── B5: PostMessage ─────────────────────────────────────────────────────
  { id:'postmsg-wildcard', cat:'PostMessage',  sev:'high',
    re:/\.postMessage\s*\([^)]+,\s*['"][*]['"]/g, ctx: null },
  { id:'postmsg-nocheck',  cat:'PostMessage',  sev:'medium',
    re:/addEventListener\s*\(\s*['"]message['"]/g,
    ctx: m => !/event\.origin|e\.origin/.test(m.slice(0, 400)) },

  // ── B6: Insufficient Randomness ─────────────────────────────────────────
  { id:'rand-date-token',  cat:'Broken Crypto', sev:'high',
    re:/(?:Date\.now\(\)|new\s+Date\(\)\.getTime\(\))/g,
    ctx: m => /token|nonce|csrf|session|secret|key|nonce/i.test(m) },
  { id:'rand-math-token',  cat:'Broken Crypto', sev:'high',
    re:/Math\.random\(\)\s*\.\s*toString\s*\(\s*36\s*\)/g,
    ctx: m => {
      const c = m.slice(0, 300);
      return /token|nonce|csrf|session|secret|key|nonce|id|guid|uuid/i.test(c);
    } },
  { id:'rand-math-predictable', cat:'Broken Crypto', sev:'medium',
    re:/Math\.random\(\)/g,
    ctx: m => {
      const c = m.slice(0, 400);
      // Only flag when used in contexts where cryptographic randomness is expected
      return /token|nonce|csrf|session|secret|key|password|reset|otp|crypto|salt|hash/g.test(c)
        && !/Math\.floor|Math\.round|Math\.ceil|parseInt|parseFloat/g.test(c);
    } },

  // ── B7: Complete bypassSecurityTrust* ───────────────────────────────────
  { id:'bypass-style',   cat:'Angular Security', sev:'high',
    re:/bypassSecurityTrustStyle\s*\(/g, ctx: null },
  { id:'bypass-url',     cat:'Angular Security', sev:'critical',
    re:/bypassSecurityTrustUrl\s*\(/g, ctx: null },
  { id:'bypass-resurl',  cat:'Angular Security', sev:'critical',
    re:/bypassSecurityTrustResourceUrl\s*\(/g, ctx: null },
  { id:'bypass-script',  cat:'Angular Security', sev:'critical',
    re:/bypassSecurityTrustScript\s*\(/g, ctx: null },

  // ── B8: Error Handling Leakage ──────────────────────────────────────────
  { id:'err-console',    cat:'Info Leakage',  sev:'medium',
    re:/console\.(log|error|warn|info)\s*\(\s*(?:error|err|e|ex)\b/g, ctx: null },
  { id:'err-alert',      cat:'Info Leakage',  sev:'medium',
    re:/alert\s*\(\s*(?:error|err|e|ex)(?:\.message|\.stack)?\s*\)/g, ctx: null },
  { id:'err-tostring',   cat:'Info Leakage',  sev:'low',
    re:/\.toString\s*\(\s*\).*(?:innerHTML|textContent|innerText)\s*=/g, ctx: null },
  { id:'err-stacktrace', cat:'Info Leakage',  sev:'high',
    re:/(?:error|err|e)\.stack\b/g, ctx: null },

  // ── B9: Source Map Artifacts ────────────────────────────────────────────
  { id:'sourcemap-ref',  cat:'Info Leakage',  sev:'low',
    re:/\/\/[#@]\s*sourceMappingURL\s*=/g, ctx: null },
  { id:'sourcemap-file', cat:'Info Leakage',  sev:'low',
    re:/\.map["']\s*\)|\bsource-maps?\b/gi, ctx: null },

  // ── B10: Web Workers ────────────────────────────────────────────────────
  { id:'worker-new',     cat:'Web Worker',    sev:'info',
    re:/new\s+Worker\s*\(\s*(?:new\s+URL|['"`])/g, ctx: null },
  { id:'worker-blob',    cat:'Web Worker',    sev:'medium',
    re:/new\s+Worker\s*\(\s*URL\.createObjectURL/g, ctx: null },
  { id:'worker-importscripts', cat:'Web Worker', sev:'high',
    re:/importScripts\s*\(/g, ctx: null },

  // ── B11: File Upload Validation ─────────────────────────────────────────
  { id:'upload-type-client', cat:'File Upload', sev:'medium',
    re:/\.type\.(?:includes?|startsWith|indexOf|match)\s*\(\s*['"](?:image|video|text|application)/gi,
    ctx: null },
  { id:'upload-ext-client',  cat:'File Upload', sev:'medium',
    re:/\.name\.(?:endsWith|split|match)\s*\([^)]*(?:jpg|png|pdf|zip|exe|svg)/gi, ctx: null },
  { id:'upload-size-client', cat:'File Upload', sev:'low',
    re:/\.size\s*(?:>|<|>=|<=|===)\s*\d+(?:\s*\*\s*1024)?/g,
    ctx: m => /file|upload|attach/i.test(m) },
];

// ═══════════════════════════════════════════════════════════════════════════
//  FRAMEWORK FINGERPRINTS — A1: Hierarchical detection (confidence-scored)
//  Vue false-positive fix: {{ }} alone does NOT count as Vue.
//  Multi-stage: unique decorators > API patterns > shared syntax (tiebreaker)
// ═══════════════════════════════════════════════════════════════════════════
const FRAMEWORKS = [
  { name:'Angular',   re:/ɵɵdefineComponent|angular\.json|NgModule|@angular\//,
    score: s => (s.match(/ɵɵdefineComponent|ɵɵdefineInjectable|ɵɵelement/g)||[]).length,
    // Unique angular markers — must have at least one to count as Angular
    uniqueMarkers: [/@Component\s*\(/, /@NgModule\s*\(/, /@Injectable\s*\(/, /from\s*['"]@angular\/core['"]/, /ɵɵdefineComponent/],
  },
  { name:'Webpack 5', re:/webpackChunk[a-zA-Z]|__webpack_require__|self\.webpackChunk|performance\.mark\(\s*["']js-parse-end/,
    score: s => (s.match(/webpackChunk|__webpack_require__|__webpack_modules__/g)||[]).length,
  },
  { name:'Socket.io', re:/socket\.io|io\.connect|io\(\)|\\.emit\(|\\.on\("connect"\)/,
    score: s => (s.match(/socket\.io|\.emit\s*\(|\.on\s*\(\s*['"]connect['"]/g)||[]).length,
  },
  { name:'RxJS',      re:/BehaviorSubject|switchMap|catchError|combineLatest|pipe\(/,
    score: s => (s.match(/BehaviorSubject|switchMap|catchError|combineLatest|\.pipe\s*\(/g)||[]).length,
  },
  { name:'Svelte',    re:/SvelteComponent|mount_component|create_fragment|svelte\/internal/,
    score: s => (s.match(/SvelteComponent|mount_component|create_fragment|svelte\/internal/g)||[]).length,
    guard: s => !/angular|react/.test(s.toLowerCase().slice(0,2000)),
  },
  { name:'Next.js',   re:/__NEXT_DATA__|next\/dist|_next\/static|usePathname|__N_SSP/,
    score: s => (s.match(/__NEXT_DATA__|__N_SSP|__N_SSG|usePathname|useSearchParams|_next\/static/g)||[]).length,
  },
  { name:'Vite',      re:/__vitePreload|import\.meta\.hot|__vite__mapDeps|@vite\/client/,
    score: s => (s.match(/__vitePreload|__vite__mapDeps|import\.meta\.hot|@vite\/client/g)||[]).length,
  },
  {
    name:'Vue',
    // A1 FIX: Require Vue-specific unique markers — NOT just {{ }} template syntax
    re:/from\s*['"]vue['"]|createApp\s*\(|defineComponent\s*\(\s*\{|__vccOpts|createElementVNode|Vue\.extend\s*\(|new\s+Vue\s*\(/,
    score: s => (s.match(/createApp\s*\(|defineComponent\s*\(|createElementVNode|__vccOpts|openBlock\s*\(/g)||[]).length,
    guard: s => {
      // Must have at least one Vue-unique marker (not shared with Angular)
      const hasAngular = /@angular\/|ɵɵ|NgModule/.test(s.slice(0,5000));
      if (hasAngular) return false;  // Angular takes precedence
      return true;
    },
    uniqueMarkers: [/from\s*['"]vue['"]/, /createApp\s*\(/, /defineComponent\s*\(\s*\{/, /new\s+Vue\s*\(/],
  },
  { name:'React',     re:/React\.createElement|ReactDOM\.render|useState\s*\(|jsx-runtime/,
    score: s => (s.match(/React\.createElement|ReactDOM\.render|useState\s*\(|useEffect\s*\(|useRef\s*\(|jsx-runtime/g)||[]).length,
  },
  { name:'Express',   re:/app\.(?:get|post|put|delete|use)\s*\(\s*["']\//,
    score: s => (s.match(/app\.(?:get|post|put|delete|use)\s*\(\s*['"]/g)||[]).length,
    guard: s => !/angular|router\.navigate/.test(s.slice(0,3000)),
  },
  { name:'jQuery',    re:/\$\s*\(\s*document\s*\)|jQuery\s*\(/,
    score: s => (s.match(/jQuery\s*\(|\$\s*\(\s*document\s*\)/g)||[]).length,
  },
  { name:'Lodash',    re:/import\s+_\s+from\s+['"]lodash["']|_\.map\(|_\.filter\(/,
    score: s => (s.match(/_\.map\s*\(|_\.filter\s*\(|_\.reduce\s*\(|_\.find\s*\(|_\.assign\s*\(/g)||[]).length,
  },
  { name:'D3',        re:/d3\.select|d3\.scale|d3\.arc/,
    score: s => (s.match(/d3\.select|d3\.scale|d3\.arc|d3\.axis|d3\.csv/g)||[]).length,
  },
];

// ═══════════════════════════════════════════════════════════════════════════
//  WEBPACK MODULE ID → npm package name map (Phase 0)
//
//  ⚠ SAMPLE MAP — these IDs were reverse-engineered from ONE specific bundle
//  (Juice Shop). Webpack module IDs are STABLE per-build but DIFFER across
//  builds. To resolve your bundle's IDs, use `--module-map <file.json>` with
//  a JSON file of { "moduleId": "package-name" } entries derived from your
//  webpack stats.json or source-map.
//
//  The auto-detect heuristic below (resolveModuleAliases) also tries to
//  infer names from common in-bundle patterns (require() calls, package.json
//  references) when no map entry exists.
// ═══════════════════════════════════════════════════════════════════════════
const WEBPACK_MODULE_MAP = {
  2615:'@angular/core',           9330:'@angular/common/http',
  3664:'@angular/core/rendering', 5312:'environment',
  7916:'configuration-service',   9437:'rxjs/operators/catchError',
  6354:'rxjs/operators/map',       9711:'rxjs/operators',
  7810:'rxjs/operators2',          6556:'rxjs/operators3',
  1943:'@angular/router',          5416:'@angular/material/snack-bar',
  1585:'@angular/material/dialog', 4382:'socket.io-client',
  9946:'jwt-decode',               5635:'@ngx-translate/core',
  3955:'@ngx-translate/core2',     2629:'@angular/material/button',
  455: '@angular/router-link',     8834:'@angular/material/icon',
  9417:'@angular/forms',           1228:'@angular/common',
  3746:'@angular/forms2',          9588:'@angular/forms3',
  6192:'@angular/material/table',  882: '@angular/material/sidenav',
  6471:'@angular/material/card',   3902:'@angular/material/list',
  3029:'ngx-highlightjs',          7468:'rxjs/forkJoin',
  3869:'@angular/cdk/collections', 6369:'ngx-highlightjs2',
  4843:'rxjs/firstValueFrom',      9183:'@angular/cdk/drag-drop',
  2578:'file-saver',               6648:'rxjs/from',
  4257:'@angular/platform-browser-dynamic',
  8132:'@angular/common/http2',    5951:'@angular/cdk/portal',
  2496:'@angular/material/autocomplete', 7200:'ng2-file-upload',
  8288:'qrcode',                   4370:'ngx-text-diff',
  107: 'ngx-gallery',              767: '@angular/common/location',
};

// Common package signatures → name. Used by autoDetectModuleNames() to guess
// package names for module IDs that aren't in WEBPACK_MODULE_MAP. Each entry
// is tested against the module body text; first match wins.
const MODULE_SIGNATURE_PATTERNS = [
  // ── Original entries ──
  { sig: /ɵɵdefineComponent|ɵɵdefineInjectable|ɵɵdefineNgModule/, name: '@angular/core' },
  { sig: /HttpClient|HttpHeaders|HttpInterceptor/,                  name: '@angular/common/http' },
  { sig: /Router|ActivatedRoute|canActivate/,                       name: '@angular/router' },
  { sig: /MatDialog|MatSnackBar|MatTable/,                          name: '@angular/material' },
  { sig: /BehaviorSubject|switchMap|catchError|combineLatest/,     name: 'rxjs' },
  { sig: /socket\.io|\.emit\s*\(\s*['"]connect['"]/,               name: 'socket.io-client' },
  { sig: /jwt_decode|jwtDecode/,                                    name: 'jwt-decode' },
  { sig: /TranslateService|@ngx-translate/,                         name: '@ngx-translate/core' },
  { sig: /createStore|useStore|devtools/,                           name: 'zustand' },
  { sig: /produce|createDraft|finishDraft/,                         name: 'immer' },
  { sig: /z\.object|z\.string|safeParse/,                           name: 'zod' },
  { sig: /formatISO|parseISO|differenceInDays/,                     name: 'date-fns' },
  { sig: /_\.map\s*\(|_\.filter\s*\(|_\.reduce\s*\(/,              name: 'lodash' },
  { sig: /d3\.select|d3\.scale|d3\.arc/,                            name: 'd3' },
  { sig: /React\.createElement|useState|useEffect/,                name: 'react' },
  { sig: /createApp|defineComponent|createElementVNode/,            name: 'vue' },
  { sig: /__NEXT_DATA__|usePathname|__N_SSP/,                       name: 'next' },
  { sig: /SvelteComponent|mount_component|create_fragment/,         name: 'svelte' },
  { sig: /moment\s*\(|moment\.isBefore|moment\.format/,             name: 'moment' },
  { sig: /axios\.get|axios\.post|axios\.create/,                    name: 'axios' },
  { sig: /jQuery\s*\(|\$\s*\(\s*document\s*\)/,                     name: 'jquery' },

  // ── Stage 3C: extended fingerprints ──
  // State management
  { sig: /Provider\s*=\s*createContext|useReducer|useSelector|dispatch\s*\(/, name: '@reduxjs/toolkit' },
  { sig: /RecoilRoot|useRecoilState|atom\s*\(/,                     name: 'recoil' },
  { sig: /MobXProvider|observable\s*\(|autorun\s*\(/,               name: 'mobx' },
  { sig: /createStore\s*\(|combineReducers\s*\(/,                   name: 'redux' },

  // UI frameworks / libraries
  { sig: /styled\.\w+|styled\.div|css\s*`|keyframes\s*`/,          name: '@emotion/styled' },
  { sig: /styled\.\w+\s*`|makeStyles\s*\(/,                        name: '@material-ui/core' },
  { sig: /chakra|ChakraProvider/,                                  name: '@chakra-ui/react' },
  { sig: /MantineProvider|createStyles\s*\(/,                      name: '@mantine/core' },
  { sig: /StyledComponentsProvider|styled\.div\s*`/,               name: 'styled-components' },
  { sig: /tw\s*`|className\s*=\s*\{?\s*["']/,                       name: 'tailwindcss' },

  // Routing (non-Angular)
  { sig: /BrowserRouter|Route\s+path|<Switch/,                      name: 'react-router-dom' },
  { sig: /createRouter|RouterView|createWebHistory/,               name: 'vue-router' },

  // Forms / validation
  { sig: /useForm|FormProvider|register\s*\(/,                     name: 'react-hook-form' },
  { sig: /Formik|Field\s+name|validate\s*\(/,                      name: 'formik' },
  { sig: /yup\.object|yup\.string|yup\.number/,                    name: 'yup' },

  // HTTP / data fetching
  { sig: /useQuery|useMutation|QueryClient/,                       name: '@tanstack/react-query' },
  { sig: /gql\s*`|useLazyQuery|ApolloProvider/,                    name: '@apollo/client' },
  { sig: /swr|useSWR|SWRConfig/,                                   name: 'swr' },

  // i18n
  { sig: /useTranslation|i18n\.t\s*\(|Trans\s+/,                    name: 'react-i18next' },
  { sig: /I18nProvider|useLingui|\.i18n\.t\s*\(/,                   name: '@lingui/core' },

  // Charts / visualization
  { sig: /Chart\s+data|PieChart|LineChart|BarChart/,                name: 'recharts' },
  { sig: /VictoryChart|VictoryBar|VictoryLine/,                     name: 'victory' },
  { sig: /Chart\.register|Chart\.defaults/,                         name: 'chart.js' },

  // Animation
  { sig: /motion\.div|AnimatePresence|useSpring/,                   name: 'framer-motion' },
  { sig: /useTransition|Transition\s+/,                             name: '@headlessui/react' },

  // Utilities
  { sig: /clsx\s*\(|cva\s*\(/,                                      name: 'clsx' },
  { sig: /dayjs\s*\(|dayjs\.extend/,                               name: 'dayjs' },
  { sig: /nanoid\s*\(/,                                            name: 'nanoid' },
  { sig: /uuidv4|v4\s*\(\s*\)|v5\s*\(/,                            name: 'uuid' },

  // Backend / SSR (when these appear in bundles)
  { sig: /app\.(?:get|post|put|delete)\s*\(\s*['"]/,               name: 'express' },
  { sig: /createServer|listen\s*\(\s*\d+/,                          name: 'http' },
  { sig: /fastify\.(get|post|put|delete)\s*\(/,                     name: 'fastify' },

  // Web3
  { sig: /ethers\.\w+|Contract\s*\(|Wallet\s*\(/,                  name: 'ethers' },
  { sig: /Web3\s*\(|web3\.eth\./,                                  name: 'web3' },

  // Testing (when these appear, indicates test code shipped to prod)
  { sig: /describe\s*\(\s*['"]|it\s*\(\s*['"]|expect\s*\(/,       name: 'jest' },
  { sig: /render\s*\(\s*<|screen\.getBy/,                           name: '@testing-library/react' },
];

// Auto-detect module names from in-bundle signatures. Returns a map of
// { moduleId: guessedName } for any module whose body matches a known
// signature. Existing WEBPACK_MODULE_MAP entries take precedence (caller
// should merge with override).
function autoDetectModuleNames(src, astModules) {
  const detected = {};
  if (!astModules || !astModules.length) return detected;
  for (const mod of astModules) {
    // Skip if already mapped
    if (WEBPACK_MODULE_MAP[mod.id]) continue;
    const body = src.slice(mod.startPos, mod.endPos);
    for (const { sig, name } of MODULE_SIGNATURE_PATTERNS) {
      if (sig.test(body)) {
        detected[mod.id] = name;
        break;
      }
    }
  }
  return detected;
}

// ═══════════════════════════════════════════════════════════════════════════
//  CLI PARSING
// ═══════════════════════════════════════════════════════════════════════════
function parseArgs() {
  const args = process.argv.slice(2);
  if (!args.length || args[0] === '--help' || args[0] === '-h') {
    printHelp(); process.exit(0);
  }
  const o = {
    input: args[0],
    out: './omega_output',
    splitModules: false, beautify: true,
    secrets: false, routes: false, security: false,
    graph: false, report: false, verbose: false,
    ast: null, // null=auto (on with --security), true=force, false=disable
    moduleMap: null,       // path to external module-map JSON (or null)
    severityFloor: 'info', // minimum severity to include in reports
    maxHops: 5,           // inter-procedural backward slice depth (default 5)
    fetchCves: false,      // query OSV.dev API for live CVE data
    fetchSourcemaps: false,// fetch external .map files via http/https
    multi: false,          // multi-bundle cross-analysis mode
    quiet: false,          // suppress non-essential output (CI-friendly)
    llmPayload: true,      // include LLM-specific payload (function summaries, backward slices, VRT, source expander)
    baseline: null,        // path to .omega-ignore baseline file
    updateBaseline: false, // write current findings as new baseline
    watch: false,          // re-scan on file change
    diff: null,            // path to previous report.json for diff mode
  };
  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case '--out':           o.out          = args[++i]; break;
      case '--split-modules': o.splitModules = true;      break;
      case '--no-beautify':   o.beautify     = false;     break;
      case '--secrets':       o.secrets      = true;      break;
      case '--routes':        o.routes       = true;      break;
      case '--security':      o.security     = true;      break;
      case '--graph':         o.graph        = true;      break;
      case '--report':        o.report       = true;      break;
      case '--ast':           o.ast          = true;      break;
      case '--no-ast':        o.ast          = false;     break;
      case '--verbose':       o.verbose      = true;      break;
      case '--no-color':      setColorEnabled(false); break;
      case '--module-map':    o.moduleMap    = args[++i]; break;
      case '--severity-floor': o.severityFloor = args[++i]; break;
      case '--max-hops':      o.maxHops      = parseInt(args[++i], 10) || 5; break;
      case '--fetch-cves':    o.fetchCves    = true;      break;
    case '--fetch-sourcemaps': o.fetchSourcemaps = true; break;
    case '--multi':         o.multi        = true;      break;
    case '--quiet':         o.quiet        = true;      break;
    case '--no-llm-payload': o.llmPayload  = false;     break;
    case '--baseline':      o.baseline     = args[++i]; break;
    case '--update-baseline': o.updateBaseline = true;   break;
    case '--watch':          o.watch          = true;     break;
    case '--diff':           o.diff           = args[++i]; break;
    case '--all':
        o.splitModules = o.secrets = o.routes = o.security =
        o.graph = o.report = o.ast = true; break;
    }
  }
  return o;
}

function printHelp() {
  console.log(`\n${C.bold}${C.cyan}JS Decoder OMEGA v5${C.reset} ${VERSION}\n`);
  console.log('Usage:  node omega-5.0.js <file.js> [options]\n');
  console.log('  --out <dir>        Output directory (default: ./omega_output)');
  console.log('  --split-modules    Write each webpack module to its own file');
  console.log('  --no-beautify      Skip formatting pass');
  console.log('  --secrets          Credential & secret key scanner (32 patterns)');
  console.log('  --routes           API route / endpoint extractor');
  console.log('  --security         Full security scan (all phases, enables --ast)');
  console.log('  --ast              Force AST structural analysis');
  console.log('  --no-ast           Disable AST pass (regex-only fallback)');
  console.log('  --graph            Webpack module dependency graph');
  console.log('  --report           Generate HTML + JSON + Markdown reports');
  console.log('  --all              Enable everything');
  console.log('  --verbose          Verbose progress output');
  console.log('  --no-color         Plain output (for pipes/CI)');
  console.log('  --module-map <f>   Load external webpack module-id → name map (JSON)');
  console.log('                     Format: {"1234":"@scope/pkg", "5678":"rxjs", ...}');
  console.log('  --severity-floor <s>  Minimum severity to include in reports');
  console.log('                     One of: critical, high, medium, low, info (default)');
  console.log('  --max-hops <n>      Max backward-slice depth for inter-procedural taint (default: 5)');
  console.log('  --fetch-cves       Query OSV.dev API for live vulnerability data (uses node:https)');
  console.log('  --fetch-sourcemaps Fetch and decode external .map files (uses node:https)');
  console.log('  --quiet            Suppress non-essential output (CI-friendly)');
  console.log('  --multi            Cross-bundle analysis mode (comma-separated inputs)');
  console.log('  --no-llm-payload   Omit LLM-specific JSON sections (function summaries, backward');
  console.log('                     slices, VRT, source expander) — reduces report size ~70%');
  console.log('  --baseline <file>  Load baseline file (.omega-ignore JSON) to suppress known findings');
  console.log('  --update-baseline  Write current findings to .omega-ignore file');
  console.log('  --watch            Watch input file for changes and re-scan (uses fs.watch)');
  console.log('  --diff <file>      Compare against previous report.json — only show new findings');
  console.log('  --multi            Cross-bundle analysis mode (comma-separated inputs)');
  console.log('');
  console.log('  CI exit codes (configure via OMEGA_FAIL_ON env var):');
  console.log('                     0=clean, 1=error, 2=critical (default),');
  console.log('                     3=high+, 4=medium+, 5=low+, none=always 0');
  console.log('  OMEGA_FAIL_ON=critical|high|medium|low|none\n');
  console.log('OMEGA-5.0 NEW capabilities (Tier 1 structural upgrade):');
  console.log('  [T1.1] AST-based framework detection (Angular cmp/svc/mod/pipe/dir, Vue, React)');
  console.log('  [T1.2] Webpack 5 dynamic module resolver (parses webpackChunk_xxx runtime)');
  console.log('  [T1.3] Call graph builder (module-level + function-level edge analysis)');
  console.log('  [T1.4] AST cross-statement taint tracking (replaces regex Phase 12j)');
  console.log('  [T1.5] Bundler detection + per-bundler Phase 13 (webpack5/4/vite/rollup)');
  console.log('  [T1.6] Modern crypto patterns: JWT decode, WebCrypto, Node hashes, bcrypt, bearer');
  console.log('  [T1.10] Network surface extractor (URLs, hosts, RFC1918, cloud metadata)\n');
  console.log('OMEGA-4.0 retained capabilities (30 behavioral detectors):');
  console.log('  [A1]  Hierarchical framework detection with confidence scoring (Vue FP fix)');
  console.log('  [A2]  Route-guard ↔ API endpoint authorization correlation');
  console.log('  [B1]  Dynamic code execution: setTimeout/setInterval/Function()/Wasm');
  console.log('  [B2]  Complete DOM-XSS sink catalog (outerHTML/insertAdjacentHTML/srcdoc…)');
  console.log('  [B3]  Angular template injection / $compile detection');
  console.log('  [B4]  Prototype pollution + gadget detection');
  console.log('  [B5]  PostMessage wildcard origin / missing validation');
  console.log('  [B6]  Insufficient randomness in security contexts');
  console.log('  [B7]  bypassSecurityTrust* full family (Style/Url/ResourceUrl/Script)');
  console.log('  [B8]  Error-handling information leakage');
  console.log('  [B9]  Source-map artifact detection');
  console.log('  [B10] Web Workers / importScripts security');
  console.log('  [B11] Client-side file upload validation');
  console.log('  [B14] Attack surface prioritisation scorer');
  console.log('  [C1]  Business logic: rate-limit/balance/coupon/role bypass vectors');
  console.log('  [C2]  WebSocket message content → DOM sink taint tracing');
  console.log('  [C3]  Socket.io event → side-effect + sensitive payload mapping');
  console.log('  [C4]  Cryptographic context: privkey/static-IV/ECB/subtle misuse');
  console.log('  [C5]  Information leakage: stack trace/debug/path/enumeration');
  console.log('  [C6]  IDOR: user-ID in URL/localStorage without ownership check');
  console.log('  [C7]  Static dependency CVE correlation (10 known-vuln packages)');
  console.log('  [C8]  Race conditions in async localStorage read-modify-write');
  console.log('  [D1]  Heuristic taint-flow: URL/postMessage/storage → innerHTML/eval');
  console.log('  [D2]  Web3/blockchain: privkey/sendTx/sig-replay/reentrancy');
  console.log('  [D3]  Config-driven behaviour: disabled auth/CORS wildcard/debug flags');
  console.log('  [D4]  Lazy-loading: unguarded chunks + user-controlled dynamic import()\n');
  console.log('Phase 5b frameworks: Vue3, React, Svelte, Next.js, Webpack, Vite,');
  console.log('                     Lodash-ES, date-fns, Zod, Zustand, Immer, core-js\n');
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 0 — MODULE ALIAS RESOLVER
// ═══════════════════════════════════════════════════════════════════════════
function resolveModuleAliases(src, opts) {
  let resolved = 0;
  const aliases = {};
  const aliasRe = /(?:var|const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*d\((\d+)\)/g;
  let m;
  while ((m = aliasRe.exec(src)) !== null) {
    const [, varName, modId] = m;
    const pkgName = WEBPACK_MODULE_MAP[modId];
    if (pkgName) {
      aliases[varName] = pkgName;
      resolved++;
    }
  }
  if (opts.verbose && resolved)
    console.log(info(`  Resolved ${resolved} module aliases`));
  return { src, aliases, count: resolved };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 1 — ESCAPE DECODE
// ═══════════════════════════════════════════════════════════════════════════
function decodeEscapes(src) {
  const stats = { unicode:0, hex:0, octal:0, htmlEnt:0 };
  src = src.replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, h) => {
    stats.unicode++; return String.fromCodePoint(parseInt(h,16));
  });
  src = src.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => {
    stats.unicode++; return String.fromCharCode(parseInt(h,16));
  });
  src = src.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => {
    stats.hex++; return String.fromCharCode(parseInt(h,16));
  });
  const htmlEnts = { '&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&apos;':"'",'&nbsp;':'\u00a0' };
  src = src.replace(/&(?:amp|lt|gt|quot|apos|nbsp);/g, e => {
    stats.htmlEnt++; return htmlEnts[e] || e;
  });
  return { src, stats };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 2 — STRING DECODE (10-pass iterative)
// ═══════════════════════════════════════════════════════════════════════════
function decodeStrings(src) {
  const totals = { charCode:0, base64:0, hexArr:0, concat:0 };
  for (let pass = 0; pass < 10; pass++) {
    let changed = false;

    src = src.replace(/String\.fromCharCode\s*\(([^)]+)\)/g, (_, args) => {
      try {
        const codes = args.split(',').map(x => {
          const t = x.trim();
          return parseInt(t, t.startsWith('0x') ? 16 : 10);
        }).filter(n => !isNaN(n));
        if (!codes.length) return _;
        totals.charCode++; changed = true;
        return JSON.stringify(codes.map(c => String.fromCharCode(c)).join(''));
      } catch { return _; }
    });

    src = src.replace(/atob\s*\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)/g, (_, b) => {
      try {
        totals.base64++; changed = true;
        return JSON.stringify(Buffer.from(b,'base64').toString('utf8'));
      } catch { return _; }
    });

    src = src.replace(/\[\s*((?:0x[0-9a-fA-F]{1,4}\s*,?\s*)+)\]/g, (_, inner) => {
      try {
        const nums = inner.split(',').map(x => parseInt(x.trim(),16)).filter(n => !isNaN(n));
        if (nums.length < 2) return _;
        const s = nums.map(c => String.fromCharCode(c)).join('');
        if (!/^[\x20-\x7e\t\n\r]+$/.test(s)) return _;
        totals.hexArr++; changed = true;
        return JSON.stringify(s);
      } catch { return _; }
    });

    src = src.replace(/["']([^"']*)["']\s*\+\s*["']([^"']*)["']/g, (_, a, b) => {
      totals.concat++; changed = true;
      return JSON.stringify(a + b);
    });
    for (let j = 0; j < 4; j++) {
      src = src.replace(/["']([^"']*)["']\s*\+\s*["']([^"']*)["']/g, (_, a, b) => {
        totals.concat++; return JSON.stringify(a + b);
      });
    }
    if (!changed) break;
  }
  return { src, stats: totals };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 2b — CHARCODE OBFUSCATION DECODER  (NEW in OMEGA-3.0)
//
//  Decodes the pattern:
//    function(...args){ r=Array.slice(args); e=r.shift();
//      return r.reverse().map((o,a)=>String.fromCharCode(o-e-OFFSET-a)).join("") }(seed,...bytes)
//
//  Two offset variants seen in the wild:
//    · o - e - 45 - a  (Juice Shop token/route segments)
//    · o - e - 24 - a  (Juice Shop coupon/secondary segments)
//  Collects all printable decoded strings and returns them for injection
//  into the decoded source as comments AND into a dedicated findings array.
// ═══════════════════════════════════════════════════════════════════════════
function decodeCharCodeObfuscation(src) {
  const findings = [];

  // ── Pass 1: collect all individual CharCode IIFE matches (no src mutation yet) ──
  const ctxRe = /reverse\(\s*\)\.map\s*\(\s*function\s*\([^)]*\)\s*\{\s*return\s+String\.fromCharCode\s*\(([^)]+)\)\s*\}\s*\)\.join\s*\(\s*["']["']\s*\)\s*\}\s*\(([^)]+)\)/g;
  let m;
  const rawMatches = []; // { index, end, match, decoded, seed, bytes, offsetExpr }

  while ((m = ctxRe.exec(src)) !== null) {
    const offsetExpr = m[1].trim();
    const argStr     = m[2].trim();
    const args = argStr.split(',').map(x => parseInt(x.trim(), 10)).filter(n => !isNaN(n));
    if (args.length < 3 || args.length > 32) continue;

    const fixedOffset = [...offsetExpr.matchAll(/\d+/g)]
      .map(x => parseInt(x[0])).reduce((a, b) => a + b, 0);
    const seed    = args[0];
    const bytes   = args.slice(1);
    const decoded = [...bytes].reverse()
      .map((o, a) => String.fromCharCode(o - seed - fixedOffset - a)).join('');

    if (!/^[\x20-\x7e]{2,}$/.test(decoded)) continue;

    rawMatches.push({
      index: m.index, end: m.index + m[0].length,
      match: m[0], decoded, seed, bytes: args, offsetExpr,
      context: src.slice(Math.max(0, m.index - 60), m.index + 80).replace(/\n/g, ' '),
    });
  }

  // ── Pass 2: detect adjacent-concat assemblies on the unmutated src ───
  const assembledSeen = new Set();

  for (let i = 0; i < rawMatches.length; i++) {
    // Look at the window AFTER this match's end to find a concat chain
    const gap   = src.slice(rawMatches[i].end, rawMatches[i].end + 600);
    // Pattern: +"literal".toLowerCase() +function...}(seed,...) +"literal".toLowerCase()
    const adjacentLookRe = /^((?:\s*\+\s*["'][a-zA-Z0-9\-_/]*["'](?:\.toLowerCase\(\))?\s*)*)\s*\+\s*function/;
    const adj = adjacentLookRe.exec(gap);
    if (!adj) continue;

    // Find the next rawMatch that starts within the gap
    const nextMatch = rawMatches[i + 1];
    if (!nextMatch) continue;
    if (nextMatch.index > rawMatches[i].end + 600) continue;

    // Extract string literals between the two calls
    const betweenText = src.slice(rawMatches[i].end, nextMatch.end);
    const midLiterals = [...betweenText.matchAll(/["']([a-zA-Z0-9\-_/]{0,20})["']\.toLowerCase\(\)/g)]
      .map(x => x[1]);

    // Extract trailing literals after the second call
    const afterText = src.slice(nextMatch.end, nextMatch.end + 200);
    const trailLiterals = [...afterText.matchAll(/\+\s*["']([a-zA-Z0-9\-_/]{0,20})["']\.toLowerCase\(\)/g)]
      .map(x => x[1]);

    const assembled = rawMatches[i].decoded
      + midLiterals.join('')
      + nextMatch.decoded
      + trailLiterals.join('');

    if (assembled.length < 4 || assembledSeen.has(assembled)) continue;
    if (!/^[\x20-\x7e]+$/.test(assembled)) continue;
    assembledSeen.add(assembled);

    findings.push({
      decoded:     assembled,
      seed:        rawMatches[i].seed,
      bytes:       [],
      offsetExpr:  'multi-segment-concat',
      isAssembled: true,
      segments:    [rawMatches[i].decoded, nextMatch.decoded],
      literals:    [...midLiterals, ...trailLiterals],
      context:     betweenText.slice(0, 120).replace(/\n/g, ' '),
    });
  }

  // ── Pass 3: add individual decoded findings (dedup) + inject comments ─
  const indivSeen = new Set();
  for (const rm of rawMatches) {
    if (!indivSeen.has(rm.decoded)) {
      indivSeen.add(rm.decoded);
      findings.unshift({  // individual findings go first
        decoded: rm.decoded, seed: rm.seed, bytes: rm.bytes,
        offsetExpr: rm.offsetExpr, context: rm.context,
      });
    }
    // Inject comment — process in reverse order to preserve positions
  }

  // Inject comments in reverse order so positions stay valid
  let mutatedSrc = src;
  for (const rm of [...rawMatches].reverse()) {
    mutatedSrc = mutatedSrc.slice(0, rm.index)
      + `/* OMEGA-decoded: "${rm.decoded}" */`
      + mutatedSrc.slice(rm.index);
  }

  return { src: mutatedSrc, findings };
}


// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 2c — OBFUSCATOR.IO STRING-ARRAY DECODER (Stage 5)
//
//  Reverses the string-array obfuscation emitted by obfuscator.io and similar
//  tools. The obfuscator transforms:
//    "hello"  →  _0xDEC(0x1a2, 'key')
//  where _0xDEC is a decoder function that indexes into a rotated string
//  array and (optionally) RC4-decrypts the result.
//
//  Algorithm:
//    1. Extract the string-array declaration: var _0xARR = ['s1','s2',...]
//    2. Extract the rotation IIFE: (function(arr, key){ ...push/shift... })(arr, 0xNNN)
//    3. Apply the rotation N times (push then shift, where N = key % arr.length)
//    4. Extract the decoder function shape (base64 or RC4)
//    5. Walk all calls to _0xDEC with constant args, evaluate, and replace
//       the call with the decoded string literal
//
//  Safety constraints (we REFUSE to evaluate):
//    · Calls where either argument is not a literal
//    · Decoder functions that call user code or eval
//    · String arrays longer than 10000 entries (DoS guard)
//    · Rotation counts > 10000 (DoS guard)
// ═══════════════════════════════════════════════════════════════════════════
function decodeObfuscatorIo(src) {
  const findings = [];
  const decodedStrings = [];

  // ── Step 1: extract string-array declaration ───────────────────────────
  // Pattern: var|const|let NAME = ['s1','s2',...];  (at least 3 strings)
  const saDeclRe = /(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*\[((?:["'][^"']*["']\s*,?\s*){3,})\]\s*;/g;
  let saMatch;
  const stringArrays = [];  // { name, strings, pos, endPos }

  while ((saMatch = saDeclRe.exec(src)) !== null) {
    const name = saMatch[1];
    const arrayLiteral = saMatch[2];
    // Parse the strings out of the array literal
    const strings = [];
    const strRe = /(["'])((?:\\.|(?!\1).)*)\1/g;
    let sm;
    while ((sm = strRe.exec(arrayLiteral)) !== null) {
      // Unescape basic sequences
      strings.push(sm[2].replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\n/g, '\n').replace(/\\t/g, '\t'));
    }
    if (strings.length >= 3 && strings.length <= 10000) {
      stringArrays.push({
        name,
        strings,
        pos: saMatch.index,
        endPos: saMatch.index + saMatch[0].length,
      });
    }
  }

  if (stringArrays.length === 0) {
    return { src, findings, decodedStrings };
  }

  // ── Step 2: extract rotation IIFE ──────────────────────────────────────
  // Pattern: (function(NAME, KEY){ ...push/shift... }(NAME, 0xNNN))
  // The rotation count is 0xNNN % arr.length
  for (const sa of stringArrays) {
    const rotateRe = new RegExp(
      `\\(function\\s*\\(\\s*${sa.name}\\s*,\\s*[A-Za-z_$][\\w$]*\\s*\\)\\s*\\{[\\s\\S]{0,1000}?(?:push|shift)[\\s\\S]{0,1000}?\\}\\s*\\(\\s*${sa.name}\\s*,\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\)\\s*\\)`
    );
    const rm = rotateRe.exec(src);
    if (rm) {
      const rotateCount = parseInt(rm[1], rm[1].startsWith('0x') ? 16 : 10);
      const effective = rotateCount % sa.strings.length;
      // Apply rotation: push then shift, N times. This moves the first element
      // to the end N times, equivalent to slicing at N.
      sa.strings = sa.strings.slice(effective).concat(sa.strings.slice(0, effective));
      sa.rotated = true;
      findings.push({
        id: 'obfuscator-io-rotation',
        category: 'Obfuscator.io Decoder',
        severity: 'info',
        value: `rotated ${sa.name} by ${effective} (key=${rotateCount})`,
        context: `array of ${sa.strings.length} strings`,
        description: `Applied obfuscator.io string-array rotation: ${effective} positions`,
      });
    }
  }

  // ── Step 3: extract decoder function ───────────────────────────────────
  // obfuscator.io decoders have the shape:
  //   function NAME(idx, key) {
  //     var s = ARRAY[idx];
  //     ... optional RC4 decrypt using key ...
  //     return s;
  //   }
  // We support two variants:
  //   (a) Base64-only: no key used, just atob(s)
  //   (b) RC4: key is used, charCodeAt loop
  for (const sa of stringArrays) {
    // Find decoder functions that reference this array
    const decoderRe = new RegExp(
      `function\\s+([A-Za-z_$][\\w$]*)\\s*\\(\\s*([A-Za-z_$][\\w$]*)\\s*,\\s*([A-Za-z_$][\\w$]*)\\s*\\)\\s*\\{[\\s\\S]{0,800}?${sa.name}\\[\\s*\\2\\s*\\][\\s\\S]{0,800}?\\}`,
      'g'
    );
    let dm;
    while ((dm = decoderRe.exec(src)) !== null) {
      const decName = dm[1];
      const idxParam = dm[2];
      const keyParam = dm[3];
      const body = dm[0];

      // Determine decoder type
      const isRC4 = /charCodeAt[\s\S]{0,200}fromCharCode/.test(body) && body.includes(keyParam);
      const isBase64 = /atob\s*\(/.test(body) && !isRC4;
      const isPlain = !isRC4 && !isBase64;  // just array indexing, no transform

      if (!isRC4 && !isBase64 && !isPlain) continue;

      findings.push({
        id: 'obfuscator-io-decoder',
        category: 'Obfuscator.io Decoder',
        severity: 'info',
        value: `${decName}(${idxParam}, ${keyParam}) — ${isRC4 ? 'RC4' : isBase64 ? 'base64' : 'plain'}`,
        context: body.slice(0, 100),
        description: `Found obfuscator.io decoder function ${decName}`,
      });

      // ── Step 4: find all calls to this decoder with constant args ──────
      const callRe = new RegExp(
        `\\b${decName}\\s*\\(\\s*(0x[0-9a-fA-F]+|\\d+)\\s*,\\s*["']([^"']*)["']\\s*\\)`,
        'g'
      );
      let replacedCount = 0;
      src = src.replace(callRe, (full, idxStr, key) => {
        const idx = parseInt(idxStr, idxStr.startsWith('0x') ? 16 : 10);
        if (idx < 0 || idx >= sa.strings.length) return full;

        let decoded;
        try {
          const raw = sa.strings[idx];
          if (isPlain) {
            decoded = raw;
          } else if (isBase64) {
            decoded = Buffer.from(raw, 'base64').toString('utf8');
          } else if (isRC4) {
            decoded = rc4Decrypt(raw, key);
          }
        } catch (_) {
          return full;
        }

        if (typeof decoded !== 'string') return full;
        if (!/^[\x20-\x7e\s]*$/.test(decoded)) return full;

        const escaped = decoded.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
        replacedCount++;

        decodedStrings.push({
          call: full,
          decoded,
          idx,
          key: isRC4 ? key : null,
        });

        return `'${escaped}'`;
      });

      if (replacedCount > 0) {
        findings.push({
          id: 'obfuscator-io-decoded',
          category: 'Obfuscator.io Decoder',
          severity: 'low',
          value: `${replacedCount} strings decoded via ${decName}`,
          context: `decoder type: ${isRC4 ? 'RC4' : isBase64 ? 'base64' : 'plain'}`,
          description: `Decoded ${replacedCount} obfuscator.io string references`,
        });
      }
    }
  }

  return { src, findings, decodedStrings };
}

// ── RC4 decryption helper (obfuscator.io-compatible) ────────────────────
// obfuscator.io's RC4 variant: key-scheduling + XOR stream cipher
// Input: ciphertext (base64-decoded), key (string)
// Output: plaintext string
function rc4Decrypt(ciphertext, key) {
  // obfuscator.io sometimes base64-encodes the ciphertext before RC4
  let data;
  try {
    data = Buffer.from(ciphertext, 'base64');
  } catch (_) {
    data = Buffer.from(ciphertext, 'binary');
  }
  // Key scheduling
  const s = [];
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key.charCodeAt(i % key.length)) & 0xFF;
    const tmp = s[i]; s[i] = s[j]; s[j] = tmp;
  }
  // Stream generation + XOR
  let i = 0; j = 0;
  const out = [];
  for (let n = 0; n < data.length; n++) {
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    const tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    const k = s[(s[i] + s[j]) & 0xFF];
    out.push(data[n] ^ k);
  }
  return Buffer.from(out).toString('utf8');
}


// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 2d — CONSTANT-EXPRESSION EVALUATOR (Stage 5)
//
//  A safe partial evaluator for the constrained subset of JavaScript that
//  commonly appears in obfuscated string construction:
//    · Literal arithmetic: 0x41 + 0x20 → 0x61
//    · String concatenation: "a" + "b" → "ab"
//    · Array indexing into known-constant arrays: table[3]
//    · String.fromCharCode(N1, N2, ...) on constant args
//    · atob("...") / btoa("...") on constant args
//    · parseInt("0xNN", 16) / N.toString(R) on constants
//    · "str".charCodeAt(N) on known strings
//
//  We REFUSE to evaluate anything that falls outside this subset. This is
//  not a JS interpreter — it's a constant folder. No user functions, no
//  Proxy, no getters, no eval, no with.
//
//  The evaluator is iterative (not recursive) to avoid stack overflow on
//  deeply-nested expressions. Max nesting depth: 20.
// ═══════════════════════════════════════════════════════════════════════════
function evaluateConstantExpressions(src) {
  // Size guard: constant evaluation involves multi-pass string replacement;
  // skip for large bundles where it's unlikely to add value.
  const MAX_SIZE = 1024 * 1024; // 1 MB
  if (src.length > MAX_SIZE) return { src, findings: [] };

  const findings = [];
  let changed = true;
  let passes = 0;
  const MAX_PASSES = 10;

  while (changed && passes < MAX_PASSES) {
    changed = false;
    passes++;

    // Each pass uses `src.replace(re, callback)` — the JS engine builds the
    // result string in a single O(N) pass regardless of match count, avoiding
    // the O(N×M) quadratic allocation of the old `while(exec){slice+repl+slice}` pattern.

    // ── String.fromCharCode(N1, N2, ...) ──────────────────────────────
    src = src.replace(/String\.fromCharCode\s*\(\s*([^)]+)\s*\)/g, (full, argsStr) => {
      const args = argsStr.split(',').map(a => {
        try { return evalConstantArith(a.trim()); } catch (_) { return null; }
      });
      if (args.some(a => a === null)) return full;
      const decoded = args.map(c => String.fromCharCode(c)).join('');
      const escaped = decoded.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
      changed = true;
      findings.push({
        id: 'const-expr-fromcharcode',
        category: 'Constant Evaluator',
        severity: 'info',
        value: `String.fromCharCode → "${decoded.slice(0, 40)}"`,
        context: '',
        description: 'Evaluated constant String.fromCharCode expression',
      });
      return `'${escaped}'`;
    });

    // ── atob("...") on constant string ────────────────────────────────
    src = src.replace(/\batob\s*\(\s*["']([A-Za-z0-9+/=]{4,100})["']\s*\)/g, (full, b64) => {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        if (!/^[\x20-\x7e\s]*$/.test(decoded)) return full;
        const escaped = decoded.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        changed = true;
        findings.push({
          id: 'const-expr-atob',
          category: 'Constant Evaluator',
          severity: 'info',
          value: `atob → "${decoded.slice(0, 40)}"`,
          context: '',
          description: 'Evaluated constant atob() expression',
        });
        return `'${escaped}'`;
      } catch (_) { return full; }
    });

    // ── "str".charCodeAt(N) on known string ───────────────────────────
    src = src.replace(/["']([^"']{1,100})["']\s*\.charCodeAt\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)/g, (full, str, idxStr) => {
      const idx = parseInt(idxStr, idxStr.startsWith('0x') ? 16 : 10);
      if (idx < 0 || idx >= str.length) return full;
      const code = str.charCodeAt(idx);
      changed = true;
      findings.push({
        id: 'const-expr-charcodeat',
        category: 'Constant Evaluator',
        severity: 'info',
        value: `charCodeAt → ${code}`,
        context: '',
        description: 'Evaluated constant charCodeAt expression',
      });
      return String(code);
    });

    // ── parseInt("0xNN", 16) / parseInt("NN", 10) ─────────────────────
    src = src.replace(/parseInt\s*\(\s*["'](0x[0-9a-fA-F]+|\d+)["']\s*,\s*(16|10|8|2)\s*\)/g, (full, valStr, radixStr) => {
      const val = parseInt(valStr, parseInt(radixStr));
      changed = true;
      findings.push({
        id: 'const-expr-parseint',
        category: 'Constant Evaluator',
        severity: 'info',
        value: `parseInt → ${val}`,
        context: '',
        description: 'Evaluated constant parseInt expression',
      });
      return String(val);
    });

    // ── String literal concatenation: "a" + "b" → "ab" ────────────────
    // Multi-pass: a single replacement may expose new concatenations.
    const concatRe = /(["'])((?:[^\\'"]|\\.)*)\1\s*\+\s*(["'])((?:[^\\'"]|\\.)*)\3/g;
    for (let j = 0; j < 4; j++) {
      src = src.replace(concatRe, (full, q1, a, q2, b) => {
        const combined = a + b;
        const escaped = combined.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
        changed = true;
        return `'${escaped}'`;
      });
    }

    // ── N.toString(R) on numeric literal ──────────────────────────────
    src = src.replace(/\b(\d+|0x[0-9a-fA-F]+)\.toString\s*\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)/g, (full, numStr, radStr) => {
      const num = parseInt(numStr, numStr.startsWith('0x') ? 16 : 10);
      const radix = parseInt(radStr, radStr.startsWith('0x') ? 16 : 10);
      if (radix < 2 || radix > 36) return full;
      const result = num.toString(radix);
      changed = true;
      findings.push({
        id: 'const-expr-tostring',
        category: 'Constant Evaluator',
        severity: 'info',
        value: `toString → "${result}"`,
        context: '',
        description: 'Evaluated constant toString expression',
      });
      return `'${result}'`;
    });
  }

  return { src, findings };
}

// ── Constant arithmetic evaluator (helper) ──────────────────────────────
// Evaluates a simple arithmetic expression containing only numeric literals
// and + - * / operators. Returns a number or throws.
function evalConstantArith(expr) {
  // Tokenize: numbers and operators
  const tokens = expr.match(/(?:0x[0-9a-fA-F]+|\d+)|[+\-*/]/g);
  if (!tokens || tokens.length === 0) throw new Error('no tokens');

  // Convert hex to decimal
  const nums = tokens.map(t => {
    if (t === '+' || t === '-' || t === '*' || t === '/') return t;
    return parseInt(t, t.startsWith('0x') ? 16 : 10);
  });

  // Simple left-to-right evaluation (no operator precedence — matches
  // obfuscator.io's typical usage where each arg is a single expression)
  let result = nums[0];
  for (let i = 1; i < nums.length; i += 2) {
    const op = nums[i];
    const next = nums[i + 1];
    if (op === '+') result += next;
    else if (op === '-') result -= next;
    else if (op === '*') result *= next;
    else if (op === '/') { if (next === 0) throw new Error('div by zero'); result = Math.floor(result / next); }
    else throw new Error('bad op: ' + op);
  }
  if (typeof result !== 'number' || isNaN(result)) throw new Error('not a number');
  return result;
}


function normaliseBooleans(src) {
  return src
    .replace(/\b!0\b/g, 'true')
    .replace(/\b!1\b/g, 'false')
    .replace(/\bvoid\s+0\b/g, 'undefined')
    .replace(/\bvoid\(0\)/g, 'undefined')
    .replace(/\b!!\[\]/g, 'true')
    .replace(/\b!\[\]/g, 'false')
    .replace(/\+\[\]/g, '0');
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 4 — WEBPACK CLEANUP
// ═══════════════════════════════════════════════════════════════════════════
function cleanupWebpack(src) {
  src = src.replace(/\(0\s*,\s*([A-Za-z_$][A-Za-z0-9_$.]*)\)\s*\(/g, '$1(');
  src = src.replace(/__webpack_require__/g, 'require');
  src = src.replace(/Object\.defineProperty\s*\(\s*\w+\s*,\s*["']__esModule["']\s*,\s*\{[^}]*\}\s*\)\s*;?/g, '/* ESModule */');
  src = src.replace(/\/\*\*\*\/\s*\(function\s*\(/g, '/* webpack-module */ (function(');
  src = src.replace(/\/\*\s*!eval\s*\*\//g, '/* eval */');
  return src;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 5 — ANGULAR IVY ANNOTATION
// ═══════════════════════════════════════════════════════════════════════════
function annotateAngularIvy(src) {
  for (const [pat, repl] of Object.entries(ANGULAR_UNICODE_PROPS)) {
    src = src.replace(new RegExp(pat, 'g'), repl);
  }
  for (const [short, full] of Object.entries(ANGULAR_IVY_MAP)) {
    const escaped = short.replace(/[$]/g,'\\$');
    src = src.replace(new RegExp(`(\\w+)\\.${escaped}(\\s*\\()`, 'g'), `$1.${full}$2`);
    src = src.replace(new RegExp(`(?<![.\\w])${escaped}(\\s*\\()`, 'g'), `${full}$1`);
  }
  for (const [pat, repl] of Object.entries(ANGULAR_STATIC_MAP)) {
    src = src.split(pat).join(repl);
  }
  return src;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 5b — MULTI-FRAMEWORK SYMBOL ANNOTATION  (NEW in OMEGA-2.0)
//
//  Strategy:
//   · detectFrameworkHits()  — fast heuristic scan, returns a hits object
//   · applySymbolMap()       — namespace + top-level identifier replacement
//                              only for keys >= 3 chars (FP safety)
//   · applyLiteralMap()      — simple split/join for long string keys
//  Only maps whose framework is detected are applied — avoids cross-
//  framework false-positive renames in single-framework codebases.
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Fast heuristic: returns boolean flags for each supported framework.
 * Deliberately separate from the heavier FRAMEWORKS fingerprint array
 * so Phase 5b can run before Phase 9.
 */
function detectFrameworkHits(src) {
  return {
    angular: /ɵɵ|ɵcmp|ɵfac|ɵprov|ivy/.test(src),
    vue:     /__vccOpts|createElementVNode|openBlock|__vueParentComponent/.test(src),
    react:   /React\.createElement|__reactFiber|jsx-runtime|react-dom/.test(src),
    svelte:  /SvelteComponent|mount_component|create_fragment|svelte\/internal/.test(src),
    nextjs:  /__NEXT_DATA__|next\/dist|_next\/static|usePathname/.test(src),
    webpack: /__webpack_require__|webpackChunk|webpackJsonp|performance\.mark\(\s*["']js-parse-end/.test(src),
    vite:    /__vitePreload|import\.meta\.hot|__vite__mapDeps/.test(src),
    lodash:  /import\s+_\s+from|lodash-es|_\.map\(|_\.filter\(/.test(src),
    dateFns: /date-fns|parseISO|formatISO|differenceInDays/.test(src),
    zod:     /z\.object|z\.string|\.safeParse|zod/.test(src),
    zustand: /create.*store|useStore|devtools.*zustand|zustand/.test(src),
    immer:   /produce|createDraft|finishDraft|immer/.test(src),
    corejs:  /__core-js_shared__|IS_PURE|NATIVE_WEAK_MAP|core-js/.test(src),
  };
}

/**
 * Apply a symbol map (short mangled key → readable name) using two patterns:
 *  1. Namespaced:   someVar.mangledKey(  →  someVar.readableName(
 *  2. Top-level:    mangledKey(           →  readableName(
 * Keys shorter than 3 chars are skipped to avoid false positives.
 */
// minTopLevel=2 when framework is confirmed (safe in-context), 3 for generic
function applySymbolMap(src, map, minTopLevel) {
  if (minTopLevel === undefined) minTopLevel = 3;
  let count = 0;
  for (const [short, full] of Object.entries(map)) {
    if (short.length < 2) continue; // single-char always skipped
    const esc = short.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const prev = src;
    // Namespaced: word.key( — safe for 2+ char keys
    src = src.replace(new RegExp('(\\w+)\\.' + esc + '(\\s*\\()', 'g'), '$1.' + full + '$2');
    // Top-level: key( — threshold-gated to reduce false positives
    if (short.length >= minTopLevel) {
      src = src.replace(new RegExp('(?<![.\\w])' + esc + '(\\s*\\()', 'g'), full + '$1');
    }
    if (src !== prev) count++;
  }
  return { src, count };
}

/**
 * Apply a literal-string annotation map: exact key → annotated replacement.
 * Used for long webpack/vite/core-js identifiers where regex would be overkill.
 */
function applyLiteralMap(src, map) {
  let count = 0;
  for (const [key, replacement] of Object.entries(map)) {
    if (src.includes(key)) {
      src = src.split(key).join(replacement);
      count++;
    }
  }
  return { src, count };
}

function annotateFrameworkSymbols(src, opts) {
  const hits  = detectFrameworkHits(src);
  const stats = { frameworks: [], symbolsAnnotated: 0 };

  const apply = (map, label, minTopLevel) => {
    const r = applySymbolMap(src, map, minTopLevel !== undefined ? minTopLevel : 2);
    src = r.src;
    if (r.count > 0) {
      stats.symbolsAnnotated += r.count;
      if (!stats.frameworks.includes(label)) stats.frameworks.push(label);
    }
  };
  const literal = (map, label) => {
    const r = applyLiteralMap(src, map);
    src = r.src;
    if (r.count > 0) {
      stats.symbolsAnnotated += r.count;
      if (!stats.frameworks.includes(label)) stats.frameworks.push(label);
    }
  };

  if (hits.vue) {
    if (opts.verbose) console.log(info('  Phase 5b: Vue 3 symbol annotation…'));
    apply(VUE3_VNODE_MAP,   'Vue3');
    apply(VUE_ROUTER_MAP,   'Vue3-Router');
    literal(VUE3_INTERNAL_PROPS, 'Vue3-Internals');
  }
  if (hits.react) {
    if (opts.verbose) console.log(info('  Phase 5b: React symbol annotation…'));
    apply(REACT_HOOKS_MAP,  'React-Hooks');
    apply(REACT_DOM_MAP,    'React-DOM');
    apply(REACT_EVENTS_MAP, 'React-Events');
    // React fiber props use escaped $ in keys — apply as literal with regex
    for (const [rawKey, replacement] of Object.entries(REACT_FIBER_PROPS)) {
      try {
        src = src.replace(new RegExp(rawKey, 'g'), replacement);
        stats.symbolsAnnotated++;
      } catch { /* skip malformed pattern */ }
    }
    if (!stats.frameworks.includes('React')) stats.frameworks.push('React');
  }
  if (hits.svelte) {
    if (opts.verbose) console.log(info('  Phase 5b: Svelte symbol annotation…'));
    apply(SVELTE_RUNTIME_MAP, 'Svelte');
  }
  if (hits.nextjs) {
    if (opts.verbose) console.log(info('  Phase 5b: Next.js symbol annotation…'));
    apply(NEXTJS_RUNTIME_MAP,  'Next.js');
    literal(NEXTJS_LITERAL_MAP,'Next.js-Internals');
  }
  if (hits.webpack) {
    if (opts.verbose) console.log(info('  Phase 5b: Webpack runtime comment tags…'));
    literal(WEBPACK_RUNTIME_COMMENTS, 'Webpack-Runtime');
  }
  if (hits.vite) {
    if (opts.verbose) console.log(info('  Phase 5b: Vite runtime comment tags…'));
    literal(VITE_RUNTIME_COMMENTS, 'Vite-Runtime');
  }
  if (hits.lodash) {
    if (opts.verbose) console.log(info('  Phase 5b: Lodash-ES symbol annotation…'));
    apply(LODASH_ES_MAP, 'Lodash-ES');
  }
  if (hits.dateFns) {
    if (opts.verbose) console.log(info('  Phase 5b: date-fns symbol annotation…'));
    apply(DATE_FNS_MAP, 'date-fns');
  }
  if (hits.zod) {
    if (opts.verbose) console.log(info('  Phase 5b: Zod symbol annotation…'));
    apply(ZOD_MAP, 'Zod');
  }
  if (hits.zustand) {
    if (opts.verbose) console.log(info('  Phase 5b: Zustand symbol annotation…'));
    apply(ZUSTAND_MAP, 'Zustand');
  }
  if (hits.immer) {
    if (opts.verbose) console.log(info('  Phase 5b: Immer symbol annotation…'));
    apply(IMMER_MAP, 'Immer');
  }
  if (hits.corejs) {
    if (opts.verbose) console.log(info('  Phase 5b: core-js shim comment tags…'));
    literal(COREJS_SHIMS_COMMENTS, 'core-js');
  }

  return { src, hits, stats };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 6 — RXJS ANNOTATION
// ═══════════════════════════════════════════════════════════════════════════
function annotateRxJS(src) {
  for (const [pattern, comment] of Object.entries(RXJS_OPERATORS)) {
    const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    src = src.replace(new RegExp(`(?<![\\w])${escaped}(?![\\w])`, 'g'), `${comment}${pattern}`);
  }
  return src;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 7 — TOKEN-BASED BEAUTIFIER
//
//  FIXES (OMEGA-5.0 patch):
//   · Multi-char operators (=>, ===, >=, &&, ??, ++, +=, …) are now matched
//     greedily as atomic tokens, fixing the `)=>` → `) = >` corruption that
//     broke AST passes on beautified output.
//   · Template literals (`...${expr}...`) are scanned as a unit, including
//     nested ${} substitutions and nested backticks. Previously the `tmpl`
//     counter was dead code (the first backtick always entered `inStr` mode,
//     so `tmpl` was never incremented), and `${...}` substitutions had their
//     braces treated as code, corrupting depth tracking.
//   · Removed the dead `tmpl` counter entirely.
// ═══════════════════════════════════════════════════════════════════════════
function beautify(src) {
  const out = [];
  let depth = 0, i = 0;
  const n = src.length;
  let inLineComment = false, inBlockComment = false;
  let lastNonWs = '';
  let pendingSpace = false; // true if input had whitespace before current pos

  const pushLine = () => { if (out.length && out[out.length-1] !== '\n') out.push('\n'); };
  const indent   = () => INDENT.repeat(Math.max(0, depth));

  // Multi-char operators, longest first so greedy matching works.
  const MULTI_OPS = [
    '>>>=', '...',  // 4 / 3 char
    '===', '!==', '>>>', '**=', '<<=', '>>=',
    '=>', '==', '!=', '>=', '<=', '>>', '<<', '&&', '||', '??', '?.', '**', '++', '--',
    '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=',
  ];
  // Operators that should have a space on both sides (binary/comparison).
  const SPACE_AROUND = new Set([
    '=>','==','===','!==','!=','>=','<=','&&','||','??',
    '>>','<<','>>>','+','-','*','/','%', '&','|','^',
  ]);
  // Operators that bind to the following operand (no space after).
  const NO_SPACE_AFTER = new Set(['!', '~', '...', '?.']);
  // Chars that, when preceding an operator, mean "don't add a leading space"
  // (e.g. `(`, `[`, `{`, `,`, `;`, another operator).
  const NO_SPACE_BEFORE_CTX = '([{,;:!&|+-*%<>^~?=';

  // Helper: scan a quoted string (already on opening quote), push verbatim.
  function scanString(quote) {
    out.push(quote); i++;
    while (i < n) {
      const c = src[i];
      const c2 = src[i+1] || '';
      if (c === '\\') { out.push(c, c2); i += 2; continue; }
      out.push(c);
      if (c === quote) { i++; break; }
      i++;
    }
    lastNonWs = quote;
  }

  // Helper: scan a template literal (already on opening backtick), push verbatim.
  // Handles nested ${...} substitutions and nested backticks recursively.
  function scanTemplate() {
    out.push('`'); i++;
    while (i < n) {
      const c = src[i];
      const c2 = src[i+1] || '';
      if (c === '\\') { out.push(c, c2); i += 2; continue; }
      if (c === '`') { out.push(c); i++; break; }
      if (c === '$' && c2 === '{') {
        // Substitution: copy verbatim until matching `}` at depth 0.
        // We must respect nested {}, strings, and nested template literals
        // so the depth counter stays accurate.
        out.push('$', '{'); i += 2;
        let d = 1;
        while (i < n && d > 0) {
          const sc = src[i];
          const sc2 = src[i+1] || '';
          // Skip line/block comments inside substitution
          if (sc === '/' && sc2 === '/') {
            out.push(sc, sc2); i += 2;
            while (i < n && src[i] !== '\n') { out.push(src[i]); i++; }
            continue;
          }
          if (sc === '/' && sc2 === '*') {
            out.push(sc, sc2); i += 2;
            while (i < n && !(src[i] === '*' && src[i+1] === '/')) { out.push(src[i]); i++; }
            if (i < n) { out.push('*', '/'); i += 2; }
            continue;
          }
          // Skip quoted strings inside substitution
          if (sc === '"' || sc === "'") {
            const sq = sc;
            out.push(sc); i++;
            while (i < n) {
              const ic = src[i];
              const ic2 = src[i+1] || '';
              if (ic === '\\') { out.push(ic, ic2); i += 2; continue; }
              out.push(ic);
              if (ic === sq) { i++; break; }
              i++;
            }
            continue;
          }
          // Nested template literal — recurse by calling scanTemplate logic inline
          if (sc === '`') {
            out.push(sc); i++;
            let nd = 1;
            while (i < n && nd > 0) {
              const nc  = src[i];
              const nc2 = src[i+1] || '';
              if (nc === '\\') { out.push(nc, nc2); i += 2; continue; }
              if (nc === '$' && nc2 === '{') {
                // Recursively handle nested substitution — for simplicity we
                // copy verbatim until the matching `}` (depth-aware). This
                // won't beautify the inner expression, but it preserves the
                // source exactly, which is the correct contract.
                out.push('$', '{'); i += 2;
                let sd = 1;
                while (i < n && sd > 0) {
                  const ssc = src[i];
                  if (ssc === '{') sd++;
                  else if (ssc === '}') sd--;
                  if (sd === 0) { out.push(ssc); i++; break; }
                  out.push(ssc); i++;
                }
                continue;
              }
              if (nc === '`') { nd--; out.push(nc); i++; if (nd === 0) break; continue; }
              out.push(nc); i++;
            }
            continue;
          }
          // Brace depth tracking
          if (sc === '{') { d++; out.push(sc); i++; continue; }
          if (sc === '}') {
            d--;
            out.push(sc); i++;
            if (d === 0) break;
            continue;
          }
          out.push(sc); i++;
        }
        continue;
      }
      out.push(c); i++;
    }
    lastNonWs = '`';
  }

  while (i < n) {
    const ch = src[i];
    const ch2 = src[i+1] || '';

    // ── Comments ──
    if (!inLineComment && !inBlockComment && ch === '/' && ch2 === '/') inLineComment = true;
    if (inLineComment) {
      out.push(ch);
      if (ch === '\n') { inLineComment = false; out.push(indent()); }
      i++; continue;
    }
    if (!inBlockComment && ch === '/' && ch2 === '*') inBlockComment = true;
    if (inBlockComment) {
      out.push(ch);
      if (ch === '*' && ch2 === '/') { inBlockComment = false; out.push('/'); i += 2; continue; }
      i++; continue;
    }

    // ── Quoted strings ──
    if (ch === '"' || ch === "'") { scanString(ch); continue; }

    // ── Template literals (with nested ${...}) ──
    if (ch === '`') { scanTemplate(); continue; }

    // ── Whitespace: don't skip silently — record that input had a break ──
    // This lets us distinguish `return Q` (input has space) from `returnQ`
    // (single identifier, no space) when deciding whether to insert a space.
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      pendingSpace = true;
      i++; continue;
    }

    // ── Braces / semicolons / commas ──
    if (ch === '{') {
      // Strip trailing space left by a preceding binary operator like `=>`
      if (out.length && out[out.length - 1] === ' ') out.pop();
      out.push(' {\n'); depth++; out.push(indent()); lastNonWs = '{';
      pendingSpace = false;
      i++; continue;
    }
    if (ch === '}') {
      depth = Math.max(0, depth - 1);
      // Strip trailing whitespace+newline+indent left by the previous `;`
      // so we get `;\n}` instead of `;\n  \n}`.
      while (out.length && (out[out.length - 1] === ' ' || out[out.length - 1] === INDENT || out[out.length - 1] === '\n')) {
        out.pop();
      }
      out.push('\n'); out.push(indent());
      out.push('}'); lastNonWs = '}';
      pendingSpace = false;
      i++; continue;
    }
    if (ch === ';') {
      out.push(';'); out.push('\n'); out.push(indent()); lastNonWs = ';';
      pendingSpace = false;
      i++; continue;
    }
    if (ch === ',') {
      out.push(', '); lastNonWs = ',';
      pendingSpace = false;
      i++; continue;
    }

    // ── Identifier / keyword chars ──
    // Insert a space ONLY when the input had whitespace between two
    // identifier chars (preserves `return Q` without splitting `returnQ`).
    if (/[A-Za-z0-9_$]/.test(ch)) {
      if (pendingSpace && lastNonWs && /[A-Za-z0-9_$]/.test(lastNonWs)) {
        out.push(' ');
      }
      out.push(ch);
      lastNonWs = ch;
      pendingSpace = false;
      i++; continue;
    }

    // ── `(` — needs leading space after control keywords (if/for/while/…) ──
    if (ch === '(') {
      // Find the last identifier accumulated in output
      let lastIdent = '';
      for (let j = out.length - 1; j >= 0; j--) {
        const oc = out[j];
        if (oc && /[A-Za-z0-9_$]/.test(oc)) lastIdent = oc + lastIdent;
        else break;
      }
      const CONTROL_KW = new Set([
        'if','for','while','switch','catch','return','typeof','instanceof',
        'in','void','delete','new','await','yield','of','function',
      ]);
      if (lastIdent && CONTROL_KW.has(lastIdent)) out.push(' ');
      out.push('(');
      lastNonWs = '(';
      pendingSpace = false;
      i++; continue;
    }

    // ── Multi-char operator matching (greedy, longest first) ──
    let matchedOp = null;
    for (const op of MULTI_OPS) {
      if (src.startsWith(op, i)) { matchedOp = op; break; }
    }
    if (matchedOp) {
      const op = matchedOp;
      const noSpaceBefore = NO_SPACE_BEFORE_CTX.includes(lastNonWs) || lastNonWs === '';
      if (!noSpaceBefore && SPACE_AROUND.has(op)) out.push(' ');
      out.push(op);
      const nextCh = src[i + op.length];
      if (SPACE_AROUND.has(op) && !NO_SPACE_AFTER.has(op) && nextCh !== '{') out.push(' ');
      lastNonWs = op[op.length - 1];
      pendingSpace = false;
      i += op.length;
      continue;
    }

    // ── Single-char operators ──
    if ('=!&|*%<>^~'.includes(ch)) {
      const noSpaceBefore = NO_SPACE_BEFORE_CTX.includes(lastNonWs) || lastNonWs === '';
      if (!noSpaceBefore) out.push(' ');
      out.push(ch);
      if (ch !== '!' && ch !== '~') {
        const nextCh = src[i + 1];
        if (nextCh !== '{') out.push(' ');
      }
      lastNonWs = ch;
      pendingSpace = false;
      i++; continue;
    }
    if ('+-'.includes(ch)) {
      const isUnaryPrefix = NO_SPACE_BEFORE_CTX.includes(lastNonWs) || lastNonWs === '';
      if (!isUnaryPrefix) out.push(' ');
      out.push(ch);
      if (!isUnaryPrefix) {
        const nextCh = src[i + 1];
        if (nextCh !== '{') out.push(' ');
      }
      lastNonWs = ch;
      pendingSpace = false;
      i++; continue;
    }
    if (ch === '?') {
      out.push(' ? ');
      lastNonWs = '?';
      pendingSpace = false;
      i++; continue;
    }

    // ── Default: dot, brackets, etc. ──
    out.push(ch);
    lastNonWs = ch;
    pendingSpace = false;
    i++;
  }
  return out.join('').replace(/\n{3,}/g, '\n\n').trim();
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 8 — CODE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════
function analyseCode(src) {
  const fnRe = /(?:function\s*\*?\s*\w*\s*\(|=>\s*\{|\b(?:async\s+)?function\s*\()/g;
  const functions  = (src.match(fnRe) || []).length;
  const classes    = (src.match(/\bclass\s+\w+/g) || []).length;
  const components = (src.match(/ɵɵdefineComponent/g) || []).length;
  const services   = (src.match(/ɵɵdefineInjectable/g) || []).length;
  const pipes      = (src.match(/ɵɵdefinePipe/g) || []).length;
  const directives = (src.match(/ɵɵdefineDirective/g) || []).length;
  const httpCalls  = (src.match(/this\.\w+\.(?:get|post|put|delete|patch)\s*\(/g) || []).length;
  const evalCalls  = (src.match(/\beval\s*\(/g) || []).length;
  const decisions  = (src.match(/\bif\b|\belse\b|\bfor\b|\bwhile\b|\bcase\b|\bcatch\b|\?\s*[^:]/g) || []).length;
  const cyclomatic = decisions + 1;

  let maxDepth = 0, currDepth = 0;
  let inStr2 = false, strCh2 = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (!inStr2 && (c === '"' || c === "'" || c === '`')) { inStr2 = true; strCh2 = c; continue; }
    if (inStr2) { if (src[i-1] !== '\\' && c === strCh2) inStr2 = false; continue; }
    if (c === '{') { currDepth++; maxDepth = Math.max(maxDepth, currDepth); }
    if (c === '}') currDepth = Math.max(0, currDepth - 1);
  }

  const guardMatches = [...src.matchAll(/canActivate\s*:\s*\[([^\]]+)\]/g)];
  const routeGuards  = guardMatches.map(m => m[1].trim());
  const socketEmits  = [...(src.matchAll(/\.emit\s*\(\s*["']([^"']+)["']/g))].map(m => m[1]);
  const socketOns    = [...(src.matchAll(/\.on\s*\(\s*["']([^"']+)["']/g))].map(m => m[1]);

  // React component count (heuristic)
  // FIX (Stage 4 audit): previous regex only matched `function Foo() { return <div/>; }`.
  // Now matches four common forms:
  //   1. function Foo() { return <...|jsx(...)|createElement(...) }
  //   2. const Foo = () => { return <...|jsx(...)|createElement(...) }
  //   3. const Foo = (props) => jsx(...) | createElement(...)   (expr body)
  //   4. const Foo = function() { return <...|jsx(...)|createElement(...) }
  // Each alternative requires a Capitalised identifier (React convention).
  let reactComponents = 0;
  {
    const m1 = src.match(/function\s+[A-Z][A-Za-z0-9]+\s*\([^)]*\)\s*\{[^}]{0,300}return\s*(?:<|jsx\s*\(|React\.createElement)/g);
    if (m1) reactComponents += m1.length;
  }
  {
    const m2 = src.match(/const\s+[A-Z][A-Za-z0-9]+\s*=\s*(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*\{[^}]{0,300}return\s*(?:<|jsx\s*\(|React\.createElement)/g);
    if (m2) reactComponents += m2.length;
  }
  {
    // Arrow with expression body (no block): const Foo = (p) => jsx(...) / createElement(...)
    const m3 = src.match(/const\s+[A-Z][A-Za-z0-9]+\s*=\s*(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*(?:jsx\s*\(|React\.createElement\s*\(|createElement\s*\()/g);
    if (m3) reactComponents += m3.length;
  }
  {
    // Function expression: const Foo = function() { return <...|jsx|createElement }
    const m4 = src.match(/const\s+[A-Z][A-Za-z0-9]+\s*=\s*function\s*\([^)]*\)\s*\{[^}]{0,300}return\s*(?:<|jsx\s*\(|React\.createElement)/g);
    if (m4) reactComponents += m4.length;
  }

  // Vue component count
  const vueComponents = (src.match(/createElementVNode|defineComponent|__vccOpts/g) || []).length;

  // Svelte component count
  const svelteComponents = (src.match(/SvelteComponent|create_fragment/g) || []).length;

  return {
    functions, classes, components, services, pipes, directives,
    reactComponents, vueComponents, svelteComponents,
    httpCalls, evalCalls, cyclomatic, maxNesting: maxDepth,
    routeGuards: [...new Set(routeGuards)],
    socketEmits: [...new Set(socketEmits)],
    socketOns:   [...new Set(socketOns)],
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 8b — STORAGE KEY AUDIT  (NEW in OMEGA-3.0)
//
//  Enumerates every localStorage, sessionStorage, and cookieService key
//  with the full set of operations performed on it (get/set/remove).
//  Output is an attack-surface map: sensitive data keys visible to XSS.
// ═══════════════════════════════════════════════════════════════════════════
function auditStorageKeys(src) {
  const lsMap  = {};   // key → {store, ops Set}
  const ckMap  = {};   // key → {ops Set}

  let m;

  // localStorage / sessionStorage: .getItem|setItem|removeItem|clear("key")
  const storeRe = /(localStorage|sessionStorage)\.(getItem|setItem|removeItem|clear)\s*\(\s*["']([^"']+)["']/g;
  while ((m = storeRe.exec(src)) !== null) {
    const store = m[1] === 'localStorage' ? 'local' : 'session';
    const op    = m[2];
    const key   = m[3];
    if (!lsMap[key]) lsMap[key] = { store, ops: new Set() };
    lsMap[key].ops.add(op.replace('Item','').replace('clear','clear'));
  }

  // cookieService.get|put|remove("key")
  const ckRe = /cookieService\.(get|put|remove)\s*\(\s*["']([^"']+)["']/g;
  while ((m = ckRe.exec(src)) !== null) {
    const key = m[2];
    if (!ckMap[key]) ckMap[key] = { ops: new Set() };
    ckMap[key].ops.add(m[1]);
  }

  const localStorage = Object.entries(lsMap)
    .filter(([,v]) => v.store === 'local')
    .map(([key, v]) => ({ key, ops: [...v.ops].sort() }))
    .sort((a, b) => a.key.localeCompare(b.key));

  const sessionStorage = Object.entries(lsMap)
    .filter(([,v]) => v.store === 'session')
    .map(([key, v]) => ({ key, ops: [...v.ops].sort() }))
    .sort((a, b) => a.key.localeCompare(b.key));

  const cookies = Object.entries(ckMap)
    .map(([key, v]) => ({ key, ops: [...v.ops].sort() }))
    .sort((a, b) => a.key.localeCompare(b.key));

  // Flag sensitive keys
  const sensitiveRe = /token|password|secret|auth|credential|session|jwt|totp|key|email/i;
  const flagSensitive = arr => arr.map(e => ({
    ...e,
    sensitive: sensitiveRe.test(e.key),
  }));

  return {
    localStorage:    flagSensitive(localStorage),
    sessionStorage:  flagSensitive(sessionStorage),
    cookies:         flagSensitive(cookies),
    totalKeys: localStorage.length + sessionStorage.length + cookies.length,
    sensitiveCount: [...localStorage, ...sessionStorage, ...cookies]
                      .filter(e => sensitiveRe.test(e.key)).length,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 8c — AUTH SURFACE MAPPER  (NEW in OMEGA-3.0)
//
//  Extracts every Angular route with its canActivate guard(s) and flags
//  high-value routes that have NO guard whatsoever — the primary
//  auth-bypass attack surface in Angular SPAs.
// ═══════════════════════════════════════════════════════════════════════════
function mapAuthSurface(src) {
  const guardedRoutes   = [];
  const unguardedRoutes = [];

  // High-value path keywords — routes worth testing for auth bypass
  const highValueRe = /admin|account|wallet|score|payment|order|data.?export|2fa|two.?factor|deluxe|membership|recycl|address|profile|change.?pass|reset.?pass/i;

  let m;

  // Scan for path:"X" ... canActivate:[Y] within a ~400-char window
  const guardRe = /path\s*:\s*["']([^"']{0,120})["']([^{};]{0,400}?)canActivate\s*:\s*\[([^\]]+)\]/g;
  while ((m = guardRe.exec(src)) !== null) {
    guardedRoutes.push({
      path:   '/' + m[1],
      guards: m[3].trim().split(',').map(s => s.trim()),
    });
  }

  // Find ALL angular routes (path + component/loadChildren)
  const allRoutesRe = /path\s*:\s*["']([^"']{1,120})["'][^{};]{0,400}?(?:component|loadChildren)\s*:/g;
  const allPaths = new Set();
  while ((m = allRoutesRe.exec(src)) !== null) allPaths.add(m[1]);

  const guardedPaths = new Set(guardedRoutes.map(r => r.path.replace(/^\//, '')));

  for (const p of allPaths) {
    if (!guardedPaths.has(p) && highValueRe.test(p)) {
      unguardedRoutes.push({
        path: '/' + p,
        risk: 'HIGH — sensitive route with no canActivate guard detected',
      });
    }
  }

  // Capture btoa(x.email.split.reverse) crypto misuse sites with context.
  // FIX: original used `/btoa\s*\(([^)]{0,120}...[^)]{0,120})\)/g` which broke
  // on nested parens like `btoa(x.split("").reverse().join(""))` — `[^)]*`
  // stops at the first `)` (inside `split("")`), not the matching `)` of btoa.
  // Replace with a manual scanner that respects paren depth + strings.
  const btoaMisuse = [];
  const btoaSeen = new Set();
  {
    const btoaStartRe = /\bbtoa\s*\(/g;
    let btm;
    while ((btm = btoaStartRe.exec(src)) !== null) {
      const openParen = btm.index + btm[0].length - 1; // position of `(`
      // Walk to matching `)` at depth 0, respecting strings/templates/comments
      let pos = openParen + 1, depth = 1;
      let inStr = false, strCh = '', inTmpl = false, inLineCmt = false, inBlkCmt = false;
      const innerStart = pos;
      while (pos < src.length && depth > 0) {
        const c = src[pos];
        const c2 = src[pos+1] || '';
        if (inLineCmt) { if (c === '\n') inLineCmt = false; pos++; continue; }
        if (inBlkCmt)  { if (c === '*' && c2 === '/') { inBlkCmt = false; pos += 2; continue; } pos++; continue; }
        if (inStr) {
          if (c === '\\') { pos += 2; continue; }
          if (c === strCh) inStr = false;
          pos++; continue;
        }
        if (inTmpl) {
          if (c === '\\') { pos += 2; continue; }
          if (c === '`') inTmpl = false;
          pos++; continue;
        }
        if (c === '/' && c2 === '/') { inLineCmt = true; pos += 2; continue; }
        if (c === '/' && c2 === '*') { inBlkCmt = true; pos += 2; continue; }
        if (c === '"' || c === "'") { inStr = true; strCh = c; pos++; continue; }
        if (c === '`') { inTmpl = true; pos++; continue; }
        if (c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}') {
          depth--;
          if (depth === 0 && c === ')') break;
        }
        pos++;
      }
      const innerEnd = pos; // position of matching `)`
      const inner = src.slice(innerStart, innerEnd);
      // Only flag if inner contains split/reverse (the btoa-misuse signature)
      if (!/split|reverse/.test(inner)) continue;
      const expr = inner.trim().slice(0, 100);
      if (!btoaSeen.has(expr)) {
        btoaSeen.add(expr);
        btoaMisuse.push({
          expr,
          context: src.slice(Math.max(0, btm.index - 40), Math.min(src.length, innerEnd + 60)).replace(/\n/g, ' ').trim(),
          severity: 'critical',
          note: 'btoa(x.split("").reverse().join("")) — trivially reversible, not encryption',
        });
      }
    }
  }

  // ── A2: Route-endpoint correlation ──────────────────────────────────────
  // Extract API endpoints referenced by each route's component, correlate
  // with HTTP auth headers to flag endpoints reachable without auth.
  const endpointMap = [];
  const httpRe = /this\.\w+\.(?:get|post|put|delete|patch)\s*<[^>]*>\s*\(\s*["'`]([^"'`]+)["'`]/g;
  while ((m = httpRe.exec(src)) !== null) {
    const ep = m[1];
    const surrounding = src.slice(Math.max(0, m.index - 300), m.index + 50);
    const hasAuthHeader = /Authorization|Bearer|x-auth-token|token|jwt/i.test(surrounding);
    const hasGuardContext = /canActivate|AuthGuard|auth\.isLoggedIn/i.test(surrounding);
    endpointMap.push({
      endpoint: ep,
      hasAuthHeader,
      hasGuardContext,
      risk: (!hasAuthHeader && !hasGuardContext) ? 'potential-unprotected' : 'appears-protected',
    });
  }
  const unprotectedEndpoints = endpointMap.filter(e => e.risk === 'potential-unprotected');

  return { guardedRoutes, unguardedRoutes, btoaMisuse, endpointMap, unprotectedEndpoints };
}


// A1: Hierarchical framework detection with confidence scoring
function detectFrameworks(src) {
  const found = [];
  const sample = src.slice(0, 10000);

  for (const fw of FRAMEWORKS) {
    if (fw.guard && !fw.guard(sample)) continue;
    if (!fw.re.test(src)) continue;

    let confidence = 0.6; // base confidence for regex match

    // Boost confidence if uniqueMarkers are present
    if (fw.uniqueMarkers) {
      const matchedUnique = fw.uniqueMarkers.filter(m => m.test(src)).length;
      if (matchedUnique === 0) continue; // require at least one unique marker
      confidence = Math.min(0.5 + matchedUnique * 0.15, 1.0);
    }

    const entry = { name: fw.name, confidence: parseFloat(confidence.toFixed(2)) };
    if (fw.score) entry.score = fw.score(src);
    found.push(entry);
  }

  // A1: Angular takes precedence over Vue when both detected
  const hasAngular = found.some(f => f.name === 'Angular');
  const filtered = hasAngular
    ? found.filter(f => f.name !== 'Vue')
    : found;

  // Return framework names (preserves backward compat) + expose confidence via frameworkDetails
  const names = filtered.map(f => f.name);
  names._details = filtered; // attach details for report without breaking callers
  return names;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 10 — ROUTE EXTRACTION  (OMEGA-3.0: child routes + hidden routes)
// ═══════════════════════════════════════════════════════════════════════════
function extractRoutes(src, charCodeFindings, rawSrc) {
  // rawSrc = pre-beautify source for patterns cleaner before formatting (Ivy consts)
  // Map: canonical path → route object (first-write wins for type, merge flags)
  const routes = new Map();

  const addRoute = (rawPath, type, meta) => {
    if (!rawPath) return;
    let p = rawPath.replace(/\s+/g, '').replace(/\\n/g, '');
    if (!p || p.length < 1) return;
    if (!routes.has(p)) {
      routes.set(p, { path: p, type, ...(meta || {}) });
    } else {
      const existing = routes.get(p);
      if (meta && meta.guarded) existing.guarded = true;
      // Append additional source types for cross-reference (e.g. Angular-RouterLink)
      if (type !== existing.type && type === 'Angular-RouterLink') {
        existing.altTypes = existing.altTypes || [];
        if (!existing.altTypes.includes(type)) existing.altTypes.push(type);
      }
    }
  };

  let m;

  // ── REST / API literal paths ─────────────────────────────────────────
  const restRe = /["'](\/(?:api|rest|graphql|v\d+)\/[^"'\s<>{}|\\^`[\]]{1,120})["']/g;
  while ((m = restRe.exec(src)) !== null) addRoute(m[1], 'REST');

  // ── fetch / axios / http verb calls ─────────────────────────────────
  const fetchRe = /(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:get|post|put|delete))\s*\(\s*["']([^"']+)["']/g;
  while ((m = fetchRe.exec(src)) !== null) addRoute(m[1], 'HTTP');

  // ── Angular router: {path:"x", component|loadChildren} ──────────────
  // Use a wider window that crosses the closing brace (handles multi-prop objects)
  const ngRoutRe = /path\s*:\s*["']([^"']{0,120})["'][^{};]{0,400}?(?:component|loadChildren)\s*:/g;
  while ((m = ngRoutRe.exec(src)) !== null) {
    const raw = m[1];
    if (raw === '') continue; // catch-all handled separately
    // Check if canActivate appears within 300 chars forward of this match
    const ahead = src.slice(m.index, m.index + 300);
    const guarded = ahead.includes('canActivate');
    addRoute('/' + raw, 'Angular', guarded ? { guarded: true } : {});
  }
  // Catch-all wildcard route
  if (/path\s*:\s*["']\*\*["']/.test(src)) addRoute('/**', 'Angular');

  // ── Angular parent+children route blocks ────────────────────────────
  // e.g. {path:"privacy-security", component:X, children:[{path:"privacy-policy",...}]}
  // Capture the parent path and all child paths within the children:[] array
  const parentChildRe = /path\s*:\s*["']([^"']{1,80})["'][^;]{0,100}children\s*:\s*\[([^\]]{0,2000})\]/g;
  while ((m = parentChildRe.exec(src)) !== null) {
    const parentPath = m[1];
    const childBlock = m[2];
    // Add the parent itself
    addRoute('/' + parentPath, 'Angular-Parent');
    // Extract children
    const childPathRe = /path\s*:\s*["']([^"']{1,80})["']/g;
    let cm;
    while ((cm = childPathRe.exec(childBlock)) !== null) {
      if (cm[1].length > 0) addRoute('/' + parentPath + '/' + cm[1], 'Angular-Child');
    }
  }

  // ── Child route navigation arrays: ()=>["parent/child"] ─────────────
  // Raw minified form:  =()=>["privacy-security/data-export"]
  // Beautified form:    =() = >["privacy-security/data-export"]
  const childArrRe = /(?:=\s*)?\(\s*\)\s*(?:=\s*>|=>)\s*\[\s*["']([a-zA-Z0-9_\-/]{3,80})["']\s*\]/g;
  while ((m = childArrRe.exec(src)) !== null) {
    if (m[1].includes('/')) addRoute('/' + m[1], 'Angular-Child');
  }

  // ── Angular Ivy consts: "routerLink","/path" (raw compact form) ─────
  // After beautify, comma gets a space — so scan rawSrc if available
  const ivySrc = rawSrc || src;
  const ivyRouteLinkRe = /["']routerLink["']\s*,\s*["']([^"']{1,120})["']/g;
  while ((m = ivyRouteLinkRe.exec(ivySrc)) !== null) {
    const p = m[1];
    if (/^\/[a-zA-Z]/.test(p)) {
      addRoute(p, 'Angular-RouterLink');
    } else if (/^[a-zA-Z][a-zA-Z0-9\-_]+\//.test(p)) {
      addRoute('/' + p, 'Angular-RouterLink');
    }
  }

  // ── Angular router.navigate(["path"]) calls ─────────────────────────
  const navRe = /router\.navigate\s*\(\s*\[\s*["']([a-zA-Z0-9_\-/]{2,80})["']/g;
  while ((m = navRe.exec(src)) !== null) {
    const p = m[1].replace(/^\/+/, ''); // strip leading slashes
    if (p.length > 1) addRoute('/' + p, 'Angular-Nav');
  }

  // ── WebSocket ────────────────────────────────────────────────────────
  const wsRe = /wss?:\/\/[^\s"'<>]{4,80}/g;
  while ((m = wsRe.exec(src)) !== null) addRoute(m[0], 'WebSocket');

  // ── GraphQL operations ───────────────────────────────────────────────
  const gqlRe = /(?:query|mutation|subscription)\s+\w+/g;
  while ((m = gqlRe.exec(src)) !== null) addRoute(m[0], 'GraphQL');

  // ── Next.js page/app routes ──────────────────────────────────────────
  const nextRouteRe = /["'](\/(?:app|pages)\/[^"'\s]{1,80})["']/g;
  while ((m = nextRouteRe.exec(src)) !== null) addRoute(m[1], 'Next.js');

  // ── CharCode-decoded hidden routes (Phase 2b) ────────────────────────
  if (charCodeFindings && charCodeFindings.length) {
    for (const f of charCodeFindings) {
      const decoded = f.decoded || '';
      // Route: printable lowercase alnum/dash/slash, at least 3 chars
      if (/^[a-z0-9][a-z0-9\-_/]{2,}$/.test(decoded)) {
        const label = f.isAssembled ? 'Hidden-Assembled' : 'Hidden-Decoded';
        const noteSegments = f.isAssembled
          ? `segments: [${(f.segments||[]).map(s=>`"${s}"`).join(',')}] + literals: [${(f.literals||[]).map(l=>`"${l}"`).join(',')}]`
          : `seed=${f.seed}, expr=${f.offsetExpr}`;
        addRoute('/' + decoded, label, { note: `CharCode-recovered: ${noteSegments}` });
      }
    }
  }

  return [...routes.values()].sort((a, b) => a.path.localeCompare(b.path));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 11 — CREDENTIAL SCANNER
// ═══════════════════════════════════════════════════════════════════════════
function scanCredentials(src) {
  const findings = [];
  const seen = new Set();
  const abortedPatterns = [];

  const lines = src.split('\n');
  const lineStarts = [];
  let pos = 0;
  for (const l of lines) { lineStarts.push(pos); pos += l.length + 1; }

  const getLine = offset => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };

  for (const pat of CREDENTIAL_PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    // ReDoS-safe iteration: caps matches per pattern + total time budget
    safeRegexIter(re, src,
      (m) => {
        const value = (m[1] || m[0]).trim();
        if (!value || value.length < 3) return;
        if (pat.fpGuard && pat.fpGuard(value)) return;
        const key = `${pat.name}::${value}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({
          name: pat.name, severity: pat.severity,
          value: value.slice(0,120),
          line: getLine(m.index),
          context: src.slice(Math.max(0, m.index-40), m.index+80).replace(/\n/g,' '),
        });
      },
      (reason) => {
        abortedPatterns.push({ pattern: pat.name, reason });
      }
    );
  }
  // Surface aborts as info-level findings so users know data may be incomplete
  for (const a of abortedPatterns) {
    findings.push({
      name: 'Scanner Abort (ReDoS guard)', severity: 'info',
      value: `${a.pattern}: ${a.reason}`,
      line: 0,
      context: 'Pattern iteration aborted — input may be hostile or pattern too loose',
    });
  }
  return findings.sort((a,b) => {
    const order = {critical:0, high:1, medium:2, low:3, info:4};
    return (order[a.severity]||4) - (order[b.severity]||4);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12 — SECURITY ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════
function analyseSecurity(src, maxHops) {
  const findings = [];
  const seen = new Set();
  const abortedPatterns = [];

  for (const pat of SECURITY_PATTERNS) {
    const re = new RegExp(pat.re.source, 'g');
    safeRegexIter(re, src,
      (m) => {
        const snippet = src.slice(Math.max(0, m.index-100), m.index+120);
        if (pat.ctx && !pat.ctx(snippet, src)) return;
        const value = (m[1] || m[0]).slice(0,100);
        const key = `${pat.id}::${value}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({
          id: pat.id, category: pat.cat, severity: pat.sev,
          value,
          context: snippet.replace(/\n/g,' ').trim(),
        });
      },
      (reason) => { abortedPatterns.push({ pattern: pat.id, reason }); }
    );
  }
  for (const a of abortedPatterns) {
    findings.push({
      id: 'scanner-abort', category: 'Scanner Abort', severity: 'info',
      value: `${a.pattern}: ${a.reason}`,
      context: 'Pattern iteration aborted — input may be hostile',
    });
  }
  return findings.sort((a,b) => {
    const order = {critical:0, high:1, medium:2, low:3, info:4};
    return (order[a.severity]||4) - (order[b.severity]||4);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12b — B1: DYNAMIC CODE EXECUTION DETECTOR
// ═══════════════════════════════════════════════════════════════════════════
function scanDynamicCodeExecution(src) {
  const findings = [];
  const seen = new Set();
  const ctx = (i, r=150) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  const patterns = [
    // setTimeout/setInterval with string literal arg (not function reference)
    { re:/(?:setTimeout|setInterval)\s*\(\s*["'`][^"'`]{0,200}["'`]\s*,/g,
      type:'setTimeout/Interval-string', sev:'critical',
      desc:'String argument evaluated as code — use function reference instead' },
    // new Function(...)
    { re:/new\s+Function\s*\(/g, type:'Function-constructor', sev:'critical',
      desc:'Function constructor evaluates string as code' },
    // indirect eval: (0,eval)(x)
    { re:/\(\s*0\s*,\s*eval\s*\)\s*\(/g, type:'indirect-eval', sev:'critical',
      desc:'Indirect eval bypasses strict-mode eval restrictions' },
    // execScript (IE legacy)
    { re:/execScript\s*\(/g, type:'execScript', sev:'high',
      desc:'Legacy IE code execution in global scope' },
    // WebAssembly.instantiate / WebAssembly.compile
    { re:/WebAssembly\.(?:instantiate|compile|instantiateStreaming)\s*\(/g,
      type:'WebAssembly', sev:'medium',
      desc:'WebAssembly binary can execute arbitrary native code' },
    // importScripts in workers
    { re:/importScripts\s*\(\s*([^)]+)\)/g, type:'importScripts', sev:'high',
      desc:'importScripts loads external code into Worker context' },
  ];

  for (const pat of patterns) {
    const re = new RegExp(pat.re.source, 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      // Filter safe setTimeout patterns (arrow/function reference)
      if (pat.type === 'setTimeout/Interval-string') {
        const arg = m[1] || '';
        if (/^\s*(?:function|\(|[A-Za-z_$][A-Za-z0-9_$.]*\s*=>)/.test(arg)) continue;
      }
      const key = `${pat.type}::${m.index}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `dyncode-${pat.type}`, category: 'Dynamic Code Execution',
        severity: pat.sev, value: m[0].slice(0,100),
        context: ctx(m.index), description: pat.desc,
      });
    }
  }
  return findings.sort((a,b) => ({critical:0,high:1,medium:2,low:3}[a.severity]||3) - ({critical:0,high:1,medium:2,low:3}[b.severity]||3));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12c — C1: BUSINESS LOGIC DETECTOR
// ═══════════════════════════════════════════════════════════════════════════
function scanBusinessLogic(src) {
  const findings = [];
  const ctx = (i, r=200) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  // Rate limiting on client
  const rateLimitRe = /localStorage\.(?:getItem|setItem)\s*\(\s*["'](?:last|prev|time|rate|limit)[^"']*["']/gi;
  let m;
  while ((m = rateLimitRe.exec(src)) !== null) {
    findings.push({ id:'bl-ratelimit', category:'Business Logic', severity:'medium',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Client-side rate limiting via localStorage — bypass by clearing storage' });
  }

  // Balance / wallet checks on client
  const balanceRe = /(?:balance|wallet|credit|amount)\s*(?:<|>|<=|>=|===|!==)\s*(?:total|price|amount|cost|\d)/gi;
  while ((m = balanceRe.exec(src)) !== null) {
    findings.push({ id:'bl-balance', category:'Business Logic', severity:'high',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Client-side balance check — bypass by modifying JS variables in memory' });
  }

  // Coupon / promo validation on client
  const couponRe = /(?:coupon|promo|discount|voucher)\s*(?:===|==|includes?|match)/gi;
  while ((m = couponRe.exec(src)) !== null) {
    findings.push({ id:'bl-coupon', category:'Business Logic', severity:'high',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Client-side coupon validation — valid codes visible in bundle' });
  }

  // Hardcoded coupon codes
  const hcCouponRe = /["'][A-Z0-9]{4,}['"]\s*(?:===|==)\s*(?:coupon|promo|code)/gi;
  while ((m = hcCouponRe.exec(src)) !== null) {
    findings.push({ id:'bl-hardcoded-coupon', category:'Business Logic', severity:'critical',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Hardcoded coupon code comparison in client bundle' });
  }

  // Role / access control on client
  const roleRe = /(?:role|admin|premium|deluxe|vip)\s*(?:===|==|!==|!=)\s*["']\w+["']/gi;
  while ((m = roleRe.exec(src)) !== null) {
    findings.push({ id:'bl-access-control', category:'Business Logic', severity:'medium',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Client-side role check — bypass by modifying role variable' });
  }

  // Feature flags driving sensitive UI
  const featureRe = /(?:featureFlag|config|settings)\.\w+\s*(?:\?|&&)/gi;
  while ((m = featureRe.exec(src)) !== null) {
    const c = ctx(m.index);
    if (/admin|premium|beta|internal|hidden/i.test(c)) {
      findings.push({ id:'bl-feature-flag', category:'Business Logic', severity:'low',
        value: m[0].slice(0,100), context: c,
        description:'Feature flag gating sensitive functionality on client' });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12d — C2/C3: WEBSOCKET & SOCKET.IO CONTENT ANALYZER
// ═══════════════════════════════════════════════════════════════════════════
function scanWebSocketContent(src) {
  const findings = [];
  const ctx = (i, r=250) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  // socket.on handlers — look for unvalidated data flowing to DOM
  const socketOnRe = /\.on\s*\(\s*["']([^"']+)["']\s*,\s*(?:function\s*\([^)]*\)|[^)=>\s]+\s*=>)\s*\{([^}]{0,400})\}/gs;
  let m;
  while ((m = socketOnRe.exec(src)) !== null) {
    const event = m[1];
    const body = m[2];
    if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.html\(/.test(body)) {
      findings.push({ id:'ws-dom-sink', category:'WebSocket XSS', severity:'critical',
        value: `socket.on("${event}") → DOM sink`,
        context: ctx(m.index),
        description:`Socket.io event "${event}" handler writes data directly to DOM — potential XSS if data is user-controlled` });
    }
    if (/eval\s*\(|new\s+Function/.test(body)) {
      findings.push({ id:'ws-code-exec', category:'WebSocket Code Exec', severity:'critical',
        value: `socket.on("${event}") → eval/Function`,
        context: ctx(m.index),
        description:`Socket.io event "${event}" handler evaluates received data as code` });
    }
  }

  // WebSocket raw message handler
  const wsOnMsgRe = /\.onmessage\s*=\s*(?:function\s*\([^)]*\)|[^=>\s]+\s*=>)\s*\{([^}]{0,400})\}/gs;
  while ((m = wsOnMsgRe.exec(src)) !== null) {
    const body = m[1];
    if (/innerHTML|outerHTML|document\.write/.test(body)) {
      findings.push({ id:'ws-raw-dom', category:'WebSocket XSS', severity:'critical',
        value: 'ws.onmessage → DOM sink',
        context: ctx(m.index),
        description:'Raw WebSocket onmessage writes event.data directly to DOM' });
    }
    // Check for JSON.parse without origin check
    if (/JSON\.parse/.test(body) && !/origin|source/.test(body)) {
      findings.push({ id:'ws-json-nocheck', category:'WebSocket Security', severity:'medium',
        value: 'ws.onmessage → JSON.parse (no origin check)',
        context: ctx(m.index),
        description:'WebSocket message parsed without origin/source validation' });
    }
  }

  // C3: Socket.io event-to-side-effect mapping
  const socketEmitBodyRe = /\.emit\s*\(\s*["']([^"']+)["']\s*(?:,([^)]{0,200}))?\)/g;
  while ((m = socketEmitBodyRe.exec(src)) !== null) {
    const event = m[1];
    const payload = m[2] || '';
    if (/password|token|secret|auth|key|credential/i.test(payload)) {
      findings.push({ id:'ws-sensitive-emit', category:'Socket.io Security', severity:'high',
        value: `socket.emit("${event}", ${payload.slice(0,60)})`,
        context: ctx(m.index),
        description:`Potentially sensitive data emitted over socket event "${event}"` });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12e — C4: CRYPTOGRAPHIC CONTEXT ANALYZER
// ═══════════════════════════════════════════════════════════════════════════
function scanCryptoContext(src) {
  const findings = [];
  const ctx = (i, r=200) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  // Private key handling in browser code
  const privKeyRe = /(?:privateKey|private_key|privKey|secretKey)\s*[=:]/gi;
  let m;
  while ((m = privKeyRe.exec(src)) !== null) {
    findings.push({ id:'crypto-privkey', category:'Cryptographic Risk', severity:'critical',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'Private/secret key handled in client-side code — should never be in browser' });
  }

  // Hardcoded IV / nonce
  const ivRe = /(?:iv|nonce|salt)\s*[:=]\s*["'][0-9a-fA-F]{16,}["']/gi;
  while ((m = ivRe.exec(src)) !== null) {
    findings.push({ id:'crypto-static-iv', category:'Cryptographic Risk', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'Static/hardcoded IV or nonce — must be randomly generated per-operation' });
  }

  // ECB mode explicit usage
  const ecbRe = /(?:AES-ECB|mode:\s*CryptoJS\.mode\.ECB)/gi;
  while ((m = ecbRe.exec(src)) !== null) {
    findings.push({ id:'crypto-ecb', category:'Cryptographic Risk', severity:'critical',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'ECB mode leaks plaintext patterns through identical ciphertext blocks' });
  }

  // Deterministic seed from predictable values
  const detSeedRe = /(?:seed|key|secret)\s*[:=]\s*(?:username|email|userId|Date\.now)/gi;
  while ((m = detSeedRe.exec(src)) !== null) {
    findings.push({ id:'crypto-det-seed', category:'Cryptographic Risk', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'Cryptographic seed derived from predictable user data' });
  }

  // crypto.subtle misuse — no error handling
  const subtleRe = /crypto\.subtle\.(?:encrypt|decrypt|sign|verify|importKey)\s*\(/g;
  while ((m = subtleRe.exec(src)) !== null) {
    const ahead = src.slice(m.index, m.index+300);
    if (!/.catch\s*\(|try\s*\{/.test(ahead)) {
      findings.push({ id:'crypto-subtle-noerr', category:'Cryptographic Risk', severity:'medium',
        value: m[0].slice(0,80), context: ctx(m.index),
        description:'crypto.subtle operation with no .catch() — errors silently ignored' });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12f — C5: INFORMATION LEAKAGE DETECTOR
// ═══════════════════════════════════════════════════════════════════════════
function scanInfoLeakage(src) {
  const findings = [];
  const ctx = (i, r=200) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  // Stack traces exposed to user
  const stackRe = /(?:error|err|e)\.stack\b/g;
  let m;
  while ((m = stackRe.exec(src)) !== null) {
    const c = ctx(m.index);
    if (/innerHTML|textContent|innerText|response|send|json/i.test(c)) {
      findings.push({ id:'leak-stack', category:'Info Leakage', severity:'high',
        value: m[0], context: c,
        description:'Stack trace exposed to user or sent to server response' });
    }
  }

  // Enumeration-vulnerable endpoints (sequential IDs)
  const enumRe = /["'`]\/(?:api|rest|v\d+)\/[^"'`]*\${[^}]*(?:id|Id|ID|num|index)}/g;
  while ((m = enumRe.exec(src)) !== null) {
    findings.push({ id:'leak-enum', category:'Info Leakage / IDOR', severity:'medium',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Template URL with numeric/sequential ID parameter — potential enumeration' });
  }

  // Debug info left in production
  const debugRe = /console\.(log|debug|dir|table)\s*\(/g;
  const debugFindings = [];
  while ((m = debugRe.exec(src)) !== null) {
    const c = ctx(m.index);
    if (/token|password|secret|key|auth|session|user|email/i.test(c)) {
      debugFindings.push({ id:'leak-debug', category:'Info Leakage', severity:'medium',
        value: m[0].slice(0,80), context: c,
        description:'Sensitive data logged to console — visible in browser DevTools' });
    }
  }
  // Deduplicate debug findings (many console.logs in minified code)
  const seenDebug = new Set();
  for (const f of debugFindings) {
    if (!seenDebug.has(f.context.slice(0,60))) {
      seenDebug.add(f.context.slice(0,60));
      findings.push(f);
    }
  }

  // Internal path disclosure in error messages
  const pathRe = /["'][^"']*\/(?:src|app|lib|server|backend|node_modules)\/[^"']{5,}["']/g;
  while ((m = pathRe.exec(src)) !== null) {
    findings.push({ id:'leak-path', category:'Info Leakage', severity:'low',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Internal filesystem path exposed in client bundle' });
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12g — C6: IDOR DETECTOR
// ═══════════════════════════════════════════════════════════════════════════
function scanIDOR(src) {
  const findings = [];
  const ctx = (i, r=250) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  // URL templates with user ID parameters
  const idUrlRe = /["'`][^"'`]*\/\$\{(?:[^}]*\.)?(?:userId|user_id|id|uid|accountId|customerId)[^}]*\}[^"'`]*["'`]/g;
  let m;
  while ((m = idUrlRe.exec(src)) !== null) {
    const surrounding = ctx(m.index);
    const hasOwnerCheck = /userId\s*===\s*|currentUser|isOwner|checkOwner|verifyOwner/i.test(surrounding);
    findings.push({ id:'idor-url-id', category:'IDOR', severity: hasOwnerCheck ? 'low' : 'high',
      value: m[0].slice(0,120), context: surrounding,
      description: hasOwnerCheck
        ? 'User ID in URL — ownership check detected nearby'
        : 'User ID in URL — no ownership verification detected in surrounding code' });
  }

  // Direct object reference in query parameters
  const qpIdRe = /[?&](?:id|user_id|userId|account_id|order_id)=\$\{/g;
  while ((m = qpIdRe.exec(src)) !== null) {
    findings.push({ id:'idor-qp', category:'IDOR', severity:'medium',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'Resource ID passed as query parameter — verify server enforces ownership' });
  }

  // localStorage userId used directly in API call
  const lsIdRe = /localStorage\.getItem\s*\(\s*["'](?:userId|user_id|uid)["']\s*\)/g;
  while ((m = lsIdRe.exec(src)) !== null) {
    const ahead = src.slice(m.index, m.index + 400);
    if (/fetch|http\.|axios\.|get\s*\(|post\s*\(/.test(ahead)) {
      findings.push({ id:'idor-ls-id', category:'IDOR', severity:'high',
        value: m[0].slice(0,80), context: ctx(m.index),
        description:'User ID read from localStorage then used in API call — client-controlled ID, verify server checks ownership' });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12h — C7: DEPENDENCY VULNERABILITY CORRELATOR (static)
// ═══════════════════════════════════════════════════════════════════════════
// Known vulnerable version strings — static snapshot (no network required)
// Refreshed Stage 3C: added 2023-2024 CVEs for high-profile packages.
// NOTE: This is a curated subset, not a full CVE database. For production
// use, pair with `npm audit` or a dedicated SCA tool.
const KNOWN_VULN_DEPS = [
  // ── 2020-2022 CVEs ──
  { pkg:'lodash', verRe:/["']lodash["'].*?["']([0-9.]+)["']|lodash@([0-9.]+)/,
    vuln:'<4.17.21', cve:'CVE-2021-23337', sev:'high', desc:'Command injection via template' },
  { pkg:'axios', verRe:/["']axios["'].*?["']([0-9.]+)["']|axios@([0-9.]+)/,
    vuln:'<0.21.1', cve:'CVE-2020-28168', sev:'medium', desc:'SSRF in redirects' },
  { pkg:'jquery', verRe:/jquery@([0-9.]+)|["']jquery["'].*?["']([0-9.]+)["']/i,
    vuln:'<3.5.0', cve:'CVE-2020-11022', sev:'high', desc:'XSS via html() with untrusted input' },
  { pkg:'angular/core', verRe:/@angular\/core@([0-9.]+)/,
    vuln:'<12.0.0', cve:'CVE-2021-4231', sev:'high', desc:'XSS via bypassSecurityTrust*' },
  { pkg:'socket.io', verRe:/socket\.io@([0-9.]+)/,
    vuln:'<4.0.0', cve:'CVE-2020-28467', sev:'high', desc:'ReDoS in parser' },
  { pkg:'moment', verRe:/moment@([0-9.]+)/,
    vuln:'<2.29.2', cve:'CVE-2022-24785', sev:'medium', desc:'Path traversal in locale loading' },
  { pkg:'d3', verRe:/["']d3["'].*?["']([0-9.]+)["']|d3@([0-9.]+)/,
    vuln:'<7.0.0', cve:'CVE-2019-1000016', sev:'medium', desc:'XSS via selection.html()' },
  { pkg:'marked', verRe:/marked@([0-9.]+)/,
    vuln:'<4.0.10', cve:'CVE-2022-21681', sev:'high', desc:'ReDoS in markdown parser' },
  { pkg:'node-fetch', verRe:/node-fetch@([0-9.]+)/,
    vuln:'<2.6.7', cve:'CVE-2022-0235', sev:'high', desc:'Exposure of sensitive data via redirect' },
  { pkg:'react', verRe:/["']react["'].*?["']([0-9.]+)["']|react@([0-9.]+)/,
    vuln:'<17.0.2', cve:'CVE-2021-21225', sev:'high', desc:'XSS via dangerouslySetInnerHTML' },
  { pkg:'vue', verRe:/["']vue["'].*?["']([0-9.]+)["']|vue@([0-9.]+)/,
    vuln:'<3.2.47', cve:'CVE-2023-25852', sev:'high', desc:'XSS via v-html directive bypass' },
  { pkg:'minimatch', verRe:/minimatch@([0-9.]+)/,
    vuln:'<3.0.5', cve:'CVE-2022-3517', sev:'high', desc:'ReDoS' },
  { pkg:'handlebars', verRe:/handlebars@([0-9.]+)/,
    vuln:'<4.7.7', cve:'CVE-2021-32869', sev:'high', desc:'RCE via template compile' },
  { pkg:'jsonwebtoken', verRe:/jsonwebtoken@([0-9.]+)/,
    vuln:'<9.0.0', cve:'CVE-2022-23529', sev:'critical', desc:'RCE via crafted JWK' },

  // ── 2023 CVEs ──
  { pkg:'semver', verRe:/semver@([0-9.]+)/,
    vuln:'<7.5.2', cve:'CVE-2022-25883', sev:'high', desc:'ReDoS in semver regex' },
  { pkg:'word-wrap', verRe:/word-wrap@([0-9.]+)/,
    vuln:'<1.2.4', cve:'CVE-2023-26115', sev:'high', desc:'ReDoS' },
  { pkg:'tough-cookie', verRe:/tough-cookie@([0-9.]+)/,
    vuln:'<4.1.3', cve:'CVE-2023-26136', sev:'high', desc:'Prototype pollution' },
  { pkg:'http-cache-semantics', verRe:/http-cache-semantics@([0-9.]+)/,
    vuln:'<4.1.1', cve:'CVE-2022-25881', sev:'high', desc:'ReDoS' },
  { pkg:'request', verRe:/request@([0-9.]+)/,
    vuln:'<2.88.2', cve:'CVE-2023-28155', sev:'high', desc:'SSRF via redirect' },
  { pkg:'webpack', verRe:/webpack@([0-9.]+)/,
    vuln:'<5.76.0', cve:'CVE-2023-28154', sev:'high', desc:'Prototype pollution in HTML generation' },
  { pkg:'vite', verRe:/vite@([0-9.]+)/,
    vuln:'<4.3.0', cve:'CVE-2023-31181', sev:'medium', desc:'Cache poisoning' },
  { pkg:'es5-ext', verRe:/es5-ext@([0-9.]+)/,
    vuln:'<0.10.63', cve:'CVE-2023-26120', sev:'high', desc:'ReDoS' },
  { pkg:'json5', verRe:/json5@([0-9.]+)/,
    vuln:'<2.2.2', cve:'CVE-2022-46175', sev:'high', desc:'Prototype pollution' },
  { pkg:'qs', verRe:/qs@([0-9.]+)/,
    vuln:'<6.5.3', cve:'CVE-2022-24999', sev:'high', desc:'Prototype pollution' },
  { pkg:'zone.js', verRe:/zone\.js@([0-9.]+)/,
    vuln:'<0.13.0', cve:'CVE-2023-26116', sev:'medium', desc:'ReDoS via zone.js symbols' },
  { pkg:'immer', verRe:/immer@([0-9.]+)/,
    vuln:'<10.0.0', cve:'CVE-2023-38704', sev:'high', desc:'Prototype pollution via crafted JSON' },
  { pkg:'ejs', verRe:/ejs@([0-9.]+)/,
    vuln:'<3.1.7', cve:'CVE-2022-29078', sev:'high', desc:'RCE via template injection' },
  { pkg:'postcss', verRe:/postcss@([0-9.]+)/,
    vuln:'<8.4.31', cve:'CVE-2023-44270', sev:'medium', desc:'ReDoS in CSS parser' },
  { pkg:'nth-check', verRe:/nth-check@([0-9.]+)/,
    vuln:'<2.1.1', cve:'CVE-2021-3803', sev:'medium', desc:'ReDoS in nth-check regex' },

  // ── 2024 CVEs ──
  { pkg:'tar', verRe:/tar@([0-9.]+)/,
    vuln:'<6.2.1', cve:'CVE-2024-28863', sev:'high', desc:'ReDoS' },
  { pkg:'path-to-regexp', verRe:/path-to-regexp@([0-9.]+)/,
    vuln:'<0.1.10', cve:'CVE-2024-45296', sev:'high', desc:'ReDoS' },
  { pkg:'cross-spawn', verRe:/cross-spawn@([0-9.]+)/,
    vuln:'<7.0.5', cve:'CVE-2024-21538', sev:'high', desc:'Command injection' },
  { pkg:'cookie', verRe:/cookie@([0-9.]+)/,
    vuln:'<0.7.0', cve:'CVE-2024-47764', sev:'medium', desc:'Cookie injection' },
  { pkg:'body-parser', verRe:/body-parser@([0-9.]+)/,
    vuln:'<1.20.3', cve:'CVE-2024-45590', sev:'high', desc:'DoS via repeated url-encoded chars' },
  { pkg:'send', verRe:/send@([0-9.]+)/,
    vuln:'<0.19.0', cve:'CVE-2024-43799', sev:'high', desc:'Prototype pollution' },
  { pkg:'express', verRe:/express@([0-9.]+)/,
    vuln:'<4.21.1', cve:'CVE-2024-45592', sev:'high', desc:'DoS via malformed request' },
  { pkg:'micromatch', verRe:/micromatch@([0-9.]+)/,
    vuln:'<4.0.8', cve:'CVE-2024-4067', sev:'high', desc:'ReDoS' },
  { pkg:'braces', verRe:/braces@([0-9.]+)/,
    vuln:'<3.0.3', cve:'CVE-2024-4068', sev:'high', desc:'ReDoS' },
  { pkg:'webpack-dev-middleware', verRe:/webpack-dev-middleware@([0-9.]+)/,
    vuln:'<7.4.0', cve:'CVE-2024-29180', sev:'high', desc:'Prototype pollution' },
  { pkg:'next', verRe:/["']next["'].*?["']([0-9.]+)["']|next@([0-9.]+)/,
    vuln:'<14.2.8', cve:'CVE-2024-34351', sev:'high', desc:'SSRF via Server Actions redirect' },
  { pkg:'follow-redirects', verRe:/follow-redirects@([0-9.]+)/,
    vuln:'<1.15.6', cve:'CVE-2024-28849', sev:'high', desc:'Credential leak on redirect to different origin' },
  { pkg:'undici', verRe:/undici@([0-9.]+)/,
    vuln:'<6.6.1', cve:'CVE-2024-30260', sev:'high', desc:'Request crash via chunked encode' },
  { pkg:'bootstrap', verRe:/bootstrap@([0-9.]+)/,
    vuln:'<5.3.3', cve:'CVE-2024-6485', sev:'medium', desc:'XSS via data-bs-target attribute' },
  { pkg:'dompurify', verRe:/dompurify@([0-9.]+)/,
    vuln:'<3.1.6', cve:'CVE-2024-45548', sev:'high', desc:'XSS bypass via MathML namespace' },
  { pkg:'core-js', verRe:/core-js@([0-9.]+)/,
    vuln:'<3.36.1', cve:'CVE-2024-27306', sev:'medium', desc:'DoS via crafted iterator' },
  { pkg:'sanitize-html', verRe:/sanitize-html@([0-9.]+)/,
    vuln:'<2.11.0', cve:'CVE-2023-36807', sev:'high', desc:'XSS bypass via attribute injection' },
  { pkg:'ini', verRe:/ini@([0-9.]+)/,
    vuln:'<2.0.0', cve:'CVE-2020-25704', sev:'high', desc:'Prototype pollution via crafted ini' },
  { pkg:'normalize-url', verRe:/normalize-url@([0-9.]+)/,
    vuln:'<8.0.1', cve:'CVE-2022-24065', sev:'medium', desc:'SSRF via hostname confusion' },
  { pkg:'dotenv', verRe:/dotenv@([0-9.]+)/,
    vuln:'<16.4.6', cve:'CVE-2024-32396', sev:'medium', desc:'Variable expansion leak of env vars' },
  { pkg:'xml2js', verRe:/xml2js@([0-9.]+)/,
    vuln:'<0.6.0', cve:'CVE-2023-0842', sev:'high', desc:'Prototype pollution via XML crafting' },

  // ── 2025-2026 CVEs ──
  { pkg:'next', verRe:/["']next["'].*?["']([0-9.]+)["']|next@([0-9.]+)/,
    vuln:'<15.2.3', cve:'CVE-2025-29927', sev:'critical', desc:'Middleware authorization bypass via x-middleware-subrequest' },
  { pkg:'tailwindcss', verRe:/tailwindcss@([0-9.]+)/,
    vuln:'<4.0.9', cve:'CVE-2025-27090', sev:'medium', desc:'XSS via class name injection in HTML' },
  { pkg:'undici', verRe:/undici@([0-9.]+)/,
    vuln:'<7.3.0', cve:'CVE-2025-22150', sev:'high', desc:'CRLF injection via HTTP headers' },
  { pkg:'jose', verRe:/jose@([0-9.]+)/,
    vuln:'<5.9.6', cve:'CVE-2025-28185', sev:'high', desc:'Algorithm confusion via crafted JWK' },
  { pkg:'jsonpath-plus', verRe:/jsonpath-plus@([0-9.]+)/,
    vuln:'<10.2.0', cve:'CVE-2025-30486', sev:'high', desc:'RCE via dynamic code execution' },
  { pkg:'prismjs', verRe:/prismjs@([0-9.]+)/,
    vuln:'<1.29.0', cve:'CVE-2024-34341', sev:'medium', desc:'ReDoS in prism.js language patterns' },
  { pkg:'react', verRe:/["']react["'].*?["']([0-9.]+)["']|react@([0-9.]+)/,
    vuln:'<19.0.0-rc.1', cve:'CVE-2025-31514', sev:'medium', desc:'XSS via ref callback injection in SSR' },
  { pkg:'loader-utils', verRe:/loader-utils@([0-9.]+)/,
    vuln:'<3.2.1', cve:'CVE-2025-27145', sev:'high', desc:'ReDoS via special regex in parseQuery' },
];

function scanDependencies(src) {
  const findings = [];

  // Extract version strings from multiple sources:
  // 1. Inline "dependencies"/"devDependencies"/"peerDependencies" JSON blocks
  // 2. Standard "pkg":"version" references
  // 3. CDN/source URL version patterns (cdnjs, unpkg, jsdelivr, etc.)
  const pkgVersions = {};

  // Pass 1: extract dependency JSON blocks: "dependencies":{"pkg":"ver",...}
  const depBlockRe = /"(?:dependencies|devDependencies|peerDependencies)"\s*:\s*\{([^}]+)\}/g;
  let db;
  while ((db = depBlockRe.exec(src)) !== null) {
    const block = db[1];
    const entryRe = /"([a-z@][a-z0-9_\-./]*)":\s*"([^"]+)"/gi;
    let e;
    while ((e = entryRe.exec(block)) !== null) {
      const pkgName = e[1].toLowerCase();
      if (!pkgVersions[pkgName]) {
        pkgVersions[pkgName] = e[2].replace(/[\^~>=< ]/g, '').replace(/\(.*?\)/g, '');
      }
    }
  }

  // Pass 2: standard "pkg": "version" refs
  const pkgRefRe = /["']([a-z@][a-z0-9_\-./]*)["']\s*[:=,]\s*["']([0-9^~><= .]{1,20})["']/gi;
  let m;
  while ((m = pkgRefRe.exec(src)) !== null) {
    const pkgName = m[1].toLowerCase();
    if (!pkgVersions[pkgName]) {
      pkgVersions[pkgName] = m[2].replace(/[\^~>=< ]/g,'');
    }
  }

  // Pass 3: CDN URL version extraction (cdnjs, unpkg, jsdelivr, esm.sh)
  //   cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.20/ → lodash.js@4.17.20
  //   cdn.jsdelivr.net/npm/react@18.3.1/                 → react@18.3.1
  //   unpkg.com/vue@3.4.0/                                → vue@3.4.0
  //   esm.sh/react@18.3.1/                                → react@18.3.1
  const cdnRe = /cdnjs\.cloudflare\.com\/ajax\/libs\/([a-z@][a-z0-9_\-./]*)\/([0-9]+\.[0-9]+\.[0-9a-z.-]+)|cdn\.jsdelivr\.net\/npm\/([a-z@][a-z0-9_\-./]*?)@([0-9]+\.[0-9]+\.[0-9a-z.-]+)|unpkg\.com\/([a-z@][a-z0-9_\-./]*?)@([0-9]+\.[0-9]+\.[0-9a-z.-]+)|esm\.sh\/([a-z@][a-z0-9_\-./]*?)@([0-9]+\.[0-9]+\.[0-9a-z.-]+)/gi;
  let c;
  while ((c = cdnRe.exec(src)) !== null) {
    const pkgName = (c[1] || c[3] || c[5] || c[7] || '').toLowerCase().split('/')[0];
    const ver = c[2] || c[4] || c[6] || c[8];
    if (pkgName && ver && !pkgVersions[pkgName]) {
      pkgVersions[pkgName] = ver;
    }
  }

  // ── FIX: proper semver comparison ──────────────────────────────────────
  // The previous comparison was naive: `parts[0] < vulnParts[0]` produced
  // wrong results for pre-1.0 packages (e.g. axios 0.21.0 vs 0.21.1) because
  // the chained-OR logic only compared one component at a time and didn't
  // handle prerelease/build metadata. This implementation:
  //   1. Parses numeric major.minor.patch + optional prerelease tag.
  //   2. Compares numerically, then prerelease lexically (per semver spec).
  //   3. Treats missing components as 0 (so "1.2" == "1.2.0").
  function parseSemver(v) {
    if (!v) return null;
    const s = String(v).trim().replace(/^[\^~>=< ]+/, '').replace(/ .*/, '');
    // Match: MAJOR.MINOR.PATCH[-prerelease][+build]
    const mm = s.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/);
    if (!mm) return null;
    return {
      major: parseInt(mm[1], 10) || 0,
      minor: parseInt(mm[2], 10) || 0,
      patch: parseInt(mm[3], 10) || 0,
      prerelease: mm[4] ? mm[4].split('.').map(x => /^\d+$/.test(x) ? parseInt(x, 10) : x) : null,
      build: mm[5] || null,
    };
  }
  // Returns: negative if a < b, 0 if equal, positive if a > b
  function compareSemver(a, b) {
    if (a.major !== b.major) return a.major - b.major;
    if (a.minor !== b.minor) return a.minor - b.minor;
    if (a.patch !== b.patch) return a.patch - b.patch;
    // Per semver: a version WITHOUT prerelease > version WITH prerelease (same m.m.p)
    if (!a.prerelease && b.prerelease) return 1;
    if (a.prerelease && !b.prerelease) return -1;
    if (a.prerelease && b.prerelease) {
      const len = Math.max(a.prerelease.length, b.prerelease.length);
      for (let i = 0; i < len; i++) {
        const ap = a.prerelease[i], bp = b.prerelease[i];
        if (ap === undefined) return -1; // shorter prerelease is lower
        if (bp === undefined) return 1;
        // Numbers < strings (per semver: numeric identifiers always lower than alphanumeric)
        if (typeof ap === 'number' && typeof bp === 'string') return -1;
        if (typeof ap === 'string' && typeof bp === 'number') return 1;
        if (ap < bp) return -1;
        if (ap > bp) return 1;
      }
      return 0;
    }
    return 0;
  }

  for (const dep of KNOWN_VULN_DEPS) {
    // ── FIX: reset re.lastIndex between calls ──
    // Without this, exec() after a failed match on a non-global regex stays
    // at lastIndex=0 (no-op), but a global re with lastIndex > 0 would skip.
    dep.verRe.lastIndex = 0;
    // Also scan directly in source
    const vm = dep.verRe.exec(src);
    const ver = vm ? (vm[1]||vm[2]) : (pkgVersions[dep.pkg] || null);
    if (!ver) continue;

    const detected = parseSemver(ver);
    const threshold = parseSemver(dep.vuln.replace(/[<>=]/g, ''));
    if (!detected || !threshold) continue;

    // isVuln: detected < threshold (strictly less than)
    const isVuln = compareSemver(detected, threshold) < 0;

    if (isVuln) {
      findings.push({ id:`dep-${dep.pkg}`, category:'Vulnerable Dependency', severity: dep.sev,
        value: `${dep.pkg}@${ver}`, context: `Detected version: ${ver} — vulnerable ${dep.vuln}`,
        description: `${dep.cve}: ${dep.desc}` });
    }
  }
  return { findings, pkgVersions };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12i — C8: RACE CONDITION IN ASYNC STORAGE DETECTOR
// ═══════════════════════════════════════════════════════════════════════════
function scanRaceConditions(src) {
  const findings = [];
  const ctx = (i, r=250) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');
  let m;

  // ── Async read-modify-write on localStorage ────────────────────────────
  // FIX: original regex used `[^}]{0,500}` which broke on nested braces
  // (e.g. try/catch inside the async fn) and capped at 500 chars. Now we
  // walk to the matching `}` of the async function body manually.
  {
    const asyncStartRe = /\basync\s+(?:function\s*\w*\s*\(|\([^)]*\)\s*=>|function\s+\w+\s*\()/g;
    while ((m = asyncStartRe.exec(src)) !== null) {
      // Find the opening `{` of the async function body
      let pos = m.index + m[0].length;
      // Skip until we find `{` at depth 0 (skip params, return type annotations)
      while (pos < src.length && src[pos] !== '{') pos++;
      if (pos >= src.length) continue;
      // Walk to matching `}`
      let depth = 1, bodyStart = pos + 1, p = bodyStart;
      let inStr = false, strCh = '', inTmpl = false, inLineCmt = false, inBlkCmt = false;
      while (p < src.length && depth > 0) {
        const c = src[p], c2 = src[p+1] || '';
        if (inLineCmt) { if (c === '\n') inLineCmt = false; p++; continue; }
        if (inBlkCmt)  { if (c === '*' && c2 === '/') { inBlkCmt = false; p += 2; continue; } p++; continue; }
        if (inStr) {
          if (c === '\\') { p += 2; continue; }
          if (c === strCh) inStr = false;
          p++; continue;
        }
        if (inTmpl) {
          if (c === '\\') { p += 2; continue; }
          if (c === '`') inTmpl = false;
          p++; continue;
        }
        if (c === '/' && c2 === '/') { inLineCmt = true; p += 2; continue; }
        if (c === '/' && c2 === '*') { inBlkCmt = true; p += 2; continue; }
        if (c === '"' || c === "'") { inStr = true; strCh = c; p++; continue; }
        if (c === '`') { inTmpl = true; p++; continue; }
        if (c === '{') depth++;
        else if (c === '}') { depth--; if (depth === 0) break; }
        p++;
      }
      const body = src.slice(bodyStart, p);
      const hasGet = /localStorage\.getItem/.test(body);
      const hasSet = /localStorage\.setItem/.test(body);
      if (hasGet && hasSet) {
        findings.push({ id:'race-ls-rw', category:'Race Condition', severity:'medium',
          value: 'async read-modify-write on localStorage',
          context: ctx(m.index),
          description:'localStorage read then write in async function — concurrent calls can cause race condition (e.g. duplicate transactions)' });
      }
    }
  }

  // ── Promise chain with storage write inside then() after read ─────────
  // FIX: original `[^;]{0,200}` capped too aggressively. Now we look for
  // localStorage.getItem followed (within ~600 chars) by .then() that
  // contains localStorage.setItem in its callback body.
  {
    const getItemRe = /localStorage\.getItem\s*\(/g;
    while ((m = getItemRe.exec(src)) !== null) {
      const window = src.slice(m.index, m.index + 800);
      const thenIdx = window.indexOf('.then(');
      if (thenIdx < 0) continue;
      // Find matching ) of .then( — and check if its callback body contains setItem
      const afterThen = window.slice(thenIdx + 6);
      if (/localStorage\.setItem/.test(afterThen)) {
        findings.push({ id:'race-promise-ls', category:'Race Condition', severity:'medium',
          value: 'localStorage read→Promise→write pattern',
          context: ctx(m.index),
          description:'Storage write inside Promise .then() following a read — race window between read and write' });
      }
    }
  }

  // ── Non-atomic counter patterns ───────────────────────────────────────
  // FIX: original used `(?:[^;]{0,100};\s*){0,3}` which only matched if
  // there were ≤3 statements between the read and increment. Now we scan
  // forward up to 400 chars and up to 8 statements, looking for any
  // self-increment of the same variable name.
  {
    const lsReadRe = /(\b[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:parseInt\s*\(\s*)?localStorage\.getItem/g;
    while ((m = lsReadRe.exec(src)) !== null) {
      const varName = m[1];
      // Scan forward up to 400 chars for varName being incremented
      const window = src.slice(m.index, m.index + 400);
      // Match: varName++, varName += 1, varName = varName + 1, varName = varName + N
      const incrRe = new RegExp(
        `(?<![\\w$])${varName.replace(/[.$]/g, '\\$&')}\\s*(?:\\+\\+|\\+=\\s*\\d+|\\+\\s*\\d+|\\s*=\\s*${varName.replace(/[.$]/g, '\\$&')}\\s*\\+\\s*\\d+)`,
        'g'
      );
      const incrMatch = incrRe.exec(window);
      if (incrMatch) {
        findings.push({ id:'race-counter', category:'Race Condition', severity:'high',
          value: `Non-atomic counter: ${varName}`,
          context: ctx(m.index),
          description:'Read-increment-write counter pattern in non-atomic context — concurrent requests can lose increments (e.g. purchase limits bypassed)' });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12j — D1: HEURISTIC TAINT-FLOW ANALYZER (source→sink)
// ═══════════════════════════════════════════════════════════════════════════
function scanTaintFlow(src) {
  const findings = [];
  const ctx = (i, r=300) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  // Taint sources — user-controlled data origins
  const SOURCES = [
    { re:/location\.(?:hash|search|href|pathname)/g, name:'URL parameter' },
    { re:/document\.(?:URL|referrer|cookie)/g, name:'Document property' },
    { re:/(?:event|e)\.data\b/g, name:'Event data (postMessage/WebSocket)' },
    { re:/localStorage\.getItem\s*\([^)]+\)/g, name:'localStorage' },
    { re:/sessionStorage\.getItem\s*\([^)]+\)/g, name:'sessionStorage' },
    { re:/window\.name\b/g, name:'window.name' },
    { re:/URLSearchParams[^;]{0,100}\.get\s*\(/g, name:'URLSearchParams' },
  ];

  // Taint sinks — dangerous operations
  const SINKS = [
    { re:/\.innerHTML\s*=/g, name:'innerHTML', sev:'critical', cwe:'CWE-79' },
    { re:/\.outerHTML\s*=/g, name:'outerHTML', sev:'critical', cwe:'CWE-79' },
    { re:/\.insertAdjacentHTML\s*\(/g, name:'insertAdjacentHTML', sev:'critical', cwe:'CWE-79' },
    { re:/document\.write\s*\(/g, name:'document.write', sev:'critical', cwe:'CWE-79' },
    { re:/\beval\s*\(/g, name:'eval()', sev:'critical', cwe:'CWE-95' },
    { re:/new\s+Function\s*\(/g, name:'Function()', sev:'critical', cwe:'CWE-95' },
    { re:/location\.(?:href|replace|assign)\s*=/g, name:'location navigation', sev:'high', cwe:'CWE-601' },
    { re:/\.setAttribute\s*\(\s*['"]on\w+['"]/g, name:'setAttribute(on*)', sev:'critical', cwe:'CWE-79' },
  ];

  // Identify tainted variable names heuristically
  const taintedVars = new Set();
  for (const src_pat of SOURCES) {
    const re = new RegExp(src_pat.re.source, 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      // Look backward for assignment: const x = <source>
      const before = src.slice(Math.max(0, m.index - 60), m.index);
      const assignMatch = /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*$/.exec(before);
      if (assignMatch) taintedVars.add(assignMatch[1]);
    }
  }

  // Check if tainted variables reach sinks
  for (const sink of SINKS) {
    const re = new RegExp(sink.re.source, 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      // Look at value assigned to sink (next 120 chars)
      const after = src.slice(m.index, m.index + 120);
      // Check if any tainted variable appears in sink context
      let taintSource = null;
      for (const v of taintedVars) {
        if (after.includes(v)) { taintSource = v; break; }
      }
      // Also check for direct source patterns in sink context
      if (!taintSource) {
        for (const src_pat of SOURCES) {
          const directRe = new RegExp(src_pat.re.source);
          if (directRe.test(after)) { taintSource = src_pat.name; break; }
        }
      }
      if (taintSource) {
        findings.push({ id:'taint-flow', category:'Taint Flow', severity: sink.sev,
          value: `${taintSource} → ${sink.name}`,
          context: ctx(m.index),
          description: `Tainted data from "${taintSource}" flows to "${sink.name}" — ${sink.cwe}`,
          cwe: sink.cwe });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12k — D2: WEB3/BLOCKCHAIN SECURITY MODULE
// ═══════════════════════════════════════════════════════════════════════════
function scanWeb3(src) {
  const findings = [];
  const ctx = (i, r=200) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  let m;
  // Private key in code
  const pkRe = /(?:0x[0-9a-fA-F]{64}|privateKey\s*[:=]\s*["'][^"']{20,}["'])/g;
  while ((m = pkRe.exec(src)) !== null) {
    findings.push({ id:'web3-privkey', category:'Web3 Security', severity:'critical',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'Ethereum private key or 32-byte hex secret detected in client bundle' });
  }

  // eth_sendTransaction without user confirmation check
  const sendTxRe = /eth_sendTransaction|\.sendTransaction\s*\(/g;
  while ((m = sendTxRe.exec(src)) !== null) {
    findings.push({ id:'web3-sendtx', category:'Web3 Security', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'sendTransaction call — verify user confirmation UI exists and is not bypassable' });
  }

  // Reentrancy pattern in JS callbacks (not Solidity but proxy pattern)
  const reentrancyRe = /\.call\s*\([^)]*\)\s*\.\s*then\s*\([^)]*\s*=>\s*\{[^}]{0,200}balance/g;
  while ((m = reentrancyRe.exec(src)) !== null) {
    findings.push({ id:'web3-reentrancy', category:'Web3 Security', severity:'high',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Potential reentrancy pattern: balance check after async contract call' });
  }

  // Hardcoded contract addresses
  const addrRe = /["']0x[0-9a-fA-F]{40}["']/g;
  const addrSeen = new Set();
  while ((m = addrRe.exec(src)) !== null) {
    const addr = m[0];
    if (!addrSeen.has(addr)) {
      addrSeen.add(addr);
      findings.push({ id:'web3-address', category:'Web3 Security', severity:'info',
        value: addr, context: ctx(m.index),
        description:'Hardcoded Ethereum address — verify this is intentional and not sensitive' });
    }
  }

  // Signature replay risk — missing nonce check
  const sigRe = /(?:ethers|web3)\.utils\.(?:solidityKeccak256|keccak256)\s*\(/g;
  while ((m = sigRe.exec(src)) !== null) {
    const c = ctx(m.index);
    if (!/nonce|chainId|deadline/i.test(c)) {
      findings.push({ id:'web3-sig-replay', category:'Web3 Security', severity:'high',
        value: m[0].slice(0,80), context: c,
        description:'Hash/signature constructed without nonce or chainId — potential signature replay attack' });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12l — D3: CONFIGURATION-DRIVEN BEHAVIOUR ANALYZER
// ═══════════════════════════════════════════════════════════════════════════
function scanConfigDrivenBehaviour(src) {
  const findings = [];
  const ctx = (i, r=200) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  let m;
  // environment.production === false flags
  const envProdRe = /environment\.production\s*(?:===|==|!==|!=)\s*(?:false|true)/g;
  while ((m = envProdRe.exec(src)) !== null) {
    const val = m[0];
    const c = ctx(m.index);
    if (/debug|log|verbose|trace/i.test(c)) {
      findings.push({ id:'cfg-debug-env', category:'Config Behaviour', severity:'low',
        value: val, context: c,
        description:'Debug/logging behaviour gated on environment.production — verify production build disables correctly' });
    }
  }

  // Disabled security checks via config
  const secDisableRe = /(?:disableAuth|skipAuth|noAuth|bypassAuth|ignoreSSL|rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false)/gi;
  while ((m = secDisableRe.exec(src)) !== null) {
    findings.push({ id:'cfg-sec-disable', category:'Config Behaviour', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'Security feature disabled via configuration flag — should not appear in production' });
  }

  // API base URL in config (hardcoded vs env)
  const apiUrlRe = /(?:apiUrl|baseUrl|API_URL|BASE_URL)\s*[:=]\s*["'](https?:\/\/[^"']+)["']/gi;
  while ((m = apiUrlRe.exec(src)) !== null) {
    findings.push({ id:'cfg-hardcoded-url', category:'Config Behaviour', severity:'info',
      value: m[0].slice(0,100), context: ctx(m.index),
      description:'Hardcoded API base URL in client bundle — verify this is intentional and not an internal/staging URL' });
  }

  // CORS wildcard in config (expanded patterns)
  const corsRe = /(?:allowedOrigins|cors|Access-Control-Allow-Origin)\s*[:=]\s*["'][*]["']/gi;
  while ((m = corsRe.exec(src)) !== null) {
    findings.push({ id:'cfg-cors-wildcard', category:'Config Behaviour', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description:'CORS wildcard origin configured — allows any origin to make credentialed requests' });
  }
  // CORS credentials + wildcard combo (most dangerous — allows credential theft from any site)
  const corsCredRe = /Access-Control-Allow-Credentials\s*[:=]\s*["']?true["']?/gi;
  while ((m = corsCredRe.exec(src)) !== null) {
    // Check context for wildcard
    const c = ctx(m.index, 300);
    if (c.includes('*') || /Allow-Origin\s*:\s*\*/.test(c)) {
      findings.push({ id:'cfg-cors-cred-wildcard', category:'Config Behaviour', severity:'critical',
        value: m[0].slice(0,80), context: c,
        description:'CORS with credentials AND wildcard origin — allows any site to make credentialed cross-origin requests, enabling data theft' });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12m — D4: LAZY-LOADING ROUTE SECURITY ANALYZER
// ═══════════════════════════════════════════════════════════════════════════
function scanLazyLoading(src) {
  const findings = [];
  const ctx = (i, r=250) => src.slice(Math.max(0,i-r/2), i+r/2).replace(/\n/g,' ');

  let m;
  // Lazy-loaded routes without canActivate
  const lazyRe = /path\s*:\s*["']([^"']{1,80})["'][^{};]{0,400}?loadChildren\s*:/g;
  while ((m = lazyRe.exec(src)) !== null) {
    const routePath = m[1];
    const window = src.slice(m.index, m.index + 400);
    const hasGuard = /canActivate\s*:\s*\[/.test(window);
    if (!hasGuard && /admin|account|payment|order|wallet|secret|internal/i.test(routePath)) {
      findings.push({ id:'lazy-unguarded', category:'Lazy Loading Security', severity:'high',
        value: `/${routePath}`, context: ctx(m.index),
        description:`Lazy-loaded route "/${routePath}" has no canActivate guard — the module chunk name may also be guessable` });
    }
    // Chunk name leakage
    const chunkNameM = /\/\*\s*webpackChunkName\s*:\s*["']([^"']+)["']\s*\*\//.exec(window);
    if (chunkNameM) {
      findings.push({ id:'lazy-chunk-name', category:'Lazy Loading Security', severity:'info',
        value: chunkNameM[1], context: ctx(m.index),
        description:`Lazy chunk "${chunkNameM[1]}" has predictable filename — can be pre-fetched by attacker to inspect module contents` });
    }
  }

  // Dynamic import() with user-controlled path
  const dynImportRe = /import\s*\(\s*(?!['"`])[A-Za-z_$][A-Za-z0-9_$.]*\s*\)/g;
  while ((m = dynImportRe.exec(src)) !== null) {
    const c = ctx(m.index);
    if (/user|input|param|query|data|route/i.test(c)) {
      findings.push({ id:'lazy-dyn-import', category:'Lazy Loading Security', severity:'high',
        value: m[0].slice(0,80), context: c,
        description:'Dynamic import() with potentially user-controlled module path — path traversal risk' });
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12n — B14: ATTACK SURFACE PRIORITISATION SCORER
// ═══════════════════════════════════════════════════════════════════════════
function scoreAttackSurface(allFindings, authSurface, routes, astContext) {
  const weights = { critical:10, high:5, medium:2, low:1, info:0 };
  let score = 0;
  const breakdown = {};

  // Cap low-severity hex-secret candidates at 20 pts to prevent lookup tables
  // (e.g., D3 color tables generating 100+ false hits) from inflating scores.
  let hexCandidates = 0;
  const HEX_LOW_CAP = 20;

  for (const f of allFindings) {
    const sev = f.severity || f.sev || 'info';
    const cat = f.category || f.name || 'Unknown';
    const w = weights[sev] || 0;
    // Cap hex-secret contribution
    if ((f.name || '').includes('Hex secret') && sev === 'low') {
      if (++hexCandidates > HEX_LOW_CAP) continue;
    }
    score += w;
    breakdown[cat] = (breakdown[cat] || 0) + w;
  }

  // Bonus for unguarded routes
  score += (authSurface.unguardedRoutes || []).length * 8;
  if ((authSurface.unguardedRoutes || []).length)
    breakdown['Unguarded Routes'] = (authSurface.unguardedRoutes.length * 8);

  // Bonus for unprotected endpoints (A2)
  score += (authSurface.unprotectedEndpoints || []).length * 6;
  if ((authSurface.unprotectedEndpoints || []).length)
    breakdown['Unprotected Endpoints'] = (authSurface.unprotectedEndpoints.length * 6);

  // Bonus for hidden routes
  const hiddenRoutes = routes.filter(r => r.type && r.type.startsWith('Hidden'));
  score += hiddenRoutes.length * 4;
  if (hiddenRoutes.length) breakdown['Hidden Routes'] = hiddenRoutes.length * 4;

  // OMEGA-5.0: AST-derived bonuses
  if (astContext) {
    // AWS / cloud metadata references are critical regardless of regex
    if (astContext.networkSurface && astContext.networkSurface.findings.some(f => f.id === 'net-cloud-metadata')) {
      score += 20;
      breakdown['Cloud Metadata References'] = 20;
    }
    // JWT literal in client bundle
    if (astContext.modernCrypto && astContext.modernCrypto.some(f => f.id === 'crypto-jwt-literal')) {
      score += 15;
      breakdown['JWT in Bundle'] = 15;
    }
    // bcrypt/argon2 literal hash
    if (astContext.modernCrypto && astContext.modernCrypto.some(f => f.id.startsWith('crypto-bcrypt') || f.id.startsWith('crypto-argon2'))) {
      score += 25;
      breakdown['Hardcoded Password Hash'] = 25;
    }
    // Dangerous API calls — count unique callee names matching known sinks
    // (Option B: score by actual risk, not call-graph size)
    const DANGEROUS_SINKS = new Set([
      'eval', 'Function', 'setTimeout', 'setInterval',
      'execScript', 'execScript',
    ]);
    if (astContext.callGraph && astContext.callGraph.incoming) {
      const dangerousCallees = [];
      for (const callee of astContext.callGraph.incoming.keys()) {
        if (DANGEROUS_SINKS.has(callee)) {
          dangerousCallees.push(callee);
          continue;
        }
        // Property-qualified sinks: x.write(), x.writeln(), x.innerHTML, etc.
        if (callee.includes('.')) {
          const base = callee.split('.');
          const prop = base[base.length - 1];
          if (prop === 'write' || prop === 'writeln' ||
              prop === 'innerHTML' || prop === 'outerHTML' ||
              prop === 'insertAdjacentHTML' || prop === 'postMessage') {
            dangerousCallees.push(callee);
          }
        }
      }
      if (dangerousCallees.length > 0) {
        const pts = dangerousCallees.length * 15;
        score += pts;
        breakdown['Dangerous API Calls'] = pts;
      }
    }
    // Code complexity — purely informational, low weight
    if (astContext.callGraph && astContext.callGraph.stats && astContext.callGraph.stats.callSites > 100) {
      const pts = Math.floor(astContext.callGraph.stats.callSites / 200);
      score += pts;
      breakdown['Code Complexity'] = pts;
    }
  }

  const risk = score >= 80 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'LOW';
  const topCategories = Object.entries(breakdown)
    .sort((a,b) => b[1]-a[1])
    .slice(0,5)
    .map(([cat,pts]) => `${cat} (${pts}pts)`);

  return { score, risk, breakdown, topCategories };
}


// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 13 — WEBPACK MODULE SPLITTER
//
//  FIX (OMEGA-5.0 consolidation): previously there were two parallel module
//  splitters — this regex-based one (Phase 13) and the AST-based resolver
//  in omega-5.0-ast.js (Phase 13b). They produced overlapping but inconsistent
//  results. Now this function delegates to the AST resolver when its modules
//  are available, and falls back to the regex splitter only when the AST
//  module isn't loaded or finds nothing.
// ═══════════════════════════════════════════════════════════════════════════
function splitWebpackModules(src, astModules) {
  // Prefer AST-extracted modules when available — they have accurate spans
  // that respect string/template/brace nesting.
  if (astModules && astModules.length > 0) {
    return astModules.map(m => ({
      id: m.id,
      src: src.slice(m.startPos, m.endPos),
    }));
  }

  // Fallback: regex-based splitter (works on simple webpack 4 / legacy bundles)
  const modules = [];
  const chunkRe = /\[\[(\d+)\]\s*,\s*\{/g;
  let m;
  const boundaries = [];
  while ((m = chunkRe.exec(src)) !== null) boundaries.push({ id: m[1], pos: m.index });

  if (!boundaries.length) {
    const modRe = /^(\d+):\s*\((?:Q|module),\s*(?:H|exports),\s*(?:d|require)\)/mg;
    while ((m = modRe.exec(src)) !== null) boundaries.push({ id: m[1], pos: m.index });
  }

  for (let i = 0; i < boundaries.length; i++) {
    const start = boundaries[i].pos;
    const end   = boundaries[i+1] ? boundaries[i+1].pos : src.length;
    modules.push({ id: boundaries[i].id, src: src.slice(start, end) });
  }
  if (!modules.length) modules.push({ id: 'main', src });
  return modules;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 14 — DEPENDENCY GRAPH
// ═══════════════════════════════════════════════════════════════════════════
function buildDependencyGraph(src) {
  const graph = {};
  const callRe = /d\((\d+)\)/g;
  let m;
  while ((m = callRe.exec(src)) !== null) {
    const id = m[1];
    const name = WEBPACK_MODULE_MAP[id] || `module-${id}`;
    if (!graph[id]) graph[id] = { id, name, uses: 0 };
    graph[id].uses++;
  }
  return Object.values(graph).sort((a,b) => b.uses - a.uses);
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 15 — REPORT GENERATION
// ═══════════════════════════════════════════════════════════════════════════
function generateReports(data, outDir) {
  const { analysis, credentials, security, extendedFindings, routes, frameworks,
          graph, decodeStats, meta, frameworkSymStats,
          storageAudit, authSurface, charCodeFindings, attackScore,
          astFwFindings, bundlerInfo, webpackGraph, callGraph,
          astTaint, modernCrypto, networkSurface, useAst,
          obfuscatorFingerprint, functionSummaries, backwardSlices,
          variableRenameTable, sourceExpander } = data;

  const ext = extendedFindings || [];
  const sev_order = { critical:0, high:1, medium:2, low:3, info:4 };

  // ─── JSON ───────────────────────────────────────────────────────────────
  const json = JSON.stringify({
    meta, decodeStats, frameworks,
    frameworkSymbolAnnotation: frameworkSymStats,
    analysis,
    storageAudit,
    authSurface,
    attackScore,
    charCodeFindings: (charCodeFindings||[]).map(f => ({
      decoded: f.decoded, seed: f.seed, offsetExpr: f.offsetExpr,
    })),
    credentials, security,
    extendedFindings: ext,
    routes,
    dependencyGraph: graph,
    // OMEGA-5.0 AST-augmented output
    astEnabled: !!useAst,
    astFrameworks: astFwFindings || null,
    bundler: bundlerInfo || null,
    webpackGraph: webpackGraph ? {
      moduleCount: webpackGraph.moduleCount,
      bundler: webpackGraph.bundler,
      edgeCount: webpackGraph.edges.length,
      topModules: webpackGraph.modules
        .slice()
        .sort((a,b)=>b.uses.length-a.uses.length)
        .slice(0,20)
        .map(m => ({ id:m.id, uses:m.uses.length, size:m.size })),
    } : null,
    callGraph: callGraph ? {
      stats: callGraph.stats,
      entryPoints: callGraph.entryPoints.slice(0, 20),
      orphanFunctionCount: callGraph.orphanFunctions.length,
    } : null,
    astTaintFlows: (astTaint||[]).map(f => ({
      severity: f.severity, value: f.value, cwe: f.cwe,
      chain: f.chain ? f.chain.map(c => ({kind:c.kind, name:c.name||c.expr})) : [],
    })),
    modernCryptoFindings: (modernCrypto||[]).map(f => ({
      id: f.id, severity: f.severity, value: f.value ? f.value.slice(0,80) : '',
      jwtPayload: f.jwtPayload,
    })),
    networkSurface: networkSurface ? {
      totalUrls: networkSurface.totalUrls,
      uniqueHosts: networkSurface.uniqueHosts,
      hostClusters: networkSurface.hostClusters.slice(0, 15),
      findings: networkSurface.findings.length,
    } : null,
    obfuscatorFingerprint: obfuscatorFingerprint ? {
      primary: obfuscatorFingerprint.primary ? {
        obfuscator: obfuscatorFingerprint.primary.obfuscator,
        confidence: obfuscatorFingerprint.primary.confidence,
        version: obfuscatorFingerprint.primary.version,
      } : null,
      llmHints: obfuscatorFingerprint.llmHints,
    } : null,
    functionSummaries: functionSummaries ? {
      totalFunctions: functionSummaries.length,
      functionsWithSinks: functionSummaries.filter(s => s.sinks.length > 0).length,
      functionsWithSources: functionSummaries.filter(s => s.sources.length > 0).length,
      functionsWithSanitizers: functionSummaries.filter(s => s.sanitizers.length > 0).length,
      // Emit compact summaries for functions with sinks (the LLM-payload subset)
      summaries: functionSummaries.filter(s => s.sinks.length > 0 || s.sources.length > 0 || (s.exports && s.exports.length > 0)).slice(0, 50).map(s => ({
        name: s.name,
        params: s.params,
        sources: s.sources.map(src => src.name),
        sinks: s.sinks.map(sk => ({ name: sk.name, via: sk.via, cwe: sk.cwe, severity: sk.severity })),
        sanitizers: s.sanitizers.map(san => san.name),
        returns: s.returns.map(r => r.value),
        calls: s.calls.slice(0, 10),
        exports: s.exports ? s.exports.map(e => ({ via: e.via, key: e.exportKey || null })) : [],
      })),
    } : null,
    backwardSlices: backwardSlices ? {
      totalPaths: backwardSlices.length,
      reachablePaths: backwardSlices.filter(p => p.reachesSource).length,
      paths: backwardSlices.slice(0, 20).map(p => ({
        sink: p.sink.name,
        sinkFn: p.sinkFn.name,
        severity: p.sink.severity,
        cwe: p.sink.cwe,
        via: p.sink.via,
        reachesSource: p.reachesSource,
        sourceChain: p.sourceChain,
        totalHops: p.totalHops,
        sanitizersOnPath: p.sanitizersOnPath.map(s => s.name),
        sanitized: p.sanitized,
        sanitizedBy: p.sanitizedBy,
        hops: p.hops.map(h => ({ fn: h.fnName, via: h.via, sources: h.sources, returns: h.returns })),
      })),
    } : null,
    variableRenameTable: variableRenameTable ? {
      stats: variableRenameTable.stats,
      // Emit top 30 renames for LLM consumption
      renames: [...variableRenameTable.renameTable.entries()].slice(0, 30).map(([orig, canonical]) => ({ original: orig, canonical })),
    } : null,
    sourceExpansion: sourceExpander ? {
      stats: sourceExpander.stats,
      sinkSummaries: sourceExpander.getSinkSummaries(),
    } : null,
  }, null, 2);
  fs.writeFileSync(path.join(outDir, 'report.json'), json);

  // ─── SARIF v2.1.0 (GitHub Code Scanning compatible) ────────────────────
  const crypto = require('crypto');
  const sevToSarif = { critical:'error', high:'error', medium:'warning', low:'note', info:'none' };
  const allFindingsForSarif = [
    ...(credentials || []).map(f => ({ ...f, category: f.category || 'Credential' })),
    ...(security || []).map(f => ({ ...f, category: f.category || 'Security' })),
    ...(extendedFindings || []),
  ];
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'omega-sast',
          version: VERSION,
          informationUri: 'https://github.com/Black0ffR/omega-sast',
          rules: [...new Set(allFindingsForSarif.map(f => f.id || f.category))].map(id => ({
            id,
            name: id,
            shortDescription: { text: id },
            properties: { category: 'Security' },
          })),
        },
      },
      results: allFindingsForSarif.map((f, i) => {
        const hash = crypto.createHash('sha1').update(String(f.value || '') + String(f.pos || i)).digest('hex');
        return {
          ruleId: f.id || f.category,
          level: sevToSarif[f.severity] || 'note',
          message: { text: `${f.category || ''}: ${f.value || f.description || ''}`.trim() },
          locations: f.pos ? [{
            physicalLocation: {
              artifactLocation: { uri: data.meta.file },
              region: { offset: f.pos, length: (f.value || '').length || 1 },
            },
          }] : undefined,
          partialFingerprints: { primaryLocationLineHash: hash },
        };
      }),
    }],
  };
  fs.writeFileSync(path.join(outDir, 'report.sarif'), JSON.stringify(sarif, null, 2));

  // ─── Markdown ───────────────────────────────────────────────────────────
  const sa = storageAudit || { localStorage:[], sessionStorage:[], cookies:[], totalKeys:0, sensitiveCount:0 };
  const auth = authSurface || { guardedRoutes:[], unguardedRoutes:[], btoaMisuse:[] };
  const ccf  = charCodeFindings || [];

  const md = [
    `# JS Decoder OMEGA v5 Report`,
    `**File:** ${meta.file}  **Size:** ${meta.size}  **Date:** ${meta.date}`,
    `**Version:** ${VERSION}`,
    '',
    attackScore ? [
      `## ⚡ Attack Surface Score: ${attackScore.score} [${attackScore.risk}]`,
      `**Top categories:** ${attackScore.topCategories.join(' · ')}`,
      '',
    ].join('\n') : '',

    // ─── OMEGA-5.0 AST Structural Section ──────────────────────────────────
    useAst && astFwFindings ? [
      `## ⚙️ OMEGA-5.0 — AST Structural Analysis`,
      ``,
      `### Phase 9b-T1 — AST Framework Detection (replaces regex with class-body walk)`,
      ``,
      `**Angular (AST):** components=${astFwFindings.angular.components}  services=${astFwFindings.angular.services}  modules=${astFwFindings.angular.modules}  pipes=${astFwFindings.angular.pipes}  directives=${astFwFindings.angular.directives}  total_classes=${astFwFindings.angular.total}`,
      `**Vue (AST):** components≈${astFwFindings.vue.components}  hits=${astFwFindings.vue.total}`,
      `**React (AST):** components≈${astFwFindings.react.components}  hits=${astFwFindings.react.total}`,
      ``,
      `### Phase 13c — Bundler Detection`,
      ``,
      bundlerInfo && bundlerInfo.primary
        ? `- Detected patterns: ${bundlerInfo.detected.join(', ') || 'none'}\n- Primary: \`${bundlerInfo.primary}\`  ESM=${bundlerInfo.isEsm}  IIFE=${bundlerInfo.isIife}`
        : '_No bundler signature detected_',
      ``,
      `### Phase 13b — Webpack 5 Dynamic Module Graph`,
      ``,
      webpackGraph && webpackGraph.moduleCount > 0
        ? [
            `- Modules resolved: **${webpackGraph.moduleCount}**`,
            `- Module-to-module edges: **${webpackGraph.edges.length}**`,
            `- Top modules by outgoing d(N) usage:`,
            ...webpackGraph.modules
              .slice()
              .sort((a,b)=>b.uses.length-a.uses.length)
              .slice(0,10)
              .map(m => `  - \`mod-${m.id}\` → uses [${m.uses.join(', ')}]`),
          ].join('\n')
        : '_No webpack 5 module runtime detected_',
      ``,
      `### Phase 14b — Call Graph Builder`,
      ``,
      callGraph
        ? [
            `- Functions discovered: ${callGraph.stats.functions}`,
            `- Function-level call sites: ${callGraph.stats.callSites}`,
            `- Module-level edges: ${callGraph.stats.moduleEdges}`,
            `- Entry points (no inbound callers): ${callGraph.stats.entryPoints}`,
            `- Orphan functions (no callers, no callees): ${callGraph.orphanFunctions.length}`,
          ].join('\n')
        : '_call graph not built_',
      ``,
      `### Phase 14c — AST Cross-Statement Taint Flows (${(astTaint||[]).length})`,
      ``,
      (astTaint||[]).length
        ? astTaint.slice(0,20).map(f => {
            const chain = (f.chain || []).map(c => `\`${c.name || c.expr}\``).join(' → ');
            return `- **[${(f.severity||'info').toUpperCase()}]** ${f.cwe || ''}  ${chain}  — _${(f.description || '').slice(0,140)}_`;
          }).join('\n')
        : '_No cross-statement taint flows detected_',
      ``,
      `### Phase 12o — Modern Crypto Patterns (${(modernCrypto||[]).length})`,
      ``,
      (modernCrypto||[]).length
        ? modernCrypto.slice(0,20).map(f => {
            let line = `- **[${(f.severity||'info').toUpperCase()}]** [${f.id}] \`${f.value ? f.value.slice(0,100) : ''}\`\n  ${f.description}`;
            if (f.jwtPayload) line += `\n  JWT payload: \`${f.jwtPayload}\``;
            return line;
          }).join('\n\n')
        : '_No modern crypto patterns detected_',
      ``,
      `### Phase 12p — Network Surface`,
      ``,
      networkSurface
        ? [
            `- **${networkSurface.totalUrls}** URLs across **${networkSurface.uniqueHosts}** unique hosts`,
            networkSurface.hostClusters.length
              ? `- Top hosts:\n${networkSurface.hostClusters.slice(0,10).map(h => `  - \`${h.host}\` × ${h.count}`).join('\n')}`
              : '',
            networkSurface.findings.length
              ? `- **Cloud metadata / RFC1918 / public IP findings:**\n${networkSurface.findings.slice(0,15).map(f => `  - **[${(f.severity||'info').toUpperCase()}]** \`${f.value}\` — ${f.description}`).join('\n')}`
              : '',
          ].filter(Boolean).join('\n')
        : '_no network surface extracted_',
      ``,
    ].join('\n') : '',

    `## Frameworks Detected (A1 — Regex Confidence-Scored)`,
    (frameworks._details || frameworks.map(f=>({name:f,confidence:'?'}))).map(
      f => `- **${f.name}** (confidence: ${f.confidence || '?'})`
    ).join('\n'),
    '',
    `## A2 — Route-Endpoint Correlation`,
    (authSurface.unprotectedEndpoints||[]).length
      ? (authSurface.unprotectedEndpoints||[]).map(e => `- ⚠ \`${e.endpoint}\` — ${e.risk}`).join('\n')
      : '_No unprotected endpoints detected_',
    '',
    `## Phase 2b — CharCode Obfuscation Decoded`,
    ccf.length
      ? ccf.map(f => `- \`"${f.decoded}"\` ← seed=${f.seed}, expr=\`${f.offsetExpr}\``).join('\n')
      : '_No CharCode-obfuscated strings detected_',
    '',
    `## Phase 5b — Framework Symbol Annotation`,
    `- Frameworks annotated: ${frameworkSymStats.frameworks.join(', ') || '_none_'}`,
    `- Symbols resolved: ${frameworkSymStats.symbolsAnnotated}`,
    '',
    `## Phase 8b — Storage Key Attack Surface (${sa.totalKeys} keys, ${sa.sensitiveCount} sensitive)`,
    `### localStorage`,
    sa.localStorage.length
      ? sa.localStorage.map(e => `- ${e.sensitive?'🔴':'○'} \`${e.key}\` — ops: ${e.ops.join(',')}`).join('\n')
      : '_none_',
    `### sessionStorage`,
    sa.sessionStorage.length
      ? sa.sessionStorage.map(e => `- ${e.sensitive?'🔴':'○'} \`${e.key}\` — ops: ${e.ops.join(',')}`).join('\n')
      : '_none_',
    `### Cookies (cookieService)`,
    sa.cookies.length
      ? sa.cookies.map(e => `- ${e.sensitive?'🔴':'○'} \`${e.key}\` — ops: ${e.ops.join(',')}`).join('\n')
      : '_none_',
    '',
    `## Phase 8c — Auth Surface Map`,
    `### Guarded Routes`,
    auth.guardedRoutes.length
      ? auth.guardedRoutes.map(r => `- \`${r.path}\` — guards: \`[${r.guards.join(', ')}]\``).join('\n')
      : '_none_',
    `### ⚠ Unguarded High-Value Routes`,
    auth.unguardedRoutes.length
      ? auth.unguardedRoutes.map(r => `- **${r.path}** — ${r.risk}`).join('\n')
      : '_All high-value routes appear guarded_',
    `### Broken Crypto (btoa misuse)`,
    auth.btoaMisuse.length
      ? auth.btoaMisuse.map(b => `- \`btoa(${b.expr})\` — ${b.note}`).join('\n')
      : '_none_',
    '',
    `## Code Analysis`,
    `| Metric | Value |`,
    `|---|---|`,
    `| Functions | ${analysis.functions} |`,
    `| Classes | ${analysis.classes} |`,
    `| Angular Components | ${analysis.components} |`,
    `| Angular Services | ${analysis.services} |`,
    `| Angular Pipes | ${analysis.pipes} |`,
    `| React Components (est.) | ${analysis.reactComponents} |`,
    `| Vue Components (est.) | ${analysis.vueComponents} |`,
    `| Svelte Components (est.) | ${analysis.svelteComponents} |`,
    `| HTTP Calls | ${analysis.httpCalls} |`,
    `| Cyclomatic Complexity | ${analysis.cyclomatic} |`,
    `| Max Nesting Depth | ${analysis.maxNesting} |`,
    `| eval() calls | ${analysis.evalCalls} |`,
    '',
    `## Angular Route Guards`,
    analysis.routeGuards.length
      ? analysis.routeGuards.map(g => `- \`canActivate: [${g}]\``).join('\n')
      : '_None detected_',
    '',
    `## Socket.io Event Surface`,
    `**Emit →** ${analysis.socketEmits.join(', ') || '_none_'}`,
    `**On   ←** ${analysis.socketOns.join(', ') || '_none_'}`,
    '',
    `## Core Security Findings (${credentials.length + security.length} total)`,
    ...[...credentials, ...security]
      .sort((a,b) => { const o={critical:0,high:1,medium:2,low:3,info:4}; return (o[a.severity||a.sev]||4)-(o[b.severity||b.sev]||4); })
      .slice(0,40)
      .map(f => `- **[${(f.severity||f.sev||'info').toUpperCase()}]** ${f.name||f.category||''} — \`${(f.value||'').slice(0,80)}\``),
    '',
    `## Extended Security Findings — OMEGA-4.0 (${ext.length} total)`,
    ext.length ? [
      ...ext.sort((a,b) => { const o={critical:0,high:1,medium:2,low:3,info:4}; return (o[a.severity]||4)-(o[b.severity]||4); })
        .slice(0,60)
        .map(f=>`- **[${(f.severity||'info').toUpperCase()}]** [${f.category||f.id||''}] ${f.value||''} — ${(f.description||'').slice(0,100)}`),
    ] : ['_None detected_'],
    '',
    `## Routes & Endpoints (${routes.length})`,
    ...routes.slice(0,30).map(r => `- \`[${r.type}${r.guarded?' GUARDED':''}]\` ${r.path}${r.note?' *('+r.note+')*':''}`),
    routes.length > 30 ? `\n_...and ${routes.length-30} more. See routes.txt_` : '',
    '',
    `## Decode Statistics`,
    Object.entries(decodeStats).map(([k,v]) => `- ${k}: ${v}`).join('\n'),
  ].join('\n');
  fs.writeFileSync(path.join(outDir, 'report.md'), md);

  // ─── HTML ───────────────────────────────────────────────────────────────
  const allFindings = [...credentials, ...security, ...ext].sort(
    (a,b) => { const o={critical:0,high:1,medium:2,low:3,info:4}; return (o[a.severity||a.sev]||4)-(o[b.severity||b.sev]||4); }
  );
  const critical = allFindings.filter(f => (f.severity||f.sev) === 'critical').length;
  const high     = allFindings.filter(f => (f.severity||f.sev) === 'high').length;
  const sa2 = storageAudit || { localStorage:[], sessionStorage:[], cookies:[], totalKeys:0, sensitiveCount:0 };
  const auth2 = authSurface || { guardedRoutes:[], unguardedRoutes:[], btoaMisuse:[] };
  const ccf2  = charCodeFindings || [];

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Decoder OMEGA v5 — ${meta.file}</title>
<style>
  :root{--bg:#0d0d0d;--bg2:#1a1a1a;--bg3:#252525;--text:#e8e8e8;--dim:#888;
    --crit:#ff4444;--high:#ff8800;--med:#ffcc00;--low:#88cc00;--info:#44aaff;
    --accent:#4488ff;--green:#44cc88;--border:#333}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;font-size:13px;line-height:1.6}
  header{background:var(--bg2);border-bottom:2px solid var(--accent);padding:20px 32px;display:flex;justify-content:space-between;align-items:center}
  header h1{font-size:1.4em;color:var(--accent)}
  header .meta{color:var(--dim);font-size:11px;text-align:right}
  .container{max-width:1400px;margin:0 auto;padding:24px 32px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
  .card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px}
  .card h3{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px}
  .card .val{font-size:2em;font-weight:bold;color:var(--text)}
  .card.crit .val{color:var(--crit)}.card.high .val{color:var(--high)}.card.good .val{color:var(--green)}
  section{margin-bottom:32px}
  section h2{font-size:1em;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:16px;text-transform:uppercase;letter-spacing:.1em}
  table{width:100%;border-collapse:collapse}
  th{background:var(--bg3);color:var(--dim);font-size:11px;text-transform:uppercase;padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)}
  td{padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px;vertical-align:top;word-break:break-all}
  tr:hover td{background:var(--bg3)}
  .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:bold;text-transform:uppercase}
  .badge-critical{background:#5c0000;color:var(--crit)}.badge-high{background:#4a2600;color:var(--high)}
  .badge-medium{background:#3d3300;color:var(--med)}.badge-low{background:#1a2e00;color:var(--low)}
  .badge-info{background:#001a3d;color:var(--info)}
  .code{color:var(--dim);font-size:11px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:2px 6px;margin:2px;font-size:11px;color:var(--accent)}
  .fw-badge{background:var(--accent);color:#000;border-radius:3px;padding:4px 10px;font-size:11px;font-weight:bold;display:inline-block;margin:2px}
  .fw-badge.new5b{background:#44cc88;color:#000}
  .socket-tag{background:var(--bg3);border-radius:3px;padding:2px 6px;margin:2px;display:inline-block;font-size:11px;color:#ff8844}
  .route-type{color:var(--dim);font-size:10px;margin-right:6px}
  .route-guarded{color:var(--green);font-size:10px;margin-left:4px;font-weight:bold}
  .route-hidden{color:var(--magenta,#cc44ff);font-size:10px;margin-left:4px;font-weight:bold}
  .storage-row-sensitive td:first-child{color:var(--crit)}
  .unguarded-badge{display:inline-block;background:#4a0000;color:var(--crit);padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;margin-left:6px}
  .cc-decoded{color:var(--cyan,#44ffee);font-family:monospace}
  footer{text-align:center;color:var(--dim);font-size:11px;padding:24px;border-top:1px solid var(--border);margin-top:32px}
</style>
</head>
<body>
<header>
  <h1>🔍 JS Decoder OMEGA v5</h1>
  <div class="meta">
    <div><strong>File:</strong> ${meta.file}</div>
    <div><strong>Size:</strong> ${meta.size}</div>
    <div><strong>Date:</strong> ${meta.date}</div>
    <div><strong>Version:</strong> ${VERSION}</div>
  </div>
</header>
<div class="container">

<div class="grid">
  ${attackScore ? `<div class="card ${attackScore.risk==='CRITICAL'?'crit':attackScore.risk==='HIGH'?'high':'good'}"><h3>Attack Score</h3><div class="val">${attackScore.score}</div><div style="color:var(--dim);font-size:10px">${attackScore.risk}</div></div>` : ''}
  <div class="card ${critical>0?'crit':'good'}"><h3>Critical</h3><div class="val">${critical}</div></div>
  <div class="card ${high>0?'high':'good'}"><h3>High</h3><div class="val">${high}</div></div>
  <div class="card"><h3>Total Findings</h3><div class="val">${allFindings.length}</div></div>
  <div class="card"><h3>Routes</h3><div class="val">${routes.length}</div></div>
  <div class="card ${auth2.unguardedRoutes.length>0?'high':'good'}"><h3>Unguarded</h3><div class="val">${auth2.unguardedRoutes.length}</div></div>
  <div class="card ${(auth2.unprotectedEndpoints||[]).length>0?'high':'good'}"><h3>Unprotected EPs</h3><div class="val">${(auth2.unprotectedEndpoints||[]).length}</div></div>
  <div class="card"><h3>Storage Keys</h3><div class="val">${sa2.totalKeys}</div></div>
  <div class="card"><h3>Symbols Annotated</h3><div class="val">${frameworkSymStats.symbolsAnnotated}</div></div>
  <div class="card"><h3>Functions</h3><div class="val">${analysis.functions}</div></div>
  <div class="card"><h3>Cyclomatic</h3><div class="val">${analysis.cyclomatic}</div></div>
</div>

${attackScore ? `
<section>
  <h2>⚡ Attack Surface Prioritisation (B14)</h2>
  <div style="margin-bottom:12px">
    <span style="font-size:2em;font-weight:bold;color:${attackScore.risk==='CRITICAL'?'var(--crit)':attackScore.risk==='HIGH'?'var(--high)':'var(--green)'}">
      Score: ${attackScore.score} [${attackScore.risk}]
    </span>
  </div>
  <table>
    <tr><th>Category</th><th>Points</th></tr>
    ${Object.entries(attackScore.breakdown).sort((a,b)=>b[1]-a[1]).map(([cat,pts])=>`
    <tr><td>${cat}</td><td style="color:var(--high)">${pts}</td></tr>`).join('')}
  </table>
</section>` : ''}

<section>
  <h2>Frameworks Detected — A1 (Confidence-Scored)</h2>
  <div>${(frameworks._details || frameworks.map(f=>({name:f,confidence:'?'}))).map(f=>`<span class="fw-badge" title="confidence: ${f.confidence}">${f.name} <span style="opacity:0.6;font-size:9px">${Math.round((f.confidence||0)*100)}%</span></span>`).join('')}</div>
  ${auth2.unprotectedEndpoints && auth2.unprotectedEndpoints.length ? `
  <div style="margin-top:12px">
    <strong style="color:var(--high)">A2 — Potentially Unprotected Endpoints:</strong>
    <table style="margin-top:8px">
      <tr><th>Endpoint</th><th>Risk</th></tr>
      ${auth2.unprotectedEndpoints.map(e=>`<tr>
        <td class="code"><code>${e.endpoint}</code></td>
        <td style="color:var(--high);font-size:11px">${e.risk}</td>
      </tr>`).join('')}
    </table>
  </div>` : ''}
</section>

${ccf2.length ? `
<section>
  <h2>Phase 2b — CharCode Obfuscation Decoded (${ccf2.length})</h2>
  <table>
    <tr><th>Decoded String</th><th>Seed</th><th>Offset Expr</th></tr>
    ${ccf2.map(f=>`<tr><td class="cc-decoded">"${f.decoded}"</td><td>${f.seed}</td><td>${f.offsetExpr}</td></tr>`).join('')}
  </table>
</section>` : ''}

${useAst && astFwFindings ? `
<section>
  <h2>⚙️ OMEGA-5.0 AST Structural Analysis</h2>

  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 9b-T1 — AST Framework Detection <span style="color:var(--dim);font-size:10px">(replaces regex with class-body walk)</span></h3>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
      <div class="card">
        <h3>Angular (AST)</h3>
        <div style="font-size:14px;line-height:1.8">
          components: <b style="color:var(--green)">${astFwFindings.angular.components}</b><br>
          services: <b style="color:var(--green)">${astFwFindings.angular.services}</b><br>
          modules: <b style="color:var(--green)">${astFwFindings.angular.modules}</b><br>
          pipes: <b>${astFwFindings.angular.pipes}</b><br>
          directives: <b>${astFwFindings.angular.directives}</b><br>
          total classes: <b>${astFwFindings.angular.total}</b>
        </div>
      </div>
      <div class="card">
        <h3>Vue (AST hits)</h3>
        <div style="font-size:14px;line-height:1.8">
          createElementVNode / defineComponent / __vccOpts hits: <b>${astFwFindings.vue.total}</b><br>
          est. components: <b>${astFwFindings.vue.components}</b>
        </div>
      </div>
      <div class="card">
        <h3>React (AST hits)</h3>
        <div style="font-size:14px;line-height:1.8">
          createElement / jsx / forwardRef hits: <b>${astFwFindings.react.total}</b><br>
          est. components: <b>${astFwFindings.react.components}</b>
        </div>
      </div>
    </div>
  </div>

  ${bundlerInfo && bundlerInfo.primary ? `
  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 13c — Bundler Detection</h3>
    <div>Primary: <span class="fw-badge new5b">${bundlerInfo.primary}</span> ESM=${bundlerInfo.isEsm}  IIFE=${bundlerInfo.isIife}
      ${bundlerInfo.detected.length > 1 ? `<br><span style="color:var(--dim);font-size:11px">Also matched: ${bundlerInfo.detected.slice(1).join(', ')}</span>` : ''}
    </div>
  </div>` : ''}

  ${webpackGraph && webpackGraph.moduleCount > 0 ? `
  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 13b — Webpack 5 Dynamic Module Graph</h3>
    <div style="margin-bottom:8px;color:var(--dim);font-size:11px">
      ${webpackGraph.moduleCount} modules resolved, ${webpackGraph.edges.length} module-to-module edges
    </div>
    <table>
      <tr><th>Module ID</th><th>Outgoing d(N) uses</th></tr>
      ${webpackGraph.modules.slice().sort((a,b)=>b.uses.length-a.uses.length).slice(0,15).map(m=>`
      <tr>
        <td><code>mod-${m.id}</code></td>
        <td class="code">${m.uses.length > 0 ? m.uses.map(u => `mod-${u}`).join(', ') : '<span style="color:var(--dim)">none</span>'}</td>
      </tr>`).join('')}
    </table>
  </div>` : ''}

  ${callGraph ? `
  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 14b — Call Graph Builder</h3>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-bottom:12px">
      <div style="background:var(--bg3);padding:10px;border-radius:4px"><div style="color:var(--dim);font-size:11px">Functions</div><div style="font-size:20px;font-weight:bold">${callGraph.stats.functions}</div></div>
      <div style="background:var(--bg3);padding:10px;border-radius:4px"><div style="color:var(--dim);font-size:11px">Call sites</div><div style="font-size:20px;font-weight:bold">${callGraph.stats.callSites}</div></div>
      <div style="background:var(--bg3);padding:10px;border-radius:4px"><div style="color:var(--dim);font-size:11px">Module edges</div><div style="font-size:20px;font-weight:bold">${callGraph.stats.moduleEdges}</div></div>
      <div style="background:var(--bg3);padding:10px;border-radius:4px"><div style="color:var(--dim);font-size:11px">Entry points</div><div style="font-size:20px;font-weight:bold;color:var(--green)">${callGraph.stats.entryPoints}</div></div>
      <div style="background:var(--bg3);padding:10px;border-radius:4px"><div style="color:var(--dim);font-size:11px">Orphan fns</div><div style="font-size:20px;font-weight:bold;color:var(--high)">${callGraph.orphanFunctions.length}</div></div>
    </div>
  </div>` : ''}

  ${(astTaint||[]).length ? `
  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 14c — AST Cross-Statement Taint Flows (${(astTaint||[]).length})</h3>
    <table>
      <tr><th>Severity</th><th>CWE</th><th>Source → Function → Sink</th><th>Context</th></tr>
      ${astTaint.slice(0,20).map(f => {
        const chain = (f.chain || []).map(c =>
          `<span class="tag">${(c.name || c.expr || '').slice(0,40)}</span>`
        ).join(' → ');
        return `<tr>
          <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
          <td style="font-size:11px;color:var(--dim)">${f.cwe || ''}</td>
          <td style="font-size:11px">${chain}</td>
          <td class="code" title="${(f.context||'').replace(/"/g,'&quot;')}">${(f.context||'').replace(/</g,'&lt;').slice(0,80)}</td>
        </tr>`;
      }).join('')}
    </table>
  </div>` : ''}

  ${(modernCrypto||[]).length ? `
  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 12o — Modern Crypto Patterns (${(modernCrypto||[]).length})</h3>
    <table>
      <tr><th>Severity</th><th>Type</th><th>Match</th><th>Description</th></tr>
      ${modernCrypto.slice(0,25).map(f => `<tr>
        <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
        <td style="font-size:11px;color:var(--accent)">${f.id}</td>
        <td class="code" title="${(f.jwtPayload||'').slice(0,200)}">${(f.value||'').replace(/</g,'&lt;').slice(0,80)}</td>
        <td style="font-size:11px;color:var(--dim)">${(f.description||'').slice(0,140)}</td>
      </tr>`).join('')}
    </table>
  </div>` : ''}

  ${networkSurface ? `
  <div style="margin-bottom:16px">
    <h3 style="color:var(--accent);font-size:12px;margin-bottom:8px">Phase 12p — Network Surface</h3>
    <div style="margin-bottom:8px;color:var(--dim);font-size:12px">
      ${networkSurface.totalUrls} URLs across ${networkSurface.uniqueHosts} unique hosts
    </div>
    ${networkSurface.hostClusters.length ? `
    <table style="margin-bottom:12px">
      <tr><th>Host</th><th>Hits</th></tr>
      ${networkSurface.hostClusters.slice(0,12).map(h=>`<tr><td><code>${h.host}</code></td><td>${h.count}</td></tr>`).join('')}
    </table>` : ''}
    ${networkSurface.findings.length ? `
    <table>
      <tr><th>Severity</th><th>Type</th><th>Match</th><th>Description</th></tr>
      ${networkSurface.findings.slice(0,15).map(f => `<tr>
        <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
        <td style="font-size:11px;color:var(--accent)">${f.id}</td>
        <td class="code">${f.value}</td>
        <td style="font-size:11px;color:var(--dim)">${(f.description||'').slice(0,140)}</td>
      </tr>`).join('')}
    </table>` : ''}
  </div>` : ''}
</section>` : ''}

<section>
  <h2>Phase 5b — Multi-Framework Symbol Annotation</h2>
  <div style="margin-bottom:8px">
    <strong style="color:var(--dim)">Maps applied:</strong>
    ${frameworkSymStats.frameworks.map(f=>`<span class="fw-badge new5b">${f}</span>`).join('') || '<span style="color:var(--dim)">none detected</span>'}
  </div>
  <div><strong style="color:var(--dim)">Symbols resolved:</strong>
    <span style="color:var(--green);font-weight:bold">${frameworkSymStats.symbolsAnnotated}</span>
  </div>
</section>

<section>
  <h2>Phase 8b — Storage Key Attack Surface (${sa2.totalKeys} keys, ${sa2.sensitiveCount} sensitive)</h2>
  <table>
    <tr><th>Store</th><th>Key</th><th>Operations</th><th>Sensitive</th></tr>
    ${[
      ...sa2.localStorage.map(e=>({store:'localStorage',e})),
      ...sa2.sessionStorage.map(e=>({store:'sessionStorage',e})),
      ...sa2.cookies.map(e=>({store:'cookie',e})),
    ].map(({store,e})=>`<tr class="${e.sensitive?'storage-row-sensitive':''}">
      <td style="color:var(--dim);font-size:11px">${store}</td>
      <td><code>${e.key}</code></td>
      <td style="color:var(--dim)">${e.ops.join(', ')}</td>
      <td>${e.sensitive?'<span style="color:var(--crit)">🔴 YES</span>':'—'}</td>
    </tr>`).join('')}
  </table>
</section>

<section>
  <h2>Phase 8c — Auth Surface Map</h2>
  ${auth2.unguardedRoutes.length ? `
  <div style="margin-bottom:12px">
    <strong style="color:var(--crit)">⚠ Unguarded High-Value Routes (potential auth bypass):</strong>
    <table style="margin-top:8px">
      <tr><th>Route</th><th>Risk</th></tr>
      ${auth2.unguardedRoutes.map(r=>`<tr>
        <td><code>${r.path}</code><span class="unguarded-badge">NO GUARD</span></td>
        <td style="color:var(--high);font-size:11px">${r.risk}</td>
      </tr>`).join('')}
    </table>
  </div>` : '<div style="color:var(--green)">✔ All high-value routes appear guarded</div>'}

  ${auth2.guardedRoutes.length ? `
  <div style="margin-top:12px">
    <strong style="color:var(--dim)">Guarded Routes:</strong>
    <table style="margin-top:8px">
      <tr><th>Route</th><th>Guards</th></tr>
      ${auth2.guardedRoutes.map(r=>`<tr>
        <td><code>${r.path}</code></td>
        <td style="color:var(--accent)">[${r.guards.join(', ')}]</td>
      </tr>`).join('')}
    </table>
  </div>` : ''}

  ${auth2.btoaMisuse.length ? `
  <div style="margin-top:12px">
    <strong style="color:var(--crit)">🔴 Broken Crypto — btoa misuse (${auth2.btoaMisuse.length}):</strong>
    <table style="margin-top:8px">
      <tr><th>Expression</th><th>Note</th></tr>
      ${auth2.btoaMisuse.map(b=>`<tr>
        <td class="code"><code>btoa(${b.expr})</code></td>
        <td style="color:var(--high);font-size:11px">${b.note}</td>
      </tr>`).join('')}
    </table>
  </div>` : ''}

<section>
  <h2>Security Findings (${allFindings.length})</h2>
  <table>
    <tr><th>Severity</th><th>Type</th><th>Value / Match</th><th>Line</th></tr>
    ${allFindings.map(f=>`
    <tr>
      <td><span class="badge badge-${f.severity||f.sev}">${f.severity||f.sev}</span></td>
      <td>${f.name||f.category||f.id||''}</td>
      <td class="code" title="${(f.context||'').replace(/"/g,'&quot;')}">${(f.value||'').replace(/</g,'&lt;').slice(0,100)}</td>
      <td>${f.line||'—'}</td>
    </tr>`).join('')}
  </table>
</section>

<section>
  <h2>Angular Route Guards</h2>
  ${analysis.routeGuards.length
    ? analysis.routeGuards.map(g=>`<span class="tag">canActivate: [${g}]</span>`).join('')
    : '<span style="color:var(--dim)">None detected</span>'}
</section>

<section>
  <h2>Socket.io Event Surface</h2>
  <div><strong style="color:var(--dim)">Emit:</strong>
    ${analysis.socketEmits.map(e=>`<span class="socket-tag">→ ${e}</span>`).join('') || '<span style="color:var(--dim)">none</span>'}
  </div>
  <div style="margin-top:8px"><strong style="color:var(--dim)">On:</strong>
    ${analysis.socketOns.map(e=>`<span class="socket-tag">← ${e}</span>`).join('') || '<span style="color:var(--dim)">none</span>'}
  </div>
</section>

<section>
  <h2>Routes &amp; Endpoints (${routes.length})</h2>
  <table>
    <tr><th>Type</th><th>Path</th><th>Note</th></tr>
    ${routes.map(r=>`<tr>
      <td><span class="route-type">[${r.type}]</span>${r.guarded?'<span class="route-guarded">🔒</span>':''}${r.type==='Hidden-Decoded'?'<span class="route-hidden">⚠HIDDEN</span>':''}</td>
      <td class="code">${r.path}</td>
      <td style="color:var(--dim);font-size:10px">${r.note||''}</td>
    </tr>`).join('')}
  </table>
</section>

<section>
  <h2>Code Metrics</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    ${Object.entries({
      'Functions': analysis.functions,
      'Classes': analysis.classes,
      'Angular Components': analysis.components,
      'Angular Services': analysis.services,
      'Angular Pipes': analysis.pipes,
      'Angular Directives': analysis.directives,
      'React Components (est.)': analysis.reactComponents,
      'Vue Components (est.)': analysis.vueComponents,
      'Svelte Components (est.)': analysis.svelteComponents,
      'HTTP Calls': analysis.httpCalls,
      'Cyclomatic Complexity': analysis.cyclomatic,
      'Max Nesting Depth': analysis.maxNesting,
      'eval() calls': analysis.evalCalls,
    }).map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')}
  </table>
</section>

<section>
  <h2>Webpack Module Dependency Graph (top 20)</h2>
  <table>
    <tr><th>Module ID</th><th>Package</th><th>Uses</th></tr>
    ${graph.slice(0,20).map(g=>`<tr><td>${g.id}</td><td>${g.name}</td><td>${g.uses}</td></tr>`).join('')}
  </table>
</section>

<section>
  <h2>Decode Statistics</h2>
  <table>
    <tr><th>Type</th><th>Count</th></tr>
    ${Object.entries(decodeStats).map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')}
  </table>
</section>

${ext.length ? `
<section>
  <h2>Extended Security Findings — OMEGA-4.0 (${ext.length})</h2>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Description</th></tr>
    ${ext.sort((a,b) => { const o={critical:0,high:1,medium:2,low:3,info:4}; return (o[a.severity]||4)-(o[b.severity]||4); }).map(f=>`
    <tr>
      <td><span class="badge badge-${f.severity||'info'}">${f.severity||'info'}</span></td>
      <td style="color:var(--accent);font-size:11px">${f.category||f.id||''}</td>
      <td class="code" title="${(f.context||'').replace(/"/g,'&quot;')}">${(f.value||'').replace(/</g,'&lt;').slice(0,100)}</td>
      <td style="color:var(--dim);font-size:11px">${(f.description||'').slice(0,120)}</td>
    </tr>`).join('')}
  </table>
</section>` : ''}

</div>
<footer>Generated by JS Decoder OMEGA v5 ${VERSION} &mdash; AST-augmented, single-file pipeline</footer>
</body></html>`;
  fs.writeFileSync(path.join(outDir, 'report.html'), html);
}

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════════════
// ── In-memory OSV.dev response cache ──────────────────────────────────────
const OSV_CACHE = new Map();

// ═══════════════════════════════════════════════════════════════════════════
//  OSV.dev API query — fetches known vulnerabilities for a package+version
//  Uses Node built-in https (zero additional dependencies).
//  Caches responses in OSV_CACHE for the lifetime of the process.
// ═══════════════════════════════════════════════════════════════════════════
async function fetchOsvFindings(pkgVersions, verbose) {
  const findings = [];
  if (!pkgVersions || Object.keys(pkgVersions).length === 0) return findings;

  const https = require('https');
  const pkgEntries = Object.entries(pkgVersions);

  for (const [pkgName, ver] of pkgEntries) {
    const cacheKey = `${pkgName}@${ver}`;
    if (OSV_CACHE.has(cacheKey)) {
      const cached = OSV_CACHE.get(cacheKey);
      if (cached) findings.push(cached);
      continue;
    }

    try {
      const body = JSON.stringify({
        package: { name: pkgName, ecosystem: 'npm' },
        version: ver,
      });

      const result = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.osv.dev',
          path: '/v1/query',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
          timeout: 5000,
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            if (res.statusCode === 200) {
              try { resolve(JSON.parse(data)); }
              catch (e) { reject(new Error('OSV parse error')); }
            } else {
              resolve(null); // non-200 = skip silently
            }
          });
        });
        req.on('error', () => resolve(null)); // network error = skip silently
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.write(body);
        req.end();
      });

      if (result && result.vulns && result.vulns.length > 0) {
        for (const vuln of result.vulns) {
          const id = vuln.id || 'UNKNOWN';
          const desc = (vuln.summary || vuln.details || '').slice(0, 120);
          const f = {
            id: `osv-${pkgName.replace(/[/@]/g, '-')}-${id}`,
            category: 'Vulnerable Dependency',
            severity: vuln.database_specific?.severity === 'CRITICAL' ? 'critical'
                    : vuln.database_specific?.severity === 'HIGH' ? 'high'
                    : vuln.database_specific?.severity === 'MODERATE' ? 'medium'
                    : vuln.database_specific?.severity === 'LOW' ? 'low'
                    : 'medium',
            value: `${pkgName}@${ver}`,
            context: `${id}: ${desc}`,
            description: `${id}: ${desc}`,
          };
          OSV_CACHE.set(cacheKey, f);
          findings.push(f);
        }
      } else {
        OSV_CACHE.set(cacheKey, null); // cache no-find result
      }
    } catch (e) {
      // Network/parse errors are non-fatal
      if (verbose) console.error(`  OSV query failed for ${pkgName}@${ver}: ${e.message}`);
    }
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  External source map fetcher — uses Node built-in https (zero deps).
//  Resolves relative URLs against the bundle path.
// ═══════════════════════════════════════════════════════════════════════════
async function fetchExternalSourceMap(mapUrl, bundlePath) {
  try {
    // Resolve relative URLs against the bundle file path
    const url = mapUrl.startsWith('http://') || mapUrl.startsWith('https://')
      ? mapUrl
      : (bundlePath ? 'file://' + require('path').resolve(require('path').dirname(bundlePath), mapUrl) : mapUrl);

    // Only fetch http/https URLs; skip file:// (would need fs)
    if (!url.startsWith('http://') && !url.startsWith('https://')) return null;

    return await new Promise((resolve) => {
      const https = require('https');
      const http = require('http');
      const transport = url.startsWith('https://') ? https : http;
      const req = transport.get(url, { timeout: 8000 }, (res) => {
        if (res.statusCode !== 200) { resolve(null); return; }
        // Follow redirects (max 3)
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          resolve(fetchExternalSourceMap(res.headers.location, bundlePath));
          return;
        }
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const map = JSON.parse(data);
            if (!map || !map.version) { resolve(null); return; }
            // Decode VLQ mappings for position remapping
            const decodedLines = map.mappings
              ? ast.decodeVLQMappings(map.mappings)
              : [];
            resolve({
              sources: map.sources || [],
              sourceRoot: map.sourceRoot || null,
              sourceCount: (map.sources || []).length,
              mappings: map.mappings || '',
              decodedLines,
              names: map.names || [],
              isInline: false,
              isExternal: true,
              mapUrl,
            });
          } catch (e) { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    });
  } catch (e) { return null; }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Multi-bundle cross-analysis — scans multiple JS bundles, merges findings
//  with per-bundle attribution, and detects cross-bundle dependency conflicts.
// ═══════════════════════════════════════════════════════════════════════════
async function runMultiBundle(opts) {
  const t0 = Date.now();
  const inputList = opts.input.split(',').map(f => f.trim()).filter(f => f);
  if (inputList.length < 2) {
    console.error(fail('--multi mode requires at least 2 comma-separated input files'));
    process.exit(1);
  }

  const outDir = path.resolve(opts.out);
  fs.mkdirSync(outDir, { recursive: true });

  if (!opts.quiet) {
    console.log(`\n${C.bold}${C.cyan}JS Decoder OMEGA v5${C.reset} — ${C.bold}MULTI-BUNDLE MODE${C.reset}`);
    console.log(info(`Bundles: ${inputList.length} files`));
    console.log(info(`Output:  ${C.bold}${outDir}${C.reset}`));
  }

  const numWorkers = Math.min(inputList.length, os.cpus().length || 4);
  if (!opts.quiet) console.log(info(`Workers: ${numWorkers} parallel`));

  // ── Worker pool ──────────────────────────────────────────────────────────
  const results = new Array(inputList.length).fill(null);
  let nextIdx = 0;

  function spawnWorker(bundleIdx) {
    return new Promise((resolve) => {
      const { Worker } = require('worker_threads');
      const bundlePath = path.resolve(inputList[bundleIdx]);
      if (!fs.existsSync(bundlePath)) {
        resolve({ bundleIdx, error: `File not found: ${bundlePath}` });
        return;
      }
      const worker = new Worker(`
        const { parentPort, workerData } = require('worker_threads');
        const path = require('path');
        const fs = require('fs');
        const mainPath = ${JSON.stringify(path.resolve(__filename))};
        const omega = require(mainPath);
        async function runWorker() {
          try {
            // Build opts from workerData
            const wd = workerData;
            const opts = {
              input: wd.bundlePath,
              out: wd.outDir,
              quiet: true,
              secrets: wd.secrets, routes: wd.routes, security: wd.security,
              graph: wd.graph, report: wd.report, verbose: wd.verbose,
              ast: null, moduleMap: null, severityFloor: wd.severityFloor,
              maxHops: wd.maxHops, fetchCves: false, fetchSourcemaps: wd.fetchSourcemaps,
              multi: false, llmPayload: false, baseline: null, updateBaseline: false,
              watch: false, diff: null,
            };
            const summary = await omega.main(opts);
            // Read the JSON report to return findings data
            let findings;
            try {
              const reportPath = path.join(opts.out, 'report.json');
              if (fs.existsSync(reportPath)) {
                findings = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
              }
            } catch (_) {}
            parentPort.postMessage({ bundleIdx: wd.bundleIdx, summary, findings, success: true });
          } catch (e) {
            parentPort.postMessage({ bundleIdx: wd.bundleIdx, error: e.message, success: false });
          }
        }
        runWorker();
      `, { eval: true, workerData: { 
        bundleIdx,
        bundlePath,
        outDir: path.join(outDir, path.basename(bundlePath, path.extname(bundlePath))),
        secrets: opts.secrets, routes: opts.routes, security: opts.security,
        graph: opts.graph, report: opts.report, verbose: opts.verbose,
        severityFloor: opts.severityFloor, maxHops: opts.maxHops,
        fetchSourcemaps: opts.fetchSourcemaps,
      } });

      worker.on('message', (msg) => resolve(msg));
      worker.on('error', (err) => resolve({ bundleIdx, error: err.message, success: false }));
      worker.on('exit', (code) => {
        // If worker exits without sending message, create a placeholder
        resolve({ bundleIdx, error: `Worker exited with code ${code}`, success: false });
      });
    });
  }

  async function workerLoop() {
    const promises = [];
    for (let i = 0; i < numWorkers && nextIdx < inputList.length; i++) {
      const idx = nextIdx++;
      promises.push(spawnWorker(idx).then(r => { results[idx] = r; }));
    }
    while (nextIdx < inputList.length) {
      await Promise.race(promises);
      const idx = nextIdx++;
      promises.push(spawnWorker(idx).then(r => { results[idx] = r; }));
    }
    await Promise.all(promises);
  }

  await workerLoop();

  // ── Collect results ──────────────────────────────────────────────────────
  const bundleResults = [];
  for (let bi = 0; bi < inputList.length; bi++) {
    const bundlePath = path.resolve(inputList[bi]);
    const bundleName = path.basename(bundlePath, path.extname(bundlePath));
    if (!results[bi] || !results[bi].success) {
      console.error(warn(`Bundle ${bundleName}: ${results[bi] ? results[bi].error : 'unknown error'}`));
      continue;
    }
    const bundleSrc = fs.readFileSync(bundlePath, 'utf8');
    const bundleStat = fs.statSync(bundlePath);
    const bundleSha256 = crypto.createHash('sha256').update(bundleSrc).digest('hex');
    const deps = collectDependencies(bundleSrc);
    bundleResults.push({
      name: bundleName,
      path: bundlePath,
      size: bundleStat.size,
      sha256: bundleSha256,
      deps,
      summary: results[bi].summary,
    });
    if (!opts.quiet) {
      console.log(ok(`${bundleName}: ${(bundleStat.size/1024).toFixed(1)} KB, ${deps.length} deps, ${results[bi].summary ? results[bi].summary.totalFindings : '?'} findings`));
    }
  }

  // ── Cross-bundle version-conflict detection ──────────────────────────
  // Build a map: packageName → { versions: Set<bundleIndex>, bundles: [] }
  const pkgVersions = new Map();
  for (let bi = 0; bi < bundleResults.length; bi++) {
    const res = bundleResults[bi];
    for (const dep of res.deps) {
      const key = `${dep.name}`;
      if (!pkgVersions.has(key)) pkgVersions.set(key, new Map());
      const verMap = pkgVersions.get(key);
      if (!verMap.has(dep.version)) verMap.set(dep.version, []);
      verMap.get(dep.version).push(bi);
    }
  }

  const conflicts = [];
  for (const [pkgName, verMap] of pkgVersions) {
    if (verMap.size > 1) {
      const versions = [...verMap.keys()];
      const bundleSets = [...verMap.entries()].map(([ver, bis]) => ({
        version: ver,
        bundles: bis.map(i => bundleResults[i].name),
      }));
      conflicts.push({ package: pkgName, versions: bundleSets });
    }
  }

  // ── Generate combined report ──────────────────────────────────────────
  const conflictFindings = [];
  for (const c of conflicts) {
    const versionStr = c.versions.map(v => `${v.version} (${v.bundles.join(', ')})`).join(' vs ');
    conflictFindings.push({
      id: 'cross-bundle-version-conflict',
      category: 'Dependency Conflict',
      severity: 'medium',
      value: `"${c.package}" appears at different versions across bundles`,
      context: versionStr,
      description: `Version conflict for ${c.package}: ${versionStr}`,
    });

    if (!opts.quiet) {
      console.log(warn(`Version conflict: ${C.bold}${c.package}${C.reset} — ${versionStr}`));
    }
  }

  // ── Write combined findings to output ──────────────────────────────────
  const combined = {
    meta: {
      mode: 'multi-bundle',
      date: new Date().toISOString(),
      version: VERSION,
      bundles: bundleResults.map(r => ({
        name: r.name,
        size: `${(r.size/1024).toFixed(1)} KB`,
        sha256: r.sha256,
        deps: r.deps.length,
      })),
    },
    conflicts: conflictFindings.map(c => ({
      package: c.package,
      versions: c.versions,
    })),
    findings: conflictFindings,
  };

  fs.writeFileSync(path.join(outDir, 'multi-report.json'), JSON.stringify(combined, null, 2));
  if (!opts.quiet) {
    console.log(ok(`Multi-bundle report: ${C.bold}${path.join(outDir, 'multi-report.json')}${C.reset}`));
  }

  const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
  if (!opts.quiet) {
    console.log(`\n${C.green}${C.bold}✔ Multi-bundle complete${C.reset} — ${elapsed}s — ${bundleResults.length} bundles, ${conflicts.length} conflicts.\n`);
  }

  return {
    elapsed: parseFloat(elapsed),
    totalFindings: conflictFindings.length,
    criticalCount: 0,
    highCount: 0,
    mediumCount: conflictFindings.length,
    attackScore: 0,
    attackRisk: 'UNKNOWN',
  };
}

// Helper: collect dependencies from a JS bundle source by matching
// common patterns: webpack module IDs, import statements, require() calls.
function collectDependencies(src) {
  const deps = [];
  const seen = new Set();

  // Webpack module map patterns: "1234": "@scope/pkg"
  // Regular require: require('pkg')
  // Import: import('pkg') or import x from 'pkg'
  // Also match version comments: /* 12.3.4 */
  const patterns = [
    // Webpack module map entries
    { re: /"(\d+)":\s*"(@[^"]+|[^"]+)"\s*,?/g, nameIdx: 2, verIdx: -1 },
    // require('pkg')
    { re: /(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/g, nameIdx: 1, verIdx: -1 },
    // @preset CDN version comments: /*! pkg@1.2.3 */
    { re: /\/\*[!*]\s*([^\s@]+)@(\d+\.\d+(?:\.\d+)?)/g, nameIdx: 1, verIdx: 2 },
  ];

  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(src)) !== null) {
      const name = m[p.nameIdx];
      const version = p.verIdx >= 0 ? (m[p.verIdx] || 'unknown') : 'unknown';
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push({ name, version });
      }
    }
  }

  return deps;
}

// ── Baseline suppression (.omega-ignore) ────────────────────────────────
// JSON format: [{ id, file?, reason?, expires? }]
// Findings matching id + file are moved to a `suppressed` array.
function loadBaseline(path) {
  try {
    const raw = fs.readFileSync(path, 'utf8');
    return JSON.parse(raw);
  } catch (_) { return []; }
}

function applyBaseline(findings, baseline, filename) {
  if (!baseline || !baseline.length) return { findings, suppressed: [] };
  const suppressed = [];
  const kept = [];
  const now = Date.now();
  for (const f of findings) {
    const match = baseline.some(b => {
      if (b.expires && new Date(b.expires).getTime() < now) return false;
      if (b.id && b.id !== (f.id || f.category)) return false;
      if (b.file && b.file !== filename) return false;
      return true;
    });
    if (match) {
      suppressed.push({ ...f, suppressedBy: b => b.id });
    } else {
      kept.push(f);
    }
  }
  return { findings: kept, suppressed };
}

function generateBaseline(findings) {
  const seen = new Set();
  return findings.map(f => {
    const id = f.id || f.category;
    if (seen.has(id)) return null;
    seen.add(id);
    return { id, reason: 'review', expires: new Date(Date.now() + 90*86400000).toISOString().split('T')[0] };
  }).filter(Boolean);
}

// ── Diff mode ─────────────────────────────────────────────────────────────
// Load previous report.json, compare finding IDs + values, return only new findings.
function loadPreviousFindings(path) {
  try {
    const raw = fs.readFileSync(path, 'utf8');
    const report = JSON.parse(raw);
    const prev = [];
    for (const key of ['credentials', 'security', 'extendedFindings']) {
      if (Array.isArray(report[key])) prev.push(...report[key]);
    }
    return prev;
  } catch (_) { return null; }
}

function diffFindings(current, previous) {
  if (!previous) return current;
  const prevSet = new Set(previous.map(f => `${f.id || f.category}::${f.value || ''}`));
  return current.filter(f => !prevSet.has(`${f.id || f.category}::${f.value || ''}`));
}

async function main(externalOpts) {
  const opts = externalOpts || parseArgs();
  const t0   = Date.now();

  // ── Validate severity-floor ────────────────────────────────────────────
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  if (!SEV_ORDER.includes(opts.severityFloor)) {
    console.error(fail(`Invalid --severity-floor "${opts.severityFloor}". Must be one of: ${SEV_ORDER.join(', ')}`));
    process.exit(1);
  }

  // ── Load external module map if provided ───────────────────────────────
  // Merges user-supplied entries WITH the built-in WEBPACK_MODULE_MAP.
  // User entries take precedence (override built-ins for the same ID).
  if (opts.moduleMap) {
    const mapPath = path.resolve(opts.moduleMap);
    if (!fs.existsSync(mapPath)) {
      console.error(fail(`Module map file not found: ${mapPath}`));
      process.exit(1);
    }
    try {
      const userMap = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
      let merged = 0;
      for (const [id, name] of Object.entries(userMap)) {
        if (typeof id === 'string' && typeof name === 'string') {
          WEBPACK_MODULE_MAP[id] = name;
          merged++;
        }
      }
      console.log(ok(`Loaded ${merged} module-id mappings from ${path.basename(mapPath)}`));
    } catch (e) {
      console.error(fail(`Failed to parse module map JSON: ${e.message}`));
      process.exit(1);
    }
  }

  // ── Multi-bundle mode ──────────────────────────────────────────────────
  if (opts.multi) {
    return await runMultiBundle(opts);
  }

  const inputPath = path.resolve(opts.input);
  if (!fs.existsSync(inputPath)) {
    console.error(fail(`File not found: ${inputPath}`)); process.exit(1);
  }
  const stat = fs.statSync(inputPath);
  const sizeMB = stat.size / 1024 / 1024;
  if (sizeMB > MAX_FILE_MB) {
    console.error(fail(`File too large (${sizeMB.toFixed(1)} MB > ${MAX_FILE_MB} MB limit)`));
    process.exit(1);
  }

  const outDir = path.resolve(opts.out);
  fs.mkdirSync(outDir, { recursive: true });
  if (opts.splitModules) fs.mkdirSync(path.join(outDir,'modules'),{recursive:true});

  if (!opts.quiet) {
    console.log(`\n${C.bold}${C.cyan}JS Decoder OMEGA v5${C.reset} ${VERSION}`);
    console.log(info(`Input:  ${C.bold}${path.basename(inputPath)}${C.reset} (${(stat.size/1024).toFixed(1)} KB)`));
    console.log(info(`Output: ${C.bold}${outDir}${C.reset}`));
  }

  let src = fs.readFileSync(inputPath, 'utf8');

  if (!opts.quiet) console.log(head('DECODING'));

  // Phase 0
  if (opts.verbose) console.log(info('  Phase 0: Module alias resolution…'));
  const { aliases, count: aliasCount } = resolveModuleAliases(src, opts);

  // Phase 1
  if (opts.verbose) console.log(info('  Phase 1: Escape decoding…'));
  const { src: src1, stats: escStats } = decodeEscapes(src);
  src = src1;

  // Phase 2
  if (opts.verbose) console.log(info('  Phase 2: String decoding (10-pass)…'));
  const { src: src2, stats: strStats } = decodeStrings(src);
  src = src2;

  // Phase 2b — CharCode obfuscation decoder
  if (opts.verbose) console.log(info('  Phase 2b: CharCode obfuscation decoding…'));
  const { src: src2b, findings: charCodeFindings } = decodeCharCodeObfuscation(src);
  src = src2b;
  if (charCodeFindings.length && !opts.quiet) {
    console.log(ok(`Phase 2b decoded ${charCodeFindings.length} CharCode-obfuscated string(s):`));
    charCodeFindings.forEach(f => console.log(`  ${C.cyan}→${C.reset} "${f.decoded}"  (seed=${f.seed}, expr=${f.offsetExpr})`));
  }

  // Phase 2c — obfuscator.io string-array decoder (Stage 5)
  if (opts.verbose) console.log(info('  Phase 2c: obfuscator.io string-array decoder…'));
  const { src: src2c, findings: obfIoFindings, decodedStrings: obfIoDecoded } = decodeObfuscatorIo(src);
  src = src2c;
  if (obfIoFindings.length && !opts.quiet) {
    console.log(ok(`Phase 2c: obfuscator.io decoder — ${obfIoDecoded.length} strings decoded`));
    obfIoDecoded.slice(0, 10).forEach(d => console.log(`  ${C.cyan}→${C.reset} "${d.decoded.slice(0,40)}"  (idx=${d.idx}${d.key ? ', RC4' : ''})`));
  }

  // Phase 2d — constant-expression evaluator (Stage 5)
  if (opts.verbose) console.log(info('  Phase 2d: constant-expression evaluator…'));
  const { src: src2d, findings: constExprFindings } = evaluateConstantExpressions(src);
  src = src2d;
  if (constExprFindings.length && !opts.quiet) {
    console.log(ok(`Phase 2d: ${constExprFindings.length} constant expressions evaluated`));
  }

  // Phase 3
  if (opts.verbose) console.log(info('  Phase 3: Boolean normalisation…'));
  src = normaliseBooleans(src);

  // Phase 4
  if (opts.verbose) console.log(info('  Phase 4: Webpack cleanup…'));
  src = cleanupWebpack(src);

  // Phase 5 — Angular Ivy
  if (opts.verbose) console.log(info('  Phase 5: Angular Ivy annotation (110+ instructions)…'));
  src = annotateAngularIvy(src);

  // Phase 5b — Multi-framework
  if (opts.verbose) console.log(info('  Phase 5b: Multi-framework symbol annotation…'));
  const { src: src5b, hits: fwHits, stats: frameworkSymStats } = annotateFrameworkSymbols(src, opts);
  src = src5b;

  if (frameworkSymStats.frameworks.length) {
    if (!opts.quiet) console.log(ok(`Phase 5b annotated: ${C.bold}${frameworkSymStats.frameworks.join(', ')}${C.reset}  (${frameworkSymStats.symbolsAnnotated} symbols)`));
  } else if (!opts.quiet) {
    console.log(info('Phase 5b: No multi-framework symbols detected.'));
  }

  // Phase 6 — RxJS
  if (opts.verbose) console.log(info('  Phase 6: RxJS operator annotation…'));
  src = annotateRxJS(src);

  // Phase 7 — Beautify
  // Save pre-beautify src for route extraction (some patterns are cleaner before formatting)
  const srcPreBeautify = src;
  if (opts.beautify) {
    if (opts.verbose) console.log(info('  Phase 7: Token-based beautification…'));
    src = beautify(src);
  }

  const decodedPath = path.join(outDir, path.basename(inputPath, '.js') + '.decoded.js');
  fs.writeFileSync(decodedPath, src);
  if (!opts.quiet) {
    console.log(ok(`Decoded output: ${C.bold}${decodedPath}${C.reset}`));
    console.log(info(`Original size:  ${(stat.size/1024).toFixed(1)} KB`));
    console.log(info(`Decoded size:   ${(Buffer.byteLength(src)/1024).toFixed(1)} KB (${(Buffer.byteLength(src)/stat.size*100).toFixed(1)}% of original)`));
  }

  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(inputPath)).digest('hex').slice(0,16);
  if (!opts.quiet) console.log(info(`File SHA-256:   ${sha256}…`));

  if (!opts.quiet) console.log(head('ANALYSIS'));

  // Phase 8
  if (opts.verbose && !opts.quiet) console.log(info('  Phase 8: Code structure analysis…'));
  const analysis = analyseCode(src);

  // Phase 8b — Storage key audit
  if (opts.verbose && !opts.quiet) console.log(info('  Phase 8b: Storage key audit…'));
  const storageAudit = auditStorageKeys(src);
  if (!opts.quiet) console.log(info(`Storage keys: ${storageAudit.totalKeys} total (${storageAudit.sensitiveCount} sensitive)`));

  // Phase 8c — Auth surface mapper
  if (opts.verbose && !opts.quiet) console.log(info('  Phase 8c: Auth surface mapping…'));
  const authSurface = mapAuthSurface(src);
  if (!opts.quiet) {
    if (authSurface.unguardedRoutes.length)
      console.log(warn(`Unguarded high-value routes: ${C.bold}${authSurface.unguardedRoutes.length}${C.reset}`));
    if (authSurface.btoaMisuse.length)
      console.log(warn(`Broken crypto (btoa misuse): ${C.bold}${authSurface.btoaMisuse.length}${C.reset} instance(s)`))
  }

  // Phase 9
  if (opts.verbose && !opts.quiet) console.log(info('  Phase 9: Framework detection…'));
  const frameworks = detectFrameworks(src);
  const fwNames = frameworks.join(', ');
  // Zero-out component estimates when framework not detected — prevents jQuery
  // function patterns (return <HTML>, createElement, etc.) from falsely inflating
  // React/Vue component counts in minified non-React/Vue bundles.
  if (!fwNames.includes('React')) analysis.reactComponents = 0;
  if (!fwNames.includes('Vue')) analysis.vueComponents = 0;
  if (!fwNames.includes('Svelte')) analysis.svelteComponents = 0;
  if (!opts.quiet) {
    console.log(info(`Frameworks: ${C.bold}${fwNames}${C.reset}`));
    console.log(info(`Angular: ${analysis.components} components, ${analysis.services} services, ${analysis.pipes} pipes`));
    console.log(info(`React (est.): ${analysis.reactComponents}  Vue (est.): ${analysis.vueComponents}  Svelte (est.): ${analysis.svelteComponents}`));
    console.log(info(`Functions: ${analysis.functions}  Classes: ${analysis.classes}  Cyclomatic: ${analysis.cyclomatic}  MaxNest: ${analysis.maxNesting}`));
    console.log(info(`HTTP calls: ${analysis.httpCalls}  eval(): ${analysis.evalCalls}`));

    if (analysis.routeGuards.length)
      console.log(info(`Route guards: ${analysis.routeGuards.length}`));
    if (analysis.socketEmits.length)
      console.log(info(`Socket.io emit surface: ${analysis.socketEmits.length} events`));
  }

  // Phase 10
  const routes = (opts.routes || opts.report) ? extractRoutes(src, charCodeFindings, srcPreBeautify) : [];

  // Phase 11
  // Dedup credentials by value: same string matched by multiple patterns
  // (e.g. Stripe Key + Hardcoded API Key) should appear only once.
  const credentials = (() => {
    const raw = (opts.secrets || opts.report) ? scanCredentials(src) : [];
    const rank = { critical:0, high:1, medium:2, low:3, info:4 };
    const seen = new Map();
    for (const f of raw) {
      const key = f.value.slice(0, 64);
      const existing = seen.get(key);
      if (!existing || (rank[f.severity] ?? 4) < (rank[existing.severity] ?? 4)) {
        seen.set(key, f);
      }
    }
    return [...seen.values()];
  })();

  // Phase 12
  const security = (opts.security || opts.report) ? analyseSecurity(src, opts.maxHops) : [];

  // Phase 12b — B1: Dynamic code execution
  if (opts.verbose) console.log(info('  Phase 12b: Dynamic code execution scan…'));
  const dynCodeFindings  = (opts.security || opts.report) ? scanDynamicCodeExecution(src) : [];

  // Phase 12c — C1: Business logic
  if (opts.verbose) console.log(info('  Phase 12c: Business logic scan…'));
  const bizLogicFindings = (opts.security || opts.report) ? scanBusinessLogic(src) : [];

  // Phase 12d — C2/C3: WebSocket / Socket.io content
  if (opts.verbose) console.log(info('  Phase 12d: WebSocket/Socket.io content analysis…'));
  const wsFindings       = (opts.security || opts.report) ? scanWebSocketContent(src) : [];

  // Phase 12e — C4: Cryptographic context
  if (opts.verbose) console.log(info('  Phase 12e: Cryptographic context analysis…'));
  const cryptoFindings   = (opts.security || opts.report) ? scanCryptoContext(src) : [];

  // Phase 12f — C5: Information leakage
  if (opts.verbose) console.log(info('  Phase 12f: Information leakage scan…'));
  const leakageFindings  = (opts.security || opts.report) ? scanInfoLeakage(src) : [];

  // Phase 12g — C6: IDOR patterns
  if (opts.verbose) console.log(info('  Phase 12g: IDOR pattern scan…'));
  const idorFindings     = (opts.security || opts.report) ? scanIDOR(src) : [];

  // Phase 12h — C7: Dependency vulnerability correlation
  if (opts.verbose) console.log(info('  Phase 12h: Dependency vulnerability correlation…'));
  const depResult        = (opts.security || opts.report) ? scanDependencies(src) : { findings: [], pkgVersions: {} };
  const depFindings      = depResult.findings;
  const pkgVersions      = depResult.pkgVersions;

  // Phase 12i — C8: Race conditions
  if (opts.verbose) console.log(info('  Phase 12i: Race condition detection…'));
  const raceFindings     = (opts.security || opts.report) ? scanRaceConditions(src) : [];

  // Phase 12j — D1: Taint flow analysis
  if (opts.verbose) console.log(info('  Phase 12j: Heuristic taint-flow analysis…'));
  const taintFindings    = (opts.security || opts.report) ? scanTaintFlow(src) : [];

  // Phase 12k — D2: Web3 security
  if (opts.verbose) console.log(info('  Phase 12k: Web3/blockchain security scan…'));
  const web3Findings     = (opts.security || opts.report) ? scanWeb3(src) : [];

  // Phase 12l — D3: Config-driven behaviour
  if (opts.verbose) console.log(info('  Phase 12l: Config-driven behaviour analysis…'));
  const configFindings   = (opts.security || opts.report) ? scanConfigDrivenBehaviour(src) : [];

  // Phase 12m — D4: Lazy-loading security
  if (opts.verbose) console.log(info('  Phase 12m: Lazy-loading route security…'));
  const lazyFindings     = (opts.security || opts.report) ? scanLazyLoading(src) : [];

  // ─────────────────────────────────────────────────────────────────────────
  //  OMEGA-5.0: AST-powered structural analysis (Tier 1)
  //  Auto-enabled by --security, explicit via --ast, opt-out via --no-ast.
  // ─────────────────────────────────────────────────────────────────────────
  const useAst = opts.ast !== null
    ? opts.ast
    : (opts.security || opts.report);

  // Warn on --no-ast + --security: AST-derived features (fingerprint, backward
  // slices, network surface, structural scoring) are unavailable. Print to
  // stderr so it's visible even with --quiet.
  if (!useAst && (opts.security || opts.report)) {
    console.error(warn('--no-ast: AST structural analysis disabled. Obfuscator fingerprinting, backward slicing, network surface analysis, and AST-driven scoring will be skipped.'));
  }

  let structuralIndex = null;
  let astFwFindings   = null;
  let webpackGraph    = null;
  let bundlerInfo     = null;
  let callGraph       = null;
  let astTaint        = [];
  let modernCrypto    = [];
  let networkSurface  = null;
  let sourceMapInfo   = null;
  let obfuscatorFingerprint = null;
  let functionSummaries = null;
  let backwardSlices = null;
  let variableRenameTable = null;
  let sourceExpander = null;

  if (useAst) {
    // AST/structural passes operate on the PRE-BEAUTIFY source. Phase 7
    // (token-based beautifier) breaks certain syntactic forms that the
    // webpack runtime and class-body walkers depend on (e.g. arrow
    // function `(Q, H, d) => {...}` gets split into `= >`). The regex
    // pattern passes still use the beautified source — they tokenize
    // against the line-normalized text.
    const astSrc = srcPreBeautify;

    if (opts.verbose) console.log(info('  Phase 9b: AST foundation (tokenizer + walker)…'));
    try {
      structuralIndex = ast.buildStructuralIndex(astSrc);
    } catch (e) {
      console.warn(warn(`  AST parse threw: ${e.message}`));
      structuralIndex = { classes:[], functions:[], callSites:[], memberAccess:[], identifiers:[], assignments:[], tokens:[], lex:{ errors:[{msg:e.message, pos:0}] } };
    }
    // Warn if the file has content but AST found nothing (likely syntax error)
    // Detect likely parse failure: `function` keyword tokens exist but no
    // functions were parsed (e.g. malformed param list `function broken( {`)
    if (astSrc.length > 10 && structuralIndex.functions.length === 0) {
      const fnKeywords = (structuralIndex.lex?.tokens || []).filter(t => t.type === 'keyword' && t.value === 'function').length;
      if (fnKeywords > 0) {
        console.warn(warn(`  AST found ${fnKeywords} function keyword(s) but parsed 0 functions — possible syntax error`));
      }
    }
    if (opts.verbose) {
      console.log(info(`  AST: classes=${structuralIndex.classes.length}  functions=${structuralIndex.functions.length}  callsites=${structuralIndex.callSites.length}  members=${structuralIndex.memberAccess.length}  idents=${structuralIndex.identifiers.length}`));
    }

    // Phase 9b-T1 — Tier 1.1: AST framework detection
    if (opts.verbose) console.log(info('  Phase 9b-T1: AST framework detection (Tier 1.1)…'));
    astFwFindings = ast.detectFrameworksAST(astSrc, structuralIndex);
    if (opts.verbose && astFwFindings) {
      const a = astFwFindings.angular, v = astFwFindings.vue, r = astFwFindings.react;
      console.log(info(`  AST frameworks: Angular{cmp=${a.components} svc=${a.services} mod=${a.modules} pipe=${a.pipes} dir=${a.directives}} Vue{cmp=${v.components}} React{cmp=${r.components}}`));
    }

    // Phase 13c — Tier 1.5: Bundler detection (cheap, do first)
    if (opts.verbose) console.log(info('  Phase 13c: Bundler detection (Tier 1.5)…'));
    bundlerInfo = ast.detectBundler(astSrc);
    if (opts.verbose && bundlerInfo.primary) {
      console.log(info(`  Bundler: ${bundlerInfo.primary}  ESM=${bundlerInfo.isEsm}  IIFE=${bundlerInfo.isIife}`));
    }

    // Phase 13b — Tier 1.2: Webpack 5 dynamic module resolver
    if (opts.verbose) console.log(info('  Phase 13b: Webpack 5 dynamic module resolver (Tier 1.2)…'));
    webpackGraph = ast.resolveWebpack5Modules(astSrc);
    if (opts.verbose) {
      console.log(info(`  Webpack resolver: ${webpackGraph.moduleCount} modules, ${webpackGraph.edges.length} edges`));
    }

    // Auto-detect module names from in-bundle signatures (Phase 0 extension)
    // Merges detected names into WEBPACK_MODULE_MAP so subsequent Phase 0
    // alias resolution and Phase 14 dependency graph can use them.
    if (webpackGraph.modules && webpackGraph.modules.length > 0) {
      const detected = autoDetectModuleNames(astSrc, webpackGraph.modules);
      const detectedCount = Object.keys(detected).length;
      if (detectedCount > 0) {
        for (const [id, name] of Object.entries(detected)) {
          WEBPACK_MODULE_MAP[id] = name;
        }
        if (opts.verbose) console.log(info(`  Auto-detected ${detectedCount} module names from in-bundle signatures`));
      }
    }

    // Phase 14b — Tier 1.3: Call graph builder
    if (opts.verbose) console.log(info('  Phase 14b: Call graph builder (Tier 1.3)…'));
    callGraph = ast.buildCallGraph(structuralIndex, webpackGraph);
    if (opts.verbose) {
      console.log(info(`  Call graph: ${callGraph.stats.functions} fns, ${callGraph.stats.callSites} call sites, ${callGraph.stats.moduleEdges} module edges, ${callGraph.stats.entryPoints} entry points`));
    }

    // Phase 14c — Tier 1.4: AST-based taint tracker
    if (opts.verbose) console.log(info('  Phase 14c: AST cross-statement taint tracker (Tier 1.4)…'));
    astTaint = ast.trackTaintAST(astSrc, structuralIndex, callGraph);
    if (opts.verbose) console.log(info(`  AST taint flows found: ${astTaint.length}`));

    // Phase 12o — Tier 1.6: Modern crypto patterns
    if (opts.verbose) console.log(info('  Phase 12o: Modern crypto patterns (Tier 1.6)…'));
    modernCrypto = ast.scanModernCrypto(astSrc, structuralIndex);
    if (opts.verbose) console.log(info(`  Modern crypto findings: ${modernCrypto.length}`));

    // Phase 12p — Tier 1.10: Network surface extractor
    if (opts.verbose) console.log(info('  Phase 12p: Network surface extractor (Tier 1.10)…'));
    networkSurface = ast.extractNetworkSurface(astSrc);
    if (opts.verbose) console.log(info(`  Network: ${networkSurface.totalUrls} URLs, ${networkSurface.uniqueHosts} unique hosts, ${networkSurface.findings.length} findings`));

    // Phase 12q — Source map awareness (Stage 3E)
    if (opts.verbose) console.log(info('  Phase 12q: Source map parser (Stage 3E)…'));
    sourceMapInfo = ast.parseSourceMap(astSrc);
    if (opts.verbose && sourceMapInfo.found) {
      console.log(info(`  Source map: ${sourceMapInfo.isInline ? 'inline' : sourceMapInfo.isExternal ? 'external' : 'unknown'}, ${sourceMapInfo.sourceCount} sources, ${sourceMapInfo.findings.length} findings`));
      // If external and fetch-sourcemaps is enabled, fetch and decode
      if (sourceMapInfo.isExternal && opts.fetchSourcemaps && sourceMapInfo.mapUrl) {
        if (opts.verbose) console.log(info(`  Phase 12q-ext: Fetching external source map from ${sourceMapInfo.mapUrl}…`));
        const fetched = await fetchExternalSourceMap(sourceMapInfo.mapUrl, inputPath);
        if (fetched) {
          sourceMapInfo.isInline = false;
          sourceMapInfo.sources = fetched.sources;
          sourceMapInfo.sourceRoot = fetched.sourceRoot;
          sourceMapInfo.sourceCount = fetched.sourceCount;
          sourceMapInfo.mappings = fetched.mappings;
          sourceMapInfo.names = fetched.names;
          sourceMapInfo.findings.push({
            id: 'sourcemap-fetched', category: 'Source Map', severity: 'medium',
            value: `${fetched.sourceCount} original source files recovered from external map`,
            context: `sources[0..5]: ${fetched.sources.slice(0, 5).join(', ')}`,
            description: 'External source map fetched and decoded — source structure recovered',
          });
          // Flag sensitive paths in the fetched map too
          const sensitivePatterns = [
            { re: /\/(?:src|app|lib|server|backend|internal)\//i, sev: 'high', desc: 'Internal source path disclosed' },
            { re: /\/(?:test|spec|__tests__)\//i, sev: 'medium', desc: 'Test file paths disclosed' },
            { re: /\.(?:env|key|pem|p12|crt)$/, sev: 'critical', desc: 'Sensitive file (env/key/cert) in source map' },
          ];
          for (const srcPath of fetched.sources) {
            for (const p of sensitivePatterns) {
              if (p.re.test(srcPath)) {
                sourceMapInfo.findings.push({
                  id: 'sourcemap-sensitive-path', category: 'Source Map', severity: p.sev,
                  value: srcPath.slice(0, 100), context: `source: ${srcPath}`,
                  description: p.desc,
                });
              }
            }
          }
          if (opts.verbose) console.log(info(`  Fetched source map: ${fetched.sourceCount} sources recovered`));
        } else {
          if (opts.verbose) console.warn(warn(`  Failed to fetch source map from ${sourceMapInfo.mapUrl}`));
        }
      }
    }

    // Phase 16 — Obfuscator fingerprinting (Stage 5)
    if (opts.verbose) console.log(info('  Phase 16: Obfuscator fingerprinting (Stage 5)…'));
    obfuscatorFingerprint = ast.fingerprintObfuscator(astSrc);
    if (opts.verbose && obfuscatorFingerprint.primary) {
      console.log(info(`  Obfuscator: ${obfuscatorFingerprint.primary.obfuscator} (${(obfuscatorFingerprint.primary.confidence * 100).toFixed(0)}% confidence) — ${obfuscatorFingerprint.primary.matched.length} signatures`));
    }

    // Phase 17 — Function summary emitter (Stage 6) [LLM payload]
    if (opts.llmPayload) {
      if (opts.verbose) console.log(info('  Phase 17: Function summary emitter (Stage 6)…'));
      functionSummaries = ast.computeFunctionSummaries(astSrc, structuralIndex);
      const fnsWithSinks = functionSummaries.filter(s => s.sinks.length > 0).length;
      const fnsWithSources = functionSummaries.filter(s => s.sources.length > 0).length;
      const fnsWithSanitizers = functionSummaries.filter(s => s.sanitizers.length > 0).length;
      if (!opts.quiet)
        console.log(info(`  Summaries: ${functionSummaries.length} fns, ${fnsWithSinks} with sinks, ${fnsWithSources} with sources, ${fnsWithSanitizers} with sanitizers`));
    }

    // Phase 18 — Sink-anchored backward slicer (Stage 6) [LLM payload]
    if (opts.llmPayload) {
      if (opts.verbose) console.log(info('  Phase 18: Sink-anchored backward slicer (Stage 6)…'));
      backwardSlices = ast.buildBackwardSlices(astSrc, structuralIndex, functionSummaries, callGraph, opts.maxHops);
      const reachableSlices = backwardSlices.filter(p => p.reachesSource).length;
      if (!opts.quiet)
        console.log(info(`  Slices: ${backwardSlices.length} paths, ${reachableSlices} reach a taint source`));
    }

    // Phase 19 — Variable Rename Table (Stage 7) [LLM payload]
    if (opts.llmPayload) {
      if (opts.verbose) console.log(info('  Phase 19: Variable rename table (Stage 7)…'));
      variableRenameTable = ast.buildVariableRenameTable(structuralIndex, functionSummaries);
      if (!opts.quiet)
        console.log(info(`  VRT: ${variableRenameTable.stats.renamed} renamed (${variableRenameTable.stats.params} params, ${variableRenameTable.stats.locals} locals, ${variableRenameTable.stats.functions} functions)`));
    }

    // Phase 20 — On-demand source expansion (Stage 7) [LLM payload]
    if (opts.llmPayload) {
      if (opts.verbose) console.log(info('  Phase 20: Source expansion interface (Stage 7)…'));
      sourceExpander = ast.createSourceExpander(astSrc, structuralIndex, functionSummaries);
      if (!opts.quiet) {
        const sinkSummaries = sourceExpander.getSinkSummaries();
        console.log(info(`  Source expander: ${sinkSummaries.length} sink summaries`));
      }
    }

    // Phase 18 — Sink-anchored backward slicer (Stage 6)
    if (opts.verbose) console.log(info('  Phase 18: Sink-anchored backward slicer (Stage 6)…'));
    backwardSlices = ast.buildBackwardSlices(astSrc, structuralIndex, functionSummaries, callGraph, opts.maxHops);
    const reachableSlices = backwardSlices.filter(p => p.reachesSource).length;
    if (opts.verbose) {
      console.log(info(`  Slices: ${backwardSlices.length} paths, ${reachableSlices} reach a taint source`));
    }

    // Phase 19 — Variable Rename Table (Stage 7)
    if (opts.verbose) console.log(info('  Phase 19: Variable rename table (Stage 7)…'));
    variableRenameTable = ast.buildVariableRenameTable(structuralIndex, functionSummaries);
    if (opts.verbose) {
      console.log(info(`  VRT: ${variableRenameTable.stats.renamed} renamed (${variableRenameTable.stats.params} params, ${variableRenameTable.stats.locals} locals, ${variableRenameTable.stats.functions} functions)`));
    }

    // Phase 20 — On-demand source expansion (Stage 7)
    if (opts.verbose) console.log(info('  Phase 20: Source expansion interface (Stage 7)…'));
    sourceExpander = ast.createSourceExpander(astSrc, structuralIndex, functionSummaries);
    if (opts.verbose) {
      const sinkSummaries = sourceExpander.getSinkSummaries();
      console.log(info(`  Expander: ${sinkSummaries.length} sink summaries ready (cache empty, on-demand)`));
    }
  }

  // ── Dedup taint findings between regex Phase 12j and AST Phase 14c ────
  // FIX: previously both scanners ran and produced overlapping findings for
  // the same source→sink pair. The AST scanner is more precise (SSA-tracked),
  // so when both flag the same (source, sink, enclosing-function) tuple we
  // keep the AST version (richer chain info) and drop the regex duplicate.
  // Heuristic: same sink NAME + same enclosing function NAME → duplicate.
  {
    const astKeys = new Set();
    for (const f of astTaint) {
      const sinkName = (f.value || '').split('→').pop().trim();
      const fnName = (f.chain || []).find(c => c.kind === 'function')?.name || '';
      astKeys.add(`${sinkName}::${fnName}`);
    }
    const beforeCount = taintFindings.length;
    for (let i = taintFindings.length - 1; i >= 0; i--) {
      const f = taintFindings[i];
      const sinkName = (f.value || '').split('→').pop().trim();
      // The regex scanner doesn't populate `chain`, so we approximate the
      // enclosing-function name from the context (first function-looking token)
      const ctxMatch = (f.context || '').match(/(?:function\s+(\w+)|(\w+)\s*\([^)]*\)\s*\{)/);
      const fnName = ctxMatch ? (ctxMatch[1] || ctxMatch[2] || '') : '';
      if (astKeys.has(`${sinkName}::${fnName}`)) {
        taintFindings.splice(i, 1);
      }
    }
    if (opts.verbose && beforeCount !== taintFindings.length) {
      console.log(info(`  Taint dedup: removed ${beforeCount - taintFindings.length} regex duplicates also found by AST`));
    }
  }

  // Combine OMEGA-4.0 regex taint + OMEGA-5.0 AST taint (post-dedup)
  const taintAll = [...taintFindings, ...astTaint];

  // ── Module-export taint findings — emit when a module exports tainted data ─
  if (functionSummaries) {
    for (const sm of functionSummaries) {
      if (!sm.exports || sm.exports.length === 0) continue;
      for (const ex of sm.exports) {
        if (ex.via !== 'unknown') {
          extendedFindings.push({
            id: 'tainted-export',
            category: 'Taint Flow',
            severity: 'high',
            value: `${sm.name} exports tainted data via: ${ex.via}`,
            context: `export expression: ${ex.expr.slice(0, 120)}`,
            description: `Module ${sm.name} exports a value derived from taint source ${ex.via} — consuming modules receive this taint`,
          });
        }
      }
    }
  }

  // ── Phase 12h extension: OSV.dev live CVE fetch (opt-in) ────────────────
  if (opts.fetchCves && pkgVersions && Object.keys(pkgVersions).length > 0) {
    if (opts.verbose) console.log(info('  Phase 12h-ext: OSV.dev live CVE query…'));
    const osvFindings = await fetchOsvFindings(pkgVersions, opts.verbose);
    if (osvFindings.length > 0) {
      depFindings.push(...osvFindings);
      if (opts.verbose) console.log(info(`  OSV.dev: ${osvFindings.length} live CVE(s) found`));
    }
  }

  // Aggregate all extended findings (OMEGA-4.0 + OMEGA-5.0)
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
  ];

  // ── Apply severity-floor filter ────────────────────────────────────────
  // Filters out findings below the user-specified threshold before they reach
  // reports. Affects: credentials, security, extendedFindings. Does NOT affect
  // metrics, routes, or counts in the analysis object.
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const floorRank = SEV_RANK[opts.severityFloor];
  const meetsFloor = sev => {
    const r = SEV_RANK[sev];
    return r === undefined || r <= floorRank;
  };
  if (floorRank < SEV_RANK.info) {
    const before = credentials.length + security.length + extendedFindings.length;
    for (let i = credentials.length - 1; i >= 0; i--) {
      if (!meetsFloor(credentials[i].severity)) credentials.splice(i, 1);
    }
    for (let i = security.length - 1; i >= 0; i--) {
      if (!meetsFloor(security[i].sev || security[i].severity)) security.splice(i, 1);
    }
    for (let i = extendedFindings.length - 1; i >= 0; i--) {
      if (!meetsFloor(extendedFindings[i].severity)) extendedFindings.splice(i, 1);
    }
    const after = credentials.length + security.length + extendedFindings.length;
    if (opts.verbose) console.log(info(`  Severity floor "${opts.severityFloor}": ${before - after} findings filtered, ${after} kept`));
  }

  // Phase 13 — webpack module splitter (delegates to AST resolver when available)
  let modules = [];
  if (opts.splitModules) {
    if (opts.verbose) console.log(info('  Phase 13: Webpack module splitting…'));
    // Pass AST-resolved modules when available — they have accurate spans
    const astMods = (useAst && webpackGraph) ? webpackGraph.modules : null;
    modules = splitWebpackModules(src, astMods);
    for (const mod of modules)
      fs.writeFileSync(path.join(outDir,'modules',`module_${mod.id}.js`), mod.src);
    console.log(ok(`Extracted ${modules.length} webpack module(s) → ${outDir}/modules`));
  }

  // Phase 14 — original regex dependency graph (legacy)
  const graph = (opts.graph || opts.report) ? buildDependencyGraph(src) : [];

  // Phase 12n — B14: Attack surface prioritisation (with AST-augmented scoring)
  const astContext = useAst ? {
    structuralIndex, modernCrypto, networkSurface, callGraph, astFwFindings, bundlerInfo, webpackGraph,
  } : null;
  const attackScore = (opts.security || opts.report)
    ? scoreAttackSurface([...credentials, ...security, ...extendedFindings], authSurface, routes, astContext)
    : null;

  // Security summary
  const allSec = [...credentials, ...security, ...extendedFindings];

  // Source-map correlation: remap finding positions to original source locations
  if (sourceMapInfo && sourceMapInfo.found && sourceMapInfo.mappings) {
    const decodedLines = ast.decodeVLQMappings(sourceMapInfo.mappings);
    const sources = sourceMapInfo.sources || [];
    const sourceRoot = sourceMapInfo.sourceRoot || '';
    for (const f of allSec) {
      if (f.pos == null) continue;
      const genLine = src.slice(0, f.pos).split('\n').length;
      const genCol = f.pos - src.lastIndexOf('\n', f.pos) - 1;
      const remapped = ast.mapSourcePosition(genLine, Math.max(0, genCol), decodedLines, sources, sourceRoot);
      if (remapped && remapped.source) {
        f.sourceLocation = {
          file: remapped.source,
          line: remapped.line,
          column: remapped.column,
        };
      }
    }
  }

  // Apply baseline suppression
  let suppressed = [];
  if (opts.baseline) {
    const baseline = loadBaseline(opts.baseline);
    const result = applyBaseline(allSec, baseline, meta.file || path.basename(inputPath));
    allSec.length = 0; allSec.push(...result.findings);
    suppressed = result.suppressed;
    if (suppressed.length && !opts.quiet) {
      console.log(info(`Baseline suppressed ${suppressed.length} findings (${opts.baseline})`));
    }
  }

  // Diff mode — filter to new findings only
  if (opts.diff) {
    const previous = loadPreviousFindings(opts.diff);
    const newFindings = diffFindings(allSec, previous);
    const removedCount = allSec.length - newFindings.length;
    allSec.length = 0; allSec.push(...newFindings);
    if (!opts.quiet && removedCount > 0) {
      console.log(info(`Diff mode: ${removedCount} pre-existing findings hidden (${opts.diff})`));
    }
  }

  // Write baseline if --update-baseline
  if (opts.updateBaseline) {
    const baselinePath = path.join(opts.out, '.omega-ignore');
    const baseline = generateBaseline(allSec);
    fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
    if (!opts.quiet) console.log(ok(`Baseline written: ${C.bold}${baselinePath}${C.reset}`));
  }
  const critCount = allSec.filter(f=>(f.severity||f.sev)==='critical').length;
  const highCount = allSec.filter(f=>(f.severity||f.sev)==='high').length;
  const medCount  = allSec.filter(f=>(f.severity||f.sev)==='medium').length;

  if (allSec.length && !opts.quiet) {
    console.log(`\n${C.bgRed}${C.white} SECURITY FINDINGS ${C.reset}`);
    console.log(info(`Total: ${allSec.length}  Critical: ${critCount}  High: ${highCount}  Medium: ${medCount}`));
    if (attackScore) {
      const riskCol = attackScore.risk==='CRITICAL'?C.red:attackScore.risk==='HIGH'?C.yellow:C.green;
      console.log(info(`Attack Surface Score: ${riskCol}${C.bold}${attackScore.score} [${attackScore.risk}]${C.reset}`));
      console.log(info(`Top categories: ${attackScore.topCategories.join(' · ')}`));
    }
    const top = allSec.filter(f => {
      const s = f.severity || f.sev || '';
      return s === 'critical' || s === 'high';
    }).slice(0,12);
    for (const f of top) {
      const sev = (f.severity || f.sev || 'info').toUpperCase();
      const col = sev==='CRITICAL'?C.red:sev==='HIGH'?C.yellow:C.white;
      console.log(`  ${col}[${sev}]${C.reset} ${f.name||f.category||f.id}: ${C.dim}${(f.value||'').slice(0,70)}${C.reset}`);
    }
  }

  // A2: Unprotected endpoints summary
  if (authSurface.unprotectedEndpoints && authSurface.unprotectedEndpoints.length) {
    console.log(warn(`A2 Unprotected API endpoints: ${C.bold}${authSurface.unprotectedEndpoints.length}${C.reset}`));
    for (const ep of authSurface.unprotectedEndpoints.slice(0,5))
      console.log(`  ${C.red}→${C.reset} ${ep.endpoint}`);
  }

  if (routes.length) {
    if (!opts.quiet) {
      console.log(`\n${C.bold}${C.yellow}📍 Routes & Endpoints (${routes.length}):${C.reset}`);
      for (const r of routes.slice(0,20)) console.log(`  ${C.dim}[${r.type}]${C.reset} ${r.path}`);
      if (routes.length > 20) console.log(`  ${C.dim}…and ${routes.length-20} more → routes.txt${C.reset}`);
    }
    fs.writeFileSync(path.join(outDir,'routes.txt'), routes.map(r=>`[${r.type}] ${r.path}`).join('\n'));
  }

  // Phase 15
  if (opts.report) {
    if (!opts.quiet) console.log(head('REPORTS'));
    const decodeStats = {
      Unicode:          escStats.unicode,
      Hex:              escStats.hex,
      HTMLEntity:       escStats.htmlEnt,
      fromCharCode:     strStats.charCode,
      base64:           strStats.base64,
      hexArray:         strStats.hexArr,
      concat:           strStats.concat,
      aliasesResolved:  aliasCount,
      frameworkSymbols: frameworkSymStats.symbolsAnnotated,
      charCodeDecoded:  charCodeFindings.length,
    };
    generateReports({
      analysis, credentials, security, extendedFindings, routes, frameworks,
      graph, decodeStats, frameworkSymStats,
      storageAudit, authSurface, charCodeFindings, attackScore,
      astFwFindings, bundlerInfo, webpackGraph, callGraph,
      astTaint, modernCrypto, networkSurface, useAst,
      obfuscatorFingerprint, functionSummaries, backwardSlices,
      variableRenameTable, sourceExpander,
      meta: {
        file:    path.basename(inputPath),
        size:    `${(stat.size/1024).toFixed(1)} KB`,
        sha256, date: new Date().toISOString(),
        version: VERSION,
      },
    }, outDir);
    console.log(ok(`HTML report: ${C.bold}${path.join(outDir,'report.html')}${C.reset}`));
    console.log(ok(`JSON report: ${C.bold}${path.join(outDir,'report.json')}${C.reset}`));
    console.log(ok(`SARIF report:${C.bold}${path.join(outDir,'report.sarif')}${C.reset}`));
    console.log(ok(`MD report:   ${C.bold}${path.join(outDir,'report.md')}${C.reset}`));
  }

  const elapsed = ((Date.now()-t0)/1000).toFixed(2);
  if (!opts.quiet) {
    console.log(`\n${C.green}${C.bold}✔ Complete${C.reset} — ${elapsed}s — zero external dependencies.\n`);
  }

  // Return a summary for the entry-point wrapper to use for exit-code logic.
  return {
    elapsed: parseFloat(elapsed),
    totalFindings: allSec.length,
    criticalCount: critCount,
    highCount: highCount,
    mediumCount: medCount,
    attackScore: attackScore ? attackScore.score : 0,
    attackRisk: attackScore ? attackScore.risk : 'UNKNOWN',
  };
}

// ── Entry point with CI-friendly exit codes ─────────────────────────────
// Exit codes:
//   0  — success, no findings at or above the fail threshold
//   1  — runtime error (file not found, parse failure, etc.)
//   2  — success, but critical findings detected (default fail threshold)
//   3  — success, but high-or-above findings detected (OMEGA_FAIL_ON=high)
//   4  — success, but medium-or-above findings detected (OMEGA_FAIL_ON=medium)
//   5  — success, but low-or-above findings detected (OMEGA_FAIL_ON=low)
//
// Configure via the OMEGA_FAIL_ON environment variable:
//   OMEGA_FAIL_ON=critical  (default) — exit 2 if any critical findings
//   OMEGA_FAIL_ON=high                — exit 3 if any high+ findings
//   OMEGA_FAIL_ON=medium              — exit 4 if any medium+ findings
//   OMEGA_FAIL_ON=low                 — exit 5 if any low+ findings
//   OMEGA_FAIL_ON=none                — always exit 0 (CI gate disabled)
// Only auto-run when invoked as the main module (CLI mode)
if (require.main === module) {
  const _opts = parseArgs();

  async function _run() {
    const summary = await main();
    const failLevel = (process.env.OMEGA_FAIL_ON || 'critical').toLowerCase();
    const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 99 };
    if (failLevel === 'none' || RANK[failLevel] === undefined) process.exit(0);
    const failRank = RANK[failLevel];
    if (summary.criticalCount > 0 && failRank <= RANK.critical) process.exit(2);
    if (summary.highCount > 0     && failRank <= RANK.high)     process.exit(3);
    if (summary.mediumCount > 0   && failRank <= RANK.medium)   process.exit(4);
    if (failRank <= RANK.low && summary.totalFindings > 0)      process.exit(5);
    process.exit(0);
  }

  if (_opts.watch) {
    const watchFile = _opts.input;
    console.log(info(`Watching ${watchFile} for changes…`));
    // Run once, then watch
    main().then(() => {
      fs.watch(watchFile, (eventType) => {
        if (eventType === 'change') {
          console.log(info(`Change detected — re-scanning…`));
          main().catch(e => { console.error(fail(e.message)); });
        }
      });
    }).catch(e => { console.error(fail(e.message)); process.exit(1); });
  } else {
    _run().catch(e => { console.error(fail(e.message)); process.exit(1); });
  }
}

// Export functions for programmatic use
function runCLI() {
  return main()
    .then((summary) => {
      const failLevel = (process.env.OMEGA_FAIL_ON || 'critical').toLowerCase();
      const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 99 };
      if (failLevel === 'none' || RANK[failLevel] === undefined) process.exit(0);
      const failRank = RANK[failLevel];
      if (summary.criticalCount > 0 && failRank <= RANK.critical) process.exit(2);
      if (summary.highCount > 0     && failRank <= RANK.high)     process.exit(3);
      if (summary.mediumCount > 0   && failRank <= RANK.medium)   process.exit(4);
      if (failRank <= RANK.low && summary.totalFindings > 0)      process.exit(5);
      process.exit(0);
    })
    .catch(e => { console.error(fail(e.message)); process.exit(1); });
}

module.exports = {
  main,
  runCLI,
  parseArgs,
  printHelp,
};


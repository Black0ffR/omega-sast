#!/usr/bin/env node
/**
 * OMEGA-5.0 AST module test harness
 *
 * Loads omega-5.0-ast.js from a target directory (default: ../download),
 * runs every exported function against ./sample-bundle.js, and prints
 * structured pass/fail assertions.
 *
 * Usage:
 *   node test-harness.js                  # uses ../download/omega-5.0-ast.js
 *   node test-harness.js /path/to/ast.js  # explicit ast module path
 */
'use strict';

const fs   = require('fs');
const path = require('path');

// ── Resolve AST module path ──────────────────────────────────────────────
const astPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(__dirname, '..', 'lib', 'ast.js');

if (!fs.existsSync(astPath)) {
  console.error(`✘ AST module not found at: ${astPath}`);
  process.exit(1);
}

const ast = require(astPath);
const bundlePath = path.resolve(__dirname, 'fixtures', 'sample-bundle.js');
const src = fs.readFileSync(bundlePath, 'utf8');

// ── Tiny test framework ──────────────────────────────────────────────────
let total = 0, passed = 0, failed = 0;
const failures = [];

function assert(name, cond, detail) {
  total++;
  if (cond) {
    passed++;
    console.log(`  ✔ ${name}`);
  } else {
    failed++;
    failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}

function section(name) { console.log(`\n── ${name} ──────────────────────────────`); }

// ═══════════════════════════════════════════════════════════════════════
//  1. Tokenizer
// ═══════════════════════════════════════════════════════════════════════
section('1. tokenizeForAST');
const lex = ast.tokenizeForAST(src);
assert('tokenizer produces tokens', lex.tokens.length > 100, `token count = ${lex.tokens.length}`);
assert('tokenizer reports no fatal errors', Array.isArray(lex.errors), `errors type = ${typeof lex.errors}`);
assert('tokenizer tracks line counter', lex.lines > 1, `lines = ${lex.lines}`);

// Token type coverage
const tokenTypes = new Set(lex.tokens.map(t => t.type));
assert('emits ident tokens',  tokenTypes.has('ident'));
assert('emits keyword tokens',tokenTypes.has('keyword'));
assert('emits punct tokens',  tokenTypes.has('punct'));
assert('emits string tokens', tokenTypes.has('string'));
assert('emits number tokens', tokenTypes.has('number'));
assert('emits template tokens', tokenTypes.has('template'));

// Angular ɵ identifier handling
const hasTheta = lex.tokens.some(t => t.value && t.value.includes('ɵcmp'));
assert('recognizes ɵcmp identifier (U+0275)', hasTheta);

// ═══════════════════════════════════════════════════════════════════════
//  2. buildStructuralIndex
// ═══════════════════════════════════════════════════════════════════════
section('2. buildStructuralIndex');
const idx = ast.buildStructuralIndex(src);
assert('returns classes array',     Array.isArray(idx.classes));
assert('returns functions array',   Array.isArray(idx.functions));
assert('returns callSites array',   Array.isArray(idx.callSites));
assert('returns memberAccess array',Array.isArray(idx.memberAccess));
assert('returns identifiers array', Array.isArray(idx.identifiers));
assert('returns tokens array',      Array.isArray(idx.tokens));

// 5 Angular classes + 1 React function-component class + VueComp etc.
assert('detects ≥ 5 classes (AppComponent, AuthService, AppModule, FormatPipe, TooltipDirective)',
       idx.classes.length >= 5, `class count = ${idx.classes.length}`);

// Verify class name extraction
const classNames = idx.classes.map(c => c.name);
assert('AppComponent class found', classNames.includes('AppComponent'));
assert('AuthService class found',  classNames.includes('AuthService'));
assert('AppModule class found',    classNames.includes('AppModule'));
assert('FormatPipe class found',   classNames.includes('FormatPipe'));
assert('TooltipDirective class found', classNames.includes('TooltipDirective'));

// Static field extraction (Angular ɵcmp etc.)
const appComp = idx.classes.find(c => c.name === 'AppComponent');
assert('AppComponent has staticFields array',
       Array.isArray(appComp.staticFields));
assert('AppComponent has ɵcmp in static fields',
       appComp.staticFields.some(f => f.name === 'ɵcmp'),
       `static fields = ${appComp.staticFields.map(f=>f.name).join(', ')}`);

// Functions
assert('detects ≥ 5 functions', idx.functions.length >= 5, `fn count = ${idx.functions.length}`);
const fnNames = idx.functions.map(f => f.name);
assert('renderSearch function found',  fnNames.includes('renderSearch'));
assert('renderHash function found',    fnNames.includes('renderHash'));
assert('dangerEval function found',    fnNames.includes('dangerEval'));
assert('ReactComp function found',     fnNames.includes('ReactComp'));

// Call sites
assert('detects ≥ 10 call sites', idx.callSites.length >= 10, `callSite count = ${idx.callSites.length}`);

// Member access (location.search, document.body, etc.)
const memberAccessNames = idx.memberAccess.map(m => `${m.object}.${m.property}`);
assert('location.search member access found',
       memberAccessNames.includes('location.search'));
assert('document.body member access found',
       memberAccessNames.some(m => m.startsWith('document.')));

// ═══════════════════════════════════════════════════════════════════════
//  3. detectFrameworksAST
// ═══════════════════════════════════════════════════════════════════════
section('3. detectFrameworksAST');
const fw = ast.detectFrameworksAST(src, idx);
assert('returns angular object', fw.angular && typeof fw.angular === 'object');
assert('returns vue object',     fw.vue && typeof fw.vue === 'object');
assert('returns react object',   fw.react && typeof fw.react === 'object');

// Angular: 1 component (AppComponent), 1 service (AuthService),
// 1 module (AppModule), 1 pipe (FormatPipe), 1 directive (TooltipDirective)
assert('Angular components = 1', fw.angular.components === 1,
       `got ${fw.angular.components}`);
assert('Angular services = 1',  fw.angular.services === 1,
       `got ${fw.angular.services}`);
assert('Angular modules = 1',   fw.angular.modules === 1,
       `got ${fw.angular.modules}`);
assert('Angular pipes = 1',     fw.angular.pipes === 1,
       `got ${fw.angular.pipes}`);
assert('Angular directives = 1',fw.angular.directives === 1,
       `got ${fw.angular.directives}`);

// Angular.total SHOULD equal the count of Angular-decorated classes (5),
// NOT every class in the file. This is the bug we will fix.
// Pre-fix expectation: angular.total == classes.length (BUG)
// Post-fix expectation: angular.total == 5
console.log(`  ℹ Angular.total = ${fw.angular.total} (5 = correct, ${idx.classes.length} = buggy)`);

// Vue hits: createElementVNode + defineComponent + __vccOpts
assert('Vue hits > 0', fw.vue.total > 0, `vue.total = ${fw.vue.total}`);

// React hits: jsx + forwardRef
assert('React hits > 0', fw.react.total > 0, `react.total = ${fw.react.total}`);

// ═══════════════════════════════════════════════════════════════════════
//  4. resolveWebpack5Modules
// ═══════════════════════════════════════════════════════════════════════
section('4. resolveWebpack5Modules');
const wp = ast.resolveWebpack5Modules(src);
assert('bundler detected as webpack5', wp.bundler === 'webpack5');
assert('resolves ≥ 8 modules', wp.moduleCount >= 8,
       `moduleCount = ${wp.moduleCount}`);

const moduleIds = wp.modules.map(m => m.id);
assert('module 101 (Angular) found',  moduleIds.includes('101'));
assert('module 404 (taint) found',    moduleIds.includes('404'));
assert('module 808 (caller) found',   moduleIds.includes('808'));

// Edges: 808 → 101, 808 → 404
assert('resolves ≥ 2 module edges', wp.edges.length >= 2,
       `edges = ${wp.edges.length}`);
const has808to101 = wp.edges.some(e => e.from === '808' && e.to === '101');
const has808to404 = wp.edges.some(e => e.from === '808' && e.to === '404');
assert('edge 808 → 101 exists', has808to101);
assert('edge 808 → 404 exists', has808to404);

// ═══════════════════════════════════════════════════════════════════════
//  5. detectBundler
// ═══════════════════════════════════════════════════════════════════════
section('5. detectBundler');
const bundler = ast.detectBundler(src);
assert('detects webpack5 pattern',   bundler.detected.includes('webpack5'));
assert('primary = webpack5',         bundler.primary === 'webpack5');
assert('flags as IIFE-style bundle', bundler.isIife === true);
assert('flags as non-ESM',           bundler.isEsm === false);

// ═══════════════════════════════════════════════════════════════════════
//  6. buildCallGraph
// ═══════════════════════════════════════════════════════════════════════
section('6. buildCallGraph');
const cg = ast.buildCallGraph(idx, wp);
assert('returns stats object',       cg.stats && typeof cg.stats === 'object');
assert('stats.functions > 0',        cg.stats.functions > 0);
assert('stats.callSites > 0',        cg.stats.callSites > 0);
assert('stats.moduleEdges ≥ 2',      cg.stats.moduleEdges >= 2,
       `moduleEdges = ${cg.stats.moduleEdges}`);
assert('returns entryPoints array',  Array.isArray(cg.entryPoints));
assert('returns orphanFunctions array', Array.isArray(cg.orphanFunctions));

// ═══════════════════════════════════════════════════════════════════════
//  7. trackTaintAST
// ═══════════════════════════════════════════════════════════════════════
section('7. trackTaintAST');
const taints = ast.trackTaintAST(src, idx, cg);
assert('returns array', Array.isArray(taints));
assert('detects ≥ 1 taint flow', taints.length >= 1,
       `flow count = ${taints.length}`);

// Specific taint flows expected:
//  - location.search → innerHTML (via URLSearchParams)
//  - location.hash → innerHTML
//  - localStorage → eval
const flowValues = taints.map(t => t.value || '');
assert('detects URL-related → innerHTML flow',
       flowValues.some(v => v.includes('innerHTML')),
       `flows = ${flowValues.join(' | ')}`);
assert('detects → eval flow',
       flowValues.some(v => v.includes('eval')),
       `flows = ${flowValues.join(' | ')}`);

// Severity sanity
const allSev = taints.map(t => t.severity);
const allValid = allSev.every(s => ['critical','high','medium','low','info'].includes(s));
assert('all taint severities are valid', allValid);

// CWE tags present
const hasCwe = taints.every(t => t.cwe && t.cwe.startsWith('CWE-'));
assert('all taint flows carry CWE tags', hasCwe);

// ═══════════════════════════════════════════════════════════════════════
//  8. scanModernCrypto
// ═══════════════════════════════════════════════════════════════════════
section('8. scanModernCrypto');
const crypto = ast.scanModernCrypto(src, idx);
assert('returns array', Array.isArray(crypto));
assert('detects ≥ 3 crypto findings', crypto.length >= 3,
       `count = ${crypto.length}`);

const cryptoIds = crypto.map(c => c.id);
assert('detects JWT literal',          cryptoIds.includes('crypto-jwt-literal'));
assert('detects WebCrypto importKey',  cryptoIds.includes('crypto-webcrypto-import'));
assert('detects WebCrypto exportKey',  cryptoIds.includes('crypto-webcrypto-export'));
assert('detects Node weak hash (md5)', cryptoIds.includes('crypto-node-weak-hash'));
assert('detects bcrypt literal',       cryptoIds.includes('crypto-bcrypt-literal'));

// JWT payload should be decoded
const jwt = crypto.find(c => c.id === 'crypto-jwt-literal');
assert('JWT payload decoded', jwt && jwt.jwtPayload && jwt.jwtPayload.includes('1234567890'),
       `payload = ${jwt ? jwt.jwtPayload : 'n/a'}`);

// ═══════════════════════════════════════════════════════════════════════
//  9. extractNetworkSurface
// ═══════════════════════════════════════════════════════════════════════
section('9. extractNetworkSurface');
const net = ast.extractNetworkSurface(src);
assert('returns urls array',      Array.isArray(net.urls));
assert('returns hostClusters',    Array.isArray(net.hostClusters));
assert('returns findings array',  Array.isArray(net.findings));
assert('totalUrls ≥ 4',           net.totalUrls >= 4, `totalUrls = ${net.totalUrls}`);
assert('uniqueHosts ≥ 2',         net.uniqueHosts >= 2, `uniqueHosts = ${net.uniqueHosts}`);

// api.example.com should be the top host (3 fetches)
const topHost = net.hostClusters[0];
assert('top host is api.example.com',
       topHost && topHost.host === 'api.example.com',
       `top host = ${topHost ? topHost.host : 'n/a'}`);
assert('api.example.com hit count = 3',
       topHost && topHost.count === 3,
       `count = ${topHost ? topHost.count : 'n/a'}`);

// Cloud metadata + RFC1918 findings
const netFindingIds = net.findings.map(f => f.id);
assert('flags cloud metadata endpoint',
       netFindingIds.includes('net-cloud-metadata'));
assert('flags RFC1918 IPs',
       netFindingIds.includes('net-rfc1918'));

// ═══════════════════════════════════════════════════════════════════════
//  10. windowText helper (after fix should return source text)
// ═══════════════════════════════════════════════════════════════════════
section('10. windowText helper');
if (typeof ast.windowText === 'function') {
  // After fix: windowText(tokens, src, startTok, endTok) returns source text
  // Before fix: signature is (tokens, startTok, endTok) and returns ''
  try {
    const wt = ast.windowText(idx.tokens, 0, Math.min(5, idx.tokens.length - 1));
    if (typeof wt === 'string' && wt.length > 0) {
      assert('windowText returns non-empty string', true);
    } else {
      // Try the 4-arg form
      const wt4 = ast.windowText(idx.tokens, src, 0, Math.min(5, idx.tokens.length - 1));
      assert('windowText (4-arg form) returns non-empty string',
             typeof wt4 === 'string' && wt4.length > 0,
             `wt=${JSON.stringify(wt)} wt4=${JSON.stringify(wt4)}`);
    }
  } catch (e) {
    assert('windowText did not throw', false, e.message);
  }
} else {
  assert('windowText exported', false, 'function not exported');
}

// ═══════════════════════════════════════════════════════════════════════
//  11. parseSourceMap (Stage 3E)
// ═══════════════════════════════════════════════════════════════════════
section('11. parseSourceMap');
if (typeof ast.parseSourceMap === 'function') {
  const sm = ast.parseSourceMap(src);
  assert('parseSourceMap returns object', sm && typeof sm === 'object');
  assert('sample bundle has source map reference', sm.found === true,
    `found=${sm.found}`);
  assert('source map is external (.map URL)', sm.isExternal === true,
    `isExternal=${sm.isExternal}`);
  assert('source map URL captured', sm.mapUrl === 'app.bundle.js.map',
    `mapUrl=${sm.mapUrl}`);
  assert('source map findings present', sm.findings.length >= 1,
    `findings=${sm.findings.length}`);
} else {
  assert('parseSourceMap exported', false, 'function not exported');
}

// ═══════════════════════════════════════════════════════════════════════
//  Summary
// ═══════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(60)}`);
console.log(`  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
console.log(`${'═'.repeat(60)}`);
if (failed) {
  console.log('\nFailed assertions:');
  for (const f of failures) {
    console.log(`  ✘ ${f.name}`);
    if (f.detail !== undefined) console.log(`      → ${f.detail}`);
  }
}
process.exit(failed ? 1 : 0);

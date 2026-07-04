#!/usr/bin/env node
/**
 * Stage 7 tests: destructuring support, VRT, source expansion, ReDoS worker
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const astPath = path.resolve(__dirname, '..', 'lib', 'ast.js');
const ast = require(astPath);

let total = 0, passed = 0, failed = 0;
const failures = [];
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++; failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

function summarize(src) {
  const idx = ast.buildStructuralIndex(src);
  const summaries = ast.computeFunctionSummaries(src, idx);
  const cg = ast.buildCallGraph(idx, null);
  const slices = ast.buildBackwardSlices(src, idx, summaries, cg, 3);
  return { idx, summaries, slices };
}

// ═══════════════════════════════════════════════════════════════════════
section('1. Object destructuring from source');
{
  const src = `
function leakDestructured() {
  const { search } = window.location;
  document.body.innerHTML = search;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakDestructured');
  assert('destructuring: function found', !!fn);
  assert('destructuring: has 1 source (location.*)',
    fn && fn.sources.length >= 1 && fn.sources.some(s => s.name === 'location.*' || s.name === 'window.location.*' || s.name === 'window.*'),
    `sources=${fn && fn.sources.map(s=>s.name).join(',')}`);
  assert('destructuring: has 1 sink (innerHTML)',
    fn && fn.sinks.length === 1 && fn.sinks[0].name === 'innerHTML');
  assert('destructuring: sink via = location.* (via tainted local search)',
    fn && (fn.sinks[0].via === 'location.*' || fn.sinks[0].via === 'window.*' || fn.sinks[0].via === 'window.location.*'),
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. Multi-property destructuring');
{
  const src = `
function leakMulti() {
  const { search, hash } = location;
  document.body.innerHTML = hash;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakMulti');
  assert('multi-destructuring: sink via = location.*',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. Renamed destructuring');
{
  const src = `
function leakRenamed() {
  const { hash: h } = location;
  document.body.innerHTML = h;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakRenamed');
  assert('renamed destructuring: sink via = location.*',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('4. Array destructuring from tainted source');
{
  const src = `
function leakArray() {
  const data = location.search.split("&");
  const [first] = data;
  document.body.innerHTML = first;
}`;
  const { summaries } = summarize(src);
  const fn = summaries.find(s => s.name === 'leakArray');
  assert('array destructuring: sink via = location.*',
    fn && fn.sinks[0].via === 'location.*',
    `via=${fn && fn.sinks[0].via}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('5. Variable Rename Table (VRT)');
{
  const src = `
function _0x1a2b(_0x3c4d, _0x5e6f) {
  const _0x7a8b = location.search;
  document.body.innerHTML = _0x7a8b;
  return _0x3c4d + _0x5e6f;
}`;
  const idx = ast.buildStructuralIndex(src);
  const summaries = ast.computeFunctionSummaries(src, idx);
  const vrt = ast.buildVariableRenameTable(idx, summaries);

  assert('VRT: returns object with renameTable', vrt && vrt.renameTable instanceof Map);
  assert('VRT: returns reverseTable', vrt && vrt.reverseTable instanceof Map);
  assert('VRT: returns stats', vrt && vrt.stats);
  assert('VRT: renamed >= 3 (function + params + locals)',
    vrt && vrt.stats.renamed >= 3,
    `renamed=${vrt && vrt.stats.renamed}`);

  // Check that _0x1a2b got renamed
  const renamed = vrt.renameTable.get('_0x1a2b');
  assert('VRT: _0x1a2b renamed to fn*',
    renamed && renamed.startsWith('fn'),
    `renamed=${renamed}`);

  // Check reverse lookup works
  if (renamed) {
    assert('VRT: reverse lookup works',
      vrt.reverseTable.get(renamed) === '_0x1a2b');
  }

  // Check that canonical names are shorter (token savings)
  const origLen = '_0x1a2b'.length + '_0x3c4d'.length + '_0x5e6f'.length + '_0x7a8b'.length;
  const canonLen = (vrt.renameTable.get('_0x1a2b') || '').length +
                   (vrt.renameTable.get('_0x3c4d') || '').length +
                   (vrt.renameTable.get('_0x5e6f') || '').length +
                   (vrt.renameTable.get('_0x7a8b') || '').length;
  assert('VRT: canonical names are shorter (token savings)',
    canonLen < origLen,
    `original=${origLen}, canonical=${canonLen}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('6. VRT preserves builtins and reserved names');
{
  const src = `function foo() { console.log("test"); return Math.random(); }`;
  const idx = ast.buildStructuralIndex(src);
  const summaries = ast.computeFunctionSummaries(src, idx);
  const vrt = ast.buildVariableRenameTable(idx, summaries);

  assert('VRT: does NOT rename builtins (console)',
    !vrt.renameTable.has('console'));
  assert('VRT: does NOT rename builtins (Math)',
    !vrt.renameTable.has('Math'));
  assert('VRT: does NOT rename short names',
    !vrt.renameTable.has('x') && !vrt.renameTable.has('y'));
}

// ═══════════════════════════════════════════════════════════════════════
section('7. On-demand source expansion');
{
  const src = `
function leakDirect() {
  document.body.innerHTML = location.hash;
}
function safe() { return 42; }`;
  const idx = ast.buildStructuralIndex(src);
  const summaries = ast.computeFunctionSummaries(src, idx);
  const expander = ast.createSourceExpander(src, idx, summaries);

  assert('expander: created with expand function', typeof expander.expand === 'function');
  assert('expander: created with getSummary function', typeof expander.getSummary === 'function');
  assert('expander: created with getAllSummaries function', typeof expander.getAllSummaries === 'function');
  assert('expander: created with getSinkSummaries function', typeof expander.getSinkSummaries === 'function');

  // Find the leakDirect function
  const leakFn = summaries.find(s => s.name === 'leakDirect');
  assert('expander: leakDirect summary found', !!leakFn);

  // Expand it
  const expansion = expander.expand(leakFn.id);
  assert('expander: expand returns object',
    expansion && typeof expansion === 'object');
  assert('expander: expansion has source text',
    expansion && typeof expansion.source === 'string' && expansion.source.length > 0);
  assert('expander: expansion has tokenEstimate',
    expansion && typeof expansion.tokenEstimate === 'number');
  assert('expander: expansion source includes function name',
    expansion && expansion.source.includes('leakDirect'));
  assert('expander: expansion source includes innerHTML',
    expansion && expansion.source.includes('innerHTML'));

  // Test caching: second call should hit cache
  const expansion2 = expander.expand(leakFn.id);
  assert('expander: second expand returns cached result',
    expansion2 === expansion);

  // Check stats
  assert('expander: stats show 1 expansion',
    expander.stats.expansions === 1,
    `expansions=${expander.stats.expansions}`);
  assert('expander: stats show 1 cache hit',
    expander.stats.cacheHits === 1,
    `cacheHits=${expander.stats.cacheHits}`);

  // Test getSinkSummaries (only functions with sinks)
  const sinkSummaries = expander.getSinkSummaries();
  assert('expander: getSinkSummaries returns 1 (only leakDirect has a sink)',
    sinkSummaries.length === 1,
    `count=${sinkSummaries.length}`);
  assert('expander: sink summary name = leakDirect',
    sinkSummaries[0] && sinkSummaries[0].name === 'leakDirect');

  // Test getAllSummaries
  const allSummaries = expander.getAllSummaries();
  assert('expander: getAllSummaries returns 2 (both functions)',
    allSummaries.length === 2,
    `count=${allSummaries.length}`);

  // Test expandMany (batch)
  const batch = expander.expandMany([leakFn.id, summaries.find(s => s.name === 'safe').id]);
  assert('expander: expandMany returns 2 results',
    batch.length === 2,
    `count=${batch.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('8. Source expansion — non-existent function');
{
  const src = `function foo() { return 1; }`;
  const idx = ast.buildStructuralIndex(src);
  const summaries = ast.computeFunctionSummaries(src, idx);
  const expander = ast.createSourceExpander(src, idx, summaries);

  const expansion = expander.expand(99999);  // non-existent ID
  assert('expander: expand(non-existent) returns null',
    expansion === null);
  assert('expander: getSummary(non-existent) returns null',
    expander.getSummary(99999) === null);
}

// ═══════════════════════════════════════════════════════════════════════
section('9. Worker-thread ReDoS isolation');
{
  // Test the async API
  const redos = require(path.resolve(__dirname, '..', 'lib', 'redos-worker.js'));

  assert('redos: runRegexSafe exported',
    typeof redos.runRegexSafe === 'function');
  assert('redos: runRegexSync exported',
    typeof redos.runRegexSync === 'function');
  assert('redos: safeRegexIterFallback exported',
    typeof redos.safeRegexIterFallback === 'function');
  assert('redos: isWorkerThreadsAvailable flag',
    typeof redos.isWorkerThreadsAvailable === 'boolean');

  // Test sync API with a normal regex
  const result = redos.runRegexSync(/foo/g, 'foo bar foo baz', { timeoutMs: 5000 });
  assert('redos sync: finds 2 matches',
    result.matches && result.matches.length === 2,
    `matches=${result.matches && result.matches.length}`);

  // Test sync API with no matches
  const noMatch = redos.runRegexSync(/xyz/g, 'nothing here', { timeoutMs: 5000 });
  assert('redos sync: 0 matches when pattern not found',
    noMatch.matches && noMatch.matches.length === 0);

  // Test sync API with maxMatches cap
  const capped = redos.runRegexSync(/a/g, 'a'.repeat(100), { timeoutMs: 5000, maxMatches: 10 });
  assert('redos sync: respects maxMatches cap',
    capped.matches && capped.matches.length === 10 && capped.truncated === true,
    `matches=${capped.matches && capped.matches.length}, truncated=${capped.truncated}`);

  // Test fallback (in-process)
  let fallbackMatches = 0;
  redos.safeRegexIterFallback(/foo/g, 'foo bar foo', (m) => fallbackMatches++);
  assert('redos fallback: finds 2 matches',
    fallbackMatches === 2,
    `matches=${fallbackMatches}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('10. Async worker-thread ReDoS test');
{
  const redos = require(path.resolve(__dirname, '..', 'lib', 'redos-worker.js'));

  // Test async API
  redos.runRegexSafe(/foo/g, 'foo bar foo baz', { timeoutMs: 5000 })
    .then(result => {
      assert('redos async: finds 2 matches',
        result.matches && result.matches.length === 2,
        `matches=${result.matches && result.matches.length}`);
    })
    .catch(err => {
      assert('redos async: finds 2 matches', false, err.message);
    });

  // Wait for the async test to complete (worker threads are async)
  setTimeout(() => {
    // ═══════════════════════════════════════════════════════════════════════
    section('11. Sample bundle end-to-end with all Stage 7 features');
    {
      const bundleSrc = fs.readFileSync(path.resolve(__dirname, 'fixtures', 'sample-bundle.js'), 'utf8');
      const idx = ast.buildStructuralIndex(bundleSrc);
      const summaries = ast.computeFunctionSummaries(bundleSrc, idx);
      const cg = ast.buildCallGraph(idx, null);
      const slices = ast.buildBackwardSlices(bundleSrc, idx, summaries, cg, 3);
      const vrt = ast.buildVariableRenameTable(idx, summaries);
      const expander = ast.createSourceExpander(bundleSrc, idx, summaries);

      assert('bundle: summaries produced', summaries.length > 0);
      assert('bundle: slices produced', slices.length > 0);
      assert('bundle: VRT produced', vrt.renameTable.size > 0);
      assert('bundle: expander produced', typeof expander.expand === 'function');
      assert('bundle: expander sink summaries > 0',
        expander.getSinkSummaries().length > 0);

      // Verify VRT renamed some identifiers
      const renamedCount = vrt.stats.renamed;
      assert('bundle: VRT renamed ≥ 5 identifiers',
        renamedCount >= 5,
        `renamed=${renamedCount}`);

      // Verify expander can expand at least one function
      const firstSinkFn = summaries.find(s => s.sinks.length > 0);
      if (firstSinkFn) {
        const expansion = expander.expand(firstSinkFn.id);
        assert('bundle: expander expands sink function',
          expansion && expansion.source.length > 0);
      }
    }

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
  }, 1000);
}

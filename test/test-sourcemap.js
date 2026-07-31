#!/usr/bin/env node
/**
 * Source map parser tests (Phase 12q, Stage 3E)
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

// ═══════════════════════════════════════════════════════════════════════
section('1. No source map reference');
{
  const result = ast.parseSourceMap('var x = 1; var y = 2;');
  assert('no source map: found=false', result.found === false);
  assert('no source map: 0 findings', result.findings.length === 0);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. External .map URL reference');
{
  const src = 'var x = 1;\n//# sourceMappingURL=app.bundle.js.map';
  const result = ast.parseSourceMap(src);
  assert('external URL: found=true', result.found === true);
  assert('external URL: isExternal=true', result.isExternal === true);
  assert('external URL: isInline=false', result.isInline === false);
  assert('external URL: mapUrl captured', result.mapUrl === 'app.bundle.js.map');
  // Residual 3: one canonical finding per URL — sourcemap-ref is folded into
  // sourcemap-external (relative .map keeps medium severity)
  assert('external URL: exactly 1 finding', result.findings.length === 1,
    `findings=${result.findings.map(f=>`${f.id}(${f.severity})`).join(',')}`);
  assert('external URL: sourcemap-ref folded into canonical finding',
    !result.findings.some(f => f.id === 'sourcemap-ref'));
  assert('external URL: sourcemap-external finding present',
    result.findings.some(f => f.id === 'sourcemap-external'));
  assert('external URL: relative .map severity is medium',
    result.findings[0].severity === 'medium',
    `sev=${result.findings[0] && result.findings[0].severity}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('2a. CDN https source map URL — default info, strict medium');
{
  const src = 'var x = 1;\n//# sourceMappingURL=https://cdn.example.com/maps/app.js.map';
  const result = ast.parseSourceMap(src);
  assert('https URL: found=true', result.found === true);
  assert('https URL: isExternal=true', result.isExternal === true);
  assert('https URL: exactly 1 finding', result.findings.length === 1,
    `findings=${result.findings.length}`);
  assert('https URL: default severity is info',
    result.findings[0].severity === 'info' && result.findings[0].id === 'sourcemap-external',
    `id=${result.findings[0].id} sev=${result.findings[0].severity}`);
  const strictResult = ast.parseSourceMap(src, { strictSourcemaps: true });
  assert('https URL: --strict-sourcemaps keeps medium',
    strictResult.findings[0].severity === 'medium',
    `sev=${strictResult.findings[0].severity}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('2b. Inline map: sourcemap-ref folded into inline-decoded');
{
  const map = {
    version: 3,
    sources: ['webpack:///./src/app.js'],
    names: [], mappings: 'AAAA',
  };
  const mapB64 = Buffer.from(JSON.stringify(map)).toString('base64');
  const src = `var x = 1;\n//# sourceMappingURL=data:application/json;base64,${mapB64}`;
  const result = ast.parseSourceMap(src);
  assert('inline map: no sourcemap-ref when decoded',
    !result.findings.some(f => f.id === 'sourcemap-ref'),
    `ids: ${result.findings.map(f=>f.id).join(',')}`);
  assert('inline map: sourcemap-inline-decoded present',
    result.findings.some(f => f.id === 'sourcemap-inline-decoded'));
}

// ═══════════════════════════════════════════════════════════════════════
section('2c. Malformed inline map: sourcemap-ref folded into decode-failed');
{
  const src = 'var x = 1;\n//# sourceMappingURL=data:application/json;base64,!!!notvalidbase64!!!';
  const result = ast.parseSourceMap(src);
  assert('malformed inline: no sourcemap-ref when decode-failed fires',
    !result.findings.some(f => f.id === 'sourcemap-ref'),
    `ids: ${result.findings.map(f=>f.id).join(',')}`);
  assert('malformed inline: sourcemap-decode-failed present',
    result.findings.some(f => f.id === 'sourcemap-decode-failed'));
}

// ═══════════════════════════════════════════════════════════════════════
section('2d. Bare reference (no canonical branch): sourcemap-ref fallback');
{
  const src = 'var x = 1;\n//# sourceMappingURL=app.bundle.js';
  const result = ast.parseSourceMap(src);
  assert('bare URL: sourcemap-ref fallback fires',
    result.findings.some(f => f.id === 'sourcemap-ref'),
    `ids: ${result.findings.map(f=>f.id).join(',')}`);
  assert('bare URL: exactly 1 finding', result.findings.length === 1,
    `findings=${result.findings.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. HTTP source map URL');
{
  const src = 'var x = 1;\n//# sourceMappingURL=https://cdn.example.com/maps/app.js.map';
  const result = ast.parseSourceMap(src);
  assert('http URL: found=true', result.found === true);
  assert('http URL: isExternal=true', result.isExternal === true);
  assert('http URL: mapUrl is the full URL', result.mapUrl.startsWith('https://cdn.example.com/'));
}

// ═══════════════════════════════════════════════════════════════════════
section('4. Inline (base64) source map');
{
  // Build a minimal source map and base64-encode it
  const map = {
    version: 3,
    sources: ['webpack:///./src/app/app.component.ts', 'webpack:///./src/app/auth.service.ts'],
    names: [],
    mappings: 'AAAA',
    file: 'app.bundle.js',
  };
  const mapJson = JSON.stringify(map);
  const mapB64 = Buffer.from(mapJson).toString('base64');
  const src = `var x = 1;\n//# sourceMappingURL=data:application/json;base64,${mapB64}`;
  const result = ast.parseSourceMap(src);

  assert('inline map: found=true', result.found === true);
  assert('inline map: isInline=true', result.isInline === true);
  assert('inline map: isExternal=false', result.isExternal === false);
  assert('inline map: sourceCount=2', result.sourceCount === 2, `sourceCount=${result.sourceCount}`);
  assert('inline map: sources captured', result.sources.length === 2);
  assert('inline map: first source correct',
    result.sources[0] === 'webpack:///./src/app/app.component.ts',
    `source[0]=${result.sources[0]}`);
  assert('inline map: sourcemap-inline-decoded finding present',
    result.findings.some(f => f.id === 'sourcemap-inline-decoded'));
  // Internal source path (contains /src/) should be flagged
  assert('inline map: sensitive-path finding for /src/',
    result.findings.some(f => f.id === 'sourcemap-sensitive-path' && f.severity === 'high'));
}

// ═══════════════════════════════════════════════════════════════════════
section('5. Inline map with sensitive file paths');
{
  const map = {
    version: 3,
    sources: [
      'webpack:///./src/config.env',
      'webpack:///./certs/server.key',
      'webpack:///./node_modules/lodash/lodash.js',
    ],
    names: [], mappings: '',
  };
  const mapB64 = Buffer.from(JSON.stringify(map)).toString('base64');
  const src = `var x = 1;\n//# sourceMappingURL=data:application/json;base64,${mapB64}`;
  const result = ast.parseSourceMap(src);

  // Sensitive paths collapsed into one finding (highest severity)
  {
    const sp = result.findings.filter(f => f.id === 'sourcemap-sensitive-path');
    assert('inline map: has sourcemap-sensitive-path finding', sp.length === 1);
    assert('inline map: worst severity is critical (for .key)',
      sp[0].severity === 'critical');
    assert('inline map: count includes all matched paths',
      sp[0].value.includes('sensitive paths leaked'));
  }
}

// ═══════════════════════════════════════════════════════════════════════
section('6. Block comment source map reference');
{
  const src = 'var x = 1;\n/*# sourceMappingURL=app.js.map */';
  const result = ast.parseSourceMap(src);
  assert('block comment form: found=true', result.found === true);
  assert('block comment form: mapUrl captured', result.mapUrl === 'app.js.map');
}

// ═══════════════════════════════════════════════════════════════════════
section('7. Malformed inline map');
{
  // Inline data URI but not valid base64 JSON
  const src = 'var x = 1;\n//# sourceMappingURL=data:application/json;base64,!!!notvalidbase64!!!';
  const result = ast.parseSourceMap(src);
  assert('malformed inline: found=true (reference detected)', result.found === true);
  assert('malformed inline: isInline=true', result.isInline === true);
  assert('malformed inline: decode-failed finding present',
    result.findings.some(f => f.id === 'sourcemap-decode-failed'),
    `findings: ${result.findings.map(f=>f.id).join(',')}`);
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

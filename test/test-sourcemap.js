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
  assert('external URL: has findings', result.findings.length >= 2,
    `findings=${result.findings.length}`);
  assert('external URL: sourcemap-ref finding present',
    result.findings.some(f => f.id === 'sourcemap-ref'));
  assert('external URL: sourcemap-external finding present',
    result.findings.some(f => f.id === 'sourcemap-external'));
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

  // .env file → critical
  assert('inline map: .env file flagged critical',
    result.findings.some(f => f.id === 'sourcemap-sensitive-path' && f.value.includes('.env') && f.severity === 'critical'));
  // .key file → critical
  assert('inline map: .key file flagged critical',
    result.findings.some(f => f.id === 'sourcemap-sensitive-path' && f.value.includes('.key') && f.severity === 'critical'));
  // node_modules → low
  assert('inline map: node_modules flagged low',
    result.findings.some(f => f.id === 'sourcemap-sensitive-path' && f.value.includes('node_modules') && f.severity === 'low'));
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

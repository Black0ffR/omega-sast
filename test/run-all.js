#!/usr/bin/env node
'use strict';

/**
 * Test runner — executes all test suites and reports results.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// `--strict` makes any [KNOWN FAILING] marker a hard failure instead of a
// tolerated one. Those markers exist to expose bugs "claimed fixed upstream
// but not actually applied" — which only works if something enforces them.
// Without this, a suite can stay green while a real regression is filed under
// a marker, which is exactly the failure class the markers were added for.
//
// Off by default so local runs stay forgiving; CI passes it, and `npm test
// -- --strict` enables it for anyone verifying a fix.
//
// ALLOWLIST, not a blanket flag: several suites read positional argv
// (test-harness.js takes argv[2] as the AST module path), so appending
// --strict to every file makes them fail on the unknown argument. Only files
// that explicitly handle the flag receive it.
const STRICT_CAPABLE = new Set(['test-verification-issues.js']);
const STRICT = process.argv.includes('--strict');

const testDir = path.resolve(__dirname);
const testFiles = fs.readdirSync(testDir)
  .filter(f => f.startsWith('test-') && f.endsWith('.js'))
  .sort();

let totalPass = 0;
let totalFail = 0;
const results = [];

if (STRICT) console.log('  (strict: [KNOWN FAILING] markers are hard failures)\n');

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║  OMEGA-5.0 Test Suite — Running All Tests                    ║');
console.log('╚══════════════════════════════════════════════════════════════╝\n');

for (const file of testFiles) {
  const filePath = path.join(testDir, file);
  process.stdout.write(`  ${file.padEnd(35)} `);
  try {
    const strictThis = STRICT && STRICT_CAPABLE.has(file);
    const cmd = `node ${filePath}${strictThis ? ' --strict' : ''}`;
    const output = execSync(cmd, { encoding: 'utf8', timeout: 180000 });
    // Extract counts for DISPLAY only.
    //
    // The child's EXIT CODE is authoritative for the suite verdict. Counting
    // the printed `FAILED: N` here meant a file that deliberately tolerates
    // its [KNOWN FAILING] markers (it prints FAILED: N but exits 0) still
    // failed the whole suite — so the tolerance never actually worked, and
    // --strict had nothing to tighten.
    const passMatch = output.match(/PASSED: (\d+)|PASS: (\d+)/);
    const failMatch = output.match(/FAILED: (\d+)|FAIL: (\d+)/);
    const pass = passMatch ? parseInt(passMatch[1] || passMatch[2]) : 0;
    const fail = failMatch ? parseInt(failMatch[1] || failMatch[2]) : 0;
    totalPass += pass;
    results.push({ file, pass, fail });
    if (fail === 0) {
      console.log(`\x1b[32m${pass} pass\x1b[0m`);
    } else {
      console.log(`\x1b[31m${pass} pass, ${fail} fail\x1b[0m`);
    }
  } catch (e) {
    console.log(`\x1b[31mERROR\x1b[0m`);
    results.push({ file, pass: 0, fail: 1, error: e.message });
    totalFail++;
  }
}

console.log('\n╔══════════════════════════════════════════════════════════════╗');
console.log(`║  TOTAL: ${totalPass} passed, ${totalFail} failed${' '.repeat(Math.max(0, 30 - `${totalPass} passed, ${totalFail} failed`.length))}║`);
console.log('╚══════════════════════════════════════════════════════════════╝');

process.exit(totalFail > 0 ? 1 : 0);

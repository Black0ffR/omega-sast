#!/usr/bin/env node
'use strict';

/**
 * Test runner — executes all test suites and reports results.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const testDir = path.resolve(__dirname);
const testFiles = fs.readdirSync(testDir)
  .filter(f => f.startsWith('test-') && f.endsWith('.js'))
  .sort();

let totalPass = 0;
let totalFail = 0;
const results = [];

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║  OMEGA-5.0 Test Suite — Running All Tests                    ║');
console.log('╚══════════════════════════════════════════════════════════════╝\n');

for (const file of testFiles) {
  const filePath = path.join(testDir, file);
  process.stdout.write(`  ${file.padEnd(35)} `);
  try {
    const output = execSync(`node ${filePath}`, { encoding: 'utf8', timeout: 90000 });
    // Extract pass/fail counts from output
    const passMatch = output.match(/PASSED: (\d+)|PASS: (\d+)/);
    const failMatch = output.match(/FAILED: (\d+)|FAIL: (\d+)/);
    const pass = passMatch ? parseInt(passMatch[1] || passMatch[2]) : 0;
    const fail = failMatch ? parseInt(failMatch[1] || failMatch[2]) : 0;
    totalPass += pass;
    totalFail += fail;
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

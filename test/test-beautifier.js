#!/usr/bin/env node
/**
 * Quick sanity test for the OMEGA-5.0 beautifier fixes.
 * Verifies that arrow functions survive beautification intact and
 * template literals with nested ${...} are preserved.
 */
'use strict';
const path = require('path');
const omegaPath = path.resolve(__dirname, '..', 'src', '_monolith.js');

// We need to extract just the beautify function. Since omega-5.0.js is a CLI
// script that runs main() at the bottom, we can't simply require() it.
// Instead, we read the source and eval just the function definition.
const fs = require('fs');
const src = fs.readFileSync(omegaPath, 'utf8');

// Extract the beautify function source
const m = src.match(/function beautify\(src\)\s*\{[\s\S]*?\n\}\n/);
if (!m) {
  console.error('✘ could not extract beautify()');
  process.exit(1);
}
// Provide the module-level constants the beautifier depends on
global.INDENT = '  ';
// Convert "function beautify(src) { ... }" to "(function(src) { ... })"
const fnSrc = m[0].replace(/^function beautify/, 'function');
const beautify = eval(`(${fnSrc})`);

let pass = 0, fail = 0;
function check(name, input, expected) {
  const out = beautify(input);
  if (out === expected) {
    console.log(`  ✔ ${name}`);
    pass++;
  } else {
    console.log(`  ✘ ${name}`);
    console.log(`      input:    ${JSON.stringify(input)}`);
    console.log(`      expected: ${JSON.stringify(expected)}`);
    console.log(`      got:      ${JSON.stringify(out)}`);
    fail++;
  }
}

console.log('── Beautifier fix tests ──\n');

// Fix #5: arrow functions preserved
check('arrow function preserved',
  '(Q,H,d)=>{return Q.x;}',
  '(Q, H, d) => {\n  return Q.x;\n}');

check('arrow with body block',
  'const f=(a,b)=>{return a+b;}',
  'const f = (a, b) => {\n  return a + b;\n}');

check('comparison operators preserved',
  'if(a>=b&&c<=d){return 1;}',
  'if (a >= b && c <= d) {\n  return 1;\n}');

check('equality preserved',
  'if(a===b||c!==d){return 1;}',
  'if (a === b || c !== d) {\n  return 1;\n}');

check('nullish coalescing',
  'const x=a??b;',
  'const x = a ?? b;');

check('optional chaining',
  'const y=a?.b?.c;',
  'const y = a?.b?.c;');

// Fix #6: template literals
check('simple template literal preserved',
  'const x=`hello world`;',
  'const x = `hello world`;');

check('template with substitution preserved',
  'const x=`hello ${name}!`;',
  'const x = `hello ${name}!`;');

// Template substitutions are preserved verbatim (documented contract).
// The beautifier does NOT recurse into ${...} to avoid corrupting nested
// templates and complex expressions.
check('template with expression substitution preserved',
  'const x=`sum: ${a+b}`;',
  'const x = `sum: ${a+b}`;');

check('template with nested braces in substitution',
  'const x=`obj: ${{a:1}.a}`;',
  'const x = `obj: ${{a:1}.a}`;');

check('template with object literal in substitution',
  'const x=`data: ${JSON.stringify({a:1,b:2})}`;',
  'const x = `data: ${JSON.stringify({a:1,b:2})}`;');

console.log(`\n${'═'.repeat(50)}`);
console.log(`  PASS: ${pass}   FAIL: ${fail}`);
console.log(`${'═'.repeat(50)}`);
process.exit(fail ? 1 : 0);

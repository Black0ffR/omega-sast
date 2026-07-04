#!/usr/bin/env node
/**
 * ReDoS protection tests — verifies safeRegexIter caps hostile inputs.
 *
 * Since safeRegexIter lives inside omega-5.0.js (which auto-runs main()),
 * we redefine it here with the same logic and test it directly.
 */
'use strict';

// Mirrors the constants + function in omega-5.0.js
const MAX_REGEX_MATCHES = 50; // lowered for faster tests
const REGEX_LOOP_BUDGET_MS = 1000;

function safeRegexIter(re, src, onMatch, onAbort) {
  const startedAt = Date.now();
  let count = 0;
  let m;
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
    if (m.index === re.lastIndex) re.lastIndex++;
  }
}

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✔ ${name}`); }
  else { fail++; console.log(`  ✘ ${name}`); if (detail) console.log(`      → ${detail}`); }
}

console.log('── ReDoS protection tests ──\n');

// Test 1: normal input completes without abort
{
  const matches = [];
  const re = /foo/g;
  let aborted = null;
  safeRegexIter(re, 'foo bar foo baz foo', (m) => matches.push(m[0]), (r) => aborted = r);
  check('normal input: 3 matches collected', matches.length === 3, `matches=${matches.length}`);
  check('normal input: no abort', aborted === null);
}

// Test 2: too many matches triggers abort
{
  const matches = [];
  const re = /a/g;
  let aborted = null;
  const input = 'a'.repeat(200);
  safeRegexIter(re, input, (m) => matches.push(m.index), (r) => aborted = r);
  check('hostile input: abort triggered', aborted !== null, `aborted=${aborted}`);
  check('hostile input: matches capped at MAX_REGEX_MATCHES', matches.length === 50, `matches=${matches.length}`);
}

// Test 3: zero-length match doesn't loop forever
{
  const matches = [];
  const re = /\b/g;
  let aborted = null;
  safeRegexIter(re, 'word boundary test', (m) => matches.push(m.index), (r) => aborted = r);
  check('zero-length match: terminates (no infinite loop)', matches.length < 100, `matches=${matches.length}`);
  check('zero-length match: no abort from cap', aborted === null || !aborted.includes('cap'), `aborted=${aborted}`);
}

// Test 4: non-global regex gets global flag auto-added
{
  const matches = [];
  const re = /foo/;
  let aborted = null;
  safeRegexIter(re, 'foo foo foo', (m) => matches.push(m[0]), (r) => aborted = r);
  check('non-global regex: auto-globalised, finds all matches', matches.length === 3, `matches=${matches.length}`);
}

// Test 5: no matches completes cleanly
{
  const matches = [];
  const re = /xyz/g;
  let aborted = null;
  safeRegexIter(re, 'nothing here', (m) => matches.push(m[0]), (r) => aborted = r);
  check('no matches: clean completion', matches.length === 0 && aborted === null);
}

// Test 6: lastIndex reset to 0 after abort (regex reusable)
{
  const re = /a/g;
  const input = 'a'.repeat(200);
  safeRegexIter(re, input, () => {}, () => {});
  check('post-abort: regex lastIndex reset to 0', re.lastIndex === 0, `lastIndex=${re.lastIndex}`);
}

// Test 7: original regex object not mutated (we create a new one if non-global)
{
  const re = /foo/; // non-global
  safeRegexIter(re, 'foo foo', () => {}, () => {});
  check('non-global regex: original not mutated', re.global === false, `global=${re.global}`);
}

console.log(`\n${'═'.repeat(50)}`);
console.log(`  PASS: ${pass}   FAIL: ${fail}`);
console.log(`${'═'.repeat(50)}`);
process.exit(fail ? 1 : 0);

#!/usr/bin/env node
/**
 * Regression test — modern obfuscator.io decoder shapes (real 5.8.0 output).
 *
 * Covers four decoder-pipeline gaps found by manual analysis of
 * javascript-obfuscator@5.8.0 bundles (mangled idents, high/medium presets):
 *
 *  1. Custom base64 alphabet: the template uses a lowercase-first alphabet
 *     (a-zA-Z0-9+/=), not RFC 4648. Node Buffer decodes the wrong alphabet
 *     into garbage ("0 strings decoded"). obfBase64Decode mirrors the
 *     template loop, ordered by body evidence (alphabet literal present?).
 *  2. RC4/base64 misclassification: `body.includes(keyParam)` is trivially
 *     true for single-letter params — requires identifier-boundary use now.
 *  3. Alias chains: `var i=b` then `var j=i` — Step 3d/rotateBruteForce
 *     resolve aliases to fixpoint (was single-level: j()/k() never inlined).
 *  4. Self-reassigning getter + tier-3 impostor rejection:
 *     `function a(){var t=[...];a=function(){return t;};return a();}`
 *     is linked (was: wrong getter across function boundaries); app code
 *     matching the loose getter+local shape without transform/return
 *     markers is rejected (was: swallowed the true decoder).
 *
 * Run: node test/test-obfio-modern-shapes.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const bin = path.join(repoRoot, 'bin', 'omega.js');

let total = 0, passed = 0, failed = 0;
function assert(name, cond, detail) {
  total++;
  if (cond) { passed++; console.log(`  ✔ ${name}`); }
  else {
    failed++;
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) console.log(`      → ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
}
function section(name) { console.log(`\n── ${name} ──────────────────────`); }

function scan(src) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omega-obfshape-'));
  fs.writeFileSync(path.join(tmp, 'f.js'), src);
  try {
    execFileSync('node', [bin, path.join(tmp, 'f.js'), '--all', '--out', path.join(tmp, 'out')], { stdio: 'pipe' });
  } catch (e) { /* findings exit codes are fine */ }
  const r = JSON.parse(fs.readFileSync(path.join(tmp, 'out', 'report.json'), 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  return r;
}
function b64std(s) { return Buffer.from(s, 'utf8').toString('base64'); }

// ── 1. Genuine obfuscator.io base64 template decodes ────────────────────
section('1. Lowercase-first base64 alphabet');
{
  // Mimics the 5.8.0 template: custom alphabet literal + decodeURIComponent,
  // single-letter params, base64 entries of 'wss://x' and 'onmessage'.
  const enc = (s) => {
    const L = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
    const raw = Buffer.from(s, 'utf8');
    let bits = 0, buf = 0, out = '';
    for (const byte of raw) {
      buf = (buf << 8) | byte; bits += 8;
      while (bits >= 6) { bits -= 6; out += L[(buf >> bits) & 63]; buf &= (1 << bits) - 1; }
    }
    if (bits > 0) out += L[(buf << (6 - bits)) & 63];
    while (out.length % 4) out += '=';
    return out;
  };
  const src = [
    `function a(){var n=['${enc('wss://x')}', '${enc('onmessage')}', '${enc('pad-a')}', '${enc('pad-b')}'];return n;}`,
    `(function(c,d){var h=b,e=c();while(!![]){try{var f=-parseInt(h(0x0))/0x1+parseInt(h(0x1))/0x2;if(f===d)break;else e['push'](e['shift']());}catch(g){e['push'](e['shift']());}}}(a,0x2));`,
    `function b(c,d){c=c-0x0;var e=a();var f=e[c];var g=function(j){var l='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';var m='',n='';for(var o=0x0,p,q,r=0x0;q=j['charAt'](r++);~q&&(p=o%0x4?p*0x40+q:q,o++%0x4)?m+=String['fromCharCode'](0xff&q>>(-0x2*o&0x6)):0x0){q=l['indexOf'](q);}for(var s=0x0,t=m['length'];s<t;s++){n+='%'+('00'+m['charCodeAt'](s)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(n);};return g(f);}`,
    `var i=b;var s=new WebSocket(i(0x0));`,
  ].join('\n');
  const r = scan(src);
  assert('custom-alphabet strings decoded (obfuscatorIo > 0)',
    (r.decodeStats.obfuscatorIo || 0) > 0, JSON.stringify(r.decodeStats));
}

// ── 2. Alias chains inline ──────────────────────────────────────────────
section('2. Alias-of-alias inlining');
{
  // Mirrors real 5.8.0 output: getter-wrapped array, rotation IIFE over
  // the getter, plain decoder via a local, then alias-of-alias call sites.
  const src = [
    `function a(){var n=['alpha','beta','gamma','delta'];return n;}`,
    `(function(c,d){var e=c();while(!![]){try{if(0===d)break;else e['push'](e['shift']());}catch(g){e['push'](e['shift']());}}}(a,0x1));`,
    `function b(c,d){var e=a();var f=e[c];return f;}`,
    `var i=b;`,
    `function s(){var j=i;var k=i;return j(0x0)+k(0x1);}`,
    `s();`,
  ].join('\n');
  const r = scan(src);
  assert('alias-chain calls decoded (obfuscatorIo > 0)',
    (r.decodeStats.obfuscatorIo || 0) > 0, JSON.stringify(r.decodeStats));
}

// ── 3. Self-reassigning getter links array ──────────────────────────────
section('3. Self-reassigning getter');
{
  const src = [
    `function a(){var t=['one','two','three'];a=function(){return t;};return a();}`,
    `(function(c,d){var e=c();while(!![]){try{if(0===d)break;else e['push'](e['shift']());}catch(g){e['push'](e['shift']());}}}(a,0x1));`,
    `function b(c,d){c=c-0x0;var e=a();var f=e[c];return f;}`,
    `var o=b;var x=o(0x0);`,
  ].join('\n');
  const r = scan(src);
  assert('self-reassigning getter array decoded',
    (r.decodeStats.obfuscatorIo || 0) > 0, JSON.stringify(r.decodeStats));
}

// ── 4. Plain tier-3 decoder accepted, app code rejected ─────────────────
section('4. Tier-3 content gate');
{
  // Legit plain decoder through a getter must be accepted…
  const good = [
    `function g(){var arr=['p','q','r','s'];return arr;}`,
    `(function(c,d){var e=c();e['push'](e['shift']());}(g,0x1));`,
    `function D(i,k){var l=g();return l[i];}`,
    `var a=D(0x0,'x');`,
  ].join('\n');
  const r1 = scan(good);
  assert('plain getter decoder decoded',
    (r1.decodeStats.obfuscatorIo || 0) > 0, JSON.stringify(r1.decodeStats));
  // …while app code matching the loose shape yields no decoder finding.
  const bad = [
    `function g(){var arr=['p','q','r','s'];return arr;}`,
    `function login(c,d){var r=g();var f=r(0x0);return document[f]=c,f;}`,
    `login('a','b');`,
  ].join('\n');
  const r2 = scan(bad);
  const decFindings = [...(r2.extendedFindings || [])]
    .filter(f => f.id === 'obfuscator-io-decoder' && /login/.test(f.value || ''));
  assert('app-code impostor not reported as decoder',
    decFindings.length === 0, JSON.stringify(decFindings.map(f => f.value)));
}

console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
process.exit(failed > 0 ? 1 : 0);

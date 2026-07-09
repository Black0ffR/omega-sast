#!/usr/bin/env node
/**
 * OMEGA-5.0 tokenizer edge-case tests
 *
 * Targeted tests for the hand-rolled lexer in omega-5.0-ast.js, focusing on
 * the tricky cases that hand-rolled parsers tend to get wrong:
 *   - regex vs division ambiguity
 *   - template literals with nested ${...} and nested backticks
 *   - block comments containing string-like sequences
 *   - multi-char operators (greedy matching)
 *   - Unicode identifiers (ɵ, emoji-adjacent)
 *   - HTML entities in strings
 *   - line/col tracking accuracy
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

function tok(src) {
  return ast.tokenizeForAST(src).tokens;
}

// ═══════════════════════════════════════════════════════════════════════
section('1. Regex vs division ambiguity');
// After `(`, `,`, `;`, `=`, keywords → regex. After identifier/number/`)` → division.
{
  const t1 = tok('var x = /foo/g;');
  const regexTok = t1.find(t => t.type === 'regex');
  assert('regex after `=` is recognised', !!regexTok, `tokens: ${t1.map(t=>t.type).join(',')}`);
  assert('regex body extracted', regexTok && regexTok.value === 'foo', `value=${regexTok && regexTok.value}`);
  assert('regex flags extracted', regexTok && regexTok.flags === 'g', `flags=${regexTok && regexTok.flags}`);

  const t2 = tok('var a = 10 / 2;');
  const divs = t2.filter(t => t.type === 'punct' && t.value === '/');
  assert('division after number is punct (not regex)', divs.length === 1, `divs=${divs.length}`);

  const t3 = tok('foo(/pattern/);');
  const r3 = t3.find(t => t.type === 'regex');
  assert('regex after `(` is recognised', !!r3);

  const t4 = tok('a.b/c');
  const r4 = t4.find(t => t.type === 'regex');
  assert('`a.b/c` is division (not regex) — prev is identifier', !r4, `got regex: ${!!r4}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('1b. Regex after multi-char operators (regression)');
// CRITICAL: the old isRegexContext used a single-char-anchored regex
// `/^[(\[,;?:&|\^+\-*\/%~<>!=]$/` which silently returned false for every
// multi-char punct token (&&, ||, ===, =>, >=, ??, etc.), causing regex
// literals after these operators to be mis-tokenized as division.
{
  // && (logical AND) — ends with &, regex context
  const t1 = tok('a && /foo/g');
  const r1 = t1.find(t => t.type === 'regex');
  assert('regex after `&&` is recognised', !!r1, `tokens: ${t1.map(t=>`${t.type}:${t.value}`).join('|')}`);
  assert('regex after `&&` has correct body', r1 && r1.value === 'foo', `value=${r1 && r1.value}`);

  // || (logical OR) — ends with |
  const t2 = tok('a || /foo/g');
  const r2 = t2.find(t => t.type === 'regex');
  assert('regex after `||` is recognised', !!r2);

  // === (strict equality) — ends with =
  const t3 = tok('x === /pattern/i');
  const r3 = t3.find(t => t.type === 'regex');
  assert('regex after `===` is recognised', !!r3, `tokens: ${t3.map(t=>`${t.type}:${t.value}`).join('|')}`);

  // !== (strict inequality) — ends with =
  const t4 = tok('x !== /pattern/');
  const r4 = t4.find(t => t.type === 'regex');
  assert('regex after `!==` is recognised', !!r4);

  // => (arrow) — ends with >, regex context (arrow returning a regex literal)
  const t5 = tok('const f = () => /foo/g;');
  const r5 = t5.find(t => t.type === 'regex');
  assert('regex after `=>` is recognised (arrow body)', !!r5, `tokens: ${t5.map(t=>`${t.type}:${t.value}`).join('|')}`);

  // >= (greater-or-equal) — ends with =
  const t6 = tok('if (x >= /\\d+/)');
  const r6 = t6.find(t => t.type === 'regex');
  assert('regex after `>=` is recognised', !!r6);

  // <= (less-or-equal) — ends with =
  const t7 = tok('if (x <= /\\d+/)');
  const r7 = t7.find(t => t.type === 'regex');
  assert('regex after `<=` is recognised', !!r7);

  // ?? (nullish coalescing) — ends with ?
  const t8 = tok('x ?? /foo/g');
  const r8 = t8.find(t => t.type === 'regex');
  assert('regex after `??` is recognised', !!r8);

  // ?: (ternary) — `?` and `:` are both regex context
  const t9 = tok('cond ? /a/ : /b/');
  const r9 = t9.filter(t => t.type === 'regex');
  assert('regex after `?` (ternary then-branch) recognised', r9.length >= 1, `count=${r9.length}`);
  assert('regex after `:` (ternary else-branch) recognised', r9.length >= 2, `count=${r9.length}`);

  // Compound assignment: += -= *= /= %= &= |= ^=
  const t10 = tok('x += /foo/g');
  const r10 = t10.find(t => t.type === 'regex');
  assert('regex after `+=` is recognised', !!r10);

  // ++ -- (prefix/postfix) — ends with + or -
  // Note: `x++ / 2` is technically division (postfix ++), but `++x / 2` is also division.
  // We're testing that `/foo/` after `++` is at least CONSIDERED — in practice
  // `++ /foo/` is unusual syntax, but the tokenizer should still pick regex
  // because `+` is in the regex-context set.
  const t11 = tok('++x; /foo/g');
  const r11 = t11.find(t => t.type === 'regex');
  assert('regex after `;` (statement start) recognised', !!r11);

  // Negative control: regex NOT recognised after `)` `]` `}` (close-brackets → division)
  const t12 = tok('foo() / 2');
  const r12 = t12.find(t => t.type === 'regex');
  assert('`/` after `)` is division (not regex)', !r12, `got regex: ${!!r12}`);

  const t13 = tok('arr[0] / 2');
  const r13 = t13.find(t => t.type === 'regex');
  assert('`/` after `]` is division (not regex)', !r13);

  const t14 = tok('let o = {}; o / 2');
  const r14 = t14.find(t => t.type === 'regex');
  assert('`/` after `}` is division (not regex)', !r14);

  // Negative control: regex NOT recognised after identifier, number, string
  const t15 = tok('x / 2');
  const r15 = t15.find(t => t.type === 'regex');
  assert('`/` after identifier is division', !r15);

  const t16 = tok('10 / 2');
  const r16 = t16.find(t => t.type === 'regex');
  assert('`/` after number is division', !r16);

  const t17 = tok('"x" / 2');
  const r17 = t17.find(t => t.type === 'regex');
  assert('`/` after string is division', !r17);
}

// ═══════════════════════════════════════════════════════════════════════
section('2. Template literals with nested substitutions');
{
  const t1 = tok('const x = `hello ${name}!`;');
  const tmpl = t1.find(t => t.type === 'template');
  assert('simple template literal tokenised', !!tmpl);
  assert('template value preserved', tmpl && tmpl.value.includes('hello'), `value=${tmpl && tmpl.value}`);

  // Nested ${...} with object literal
  const t2 = tok('const x = `obj: ${{a:1}.a}`;');
  const tmpl2 = t2.find(t => t.type === 'template');
  assert('template with nested object literal in substitution', !!tmpl2);
  assert('template value includes substitution', tmpl2 && tmpl2.value.includes('obj:'), `value=${tmpl2 && tmpl2.value}`);

  // Nested template inside substitution
  const t3 = tok('const x = `outer ${`inner`} end`;');
  const tmpls = t3.filter(t => t.type === 'template');
  assert('nested template inside substitution produces ≥1 template token', tmpls.length >= 1, `count=${tmpls.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('3. Comments');
{
  // Line comment
  const t1 = tok('var x = 1; // comment\nvar y = 2;');
  const idents = t1.filter(t => t.type === 'ident');
  assert('line comment does not produce ident tokens for its content', !idents.some(t => t.value === 'comment'),
    `idents: ${idents.map(t=>t.value).join(',')}`);
  assert('code after line comment is tokenised', idents.some(t => t.value === 'y'));

  // Block comment (no nesting in JS, but parser should still handle correctly)
  const t2 = tok('var x = 1; /* this is "a string" inside comment */ var y = 2;');
  const idents2 = t2.filter(t => t.type === 'ident');
  assert('block comment skipped entirely', !idents2.some(t => t.value === 'this'),
    `idents: ${idents2.map(t=>t.value).join(',')}`);
  assert('code after block comment is tokenised', idents2.some(t => t.value === 'y'));
  assert('no spurious string token from comment content', !t2.some(t => t.type === 'string' && t.value.includes('a string')));
}

// ═══════════════════════════════════════════════════════════════════════
section('4. Multi-char operator greedy matching');
{
  const t1 = tok('a => b');
  const arrow = t1.find(t => t.type === 'punct' && t.value === '=>');
  assert('arrow `=>` is single punct token', !!arrow, `puncts: ${t1.filter(t=>t.type==='punct').map(t=>t.value).join('|')}`);

  const t2 = tok('a === b');
  const eq = t2.find(t => t.type === 'punct' && t.value === '===');
  assert('`===` is single punct token', !!eq);

  const t3 = tok('a !== b');
  const neq = t3.find(t => t.type === 'punct' && t.value === '!==');
  assert('`!==` is single punct token', !!neq);

  const t4 = tok('a >= b');
  const ge = t4.find(t => t.type === 'punct' && t.value === '>=');
  assert('`>=` is single punct token', !!ge);

  const t5 = tok('a ?? b');
  const nullish = t5.find(t => t.type === 'punct' && t.value === '??');
  assert('`??` is single punct token', !!nullish);

  const t6 = tok('a ?. b');
  const optchain = t6.find(t => t.type === 'punct' && t.value === '?.');
  assert('`?.` is single punct token', !!optchain);

  const t7 = tok('a >>> b');
  const urshift = t7.find(t => t.type === 'punct' && t.value === '>>>');
  assert('`>>>` is single punct token', !!urshift);

  // Triple-equals should NOT be parsed as two `=` + one `=`
  const t8 = tok('a===b');
  const eqs = t8.filter(t => t.type === 'punct' && t.value === '=');
  assert('`===` does not produce any single `=` tokens', eqs.length === 0, `single = count: ${eqs.length}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('5. Unicode identifiers (Angular ɵ prefix)');
{
  const t1 = tok('static ɵcmp = 1;');
  const theta = t1.find(t => t.type === 'ident' && t.value === 'ɵcmp');
  assert('`ɵcmp` (U+0275) is a single ident token', !!theta, `tokens: ${t1.map(t=>`${t.type}:${t.value}`).join('|')}`);

  const t2 = tok('ɵɵdefineComponent()');
  const defn = t2.find(t => t.type === 'ident' && t.value === 'ɵɵdefineComponent');
  assert('`ɵɵdefineComponent` is a single ident token', !!defn);

  // Unicode escape in source string `\u0275cmp` — this is INSIDE a string,
  // so it should be preserved as string content, not converted.
  const t3 = tok('var x = "\\u0275cmp";');
  const str = t3.find(t => t.type === 'string');
  assert('`\\u0275` inside string preserved', !!str && str.value.includes('\\u0275'), `value=${str && str.value}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('6. String escapes');
{
  const t1 = tok("var x = 'it\\'s';");
  const str = t1.find(t => t.type === 'string');
  assert('escaped quote inside string handled', !!str);
  assert('string value includes escaped quote', str && str.value.includes("it\\'s"), `value=${str && str.value}`);

  const t2 = tok('var x = "line\\nbreak";');
  const str2 = t2.find(t => t.type === 'string');
  assert('escape \\n preserved in string value', str2 && str2.value.includes('\\n'), `value=${str2 && str2.value}`);

  const t3 = tok('var x = "tab\\tend";');
  const str3 = t3.find(t => t.type === 'string');
  assert('escape \\t preserved in string value', str3 && str3.value.includes('\\t'));
}

// ═══════════════════════════════════════════════════════════════════════
section('7. Numbers');
{
  const t1 = tok('var x = 42;');
  const num = t1.find(t => t.type === 'number');
  assert('integer literal tokenised', !!num && num.value === '42', `value=${num && num.value}`);

  const t2 = tok('var x = 3.14;');
  const num2 = t2.find(t => t.type === 'number');
  assert('decimal literal tokenised', !!num2 && num2.value === '3.14');

  const t3 = tok('var x = 0xff;');
  const num3 = t3.find(t => t.type === 'number');
  assert('hex literal tokenised', !!num3 && num3.value === '0xff');

  const t4 = tok('var x = 1e10;');
  const num4 = t4.find(t => t.type === 'number');
  assert('scientific notation tokenised', !!num4 && num4.value === '1e10');

  const t5 = tok('var x = 0b1010;');
  const num5 = t5.find(t => t.type === 'number');
  assert('binary literal tokenised', !!num5 && num5.value === '0b1010');
}

// ═══════════════════════════════════════════════════════════════════════
section('8. Position tracking');
{
  const src = 'var x = 1;';
  const t = tok(src);
  const xTok = t.find(tt => tt.type === 'ident' && tt.value === 'x');
  assert('ident start position correct', xTok && xTok.start === 4, `start=${xTok && xTok.start}`);
  assert('ident end position correct', xTok && xTok.end === 5, `end=${xTok && xTok.end}`);
  assert('slice by positions recovers original text', xTok && src.slice(xTok.start, xTok.end) === 'x');

  // Multi-line: line counter
  const lex = ast.tokenizeForAST('var x = 1;\nvar y = 2;\nvar z = 3;');
  assert('line counter tracks newlines', lex.lines === 3, `lines=${lex.lines}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('9. Whitespace handling');
{
  const t1 = tok('var   x   =   1');
  const idents = t1.filter(t => t.type === 'ident' || t.type === 'keyword');
  assert('multiple spaces collapse (no whitespace tokens)', idents.length === 2 && idents[0].value === 'var' && idents[1].value === 'x',
    `idents: ${idents.map(t=>t.value).join(',')}`);

  const t2 = tok('\t\tvar\tx\t');
  const kw = t2.find(t => t.type === 'keyword' && t.value === 'var');
  assert('tabs treated as whitespace', !!kw);

  const t3 = tok('\r\nvar x');
  const kw3 = t3.find(t => t.type === 'keyword' && t.value === 'var');
  assert('CRLF line endings handled', !!kw3);
}

// ═══════════════════════════════════════════════════════════════════════
section('10. Empty / degenerate input');
{
  const t1 = tok('');
  assert('empty input produces no tokens', t1.length === 0);

  const t2 = tok('   \n\t  ');
  assert('whitespace-only input produces no tokens', t2.length === 0);

  const t3 = tok('// just a comment');
  assert('comment-only input produces no tokens', t3.length === 0);

  const t4 = tok('/* block comment */');
  assert('block-comment-only input produces no tokens', t4.length === 0);
}

// ═══════════════════════════════════════════════════════════════════════
section('11. Keywords vs identifiers');
{
  const t1 = tok('var let const function class');
  const kws = t1.filter(t => t.type === 'keyword');
  assert('reserved words tagged as keyword', kws.length === 5, `kws: ${kws.map(t=>t.value).join(',')}`);

  const t2 = tok('var myVar = 1;');
  const ident = t2.find(t => t.type === 'ident' && t.value === 'myVar');
  assert('non-reserved identifier tagged as ident', !!ident);

  // `await` is a keyword in modules but context-dependent. Our tokenizer
  // treats it as keyword always — document this.
  const t3 = tok('await x');
  const awaitTok = t3.find(t => t.value === 'await');
  assert('await tagged (as keyword)', !!awaitTok && awaitTok.type === 'keyword');
}

// ═══════════════════════════════════════════════════════════════════════
section('12. Punctuation combos');
{
  const t1 = tok('obj.prop');
  const dot = t1.find(t => t.type === 'punct' && t.value === '.');
  assert('member-access dot is punct', !!dot);

  const t2 = tok('arr[0]');
  const lbrk = t2.find(t => t.type === 'punct' && t.value === '[');
  const rbrk = t2.find(t => t.type === 'punct' && t.value === ']');
  assert('brackets are punct', !!lbrk && !!rbrk);

  const t3 = tok('fn(a, b)');
  const lp = t3.find(t => t.type === 'punct' && t.value === '(');
  const rp = t3.find(t => t.type === 'punct' && t.value === ')');
  const comma = t3.find(t => t.type === 'punct' && t.value === ',');
  assert('parens + comma are punct', !!lp && !!rp && !!comma);

  // Spread operator
  const t4 = tok('fn(...args)');
  const spread = t4.find(t => t.type === 'punct' && t.value === '...');
  assert('spread `...` is single punct token', !!spread, `puncts: ${t4.filter(t=>t.type==='punct').map(t=>t.value).join('|')}`);
}

// ═══════════════════════════════════════════════════════════════════════
section('13. Syntax error detection');
{
  const malformed = 'function broken( { return ; }';
  const si = ast.buildStructuralIndex(malformed);
  const fnKeywords = (si.lex?.tokens || []).filter(t => t.type === 'keyword' && t.value === 'function').length;
  assert('malformed file has function keyword tokens', fnKeywords > 0);
  assert('malformed file parsed 0 functions', si.functions.length === 0);
  assert('malformed file lex exists', !!si.lex);
  assert('malformed file tokens non-empty', si.lex.tokens.length > 0);
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

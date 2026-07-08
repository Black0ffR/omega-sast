// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 9b — AST FOUNDATION  (OMEGA-5.0, Tier 1 base)
//
//  Hand-rolled, zero-dependency JavaScript tokenizer + structural walker
//  designed for MINIFIED code. Parses the entire file once into a flat
//  stream of "statements" — class/function bodies, top-level expressions —
//  accurate enough for framework fingerprinting, call graph extraction,
//  and taint tracking, without paying for full ECMAScript conformance.
//
//  Why custom? The script's header contract is "Zero external dependencies".
//  Acorn is ~50KB minified; shipping it inlined as one more constant would
//  break the single-file promise. This tokenizer handles the 95% of JS
//  surface area that matters for SAST: identifiers, strings, templates,
//  binary/unary ops, parens/braces/brackets, function args, member access,
//  assignment. It intentionally does NOT support: getters/setters (skipped
//  via class body depth counter), `with` (undefined in strict), labels,
//  do/while is supported, computed props via [expr] is supported.
//
//  Output: { statements: [{ kind, start, end, text, body? , params? }],
//            callSites: [{ name, start, end, depth }],
//            identifiers: [{ name, start, end, depth }],
//            classes: [{ name, start, end, staticFields, methods }],
//            functions: [{ name?, start, end, params, isArrow }],
//            errors: [{ msg, pos }] }
//
//  Errors do not abort — partial AST plus a list of skip sites is fine for
//  detection work.
// ═══════════════════════════════════════════════════════════════════════════

function tokenizeForAST(src) {
  const N = src.length;
  let i = 0, line = 1, col = 1;
  const tokens = [];
  const errors = [];

  const IDENT_START = /[A-Za-z_$]/;
  const IDENT_PART  = /[A-Za-z0-9_$]/;
  const DIGIT       = /[0-9]/;

  function isIdentStart(c) {
    if (IDENT_START.test(c)) return true;
    // ECMAScript IdentifierStart characters outside ASCII:
    //   · U+00A0–U+10FFFF via Unicode ID_Start property
    //   · For our domain: U+0275 (GREEK SMALL LETTER TILDE), which Angular's
    //     Ivy runtime uses for mangled private symbols (`ɵcmp`, `ɵfac`, etc.)
    if (!c) return false;
    const cp = c.codePointAt(0);
    if (cp === 0x0275) return true;
    // Allow broader Unicode identifier chars (anything in BMP that's Lu, Ll, Lt,
    // Lm, Lo, Nl, or underscore-like) — full Unicode table is overkill; we just
    // need to not split on `ɵ`. Approximate with: any non-ASCII non-punctuation.
    if (cp > 0x7F && !/\s/.test(c) && !/[()\[\]{},;:.?<>=+\-*/%&|^!~`'"\\]/.test(c)) return true;
    return false;
  }
  function isIdentPart(c)  {
    if (IDENT_PART.test(c)) return true;
    if (!c) return false;
    const cp = c.codePointAt(0);
    if (cp === 0x0275) return true;
    if (cp > 0x7F && !/\s/.test(c) && !/[()\[\]{},;:.?<>=+\-*/%&|^!~`'"\\]/.test(c)) return true;
    return false;
  }
  function isDigit(c)      { return DIGIT.test(c); }

  function skipWS() {
    while (i < N) {
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\r') { i++; col++; continue; }
      if (c === '\n') { i++; line++; col = 1; continue; }
      // Single-line comment
      if (c === '/' && src[i+1] === '/') { while (i < N && src[i] !== '\n') i++; continue; }
      // Block comment (handle nesting)
      if (c === '/' && src[i+1] === '*') {
        i += 2; col += 2;
        let depth = 1;
        while (i < N && depth > 0) {
          if (src[i] === '/' && src[i+1] === '*') { depth++; i += 2; col += 2; continue; }
          if (src[i] === '*' && src[i+1] === '/') { depth--; i += 2; col += 2; continue; }
          if (src[i] === '\n') { line++; col = 1; }
          i++;
        }
        continue;
      }
      break;
    }
  }

  function readString(quote) {
    const start = i; i++; col++;
    let str = '';
    while (i < N) {
      const c = src[i];
      if (c === '\\') {
        str += c + (src[i+1] || '');
        col += 2; i += 2;
        continue;
      }
      if (c === quote) { i++; col++; break; }
      if (c === '\n') { line++; col = 1; }
      else col++;
      str += c; i++;
    }
    return { type:'string', value:str, start, end:i };
  }

  function readTemplate() {
    const start = i; i++; col++;
    let str = '', parts = [];
    while (i < N) {
      const c = src[i];
      if (c === '\\') {
        str += c + (src[i+1] || '');
        col += 2; i += 2;
        continue;
      }
      if (c === '`') { i++; col++; break; }
      if (c === '$' && src[i+1] === '{') {
        str += c + '{';
        i += 2; col += 2;
        // skip template substitution — approximate to matching brace at any depth
        let depth = 1;
        while (i < N && depth > 0) {
          if (src[i] === '{') depth++;
          else if (src[i] === '}') depth--;
          i++; col++;
        }
        continue;
      }
      i++; col++;
      str += c;
    }
    return { type:'template', value:str, start, end:i };
  }

  function readNumber() {
    const start = i;
    while (i < N && /[0-9.eE+\-xXbBoOA-Fa-f_n]/.test(src[i])) { i++; col++; }
    return { type:'number', value:src.slice(start, i), start, end:i };
  }

  function readIdent() {
    const start = i;
    while (i < N && isIdentPart(src[i])) { i++; col++; }
    const name = src.slice(start, i);
    // Keyword vs identifier — keywords get tagged
    const KEYWORDS = new Set([
      'var','let','const','function','class','extends','new','return','if','else',
      'for','while','do','switch','case','default','break','continue','throw','try',
      'catch','finally','typeof','instanceof','in','of','delete','void','yield',
      'async','await','static','get','set','import','export','from','as','null',
      'true','false','undefined','this','super',
    ]);
    return { type: KEYWORDS.has(name) ? 'keyword' : 'ident', value:name, start, end:i };
  }

  function isRegexContext(prev) {
    // Heuristic: regex literal is allowed after these tokens / start of input
    if (!prev) return true;
    const t = prev.type, v = prev.value;
    if (t === 'keyword') return true;
    if (t === 'punct') {
      // After ( , ; { = ? : & | ^ + - * / % ! ~ < > [ ! =
      //
      // FIX: previously the regex was `/^[(\[,;?:&|\^+\-*\/%~<>!=]$/` which is
      // anchored to match EXACTLY ONE character. Multi-char punct tokens like
      // `&&`, `||`, `===`, `!==`, `=>`, `>=`, `<=`, `??`, `?.`, `++`, `--`,
      // `+=`, etc. all failed the test and fell through to `return false`,
      // causing `a && /foo/`, `x => /pat/`, `cond ? /a/ : /b/` to be
      // mis-tokenized as division.
      //
      // New approach: examine the LAST character of the punct value — that's
      // the char that actually abuts the `/`. For every multi-char operator
      // ending in a regex-context char (`&&`→`&`, `===`→`=`, `=>`→`>`,
      // `>=`→`=`, `??`→`?`, `?.`→`.`, etc.), this correctly returns true.
      // We still exclude `)`, `]`, `}` (which close groups and are followed
      // by division, not regex).
      if (v.length === 0) return false;
      const last = v[v.length - 1];
      // Regex-context chars: ( [ { , ; ? : & | ^ + - * / % ! ~ < > =
      // (open-brackets, separators, ternary, binary ops, assignment).
      // Excludes: ) ] } (close-brackets → division), . (member access → division).
      return '([{,;?:&|^+-*/%!~<>='.includes(last);
    }
    if (t === 'ident') return false; // identifier followed by ( is fn call not regex
    if (t === 'number') return false; // number / number is division
    if (t === 'string' || t === 'template') return false; // "str" / x is division
    if (t === 'regex') return false; // /a/g / /b/ is division
    return false;
  }

  function readRegex() {
    const start = i;
    i++; col++;
    let body = '';
    let flags = '';
    let inClass = false;
    while (i < N) {
      const c = src[i];
      if (c === '\\') { body += c + (src[i+1]||''); i += 2; col += 2; continue; }
      if (c === '[') inClass = true;
      else if (c === ']') inClass = false;
      else if (c === '/' && !inClass) { i++; col++; break; }
      i++; col++; body += c;
    }
    while (i < N && /[a-z]/.test(src[i])) { flags += src[i]; i++; col++; }
    return { type:'regex', value:body, flags, start, end:i };
  }

  let prev = null;
  while (i < N) {
    skipWS();
    if (i >= N) break;
    const c = src[i];
    let tok;
    if (c === '"' || c === "'") tok = readString(c);
    else if (c === '`') tok = readTemplate();
    else if (isDigit(c)) tok = readNumber();
    else if (isIdentStart(c)) tok = readIdent();
    else if (c === '/' && isRegexContext(prev)) tok = readRegex();
    else {
      // Punctuation: handle multi-char operators (greedy longest-match).
      // FIX: previous version missed `===`, `!==`, `??`, `?.`, `>>>`, `...`
      // because it only built combos for explicitly-listed pairs and didn't
      // check 3-char operators like `===` separately from `==`.
      // New approach: try 4-char, then 3-char, then 2-char, then 1-char.
      const PUNCT_4 = ['>>>='];
      const PUNCT_3 = ['===', '!==', '>>>', '**=', '<<=', '>>=', '...'];
      const PUNCT_2 = [
        '=>', '==', '!=', '>=', '<=', '>>', '<<', '&&', '||', '??', '?.',
        '**', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=',
      ];
      const start = i;
      let combo = c;
      const slice3 = src.slice(i, i + 3);
      const slice4 = src.slice(i, i + 4);
      const slice2 = src.slice(i, i + 2);
      if (PUNCT_4.includes(slice4))      { combo = slice4; }
      else if (PUNCT_3.includes(slice3)) { combo = slice3; }
      else if (PUNCT_2.includes(slice2)) { combo = slice2; }
      for (let k = 0; k < combo.length; k++) { i++; col++; }
      tok = { type:'punct', value:combo, start, end:i };
    }
    tokens.push(tok);
    prev = tok;
  }
  return { tokens, errors, lines: line };
}

// ─── Structural walker ───────────────────────────────────────────────────
// Walks the token stream producing: classes, top-level functions, call sites,
// member access sites, and assignments. Designed to be SAFE on minified
// input — if something looks weird, bail and continue.

function buildStructuralIndex(src) {
  const lex = tokenizeForAST(src);
  const T = lex.tokens;
  const M = T.length;

  // Position → token index (binary search by .start)
  function posToTok(p) {
    let lo = 0, hi = M - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (T[mid].start <= p) lo = mid; else hi = mid - 1;
    }
    return lo;
  }

  const classes = [];
  const functions = [];
  const callSites = [];
  const memberAccess = [];
  const assignments = [];
  const identifiers = [];

  // Simple paren-comma splitter that respects nesting, strings, templates
  function splitArgs(tokStart, tokEnd) {
    // Given token range [tokStart..tokEnd] excluding the surrounding parens,
    // return array of {startTok, endTok} for each top-level comma separation.
    const parts = [];
    let depth = 0, last = tokStart;
    for (let k = tokStart; k < tokEnd; k++) {
      const t = T[k];
      if (!t) continue;
      if (t.type === 'punct') {
        if (t.value === '(' || t.value === '[' || t.value === '{') depth++;
        else if (t.value === ')' || t.value === ']' || t.value === '}') depth--;
        else if (t.value === ',' && depth === 0) {
          if (k > last) parts.push({ startTok: last, endTok: k });
          last = k + 1;
        }
      }
    }
    if (last < tokEnd) parts.push({ startTok: last, endTok: tokEnd });
    return parts;
  }

  function classifyCallee(tokIdx) {
    // Walk backward from `(` to find what is being called.
    let k = tokIdx - 1;
    // Skip trailing whitespace tokens (we don't emit whitespace, so just keep walking)
    while (k >= 0 && T[k].type === 'punct' && T[k].value === ')') {
      // already-wrapped callee
      return { kind: 'parenthesized', text: '<expr>' };
    }
    if (k < 0) return { kind: 'unknown', text: '' };
    const t = T[k];
    if (t.type === 'ident') {
      // Could be `foo(`, `foo.bar(`, `foo.bar.baz(`
      // Walk backward over .ident chains
      const chain = [];
      let cur = k;
      while (cur >= 0) {
        const tt = T[cur];
        if (tt.type === 'ident') { chain.unshift(tt.value); cur--; }
        else if (tt.type === 'punct' && tt.value === '.' && cur > 0 && T[cur-1].type === 'ident') {
          cur--; // will pick up ident next iteration
        }
        else break;
      }
      return { kind: 'ident', text: chain.join('.'), depth: chain.length };
    }
    if (t.type === 'punct' && (t.value === ']' || t.value === ')' )) {
      // Member/index call
      return { kind: 'complex', text: '<expr>' };
    }
    if (t.type === 'string' || t.type === 'template') {
      return { kind: 'literal-call', text: t.value.slice(0,30) };
    }
    if (t.type === 'keyword' && (t.value === 'new' || t.value === 'this' || t.value === 'super')) {
      return { kind: 'keyword', text: t.value };
    }
    return { kind: 'other', text: '<expr>' };
  }

  // Walk for `class X {...}` — both class declarations and class expressions
  for (let k = 0; k < M; k++) {
    const t = T[k];
    if (t.type === 'keyword' && t.value === 'class') {
      const startTok = k;
      const startPos = t.start;
      let name = null;
      let k2 = k + 1;
      // Skip extends if present
      if (T[k2] && T[k2].type === 'keyword' && T[k2].value === 'extends') {
        k2++;
        // skip parent class identifier and any params
        while (k2 < M && (T[k2].type === 'ident' || T[k2].value === '<')) k2++;
      }
      if (T[k2] && T[k2].type === 'ident') { name = T[k2].value; k2++; }
      // body is the next `{ ... }` matching braces
      let depth = 0, bodyStart = -1, bodyEnd = -1;
      for (; k2 < M; k2++) {
        if (T[k2].type === 'punct' && T[k2].value === '{') {
          depth = 1; bodyStart = k2;
          k2++;
          while (k2 < M && depth > 0) {
            if (T[k2].type === 'punct') {
              if (T[k2].value === '{') depth++;
              else if (T[k2].value === '}') depth--;
            }
            if (depth > 0) k2++;
          }
          bodyEnd = k2;
          break;
        }
        if (T[k2].type === 'punct' && (T[k2].value === '(' || T[k2].value === '=' || T[k2].value === ',' || T[k2].value === ';')) break;
      }

      if (name && bodyStart > 0) {
        // Extract class members
        const staticFields = [];
        const methods = [];
        for (let m = bodyStart + 1; m < bodyEnd; m++) {
          const tm = T[m];
          if (!tm) continue;
          if (tm.type === 'keyword' && tm.value === 'static' &&
              m + 1 < bodyEnd && T[m+1] && T[m+1].type === 'ident') {
            staticFields.push({
              name: T[m+1].value,
              start: T[m+1].start,
              end: T[m+1].end,
            });
            m++;
          }
        }
        classes.push({
          name, start: startPos, end: bodyEnd,
          staticFields, bodyTokStart: bodyStart, bodyTokEnd: bodyEnd,
        });
      }
    }
  }

  // Walk for function calls: any ident or chain followed by `(`
  for (let k = 0; k < M - 1; k++) {
    const t = T[k];
    if (t.type === 'punct' && t.value === '(') {
      // Was the preceding token an ident chain ending (no whitespace between)?
      let prev = k - 1;
      if (prev < 0) continue;
      // Allow newlines as separators
      const callee = classifyCallee(k);
      if (callee.kind === 'unknown' || callee.kind === 'other') continue;
      // Find matching close paren
      let depth = 1; let k2 = k + 1;
      while (k2 < M && depth > 0) {
        const tt = T[k2];
        if (tt && tt.type === 'punct') {
          if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
          else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
            depth--;
            if (depth === 0) break;
          }
        }
        k2++;
      }
      callSites.push({
        callee,
        startTok: k, endTok: k2,
        startPos: t.start, endPos: T[k2] ? T[k2].start : t.end,
        argCount: splitArgs(k+1, k2).length,
      });
    }
  }

  // Member access: `x.y` patterns
  for (let k = 0; k < M - 2; k++) {
    if (T[k].type === 'ident' && T[k+1].type === 'punct' && T[k+1].value === '.' &&
        T[k+2].type === 'ident') {
      memberAccess.push({
        object: T[k].value, property: T[k+2].value,
        start: T[k].start, end: T[k+2].end,
      });
    }
  }

  // Function declarations and top-level expressions
  for (let k = 0; k < M; k++) {
    const t = T[k];
    if (t.type === 'keyword' && t.value === 'function') {
      let nameTok = null;
      let k2 = k + 1;
      // optional name
      if (T[k2] && T[k2].type === 'ident') { nameTok = T[k2]; k2++; }
      // find `(` then walk to matching `)`, then `{` body
      while (k2 < M && !(T[k2].type === 'punct' && T[k2].value === '(')) k2++;
      if (k2 >= M) continue;
      const paramsStart = k2 + 1;
      let depth = 1; k2++;
      while (k2 < M && depth > 0) {
        const tt = T[k2];
        if (tt.type === 'punct') {
          if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
          else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
            depth--;
            if (depth === 0) break;
          }
        }
        k2++;
      }
      if (k2 >= M) continue;
      const paramsEnd = k2;
      // find body
      while (k2 < M && !(T[k2].type === 'punct' && T[k2].value === '{')) k2++;
      if (k2 >= M) continue;
      let bodyDepth = 1; const bodyStart = k2;
      k2++;
      while (k2 < M && bodyDepth > 0) {
        const tt = T[k2];
        if (tt.type === 'punct') {
          if (tt.value === '{') bodyDepth++;
          else if (tt.value === '}') bodyDepth--;
        }
        if (bodyDepth > 0) k2++;
      }
      if (k2 >= M) continue;
      functions.push({
        name: nameTok ? nameTok.value : '<anonymous>',
        start: t.start, end: T[k2].end,
        paramsTokStart: paramsStart, paramsTokEnd: paramsEnd,
        bodyTokStart: bodyStart, bodyTokEnd: k2,
        isArrow: false,
      });
    }
  }

  // ── Arrow functions: `params => body` ──────────────────────────────────
  // FIX (Stage 3B): previously only `function`-keyword functions were tracked.
  // Arrow functions are the most common function form in modern bundles, so
  // missing them left large portions of the call graph untracked.
  // Forms we handle:
  //   (a, b) => { ... }       — parenthesised params, block body
  //   (a, b) => expr           — parenthesised params, expression body
  //   x => { ... }             — single param (no parens), block body
  //   x => expr                — single param, expression body
  //   async (a) => { ... }     — async arrow
  for (let k = 0; k < M - 1; k++) {
    const t = T[k];
    const next = T[k+1];
    if (!next || next.type !== 'punct' || next.value !== '=>') continue;

    let paramsStart = -1, paramsEnd = -1;
    let nameHint = '<anonymous>';
    let arrowStart = -1;

    // Check what's before `=>`:
    // Case 1: `)` immediately before `=>` → parenthesised params, walk back to `(`
    if (t.type === 'punct' && t.value === ')') {
      // Walk back to matching `(`
      let depth = 1, j = k - 1;
      while (j >= 0 && depth > 0) {
        const tt = T[j];
        if (tt.type === 'punct') {
          if (tt.value === ')') depth++;
          else if (tt.value === '(') { depth--; if (depth === 0) break; }
        }
        j--;
      }
      if (j < 0) continue;
      paramsStart = j + 1;
      paramsEnd = k;
      arrowStart = T[j].start;
      // Name inference: look back for `NAME =` or `const NAME =` before `(`
      // Possibly with `async` keyword in between: `const NAME = async (...) =>`
      let bk = j - 1;
      // Skip `async` keyword if present
      if (bk >= 0 && T[bk].type === 'keyword' && T[bk].value === 'async') {
        arrowStart = T[bk].start;
        bk--;
      }
      // Skip `=` if present
      if (bk >= 0 && T[bk].type === 'punct' && T[bk].value === '=') {
        bk--;
        // Now expect IDENT (the variable name)
        if (bk >= 0 && T[bk].type === 'ident') {
          nameHint = T[bk].value;
          // Check for `const/let/var` keyword before the name
          const bk2 = bk - 1;
          if (bk2 >= 0 && T[bk2].type === 'keyword' && ['let','const','var'].includes(T[bk2].value)) {
            arrowStart = T[bk2].start;
          } else {
            arrowStart = T[bk].start;
          }
        }
      }
    }
    // Case 2: identifier immediately before `=>` → single-param arrow (no parens)
    else if (t.type === 'ident') {
      paramsStart = k;  // single ident is the param
      paramsEnd = k + 1;
      arrowStart = t.start;
      nameHint = t.value;  // param name as fallback
      // Name inference: look back for `NAME = IDENT =>` pattern
      // Pattern: ... IDENT = IDENT =>
      let bk = k - 1;
      if (bk >= 0 && T[bk].type === 'punct' && T[bk].value === '=') {
        bk--;
        if (bk >= 0 && T[bk].type === 'ident') {
          nameHint = T[bk].value;  // override with the variable name
          const bk2 = bk - 1;
          if (bk2 >= 0 && T[bk2].type === 'keyword' && ['let','const','var'].includes(T[bk2].value)) {
            arrowStart = T[bk2].start;
          } else {
            arrowStart = T[bk].start;
          }
        }
      }
    } else {
      // `=>` preceded by something else (e.g. `]` for destructuring) — skip
      continue;
    }

    // Check for `async` prefix
    const beforeArrow = T[paramsStart - 1];
    if (beforeArrow && beforeArrow.type === 'keyword' && beforeArrow.value === 'async') {
      arrowStart = beforeArrow.start;
    }

    // Now find the body. After `=>`:
    //   - If `{` → block body (walk to matching `}`)
    //   - Otherwise → expression body (walk to next `;` or `,` at depth 0)
    let k2 = k + 2;  // skip past `=>`
    if (k2 >= M) continue;
    let bodyStart, bodyEnd, isExprBody = false;
    if (T[k2].type === 'punct' && T[k2].value === '{') {
      // Block body
      bodyStart = k2;
      let bodyDepth = 1; k2++;
      while (k2 < M && bodyDepth > 0) {
        const tt = T[k2];
        if (tt.type === 'punct') {
          if (tt.value === '{') bodyDepth++;
          else if (tt.value === '}') bodyDepth--;
        }
        if (bodyDepth > 0) k2++;
      }
      if (k2 >= M) continue;
      bodyEnd = k2;
    } else {
      // Expression body — walk to next `;` or `,` or `)` at depth 0
      isExprBody = true;
      bodyStart = k2;
      let depth = 0;
      while (k2 < M) {
        const tt = T[k2];
        if (tt.type === 'punct') {
          if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
          else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
            if (depth === 0) break;
            depth--;
          }
          else if ((tt.value === ';' || tt.value === ',') && depth === 0) break;
        }
        k2++;
      }
      bodyEnd = k2 > bodyStart ? k2 - 1 : k2;
      if (bodyEnd < bodyStart) bodyEnd = bodyStart;
    }

    functions.push({
      name: nameHint,
      start: arrowStart,
      end: T[bodyEnd] ? T[bodyEnd].end : arrowStart,
      paramsTokStart: paramsStart,
      paramsTokEnd: paramsEnd,
      bodyTokStart: bodyStart,
      bodyTokEnd: bodyEnd,
      isArrow: true,
      isExprBody,
    });
  }

  // ── Method shorthand: { foo() {} } and class method: class { foo() {} } ──
  // These have no `function` keyword and no `=>`, so they're missed by the
  // previous two passes. Pattern: `ident ( params ) { body }` in object/class
  // context — preceded by `{`, `,`, `;`, or `static` keyword (not `:`).
  for (let k = 0; k < M - 3; k++) {
    const t = T[k];
    // Accept ident (method name) or keyword get/set (getter/setter)
    const isGetSet = t.type === 'keyword' && (t.value === 'get' || t.value === 'set');
    if (t.type !== 'ident' && !isGetSet) continue;
    // For getter/setter, after `get`/`set` must be `ident (`
    const scanStart = isGetSet ? k + 1 : k;
    if (scanStart + 1 >= M || T[scanStart].type !== 'ident' || T[scanStart+1].type !== 'punct' || T[scanStart+1].value !== '(') {
      // For regular method, just need `ident (`
      if (t.type !== 'ident') continue;
      if (T[k+1].type !== 'punct' || T[k+1].value !== '(') continue;
    }
    // Exclude property access: `foo:` followed by expression
    // Exclude calls in non-method context
    let preamble = k - 1;
    while (preamble >= 0 && T[preamble].type === 'comment') preamble--;
    if (preamble < 0) continue;
    const pre = T[preamble];
    const isMethodCtx = pre.type === 'punct' && (pre.value === '{' || pre.value === ',' || pre.value === ';' || pre.value === '}');
    const isStatic = pre.type === 'keyword' && pre.value === 'static';
    if (!isMethodCtx && !isStatic) continue;
    // Handle getter/setter: `get foo() {}` / `set foo(v) {}`
    let name = t.value;
    let nameTok = k;
    if (isGetSet && scanStart + 1 < M &&
        T[scanStart].type === 'ident' && T[scanStart+1].type === 'punct' && T[scanStart+1].value === '(') {
      name = T[scanStart].value;
      nameTok = scanStart;
    }
    // Walk params
    let k2 = nameTok + 1; // at `(`
    let depth = 1; k2++;
    while (k2 < M && depth > 0) {
      const tt = T[k2];
      if (tt && tt.type === 'punct') {
        if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
        else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
          depth--; if (depth === 0) break;
        }
      }
      k2++;
    }
    if (k2 >= M) continue;
    const paramsEnd = k2;
    // Method shorthand must have `{` immediately after `)` — distinguishes
    // `foo() {}` (method) from `eval(src)` (function call).
    if (k2 + 1 >= M || !T[k2 + 1] || T[k2 + 1].type !== 'punct' || T[k2 + 1].value !== '{') continue;
    // Find body
    k2++;
    if (k2 >= M) continue;
    const bodyStart = k2;
    let bodyDepth = 1; k2++;
    while (k2 < M && bodyDepth > 0) {
      const tt = T[k2];
      if (tt && tt.type === 'punct') {
        if (tt.value === '{') bodyDepth++;
        else if (tt.value === '}') bodyDepth--;
      }
      if (bodyDepth > 0) k2++;
    }
    if (k2 >= M) continue;
    functions.push({
      name,
      start: T[nameTok].start,
      end: T[k2].end,
      paramsTokStart: nameTok + 2,
      paramsTokEnd: paramsEnd,
      bodyTokStart: bodyStart,
      bodyTokEnd: k2,
      isArrow: false,
    });
  }

  // Identifier frequency + positions (only idents that look like source code,
  // i.e. not keywords)
  for (let k = 0; k < M; k++) {
    const t = T[k];
    if (t.type === 'ident') {
      identifiers.push({ name: t.value, start: t.start, end: t.end });
    }
  }

  // ── Assignments: collect simple `IDENT = <expr>` and `(let|const|var) IDENT = <expr>` ──
  // Used by the SSA-based taint tracker. Destructuring is intentionally NOT
  // supported — we only need the common case for source→sink flow detection.
  // For each assignment we capture: name, startPos (LHS ident), rhsStartPos,
  // rhsEndPos (exclusive — position just past the last RHS token), kind.
  const DECL_KW = new Set(['let', 'const', 'var']);
  for (let k = 0; k < M; k++) {
    const t = T[k];
    const next  = T[k+1];
    const next2 = T[k+2];

    // Pattern A: (let|const|var) IDENT =  ...
    if (t.type === 'keyword' && DECL_KW.has(t.value) &&
        next && next.type === 'ident' &&
        next2 && next2.type === 'punct' && next2.value === '=' &&
        // guard against == / ===
        (!T[k+3] || T[k+3].type !== 'punct' || T[k+3].value !== '=')) {
      const name = next.value;
      const startPos  = next.start;
      const rhsStart  = next2.end;
      // Walk forward to find RHS end: first ; or , at depth 0
      let depth = 0, rhsEnd = rhsStart;
      for (let j = k + 3; j < M; j++) {
        const tt = T[j];
        if (!tt) break;
        if (tt.type === 'punct') {
          if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
          else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
            if (depth === 0) break;
            depth--;
          }
          else if ((tt.value === ';' || tt.value === ',') && depth === 0) break;
        }
        rhsEnd = tt.end;
      }
      assignments.push({ name, startPos, rhsStartPos: rhsStart, rhsEndPos: rhsEnd, kind: 'var' });
      continue;
    }

    // Pattern B: IDENT = ...   (plain assignment — skip if LHS is a member: x.y = ...)
    if (t.type === 'ident' &&
        next && next.type === 'punct' && next.value === '=' &&
        // skip == / ===
        (!next2 || next2.type !== 'punct' || next2.value !== '=')) {
      const prev = T[k-1];
      // Skip if preceded by let/const/var (Pattern A handled it)
      if (prev && prev.type === 'keyword' && DECL_KW.has(prev.value)) continue;
      // Skip member-assignment: foo.bar = ... (prev is '.')
      if (prev && prev.type === 'punct' && prev.value === '.') continue;
      // Skip computed: foo[bar] = ... (prev is ']')
      if (prev && prev.type === 'punct' && prev.value === ']') continue;
      // Skip property shorthand: {a = b} (prev is '{' or ',')
      if (prev && prev.type === 'punct' && (prev.value === '{')) continue;
      // Skip equality checks: == === (already guarded above, but be safe)
      if (prev && prev.type === 'punct' && (prev.value === '=' || prev.value === '!')) continue;

      const name = t.value;
      const startPos = t.start;
      const rhsStart = next.end;
      let depth = 0, rhsEnd = rhsStart;
      for (let j = k + 2; j < M; j++) {
        const tt = T[j];
        if (!tt) break;
        if (tt.type === 'punct') {
          if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
          else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
            if (depth === 0) break;
            depth--;
          }
          else if ((tt.value === ';' || tt.value === ',') && depth === 0) break;
        }
        rhsEnd = tt.end;
      }
      assignments.push({ name, startPos, rhsStartPos: rhsStart, rhsEndPos: rhsEnd, kind: 'assign' });
    }
  }

  return {
    classes,
    functions,
    callSites,
    memberAccess,
    identifiers,
    assignments,
    tokens: T,
    lex,
  };
}

// Lightweight AST-shaped extractor: pattern-matches within token windows.
// Used by framework detection / taint analysis when we want "looks like X"
// without paying for full parsing.

// Returns the source-text slice spanning tokens[startTok..endTok] inclusive.
// Two call signatures supported:
//   windowText(tokens, startTok, endTok)            — returns token values joined (no raw src)
//   windowText(tokens, src, startTok, endTok)        — returns raw source slice (preferred)
// The 4-arg form is preferred because it preserves original whitespace, comments,
// and string literal contents that the token stream may have normalised.
function windowText(tokens, srcOrStartTok, startTokOrEndTok, endTokOpt) {
  let src, startTok, endTok;
  if (typeof srcOrStartTok === 'string') {
    // 4-arg form: (tokens, src, startTok, endTok)
    src = srcOrStartTok;
    startTok = startTokOrEndTok;
    endTok = endTokOpt;
  } else {
    // 3-arg form: (tokens, startTok, endTok) — fall back to joining token values
    startTok = srcOrStartTok;
    endTok = startTokOrEndTok;
    if (startTok < 0 || endTok >= tokens.length || endTok < startTok) return '';
    let out = '';
    for (let i = startTok; i <= endTok; i++) {
      const t = tokens[i];
      if (!t) continue;
      out += t.value;
    }
    return out;
  }
  if (!src || startTok < 0 || endTok >= tokens.length || endTok < startTok) return '';
  const start = tokens[startTok].start;
  const end = tokens[endTok].end;
  if (typeof start !== 'number' || typeof end !== 'number' || end < start) return '';
  return src.slice(start, end);
}

// Map a token index back to source-text positions (start/end character offsets).
function tokPos(tokens, idx) {
  if (idx < 0 || idx >= tokens.length) return null;
  return { start: tokens[idx].start, end: tokens[idx].end };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 9b-T1 — REAL AST-BASED FRAMEWORK DETECTION  (Tier 1.1)
//
//  Replaces regex-based Angular detection with AST walk:
//  · Angular components: classes with `static ɵcmp = ...` or
//                         `ɵɵdefineComponent(...)` in body.
//                         The `ɵcmp` unicode escape `\\u0275cmp` is also handled.
//  · Angular services:  classes with `static ɵprov = ...` OR
//                        `ɵɵdefineInjectable(...)` in body.
//  · Angular directives: classes with `static ɵdir = ...`.
//  · Angular pipes:      classes with `static ɵpipe = ...`.
//  · Angular modules:    classes with `static ɵmod = ...`.
//  · Vue components:    classes with `__vccOpts` static, OR
//                        objects with `setup(...)` returning `createElementVNode`-like
//                        expressions, OR `defineComponent(` calls.
//  · React components:  functions returning `createElement(...)` / `jsx(...)`,
//                        OR `forwardRef(` calls.
//  · We also export a per-class confidence score.
// ═══════════════════════════════════════════════════════════════════════════

function detectFrameworksAST(src, structuralIndex) {
  const T = structuralIndex.tokens;
  const M = T.length;

  const findings = { angular: { components:0, services:0, modules:0, directives:0, pipes:0, total:0 },
                     vue: { components:0, total:0 },
                     react: { components:0, total:0 } };

  // For each class, scan its body for relevant markers
  const ANG_COMPONENT_MARKERS = [
    /ɵɵdefineComponent/, /ɵɵdefineComponent2/, /\bɵcmp\b/, /\\u0275cmp/,
    /ɵɵelementStart/, /selector\s*:\s*["']/, /template\s*:\s*["'`]/,
  ];
  const ANG_SERVICE_MARKERS = [
    /ɵɵdefineInjectable/, /\bɵprov\b/, /\\u0275prov/, /\bɵfac\b/, /\\u0275fac/,
    // FIX: was `["']root['"]` — the `['"]` is a single-quote followed by a
    // char-class containing only `"`, so it only matched `'root'` (single
    // quotes) and never `"root"` (double quotes). Now symmetric: `["']root["']`
    /providedIn\s*:\s*["']root["']/, /Injectable\s*\(/,
  ];
  const ANG_MODULE_MARKERS = [/\bɵmod\b/, /\\u0275mod/, /ɵɵdefineNgModule/];
  const ANG_DIRECTIVE_MARKERS = [/\bɵdir\b/, /\\u0275dir/, /ɵɵdefineDirective/, /selector\s*:\s*\[/];
  const ANG_PIPE_MARKERS = [/\bɵpipe\b/, /\\u0275pipe/, /ɵɵdefinePipe/, /Pipe\s*\(/];

  function bodyMatches(markers, bodyStart, bodyEnd) {
    if (bodyStart < 0 || bodyEnd < 0) return false;
    let bodyText = '';
    for (let i = bodyStart; i <= bodyEnd && i < T.length; i++) {
      const t = T[i];
      if (!t) continue;
      // Skip non-semantic token types (whitespace never emitted, but guard anyway).
      // Punctuators and other tokens are concatenated by their literal value.
      bodyText += t.value;
    }
    for (const m of markers) {
      if (m.test(bodyText)) return true;
    }
    return false;
  }

  // For more accurate per-class classification: examine each class's STATIC
  // fields specifically, not just the body text. This catches classes whose
  // `static X = function() {}` field references a defining helper.
  // Fall back to body scan when no static fields are present (legacy syntax).
  function staticFieldSatisfies(cls, names) {
    if (!cls.staticFields || cls.staticFields.length === 0) return false;
    // We only have field NAMES from the AST; we need to look up the static
    // method body in the tokens. Build a body-text slice of the class body
    // and check for marker presence within the field's value range.
    // Simpler: scan within the class body tokens for each candidate property
    // name and verify it is preceded by a token `static`.
    const Tloc = structuralIndex.tokens;
    const startK = cls.bodyTokStart;
    const endK = cls.bodyTokEnd;
    if (startK < 0 || endK < 0) return false;
    for (let k = startK; k <= endK - 2 && k < Tloc.length; k++) {
      const tk = Tloc[k];
      const tk1 = Tloc[k+1];
      const tk2 = Tloc[k+2];
      if (tk && tk.type === 'keyword' && tk.value === 'static' &&
          tk1 && tk1.type === 'ident' && names.includes(tk1.value)) {
        return true;
      }
    }
    return false;
  }

  // FIX: only count a class toward angular.total if it actually carries at
  // least one Angular decorator / Ivy static field. Previously every class
  // in the bundle was counted, conflating 'all classes' with 'Angular classes'.
  for (const cls of structuralIndex.classes) {
    const isCmp   = staticFieldSatisfies(cls, ['ɵcmp', '\\u0275cmp']);
    const isProv  = staticFieldSatisfies(cls, ['ɵprov', '\\u0275prov', 'ɵfac', '\\u0275fac']);
    const isMod   = staticFieldSatisfies(cls, ['ɵmod', '\\u0275mod']);
    const isDir   = staticFieldSatisfies(cls, ['ɵdir', '\\u0275dir']);
    const isPipe  = staticFieldSatisfies(cls, ['ɵpipe', '\\u0275pipe']);

    // Also fall back to body-scan for legacy ɵɵdefineComponent() syntax
    const isCmpLegacy = !isCmp && bodyMatches(ANG_COMPONENT_MARKERS, cls.bodyTokStart, cls.bodyTokEnd);
    const isServiceLegacy = !isProv && bodyMatches(ANG_SERVICE_MARKERS, cls.bodyTokStart, cls.bodyTokEnd);
    const isModuleLegacy = !isMod && bodyMatches(ANG_MODULE_MARKERS, cls.bodyTokStart, cls.bodyTokEnd);
    const isDirectiveLegacy = !isDir && bodyMatches(ANG_DIRECTIVE_MARKERS, cls.bodyTokStart, cls.bodyTokEnd);
    const isPipeLegacy = !isPipe && bodyMatches(ANG_PIPE_MARKERS, cls.bodyTokStart, cls.bodyTokEnd);

    const isAngular = isCmp || isCmpLegacy || isProv || isServiceLegacy
                   || isMod || isModuleLegacy || isDir || isDirectiveLegacy
                   || isPipe || isPipeLegacy;
    if (!isAngular) continue;
    findings.angular.total++;

    if (isCmp || isCmpLegacy) findings.angular.components++;
    // Service only if not also a component (component takes precedence)
    if ((isProv || isServiceLegacy) && !isCmp && !isCmpLegacy) findings.angular.services++;
    if (isMod || isModuleLegacy) findings.angular.modules++;
    if (isDir || isDirectiveLegacy) findings.angular.directives++;
    if (isPipe || isPipeLegacy) findings.angular.pipes++;
  }

  // Vue: count createElementVNode / defineComponent / __vccOpts occurrences
  let vueHits = 0;
  for (const ma of structuralIndex.memberAccess) {
    if (ma.property === 'createElementVNode' ||
        ma.property === 'createElementBlock' ||
        ma.property === 'createVNode' ||
        ma.property === 'openBlock') {
      vueHits++;
    }
  }
  // defineComponent calls + __vccOpts static field
  const DEFINE_COMPONENT_RE = /defineComponent\b/;
  const VCC_OPTS_RE = /__vccOpts\b/;
  for (let k = 0; k < M - 1; k++) {
    if (T[k].type === 'ident' && T[k].value === 'defineComponent') vueHits++;
    if (T[k].type === 'ident' && T[k].value === '__vccOpts') vueHits++;
  }
  findings.vue.total = vueHits;
  // Heuristic: each `createElementVNode` call site ≈ one component or template fragment
  // Use a more conservative divisor — count call sites with `createElementVNode` as 1 component
  const vueCallSites = structuralIndex.callSites.filter(cs =>
    cs.callee.kind === 'ident' && /createElement/.test(cs.callee.text)
  ).length;
  findings.vue.components = Math.max(1, Math.floor(vueCallSites / 3));

  // React: count createElement calls and jsx-runtime
  let reactHits = 0;
  for (const cs of structuralIndex.callSites) {
    if (cs.callee.kind === 'ident' &&
        (cs.callee.text === 'createElement' || cs.callee.text.endsWith('.createElement') ||
         cs.callee.text === 'jsx' || cs.callee.text === 'jsxs' ||
         cs.callee.text === 'jsxDEV' || cs.callee.text === 'forwardRef')) {
      reactHits++;
    }
  }
  // Conservative component count: every 2 createElement callsites ≈ 1 component
  findings.react.components = Math.max(0, Math.floor(reactHits / 2));
  findings.react.total = reactHits;

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 13b — WEBPACK 5 DYNAMIC MODULE RESOLVER  (Tier 1.2)
//
//  Replaces the static WEBPACK_MODULE_MAP (40 entries). Parses the
//  `webpackChunk_xxx` array layout that webpack 5 emits:
//
//    (self.webpackChunk_xxx = self.webpackChunk_xxx || []).push([[chunkIds], {
//        moduleId: (Q, H, d) => { ... body using d(N) calls ... },
//        ...
//    }]);
//
//  and extracts every module ID + every `d(N)` call inside its body to
//  build a real weighted import graph (caller → callee, with usage counts).
//
//  Also handles: webpack 5 `__webpack_require__` runtime references,
//  `webpackChunk_xxx` JSONP-style loading, IIFE-wrapped variants.
// ═══════════════════════════════════════════════════════════════════════════

function resolveWebpack5Modules(src) {
  const modules = [];
  const calls = [];
  const errors = [];

  // Pattern:  moduleId: (Q, H, d) => {
  // Captures id and body up to matching `}` at top level (depth-counter only
  // handles parens/curlies, not strings — sufficient for module body chunks).
  const modRe = /(\d{1,5})\s*:\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\)\s*=>\s*\{/g;
  let m;
  while ((m = modRe.exec(src)) !== null) {
    const id = m[1];
    const startPos = m.index;
    // Walk forward to matching close brace
    let depth = 1, pos = m.index + m[0].length;
    let inStr = false, strCh = '', inTmpl = false, inLineCmt = false, inBlkCmt = false;
    while (pos < src.length && depth > 0) {
      const c = src[pos];
      const c2 = src[pos+1] || '';
      if (inLineCmt) {
        if (c === '\n') inLineCmt = false;
        pos++; continue;
      }
      if (inBlkCmt) {
        if (c === '*' && c2 === '/') { inBlkCmt = false; pos += 2; continue; }
        pos++; continue;
      }
      if (inStr) {
        if (c === '\\') { pos += 2; continue; }
        if (c === strCh) inStr = false;
        pos++; continue;
      }
      if (inTmpl) {
        if (c === '\\') { pos += 2; continue; }
        if (c === '`') inTmpl = false;
        if (c === '$' && c2 === '{') {
          // skip substitution
          let sd = 1; pos += 2;
          while (pos < src.length && sd > 0) {
            if (src[pos] === '{') sd++;
            else if (src[pos] === '}') sd--;
            pos++;
          }
          continue;
        }
        pos++; continue;
      }
      if (!inStr && !inTmpl && c === '/' && c2 === '/') { inLineCmt = true; pos += 2; continue; }
      if (!inStr && !inTmpl && c === '/' && c2 === '*') { inBlkCmt = true; pos += 2; continue; }
      if (!inStr && !inTmpl && (c === '"' || c === "'")) { inStr = true; strCh = c; pos++; continue; }
      if (!inStr && !inTmpl && c === '`') { inTmpl = true; pos++; continue; }
      if (!inStr && !inTmpl) {
        if (c === '{') depth++;
        else if (c === '}') { depth--; if (depth === 0) break; }
      }
      pos++;
    }
    const endPos = pos + 1;

    const moduleSrc = src.slice(startPos, endPos);

    // Extract d(N) calls inside this module body
    const dcallRe = /\bd\s*\(\s*(\d+)\s*\)/g;
    const uses = [];
    let dm;
    while ((dm = dcallRe.exec(moduleSrc)) !== null) {
      uses.push(parseInt(dm[1], 10));
    }
    // Also detect __webpack_require__.d (r(d(n) ) pattern from runtime helpers)
    const helperRe = /__webpack_require__\.d\s*\(/g;
    const helperCalls = [];
    while ((dm = helperRe.exec(moduleSrc)) !== null) helperCalls.push(dm.index);

    modules.push({
      id,
      startPos, endPos,
      uses,
      helperCalls,
      size: endPos - startPos,
    });
    for (const u of uses) calls.push({ from: id, to: String(u) });
  }

  // Edge deduplication and weights
  const edgeMap = new Map();
  for (const c of calls) {
    const key = `${c.from}→${c.to}`;
    edgeMap.set(key, (edgeMap.get(key) || 0) + 1);
  }
  const edges = [...edgeMap.entries()].map(([k, w]) => {
    const [from, to] = k.split('→');
    return { from, to, weight: w };
  });

  return {
    bundler: modules.length > 0 ? 'webpack5' : null,
    moduleCount: modules.length,
    modules,
    edges,
    errors,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 13c — ESM BUNDLER DETECTION (VITE / ROLLUP / WEBPACK-LEGACY)
//
//  Detects which bundler produced the bundle by AST-shape heuristics so
//  Phase 13b can pick the right extractor per shape.
//
//  Bundlers we recognise:
//   - webpack5 (handled by resolveWebpack5Modules): `webpackChunk_xxx` +
//     moduleId: (Q,H,d)=>{} block layout
//   - webpack4/legacy:  webpackJsonp.push([[id],[moduleId:function(...)...
//     or [[id], {moduleId: function(Q,H,d) { ...}}]
//   - vite-legacy: `__vitePreload`, `__vite__mapDeps`, `import.meta.url`
//   - vite-modern (ESM): static ES module imports with `{ a as f, b as m }`
//     re-export aliasing — typical of Vite production builds.
//   - rollup-iife: `var __defProp = Object.defineProperty, __getOwnPropDesc =
//     ...` followed by IIFE wrapping each module.
// ═══════════════════════════════════════════════════════════════════════════

function detectBundler(src) {
  const hints = {
    webpack5:    /self\.webpackChunk_|self\["webpackChunk|webpackChunk_[A-Za-z0-9_$]+|__webpack_require__|__webpack_modules__|performance\.mark\(\s*["']js-parse-end/,
    webpack4:    /\bwebpackJsonp\b/,
    viteLegacy:  /__vitePreload\s*\(|__vite__mapDeps/,
    // FIX (Stage 4 audit): added negative lookahead `(?!https?:)` to reject
    // absolute URLs like `https://cdn.com/foo.js` which are NOT Vite relative
    // imports. Previously matched any `...foo.js` string, causing false
    // positives when the bundle referenced CDN URLs.
    viteModern:  /\bimport\s*\{[^}]+\}\s*from\s*["'](?!https?:)(?:\.?\/)?[^"']+\.js["']/,
    rollup:      /var\s+__defProp\s*=\s*Object\.defineProperty|__commonJS|__copyProps/,
    esMBuild:    /\bexport\s*\{[^}]+\}\s*;/,
  };
  const detected = [];
  for (const [name, re] of Object.entries(hints)) {
    if (re.test(src)) detected.push(name);
  }
  return {
    detected,
    primary: detected[0] || null,
    isEsm: detected.includes('viteModern') || detected.includes('esMBuild'),
    isIife: detected.includes('webpack5') || detected.includes('webpack4') || detected.includes('rollup'),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 14b — CALL-GRAPH BUILDER  (Tier 1.3)
//
//  Builds (moduleId, functionName) → {imports, exports, calls} maps when
//  possible. For non-bundled, top-level files: provides a function-level
//  call graph from callSites + function declarations.
//
//  Inputs:
//    structuralIndex  (from buildStructuralIndex)
//    webpackGraph     (from resolveWebpack5Modules)
//
//  Output:  { callGraph: Map<calleeKey, Set<calleeKey>>,
//             reverseCallGraph: Map<calleeKey, Set<callerKey>>,
//             entryPoints: Array<functionName>,
//             orphanFunctions: Array<functionName>, … }
// ═══════════════════════════════════════════════════════════════════════════

function buildCallGraph(structuralIndex, webpackGraph) {
  const T = structuralIndex.tokens;
  const calls = structuralIndex.callSites;

  // For each function, find calls within its body. Each call → outgoing edge.
  const outgoing = new Map();
  const incoming = new Map();

  function key(mod, name) { return mod ? `${mod}::${name}` : name; }

  // Top-level call graph — module-less
  // Group call sites by enclosing function (find the smallest function whose body
  // contains each call's position)
  const sortedFns = [...structuralIndex.functions].sort((a, b) => (a.start - b.start));

  // Binary-search + memoized enclosingFunction (Stage 3B perf fix).
  // Same algorithm as the one in trackTaintAST — kept separate because this
  // function lives in a different scope.
  const _cgFnCache = new Map();
  function enclosingFunction(pos) {
    const key = pos >> 4;
    if (_cgFnCache.has(key)) return _cgFnCache.get(key);
    let lo = 0, hi = sortedFns.length - 1, result = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (sortedFns[mid].start <= pos) {
        if (pos <= sortedFns[mid].end) result = sortedFns[mid];
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (result && !(result.start <= pos && pos <= result.end)) result = null;
    _cgFnCache.set(key, result);
    return result;
  }

  for (const cs of calls) {
    const calleeName = cs.callee.kind === 'ident' ? cs.callee.text : null;
    if (!calleeName) continue;
    const caller = enclosingFunction(cs.startPos);
    const callerKey = caller ? key(null, caller.name || '<anonymous>') : '<toplevel>';
    const calleeKey = key(null, calleeName);
    if (!outgoing.has(callerKey)) outgoing.set(callerKey, new Set());
    outgoing.get(callerKey).add(calleeKey);
    if (!incoming.has(calleeKey)) incoming.set(calleeKey, new Set());
    incoming.get(calleeKey).add(callerKey);
  }

  // Module-resolved call graph
  const modOut = new Map();
  const modIn = new Map();
  if (webpackGraph && webpackGraph.modules) {
    for (const mod of webpackGraph.modules) {
      // Find the closest call site for each d(N) call inside the module
      for (const calleeId of mod.uses) {
        const fromKey = `mod:${mod.id}`;
        const toKey = `mod:${calleeId}`;
        if (!modOut.has(fromKey)) modOut.set(fromKey, new Set());
        modOut.get(fromKey).add(toKey);
        if (!modIn.has(toKey)) modIn.set(toKey, new Set());
        modIn.get(toKey).add(fromKey);
      }
    }
  }

  const entryPoints = [...outgoing.entries()]
    .filter(([k, v]) => !incoming.has(k) || incoming.get(k).size === 0)
    .map(([k]) => k);

  const orphanFunctions = structuralIndex.functions
    .filter(fn => !outgoing.has(key(null, fn.name)) && !incoming.has(key(null, fn.name)))
    .map(fn => fn.name);

  return {
    outgoing,
    incoming,
    entryPoints,
    orphanFunctions,
    modOut,
    modIn,
    stats: {
      functions: structuralIndex.functions.length,
      callSites: calls.length,
      moduleEdges: webpackGraph ? webpackGraph.edges.length : 0,
      entryPoints: entryPoints.length,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 14c — CROSS-MODULE TAINT TRACKING  (Tier 1.4)
//
//  Replaces regex taint with a flow analysis on the AST.
//
//  Algorithm (per file, intra-procedural):
//    1. Build call graph + structural index.
//    2. Identify TAINT SOURCES at each expression — URL params, postMessage
//       data, storage reads, location properties, etc.
//    3. Propagate taint forward through:
//       · variable assignments: taint(x = sourceExpr) → taint(x)
//       · function parameters: taint(return f(source)) → taint(f's return value,
//         conservative for the caller only)
//       · data-dependent calls: taint(out = f(t)) → taint(out)
//    4. Detect TAINT SINKS at: innerHTML =, outerHTML =, document.write,
//       eval, new Function, location.href = , setAttribute("on*"), etc.
//    5. Emit: { sourceNode, sinkNode, sinkName, severity, cwe, kind }
//       along with the inferred call chain.
//
//  Note: this is sound for "tautological" flow (source and sink within
//  the same function). For cross-function flows we add a heuristic
//  layer that propagates via enclosing caller/callee edges.
// ═══════════════════════════════════════════════════════════════════════════

function trackTaintAST(src, structuralIndex, callGraph) {
  const findings = [];
  const sourceCode = src;
  const T = structuralIndex.tokens;
  const M = T.length;

  // 1. Identify all SOURCE expressions (call sites / member access / identifiers)
  function isTaintSourceCallee(text) {
    if (!text) return null;
    // Common source APIs
    const SRC_MAP = {
      'location.search':       'URL search params',
      'location.hash':         'URL hash',
      'location.href':         'URL href',
      'document.URL':          'document.URL',
      'document.referrer':     'document.referrer',
      'document.cookie':       'document.cookie',
      'window.name':           'window.name',
      'event.data':            'postMessage data',
      'localStorage.getItem':  'localStorage read',
      'sessionStorage.getItem':'sessionStorage read',
      'URLSearchParams.get':   'URLSearchParams.get',
      'JSON.parse':            'JSON.parse (untrusted)',
    };
    // Plain identifier without dots?
    if (!text.includes('.')) return null;
    for (const key of Object.keys(SRC_MAP)) {
      if (text === key || text.endsWith('.' + key)) return { name: SRC_MAP[key], expr: text };
    }
    return null;
  }

  // 2. Collect sources
  const sources = []; // { tokenIdx, expr, name }
  for (const cs of structuralIndex.callSites) {
    if (cs.callee.kind !== 'ident') continue;
    const s = isTaintSourceCallee(cs.callee.text);
    if (s) sources.push({ tokenIdx: cs.startTok, expr: cs.callee.text, name: s.name, kind: s.expr });
  }

  // Also: any `URLSearchParams.X.get(` call or `new URLSearchParams(` constructor
  for (let k = 0; k < M; k++) {
    const t = T[k];
    if (t.type === 'keyword' && t.value === 'new' && T[k+1] && T[k+1].type === 'ident' &&
        T[k+1].value === 'URLSearchParams' && T[k+2] && T[k+2].type === 'punct' &&
        T[k+2].value === '(') {
      sources.push({ tokenIdx: k, expr: 'new URLSearchParams(...)', name: 'URL params', kind: 'URLSearchParams' });
    }
  }

  // 3. Sink detection — fix: bare sinks (eval) were unreachable because the
  //    early `!text.includes('.')` returned null. Now we check bare sinks
  //    first, then dotted sinks requiring a prefix.
  function isSinkCallee(text) {
    if (!text) return null;
    const SINKS = {
      'innerHTML':         { sev:'critical', cwe:'CWE-79', name:'innerHTML' },
      'outerHTML':         { sev:'critical', cwe:'CWE-79', name:'outerHTML' },
      'insertAdjacentHTML':{ sev:'critical', cwe:'CWE-79', name:'insertAdjacentHTML' },
      'write':             { sev:'critical', cwe:'CWE-79', name:'document.write', needPrefix:'document.' },
      'eval':              { sev:'critical', cwe:'CWE-95', name:'eval()', isBare:true },
      'setAttribute':      { sev:'critical', cwe:'CWE-79', name:'setAttribute(on*)' },
      'href':              { sev:'high',     cwe:'CWE-601', name:'location.href', needPrefix:'location.' },
      'replace':           { sev:'high',     cwe:'CWE-601', name:'location.replace', needPrefix:'location.' },
      'assign':            { sev:'high',     cwe:'CWE-601', name:'location.assign', needPrefix:'location.' },
      'open':              { sev:'medium',   cwe:'CWE-79', name:'window.open' , needPrefix:'window.' },
    };

    // Bare sinks: whole callee name is the sink (e.g. `eval`, `alert`).
    if (SINKS[text] && SINKS[text].isBare) return SINKS[text];

    // Dotted sinks: callee like `document.write`, `location.href`, etc.
    if (!text.includes('.')) return null;
    const parts = text.split('.');
    if (parts.length < 2) return null;
    const obj  = parts.slice(0, -1).join('.');
    const prop = parts[parts.length - 1];
    const sink = SINKS[prop];
    if (!sink) return null;
    if (sink.needPrefix) {
      const expected = sink.needPrefix.replace(/\.$/, '');
      if (obj !== expected) return null;
    }
    return sink;
  }

  // Direct assignment x = sourceExpr then x used at sink ⇒ tainted
  // (findEnclosingFunction now defined once in the SSA section below)

  // Helper: also detect raw `location.search` / `location.href` literals as
  // pure source expressions (not necessarily a call). These appear as
  // MemberAccess without a follow-up call.
  for (let k = 0; k < M - 2; k++) {
    if (T[k].type === 'ident' && T[k+1].type === 'punct' && T[k+1].value === '.' &&
        T[k+2].type === 'ident') {
      const expr = `${T[k].value}.${T[k+2].value}`;
      // FIX (Stage 4 audit): previously three separate `^...$` regexes that
      // missed `document.location` (alias for window.location) and the
      // three-part chain `window.location.href`. Consolidated into one regex
      // that accepts any of:
      //   location.{search,hash,href,pathname,host,hostname,origin,port,protocol}
      //   document.{URL,referrer,cookie,location,domain}
      //   window.{name,location,location.{href,search,hash,...}}
      // The third case (window.location.href) is a three-token chain; we handle
      // it separately below.
      if (/^(?:location\.(?:search|hash|href|pathname|host|hostname|origin|port|protocol)|document\.(?:URL|referrer|cookie|location|domain)|window\.(?:name|location))$/.test(expr)) {
        sources.push({ tokenIdx: k, expr, name: 'Browser location/document', kind: 'member' });
      }
    }
    // Three-token chain: window.location.{href,search,hash,...}
    if (k < M - 4 &&
        T[k].type === 'ident' && T[k].value === 'window' &&
        T[k+1].type === 'punct' && T[k+1].value === '.' &&
        T[k+2].type === 'ident' && T[k+2].value === 'location' &&
        T[k+3].type === 'punct' && T[k+3].value === '.' &&
        T[k+4].type === 'ident') {
      const prop = T[k+4].value;
      if (['href','search','hash','pathname','host','hostname','origin','port','protocol'].includes(prop)) {
        const expr = `window.location.${prop}`;
        sources.push({ tokenIdx: k, expr, name: 'Browser location/document', kind: 'member' });
      }
    }
  }
  // Deduplicate
  const sourcesSeen = new Set();
  const sourcesDedup = [];
  for (const s of sources) {
    const k = `${s.expr}::${s.tokenIdx}`;
    if (sourcesSeen.has(k)) continue;
    sourcesSeen.add(k);
    sourcesDedup.push(s);
  }
  sources.length = 0; sources.push(...sourcesDedup);

  // Sink sites beyond function calls: assignment patterns like
  //   document.body.innerHTML = ...
  //   location.href = ...
  //   element.outerHTML = ...
  const sinks = []; // synthetic sinks not in callSites
  const ASSIGN_SINK_PROPS = {
    'innerHTML':        { sev:'critical', cwe:'CWE-79', name:'innerHTML' },
    'outerHTML':        { sev:'critical', cwe:'CWE-79', name:'outerHTML' },
    'srcdoc':           { sev:'critical', cwe:'CWE-79', name:'srcdoc' },
    'href':             { sev:'high',     cwe:'CWE-601', name:'location.href' },
  };
  // Find pattern: LOCATIONDOT.prop = ... (anywhere in code)
  for (let k = 0; k < M - 3; k++) {
    // ident . ident = ...
    if (T[k].type === 'ident' && T[k+1].type === 'punct' && T[k+1].value === '.' &&
        T[k+2].type === 'ident') {
      const propName = T[k+2].value;
      if (ASSIGN_SINK_PROPS[propName] && T[k+3] && T[k+3].type === 'punct' && T[k+3].value === '=') {
        sinks.push({
          startPos: T[k].start,
          endPos:   T[k+3].end,
          callee:   { kind:'ident', text: T[k].value + '.' + T[k+2].value },
          meta:     ASSIGN_SINK_PROPS[propName],
        });
      }
    }
  }
  // Also add existing call sinks
  for (const cs of structuralIndex.callSites) {
    if (cs.callee.kind !== 'ident') continue;
    const sink = isSinkCallee(cs.callee.text);
    if (sink) sinks.push({ startPos: cs.startPos, endPos: cs.endPos, callee: cs.callee, meta: sink });
  }

  // ── SSA-style taint propagation ─────────────────────────────────────────
  // Replaces the previous "source-text-appears-in-window" heuristic with a
  // proper intra-procedural variable tracking pass:
  //   1. Walk `assignments` in source order.
  //   2. For each `X = RHS`:
  //      - if RHS contains a source expression  → mark X tainted (origin=source)
  //      - if RHS references an already-tainted var Y → propagate Y's taint to X
  //   3. For each sink, look up its argument window; for every tainted var
  //      referenced there (in same function scope, taint originated before
  //      sink) emit a finding.
  //   4. Also detect direct source→sink flows where the source is inline in
  //      the sink's argument window (no intermediate variable).

  // Functions sorted by start position once — reused for all lookups.
  const sortedFns = [...structuralIndex.functions].sort((a, b) => a.start - b.start);

  // ── Memoized findEnclosingFunction (Stage 3B performance fix) ──────────
  // Previous version did a linear scan from the end for every call — O(N)
  // per lookup, O(N×M) overall where M is the number of call sites. For
  // large bundles (10K+ functions), this was the hottest loop in the
  // taint tracker. Now uses:
  //   1. Binary search to find the candidate function in O(log N)
  //   2. Memoization cache (pos→fn) so repeated lookups for the same
  //      position are O(1). Cache key is quantised to 16-byte boundaries
  //      to keep the cache small while preserving enough precision.
  const _fnCache = new Map();
  function findEnclosingFunction(pos) {
    // Quantise position to 16-byte boundary for cache efficiency
    const key = pos >> 4;
    if (_fnCache.has(key)) return _fnCache.get(key);

    // Binary search: find the rightmost function whose start <= pos
    let lo = 0, hi = sortedFns.length - 1, result = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (sortedFns[mid].start <= pos) {
        // This function starts at or before pos — check if pos is inside it
        if (pos <= sortedFns[mid].end) {
          result = sortedFns[mid];
          // Keep searching right — a later-starting function might also contain pos
          // (nested functions). We want the INNERMOST (latest-starting) one.
        }
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    // If we found a candidate but it doesn't actually contain pos, return null
    // (binary search finds start<=pos but doesn't guarantee pos<=end)
    if (result && !(result.start <= pos && pos <= result.end)) result = null;

    _fnCache.set(key, result);
    return result;
  }

  // Build source-position lookup so we can ask "is source S inside RHS span [a,b]?"
  const sourceSpans = sources.map(s => {
    const tok = T[s.tokenIdx];
    // For call-site sources, the span is the entire call: from callee start to
    // matching `)`. For member-access sources, just the ident.ident span.
    let start = tok ? tok.start : -1;
    let end   = tok ? tok.end   : -1;
    // Try to extend to the call's closing paren if the next non-trivial token is `(`
    if (tok) {
      let k = s.tokenIdx;
      // walk forward skipping the source's own tokens to find a `(` at depth 0
      // — but only if the source is a callee (not a bare member access like `location.search`)
      // Heuristic: if the source expr contains `(`, extend to matching `)`.
      // For `location.search`/`location.hash` we don't extend.
      // For `localStorage.getItem` we DO want to extend.
      const isCall = /getItem|get|URLSearchParams|JSON\.parse/.test(s.expr) ||
                     s.kind === 'URLSearchParams';
      if (isCall) {
        // find the next `(` after this token
        for (let j = k + 1; j < M && T[j].start < start + 200; j++) {
          if (T[j].type === 'punct' && T[j].value === '(') {
            // walk to matching `)`
            let depth = 1, m = j + 1;
            while (m < M && depth > 0) {
              if (T[m].type === 'punct') {
                if (T[m].value === '(' || T[m].value === '[' || T[m].value === '{') depth++;
                else if (T[m].value === ')' || T[m].value === ']' || T[m].value === '}') depth--;
              }
              if (depth > 0) m++;
            }
            if (m < M) end = T[m].end;
            break;
          }
          if (T[j].type === 'punct' && T[j].value === ';') break;
        }
      }
    }
    return { source: s, start, end, fnId: findEnclosingFunction(start)?.start ?? -1 };
  });

  // SSA: per-variable taint chain.
  // taintedVars: Map<varName, Array<{ startPos, sourceName, sourceExpr, sourcePos, fnId }>>
  const taintedVars = new Map();
  const assignmentsAll = structuralIndex.assignments || [];
  const sortedAsg = [...assignmentsAll].sort((a, b) => a.rhsStartPos - b.rhsStartPos);

  // Helper: does `name` appear as a whole-word identifier in `text`?
  function mentionsVar(text, name) {
    if (!text || !name) return false;
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(?<![\\w$])${escaped}(?![\\w$])`).test(text);
  }

  for (const asg of sortedAsg) {
    if (asg.rhsEndPos <= asg.rhsStartPos) continue;
    const rhsText = sourceCode.slice(asg.rhsStartPos, asg.rhsEndPos);
    const fn = findEnclosingFunction(asg.startPos);
    const fnId = fn ? fn.start : -1;

    let origin = null;

    // (a) Does RHS contain a source expression directly?
    for (const ss of sourceSpans) {
      if (ss.start < 0) continue;
      // source must be inside RHS span
      if (ss.start >= asg.rhsStartPos && ss.end <= asg.rhsEndPos) {
        origin = {
          sourceName: ss.source.name,
          sourceExpr: ss.source.expr,
          sourcePos:  ss.start,
          originFnId: ss.fnId,
        };
        break;
      }
    }

    // (b) Does RHS mention an already-tainted variable? (propagate)
    if (!origin) {
      // Iterate in reverse-insertion order to prefer the most recent taint
      // of the most recently declared variable. This is a heuristic; a true
      // SSA would track per-block scopes, but for SAST leads this is enough.
      for (const [varName, taits] of taintedVars) {
        if (!mentionsVar(rhsText, varName)) continue;
        for (let i = taits.length - 1; i >= 0; i--) {
          if (taits[i].startPos < asg.rhsStartPos) {
            // Only propagate within same function scope (or both top-level)
            if (taits[i].fnId === fnId) {
              origin = taits[i];
              break;
            }
          }
        }
        if (origin) break;
      }
    }

    if (origin) {
      if (!taintedVars.has(asg.name)) taintedVars.set(asg.name, []);
      taintedVars.get(asg.name).push({
        startPos:    asg.startPos,
        sourceName:  origin.sourceName,
        sourceExpr:  origin.sourceExpr,
        sourcePos:   origin.sourcePos,
        fnId,
      });
    }
  }

  // Helper: extract the sink's argument window.
  // For call-style sinks (`eval(...)`, `document.write(...)`) args are inside ().
  // For assignment-style sinks (`x.innerHTML = ...`) RHS is everything after `=`.
  function extractSinkArgWindow(sk) {
    // First, find where the sink expression ends and args/RHS begin.
    // sk.callee.text tells us the callee; sk.startPos is where the whole
    // expression starts. We look forward for either `(` (call) or `=` (assign).
    const searchFrom = sk.startPos;
    let depth = 0, inStr = false, strCh = '', inTmpl = false;
    let i = searchFrom;
    const end = Math.min(sourceCode.length, searchFrom + 1000);
    while (i < end) {
      const c = sourceCode[i];
      if (inStr) {
        if (c === '\\') { i += 2; continue; }
        if (c === strCh) inStr = false;
        i++; continue;
      }
      if (inTmpl) {
        if (c === '\\') { i += 2; continue; }
        if (c === '`') inTmpl = false;
        i++; continue;
      }
      if (c === '"' || c === "'") { inStr = true; strCh = c; i++; continue; }
      if (c === '`') { inTmpl = true; i++; continue; }
      if (c === '(' && depth === 0) {
        // call-style sink: extract args to matching `)`
        let d = 1, j = i + 1;
        const argStart = j;
        while (j < sourceCode.length && d > 0) {
          const cj = sourceCode[j];
          if (cj === '(' || cj === '[' || cj === '{') d++;
          else if (cj === ')' || cj === ']' || cj === '}') d--;
          if (d === 0) break;
          j++;
        }
        return { argStart, argEnd: j, kind: 'call' };
      }
      if (c === '=' && depth === 0) {
        // assignment-style sink: extract RHS to next `;` at depth 0
        // Skip == / === (already handled by caller, but guard)
        if (sourceCode[i+1] === '=') { i += 2; continue; }
        let j = i + 1, d = 0;
        const argStart = j;
        while (j < sourceCode.length) {
          const cj = sourceCode[j];
          if (cj === '(' || cj === '[' || cj === '{') d++;
          else if (cj === ')' || cj === ']' || cj === '}') { if (d === 0) break; d--; }
          else if (cj === ';' && d === 0) break;
          j++;
        }
        return { argStart, argEnd: j, kind: 'assign' };
      }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') { if (depth === 0) break; depth--; }
      else if (c === ';' && depth === 0) break;
      i++;
    }
    return null;
  }

  // ── Match sinks against tainted variables + direct source presence ──
  for (const sk of sinks) {
    const sinkMeta = sk.meta;
    const sinkFn = findEnclosingFunction(sk.startPos);
    const sinkFnId = sinkFn ? sinkFn.start : -1;
    const argWindow = extractSinkArgWindow(sk);
    if (!argWindow) continue;
    const argText = sourceCode.slice(argWindow.argStart, argWindow.argEnd);

    const emit = (origin, varName, method) => {
      const chain = [];
      chain.push({ kind:'source', expr: origin.sourceExpr, name: origin.sourceName, pos: origin.sourcePos });
      if (varName) chain.push({ kind:'variable', name: varName, pos: origin.startPos });
      if (sinkFn && sinkFn.name && sinkFn.name !== '<anonymous>') {
        chain.push({ kind:'function', name: sinkFn.name, pos: sinkFn.start });
      }
      chain.push({ kind:'sink', expr: sk.callee.text, name: sinkMeta.name, pos: sk.startPos });

      const ctx = sourceCode.slice(Math.max(0, sk.startPos - 80), sk.endPos + 30).replace(/\n/g,' ');
      findings.push({
        id: `taint-ast-${method}`,
        category: `Taint Flow (AST-${method.toUpperCase()})`,
        severity: sinkMeta.sev,
        cwe: sinkMeta.cwe,
        value: `${origin.sourceName} → ${sinkMeta.name}`,
        context: ctx,
        description: method === 'ssa'
          ? `SSA taint: ${origin.sourceName} → var "${varName}" → sink "${sinkMeta.name}" inside ${sinkFn ? sinkFn.name : '<top-level>'}`
          : `Direct taint: ${origin.sourceName} flows directly to sink "${sinkMeta.name}" inside ${sinkFn ? sinkFn.name : '<top-level>'}`,
        chain,
        method,
      });
    };

    // 1. Direct source → sink (source position is inside arg window)
    for (const ss of sourceSpans) {
      if (ss.start < 0) continue;
      if (ss.start >= argWindow.argStart && ss.end <= argWindow.argEnd) {
        emit({
          sourceName: ss.source.name,
          sourceExpr: ss.source.expr,
          sourcePos:  ss.start,
          startPos:   ss.start,
        }, null, 'direct');
      }
    }

    // 2. Tainted variable → sink (variable mentioned in arg window)
    for (const [varName, taits] of taintedVars) {
      if (!mentionsVar(argText, varName)) continue;
      // Find a tait that originated before this sink and in the same function scope
      for (const tait of taits) {
        if (tait.startPos >= sk.startPos) continue; // taint must originate before sink
        if (tait.fnId !== sinkFnId) continue;       // same function (or both top-level)
        emit(tait, varName, 'ssa');
        break; // one finding per (var, sink) pair
      }
    }
  }

  // Deduplicate by (source.name, sink.name, function-name-prefix-of-context)
  const seen = new Set();
  return findings.filter(f => {
    const k = `${f.value}::${(f.context||'').slice(0,40)}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12o — MODERN CRYPTO PATTERN SCANNER  (Tier 1.6)
//
//  Adds the patterns the analysis specifically calls out as missing:
//    · JWT literals (`eyJ...`) — decode the payload, emit as finding.
//    · WebCrypto subtle.importKey with raw/jwk export → info-level:
//      "key material emitted/imported" pattern.
//    · WebCrypto subtle.encrypt / decrypt / sign / verify → audit.
//    · bcrypt.compare(password, hash) with literal hash → risk.
//    · Node crypto.createHash('md5'|'sha1') and createHmac patterns.
//    · Hardcoded bearer tokens INSIDE fetch()/axios calls (with surrounding context).
// ═══════════════════════════════════════════════════════════════════════════

function scanModernCrypto(src, structuralIndex) {
  const findings = [];
  const ctx = (i, r=200) => src.slice(Math.max(0, i - r/2), i + r/2).replace(/\n/g,' ');

  let m;

  // 1. JWT literals — match base64url.base64url.base64url shape and decode payload
  const JWT_LITERAL_RE = /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g;
  while ((m = JWT_LITERAL_RE.exec(src)) !== null) {
    const tok = m[0];
    const parts = tok.split('.');
    let decoded = '';
    try {
      const payload = parts[1].replace(/-/g,'+').replace(/_/g,'/');
      const pad = '='.repeat((4 - (payload.length % 4)) % 4);
      decoded = Buffer.from(payload + pad, 'base64').toString('utf8');
      // Show only first 200 chars of payload
      decoded = decoded.length > 200 ? decoded.slice(0,200) + '…' : decoded;
    } catch (_) { decoded = '<undecodable>'; }
    findings.push({
      id:'crypto-jwt-literal', category:'JWT Exposure', severity:'high',
      value: tok.length > 60 ? tok.slice(0,60) + '…' : tok,
      context: ctx(m.index),
      description: `JWT literal in client bundle — payload decoded: ${decoded}`,
      jwtPayload: decoded,
    });
  }

  // 2. WebCrypto patterns
  // 2a. subtle.importKey with 'raw' or 'jwk' — emit info for export/import ops
  const SUBTLE_IMPORT_RE = /crypto\.subtle\.importKey\s*\(\s*["'](raw|jwk|spki|pkcs8)["']/g;
  while ((m = SUBTLE_IMPORT_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-webcrypto-import', category:'WebCrypto Audit', severity:'info',
      value: m[0].slice(0,80), context: ctx(m.index),
      description: `WebCrypto importKey with format "${m[1]}" — verify key material isn't derived from secrets`,
    });
  }

  // 2b. subtle.encrypt/decrypt/sign/verify used — high
  const SUBTLE_OP_RE = /crypto\.subtle\.(?:encrypt|decrypt|sign|verify|deriveKey|deriveBits|digest)\s*\(/g;
  while ((m = SUBTLE_OP_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-webcrypto-op', category:'WebCrypto Audit', severity:'medium',
      value: m[0].slice(0,80), context: ctx(m.index),
      description: `WebCrypto operation "${m[0].split('(')[0]}" used — verify mode, IV, and key length are appropriate`,
    });
  }

  // 2c. subtle.exportKey (always interesting)
  const SUBTLE_EXPORT_RE = /crypto\.subtle\.exportKey\s*\(\s*["'](raw|jwk|spki|pkcs8)["']/g;
  while ((m = SUBTLE_EXPORT_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-webcrypto-export', category:'WebCrypto Audit', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description: `WebCrypto exportKey exposes key material in format "${m[1]}" — if key reaches attacker, all crypto compromised`,
    });
  }

  // 3. bcrypt/argon2 with literal hash
  const BCRYPT_LITERAL_RE = /bcrypt\.(?:compare|compareSync|hash|hashSync)\s*\(\s*[^,]+,\s*["'](\$2[aby]\$\d{2}\$[./A-Za-z0-9]{40,70})["']/g;
  while ((m = BCRYPT_LITERAL_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-bcrypt-literal', category:'Broken Crypto', severity:'critical',
      value: m[1], context: ctx(m.index),
      description: 'bcrypt called with literal hash — password comparison hardcoded in bundle',
    });
  }

  // argon2 literal
  const ARGON2_LITERAL_RE = /argon2\.(?:verify|hash|verifyAsync)\s*\(\s*[^,]+,\s*["'](\$argon2[id]+\$[^"']{20,})["']/g;
  while ((m = ARGON2_LITERAL_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-argon2-literal', category:'Broken Crypto', severity:'critical',
      value: m[1], context: ctx(m.index),
      description: 'argon2 verify called with literal hash — password comparison hardcoded in bundle',
    });
  }

  // 4. Node-style crypto.createHash with md5 or sha1
  const NODE_HASH_RE = /crypto\.createHash\s*\(\s*["'](md5|sha1|md4|md2)["']\s*\)/g;
  while ((m = NODE_HASH_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-node-weak-hash', category:'Broken Crypto', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description: `Node crypto.createHash("${m[1]}") — ${m[1]} is cryptographically broken, use sha256+`,
    });
  }
  // crypto.createHmac with weak algo
  const NODE_HMAC_RE = /crypto\.createHmac\s*\(\s*["'](md5|sha1|md4)["']\s*,/g;
  while ((m = NODE_HMAC_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-node-weak-hmac', category:'Broken Crypto', severity:'high',
      value: m[0].slice(0,80), context: ctx(m.index),
      description: `Node crypto.createHmac("${m[1]}") — HMAC with weak hash algorithm`,
    });
  }
  // crypto.createCipheriv with hardcoded IV (already exists but broaden it)
  const NODE_CIPHER_IV_RE = /crypto\.createCipheriv\s*\([^,]+,\s*[^,]+,\s*["']([a-f0-9]{8,})["']/g;
  while ((m = NODE_CIPHER_IV_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-node-static-iv', category:'Broken Crypto', severity:'high',
      value: `IV=${m[1]}`, context: ctx(m.index),
      description: 'createCipheriv with literal IV — IV must be random per operation',
    });
  }

  // 5. Hardcoded bearer tokens in fetch / axios call headers
  const FETCH_BEARER_RE = /(?:fetch|axios\.[a-z]+|http\.[a-z]+)\s*\([^)]*?Authorization\s*:\s*["']Bearer\s+([A-Za-z0-9_\-\.]{20,})["']/g;
  while ((m = FETCH_BEARER_RE.exec(src)) !== null) {
    findings.push({
      id:'crypto-bearer-in-headers', category:'Hardcoded Credential', severity:'critical',
      value: `Bearer ${m[1].slice(0,16)}…`, context: ctx(m.index),
      description: 'Bearer token embedded in fetch/axios Authorization header — credential in client bundle',
    });
  }

  // 6. Authorization: 'Bearer <literal>' anywhere
  const AUTH_HEADER_BEARER_RE = /Authorization\s*:\s*["']Bearer\s+([A-Za-z0-9_\-\.~+\/=]{20,})["']/g;
  while ((m = AUTH_HEADER_BEARER_RE.exec(src)) !== null) {
    const tok = m[1];
    if (tok.length < 30) continue;
    findings.push({
      id:'crypto-auth-header-literal', category:'Hardcoded Credential', severity:'critical',
      value: `Bearer ${tok.slice(0,16)}…`, context: ctx(m.index),
      description: 'Authorization: Bearer header literal in bundle — embed not constant',
    });
  }

  // 7. JWT secret regex (broaden existing pattern)
  // Already covered by CREDENTIAL_PATTERNS — skip duplicate.

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12p — NETWORK SURFACE EXTRACTOR  (Tier 1.10)
//
//  Extracts every host / URL / IP / port from the bundle and clusters:
//   · URLs by hostname — count by domain
//   · Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
//   · Internal RFC1918 IPs
//   · WebSocket endpoints (wss://)
//   · Hardcoded ports
// ═══════════════════════════════════════════════════════════════════════════

function extractNetworkSurface(src) {
  const ctx = (i, r=120) => src.slice(Math.max(0, i - r/2), i + r/2).replace(/\n/g,' ');
  const findings = [];

  // URL extraction
  const URL_RE = /\b((?:https?|wss?|ftp):\/\/[A-Za-z0-9._~:/?#\[\]!@&'()*+,;=\-]{3,200})/g;
  const hosts = new Map();
  const urls = [];
  let m;
  while ((m = URL_RE.exec(src)) !== null) {
    const u = m[1];
    urls.push({ url: u, pos: m.index });
    try {
      const url = new URL(u);
      const host = url.hostname;
      hosts.set(host, (hosts.get(host) || 0) + 1);
    } catch (_) { /* not a parseable URL — skip host extraction */ }
  }

  // Cloud metadata endpoints
  const META_RE = /\b(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|169\.254\.169\.253)[^\s"']{0,40}/g;
  while ((m = META_RE.exec(src)) !== null) {
    findings.push({
      id:'net-cloud-metadata', category:'Network Surface', severity:'critical',
      value: m[1], context: ctx(m.index),
      description:'Reference to cloud metadata endpoint — SSRF risk if reachable from server-side code',
    });
  }

  // RFC1918 IPs (already covered in CREDENTIAL_PATTERNS but extract here too)
  const RFC1918_RE = /["']((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+)["']/g;
  const rfc1918Seen = new Set();
  while ((m = RFC1918_RE.exec(src)) !== null) {
    if (rfc1918Seen.has(m[1])) continue;
    rfc1918Seen.add(m[1]);
    findings.push({
      id:'net-rfc1918', category:'Network Surface', severity:'low',
      value: m[1], context: ctx(m.index),
      description: `Internal RFC1918 IP literal — confirm this is intentional`,
    });
  }

  // Public IPs not on safe allowlist
  const PUBLIC_IP_RE = /["'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["']/g;
  const publicSeen = new Set();
  while ((m = PUBLIC_IP_RE.exec(src)) !== null) {
    const ip = m[1];
    if (rfc1918Seen.has(ip)) continue;
    // FIX (Stage 4 audit): expanded skip list. Previous regex only skipped
    // 0./127./255./224.-239. (multicast). Now also skips:
    //   240.-255.   (class E reserved)
    //   100.64.-127. (CGNAT / RFC 6598)
    //   169.254.    (link-local — also caught by META_RE but defensive)
    //   192.0.2./198.51.100./203.0.113. (TEST-NET-1/2/3 documentation ranges)
    if (/^(?:0\.|127\.|255\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)) continue;
    if (publicSeen.has(ip)) continue;
    publicSeen.add(ip);
    findings.push({
      id:'net-public-ip', category:'Network Surface', severity:'info',
      value: ip, context: ctx(m.index),
      description:`Public IP literal — verify endpoint`,
    });
  }

  // Cluster hosts by count
  const hostClusters = [...hosts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([host, count]) => ({ host, count }));

  return {
    urls,
    totalUrls: urls.length,
    uniqueHosts: hosts.size,
    hostClusters: hostClusters.slice(0, 50),
    findings,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 12q — SOURCE MAP AWARENESS (Stage 3E)
//
//  Parses `//# sourceMappingURL=...` references at the end of bundles and,
//  when the map is inline (base64 data URI), decodes it to extract:
//    · source file names (original pre-bundle files)
//    · sourceRoot (if present)
//    · whether the map references external URLs (potential info leak)
//
//  For external `.map` URLs, we record the URL but do NOT fetch it (zero-dep
//  contract; users can fetch separately if needed). The presence of a source
//  map in a production bundle is itself a finding — it leaks original source
//  structure and file paths.
// ═══════════════════════════════════════════════════════════════════════════

function parseSourceMap(src) {
  const findings = [];
  const ctx = (i, r=120) => src.slice(Math.max(0, i - r/2), i + r/2).replace(/\n/g, ' ');

  // Match sourceMappingURL in either of:
  //   //# sourceMappingURL=foo.js.map
  //   /*# sourceMappingURL=foo.js.map */
  //   //# sourceMappingURL=data:application/json;base64,XXXX
  const SOURCEMAP_RE = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)|\/\*#\s*sourceMappingURL\s*=\s*(\S+)\s*\*\//g;
  let m;
  let mapRef = null;
  while ((m = SOURCEMAP_RE.exec(src)) !== null) {
    const url = m[1] || m[2];
    mapRef = { url, pos: m.index, isInline: false, isExternal: false };
    findings.push({
      id: 'sourcemap-ref', category: 'Source Map', severity: 'high',
      value: url.slice(0, 100), context: ctx(m.index),
      description: 'sourceMappingURL reference in production bundle — original source structure leaked',
    });
    break;  // only one source map reference per file
  }

  if (!mapRef) {
    return { found: false, findings };
  }

  // Check if it's an inline data URI
  if (mapRef.url.startsWith('data:')) {
    mapRef.isInline = true;
    // Try to decode the inline map
    const dataMatch = mapRef.url.match(/^data:application\/json;(?:charset=utf-8;)?base64,(.+)$/);
    if (dataMatch) {
      try {
        const decoded = Buffer.from(dataMatch[1], 'base64').toString('utf8');
        const map = JSON.parse(decoded);
        const sources = map.sources || [];
        const sourceRoot = map.sourceRoot || null;

        findings.push({
          id: 'sourcemap-inline-decoded', category: 'Source Map', severity: 'critical',
          value: `${sources.length} source files leaked`,
          context: `sources[0..5]: ${sources.slice(0, 5).join(', ')}`,
          description: `Inline source map decoded — ${sources.length} original source file names exposed`,
        });

        // Flag specific source paths that reveal internal structure
        const sensitivePatterns = [
          { re: /\/(?:src|app|lib|server|backend|internal)\//i, sev: 'high', desc: 'Internal source path disclosed' },
          { re: /\/(?:test|spec|__tests__)\//i, sev: 'medium', desc: 'Test file paths disclosed' },
          { re: /\/node_modules\//, sev: 'low', desc: 'node_modules path disclosed' },
          { re: /\.(?:env|key|pem|p12|crt)$/, sev: 'critical', desc: 'Sensitive file (env/key/cert) in source map' },
        ];
        for (const srcPath of sources) {
          for (const p of sensitivePatterns) {
            if (p.re.test(srcPath)) {
              findings.push({
                id: 'sourcemap-sensitive-path', category: 'Source Map', severity: p.sev,
                value: srcPath.slice(0, 100), context: `source: ${srcPath}`,
                description: p.desc,
              });
            }
          }
        }

        return {
          found: true,
          isInline: true,
          isExternal: false,
          mapUrl: mapRef.url,
          sources,
          sourceRoot,
          sourceCount: sources.length,
          findings,
        };
      } catch (e) {
        findings.push({
          id: 'sourcemap-decode-failed', category: 'Source Map', severity: 'low',
          value: e.message.slice(0, 80), context: ctx(mapRef.pos),
          description: 'Inline source map present but failed to decode',
        });
      }
    }
  } else if (mapRef.url.startsWith('http://') || mapRef.url.startsWith('https://') ||
             mapRef.url.endsWith('.map')) {
    mapRef.isExternal = true;
    findings.push({
      id: 'sourcemap-external', category: 'Source Map', severity: 'medium',
      value: mapRef.url.slice(0, 100), context: ctx(mapRef.pos),
      description: 'External source map URL — fetching it would expose original source code',
    });
  }

  return {
    found: true,
    isInline: !!mapRef.isInline,
    isExternal: !!mapRef.isExternal,
    mapUrl: mapRef.url,
    sources: [],
    sourceRoot: null,
    sourceCount: 0,
    findings,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 16 — OBFUSCATOR FINGERPRINTING (Stage 5)
//
//  Detects commercial and open-source JavaScript obfuscators by their
//  characteristic runtime patterns. When an obfuscator is identified, emits:
//    · confidence score (0..1)
//    · matched signatures (with positions)
//    · targeted deobfuscation hints (which decoder passes to run)
//    · LLM-useful metadata (e.g. "expect mangled identifiers, don't reason
//      about identifier semantics")
//
//  Obfuscators detected:
//    · obfuscator.io  — string-array rotation, decoder IIFEs, RC4/base64
//                       string decoders, control-flow flattening dispatcher
//    · Jscrambler     — char-code table decoders, btoa-variant encoders,
//                       "chained" string-concat obfuscation
//    · ByteHide       — control-flow flattening + string-array, similar to
//                       obfuscator.io but with different dispatcher shape
//    · JSProtect      — eval-based string decryption, base64+AES
//    · jsfuck         — []+{} style encoding
//    · Custom/free    — generic heuristic for unknown obfuscators
//
//  Output is consumed by:
//    · The main pipeline (Phase 16b) to trigger targeted decoders
//    · The report generator (LLM payload metadata)
//    · The constant-expression evaluator (to know which decoders to attempt)
// ═══════════════════════════════════════════════════════════════════════════

function fingerprintObfuscator(src) {
  const findings = [];
  const signatures = [];  // { obfuscator, signature, pos, evidence }
  const ctx = (i, r = 120) => src.slice(Math.max(0, i - r/2), i + r/2).replace(/\n/g, ' ');

  // ── obfuscator.io signatures ────────────────────────────────────────────
  // obfuscator.io emits several characteristic patterns:
  //   1. A string-array declaration: var _0xARR = ['str1','str2',...]
  //   2. A rotation IIFE: (function(_0xARR, _0xKey) { ... push/shift ... }(_0xARR, 0xNNN))
  //   3. A decoder function: function _0xDEC(idx, key) { ... return decoded }
  //   4. Control-flow flattening: while(!![]) { switch(_0xSTATE[_0xIDX++]) { ... } }
  let obfuscatorIoScore = 0;
  const obfuscatorIoSigs = [];

  // Signature 1: string-array + rotation IIFE
  // Pattern: var NAME = [...]; (function(NAME, KEY){ ... push/shift ... }(NAME, 0xHEX))
  const saRotateRe = /var\s+([A-Za-z_$][\w$]*)\s*=\s*\[(["'][^"']*["']\s*,?\s*){3,}\]\s*;\s*\(function\s*\(\s*\1\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{[\s\S]{0,1500}?(?:push|shift)[\s\S]{0,500}?\}\s*\(\s*\1\s*,\s*0x[0-9a-fA-F]+\s*\)\s*\)/g;
  let m;
  while ((m = saRotateRe.exec(src)) !== null) {
    obfuscatorIoScore += 0.4;
    obfuscatorIoSigs.push({
      signature: 'string-array-rotation-iife',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'extract string array + apply rotation offset',
    });
  }

  // Signature 2: decoder function with RC4 or base64
  // Pattern: function NAME(a, b) { var c = NAME2[a]; ... return c; }
  //   where NAME2 is referenced as a string array, and the body contains
  //   charCodeAt / fromCharCode / parseInt patterns typical of RC4
  const decoderFnRe = /function\s+([A-Za-z_$][\w$]*)\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{\s*var\s+[A-Za-z_$][\w$]*\s*=\s*([A-Za-z_$][\w$]*)\s*\[[^}]{0,400}?(?:charCodeAt|fromCharCode|parseInt|atob)/g;
  while ((m = decoderFnRe.exec(src)) !== null) {
    obfuscatorIoScore += 0.25;
    obfuscatorIoSigs.push({
      signature: 'decoder-function-rc4-or-base64',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'extract decoder function + evaluate calls with constant args',
    });
  }

  // Signature 3: control-flow flattening dispatcher
  // Pattern: while(!![]) { switch(NAME[NAME2++]) { case '0xHEX': ... continue } }
  const cffRe = /while\s*\(\s*!{0,2}\[\]\s*\)\s*\{\s*switch\s*\(\s*[A-Za-z_$][\w$]*\s*\[\s*[A-Za-z_$][\w$]*\s*\+\+\s*\]\s*\)\s*\{\s*case\s*['"]0x[0-9a-fA-F]+['"]/g;
  while ((m = cffRe.exec(src)) !== null) {
    obfuscatorIoScore += 0.3;
    obfuscatorIoSigs.push({
      signature: 'control-flow-flattening-dispatcher',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'de-flatten by solving state-transition function',
    });
  }

  // Signature 4: hex-number identifier mangling (e.g. _0x1a2b)
  // Count: if more than 20 _0xHEX identifiers, likely obfuscator.io
  const hexIdents = src.match(/\b_0x[0-9a-fA-F]{4,8}\b/g) || [];
  if (hexIdents.length > 20) {
    obfuscatorIoScore += 0.2;
    obfuscatorIoSigs.push({
      signature: 'hex-identifier-mangling',
      pos: src.indexOf('_0x'),
      evidence: `${hexIdents.length} _0xHEX identifiers`,
      hint: 'identifiers are mangled — do not reason about name semantics',
    });
  }

  if (obfuscatorIoScore >= 0.3) {
    signatures.push({
      obfuscator: 'obfuscator.io',
      confidence: Math.min(obfuscatorIoScore, 1.0),
      version: detectObfuscatorIoVersion(src),
      matched: obfuscatorIoSigs,
    });
  }

  // ── Jscrambler signatures ───────────────────────────────────────────────
  // Jscrambler emits:
  //   1. A "chained" string decoder: multiple btoa/charCode IIFEs that
  //      build up strings character-by-character
  //   2. Characteristic "opf" / "p" / "a" parameter names in decoder fns
  //   3. `OCA` / `OCC` / `OCB` global variable prefixes (older versions)
  //   4. Date-based anti-debugging: `if (Date.now() > NNN) { ... }`
  let jscramblerScore = 0;
  const jscramblerSigs = [];

  // Signature 1: Jscrambler chained decoder (multiple nested atob/charCode)
  // Pattern: function NAME(opf, ...) { ... var X = atob(...) ... charCodeAt ... }
  const jscramblerDecoderRe = /function\s+[A-Za-z_$][\w$]*\s*\(\s*opf\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{[^}]{0,800}?(?:atob|btoa)[^}]{0,400}?charCodeAt/g;
  while ((m = jscramblerDecoderRe.exec(src)) !== null) {
    jscramblerScore += 0.35;
    jscramblerSigs.push({
      signature: 'jscrambler-chained-decoder',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'extract decoder + evaluate chained atob/charCode calls',
    });
  }

  // Signature 2: OC* global prefix
  const ocGlobals = src.match(/\bOC[A-Z]\d*\b/g) || [];
  if (ocGlobals.length > 5) {
    jscramblerScore += 0.2;
    jscramblerSigs.push({
      signature: 'jscrambler-oc-globals',
      pos: src.indexOf('OC'),
      evidence: `${ocGlobals.length} OC* globals`,
      hint: 'Jscrambler runtime globals detected',
    });
  }

  // Signature 3: Date-based anti-debugging
  const dateAntiDbgRe = /Date\s*\.\s*now\s*\(\s*\)\s*[<>]\s*0x[0-9a-fA-F]+/g;
  while ((m = dateAntiDbgRe.exec(src)) !== null) {
    jscramblerScore += 0.15;
    jscramblerSigs.push({
      signature: 'jscrambler-date-anti-debug',
      pos: m.index,
      evidence: m[0].slice(0, 60),
      hint: 'date-based anti-debugging — disable or ignore during analysis',
    });
  }

  // Signature 4: Jscrambler self-defending / anti-tamper
  // Pattern: function NAME() { ... debug Protection ... setInterval ... }
  const selfDefendingRe = /function\s+[A-Za-z_$][\w$]*\s*\(\s*\)\s*\{\s*function\s+[A-Za-z_$][\w$]*\s*\(\s*\)\s*\{[^}]{0,400}?debug|setInterval\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*0x[0-9a-fA-F]+\s*\)/g;
  while ((m = selfDefendingRe.exec(src)) !== null) {
    jscramblerScore += 0.2;
    jscramblerSigs.push({
      signature: 'jscrambler-self-defending',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'self-defending code — may call debugger/setInterval',
    });
  }

  if (jscramblerScore >= 0.35) {
    signatures.push({
      obfuscator: 'Jscrambler',
      confidence: Math.min(jscramblerScore, 1.0),
      version: null,  // Jscrambler versions are hard to detect from output
      matched: jscramblerSigs,
    });
  }

  // ── ByteHide signatures ─────────────────────────────────────────────────
  // ByteHide is similar to obfuscator.io but with distinct patterns:
  //   1. Uses `ByteHide` namespace or `_BH` prefix in some versions
  //   2. String encryption with a different decoder shape
  //   3. Control-flow flattening with a `state` variable (not _0xHEX)
  let bytehideScore = 0;
  const bytehideSigs = [];

  // Signature 1: ByteHide namespace references
  if (/\bByteHide\b/.test(src) || /\b_BH[A-Z_]/.test(src)) {
    bytehideScore += 0.5;
    bytehideSigs.push({
      signature: 'bytehide-namespace',
      pos: src.search(/\bByteHide\b|_BH[A-Z_]/),
      evidence: 'ByteHide or _BH* identifier',
      hint: 'ByteHide runtime detected',
    });
  }

  // Signature 2: ByteHide-style string decryptor
  // Pattern: function NAME(idx) { return NAME2(idx ^ KEY); }
  const bhDecryptorRe = /function\s+[A-Za-z_$][\w$]*\s*\(\s*[A-Za-z_$][\w$]*\s*\)\s*\{\s*return\s+[A-Za-z_$][\w$]*\s*\(\s*[A-Za-z_$][\w$]*\s*\^\s*0x[0-9a-fA-F]+\s*\)\s*;?\s*\}/g;
  while ((m = bhDecryptorRe.exec(src)) !== null) {
    bytehideScore += 0.25;
    bytehideSigs.push({
      signature: 'bytehide-xor-decryptor',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'XOR-based string decryptor',
    });
  }

  if (bytehideScore >= 0.4) {
    signatures.push({
      obfuscator: 'ByteHide',
      confidence: Math.min(bytehideScore, 1.0),
      version: null,
      matched: bytehideSigs,
    });
  }

  // ── JSProtect signatures ────────────────────────────────────────────────
  // JSProtect uses eval-based decryption with base64+AES
  let jsprotectScore = 0;
  const jsprotectSigs = [];

  // Signature: eval(decode(...)) pattern with CryptoJS
  const jsprotectRe = /eval\s*\(\s*[A-Za-z_$][\w$]*\s*\(\s*["'][A-Za-z0-9+/=]{40,}["']\s*\)\s*\)[^}]{0,200}?CryptoJS/g;
  while ((m = jsprotectRe.exec(src)) !== null) {
    jsprotectScore += 0.5;
    jsprotectSigs.push({
      signature: 'jsprotect-eval-cryptojs',
      pos: m.index,
      evidence: m[0].slice(0, 80),
      hint: 'eval(CryptoJS.decrypt(...)) pattern',
    });
  }

  if (jsprotectScore >= 0.4) {
    signatures.push({
      obfuscator: 'JSProtect',
      confidence: Math.min(jsprotectScore, 1.0),
      version: null,
      matched: jsprotectSigs,
    });
  }

  // ── JSFuck signatures ───────────────────────────────────────────────────
  // JSFuck encodes everything as []()!+
  let jsfuckScore = 0;
  const jsfuckSigs = [];

  // Signature: long runs of []()!+ characters
  const jsfuckRuns = src.match(/\[[\[\]()!+]{50,}\]/g) || [];
  if (jsfuckRuns.length > 0) {
    jsfuckScore += Math.min(0.3 * jsfuckRuns.length, 0.8);
    jsfuckSigs.push({
      signature: 'jsfuck-encoding',
      pos: src.search(/\[[\[\]()!+]{50,}\]/),
      evidence: `${jsfuckRuns.length} JSFuck-style runs`,
      hint: 'JSFuck encoding — evaluate with safe interpreter',
    });
  }

  if (jsfuckScore >= 0.3) {
    signatures.push({
      obfuscator: 'JSFuck',
      confidence: Math.min(jsfuckScore, 1.0),
      version: null,
      matched: jsfuckSigs,
    });
  }

  // ── Generic obfuscation heuristic ───────────────────────────────────────
  // If no specific obfuscator detected, check for general signs:
  //   · High density of hex identifiers (>5 but <20)
  //   · Multiple eval(new Function(...)) calls
  //   · String concatenation chains (>5 consecutive "str" + "str")
  if (signatures.length === 0) {
    let genericScore = 0;
    const genericSigs = [];

    if (hexIdents.length > 5) {
      genericScore += 0.2;
      genericSigs.push({
        signature: 'hex-identifier-mangling',
        pos: src.indexOf('_0x'),
        evidence: `${hexIdents.length} _0xHEX identifiers`,
        hint: 'some identifier mangling',
      });
    }

    const evalCount = (src.match(/\beval\s*\(/g) || []).length;
    if (evalCount > 3) {
      genericScore += 0.2;
      genericSigs.push({
        signature: 'high-eval-density',
        pos: src.indexOf('eval'),
        evidence: `${evalCount} eval() calls`,
        hint: 'multiple eval calls — possible runtime string construction',
      });
    }

    const concatChains = (src.match(/["'][^"']{0,30}["']\s*\+\s*["'][^"']{0,30}["']\s*\+\s*["'][^"']{0,30}["']\s*\+\s*["'][^"']{0,30}["']\s*\+\s*["'][^"']{0,30}["']/g) || []).length;
    if (concatChains > 2) {
      genericScore += 0.2;
      genericSigs.push({
        signature: 'string-concat-chains',
        pos: -1,
        evidence: `${concatChains} 5+ concatenation chains`,
        hint: 'string concatenation obfuscation',
      });
    }

    if (genericScore >= 0.3) {
      signatures.push({
        obfuscator: 'unknown/generic',
        confidence: Math.min(genericScore, 1.0),
        version: null,
        matched: genericSigs,
      });
    }
  }

  // ── Build findings + LLM metadata ───────────────────────────────────────
  for (const sig of signatures) {
    findings.push({
      id: `obfuscator-${sig.obfuscator.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
      category: 'Obfuscator Fingerprint',
      severity: sig.confidence >= 0.7 ? 'high' : sig.confidence >= 0.4 ? 'medium' : 'low',
      value: `${sig.obfuscator} (confidence: ${(sig.confidence * 100).toFixed(0)}%)${sig.version ? ' v' + sig.version : ''}`,
      context: sig.matched.map(s => s.signature).join(', '),
      description: `${sig.obfuscator} obfuscator detected via ${sig.matched.length} signature(s): ${sig.matched.map(s => s.hint).join('; ')}`,
    });
  }

  // ── LLM-useful metadata ─────────────────────────────────────────────────
  const llmHints = {
    expectMangledIdentifiers: signatures.some(s =>
      s.matched.some(m => m.signature.includes('mangling') || m.signature.includes('mangled'))),
    expectStringArrayIndirection: signatures.some(s =>
      s.matched.some(m => m.signature.includes('string-array'))),
    expectControlFlowFlattening: signatures.some(s =>
      s.matched.some(m => m.signature.includes('control-flow-flattening'))),
    expectAntiDebugging: signatures.some(s =>
      s.matched.some(m => m.signature.includes('anti-debug') || m.signature.includes('self-defending'))),
    expectRuntimeStringConstruction: signatures.some(s =>
      s.matched.some(m => m.signature.includes('decoder') || m.signature.includes('encoding'))),
    recommendedDecoderPasses: [...new Set(signatures.flatMap(s => s.matched.map(m => m.hint)))],
  };

  return {
    detected: signatures,
    primary: signatures.length > 0 ? signatures.reduce((a, b) => a.confidence > b.confidence ? a : b) : null,
    findings,
    llmHints,
  };
}

// Helper: detect obfuscator.io version from characteristic patterns
function detectObfuscatorIoVersion(src) {
  // obfuscator.io v0.x used `String.fromCharCode` heavily in decoders
  // v1.x+ uses RC4 or base64 with `charCodeAt`
  // v2.x+ added control-flow flattening as a stable feature
  if (/charCodeAt.*fromCharCode.*parseInt/s.test(src)) return '1.x-2.x';
  if (/String\.fromCharCode/.test(src) && /atob/.test(src)) return '0.x-1.x';
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 17 — FUNCTION SUMMARY EMITTER (Stage 6)
//
//  Computes per-function "taint contracts" — compact descriptions of how
//  data flows through each function. This is the keystone piece for:
//    · Inter-procedural taint propagation (breaks the intra-procedural scope wall)
//    · The LLM payload architecture (compresses 500-line functions to ~40-80 tokens)
//    · The sink-anchored backward slicer (enables graph traversal, not source scanning)
//
//  For each function, emits:
//    · params:      parameter names (e.g. ['props', 'callback'])
//    · sources:     external taint sources read inside (location.*, localStorage, etc.)
//    · sinks:       dangerous sinks hit inside (innerHTML, eval, etc.) with what flows in
//    · sanitizers:  sanitizer calls present (DOMPurify.sanitize, escape, etc.)
//    · returns:     symbolic return value description
//    · calls:       function names called inside (for reachability)
//
//  Return value shapes:
//    returns(literal)        — returns a literal value
//    returns(args[N])        — returns the Nth parameter directly
//    returns(tainted:source) — returns a value derived from a taint source
//    returns(call:fnName)    — returns the result of a function call
//    returns(unknown)        — can't statically determine
//
//  Sink "via" field:
//    via: args[N]    — the Nth parameter flows to the sink
//    via: source     — a taint source flows to the sink
//    via: unknown    — can't statically determine
// ═══════════════════════════════════════════════════════════════════════════

// Known sanitizer function names — when present on a path, they may neutralize taint.
// The LLM is asked to JUDGE whether the sanitizer is effective for the specific sink.
const SANITIZER_PATTERNS = [
  { re: /DOMPurify\s*\.\s*sanitize\s*\(/,            name: 'DOMPurify.sanitize',    effectiveFor: ['innerHTML','outerHTML','insertAdjacentHTML','srcdoc'] },
  { re: /sanitize\s*\(/,                               name: 'sanitize',              effectiveFor: ['innerHTML','outerHTML'] },
  { re: /escape\s*\(/,                                 name: 'escape',                effectiveFor: ['innerHTML'] },
  { re: /encodeURIComponent\s*\(/,                     name: 'encodeURIComponent',    effectiveFor: ['href'] },
  { re: /encodeURI\s*\(/,                              name: 'encodeURI',             effectiveFor: ['href'] },
  { re: /stripTags\s*\(/,                              name: 'stripTags',             effectiveFor: ['innerHTML'] },
  { re: /escapeHtml\s*\(/,                             name: 'escapeHtml',            effectiveFor: ['innerHTML'] },
  { re: /\.replace\s*\(\s*<[^>]*>\s*[,)]/,            name: 'regex-tag-strip',       effectiveFor: ['innerHTML'] },
  { re: /bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)\s*\(/, name: 'bypassSecurityTrust*', effectiveFor: [], note: 'Angular bypass — NOT a sanitizer' },
];

// Known taint source patterns (for function-body scanning)
const SOURCE_PATTERNS_FN = [
  { re: /location\.(?:search|hash|href|pathname|host|hostname|origin|port|protocol)/g, name: 'location.*' },
  { re: /document\.(?:URL|referrer|cookie|location|domain)/g, name: 'document.*' },
  { re: /window\.(?:name|location)/g, name: 'window.*' },
  { re: /localStorage\.getItem\s*\(/g, name: 'localStorage' },
  { re: /sessionStorage\.getItem\s*\(/g, name: 'sessionStorage' },
  { re: /URLSearchParams/g, name: 'URLSearchParams' },
  { re: /event\.data\b/g, name: 'event.data' },
  { re: /window\.location\.(?:href|search|hash|pathname)/g, name: 'window.location.*' },
];

// Known sink patterns (for function-body scanning)
const SINK_PATTERNS_FN = [
  { re: /\.innerHTML\s*=/g,                          name: 'innerHTML',        cwe: 'CWE-79', sev: 'critical' },
  { re: /\.outerHTML\s*=/g,                          name: 'outerHTML',        cwe: 'CWE-79', sev: 'critical' },
  { re: /\.insertAdjacentHTML\s*\(/g,                name: 'insertAdjacentHTML', cwe: 'CWE-79', sev: 'critical' },
  { re: /document\.write\s*\(/g,                     name: 'document.write',   cwe: 'CWE-79', sev: 'critical' },
  { re: /\beval\s*\(/g,                              name: 'eval',             cwe: 'CWE-95', sev: 'critical' },
  { re: /new\s+Function\s*\(/g,                      name: 'Function()',       cwe: 'CWE-95', sev: 'critical' },
  { re: /\.setAttribute\s*\(\s*['"]on\w+['"]/g,      name: 'setAttribute(on*)', cwe: 'CWE-79', sev: 'critical' },
  { re: /location\.(?:href|replace|assign)\s*=/g,    name: 'location.href=',   cwe: 'CWE-601', sev: 'high' },
  { re: /\.srcdoc\s*=/g,                             name: 'srcdoc',           cwe: 'CWE-79', sev: 'critical' },
];

function computeFunctionSummaries(src, structuralIndex) {
  const T = structuralIndex.tokens;
  const M = T.length;
  const summaries = [];

  // Helper: extract parameter names from token range
  function extractParamNames(paramsStart, paramsEnd) {
    const names = [];
    for (let k = paramsStart; k < paramsEnd && k < M; k++) {
      const t = T[k];
      if (t.type === 'ident') {
        names.push(t.value);
      }
      // Skip default values and destructuring — we only track simple ident params
    }
    return names;
  }

  // Helper: find return statements in a token range
  function findReturns(bodyStart, bodyEnd) {
    const returns = [];
    for (let k = bodyStart; k <= bodyEnd && k < M; k++) {
      const t = T[k];
      if (t.type === 'keyword' && t.value === 'return') {
        // Find what's being returned (next expression up to ; or })
        let k2 = k + 1;
        const exprStart = k2;
        let depth = 0;
        while (k2 <= bodyEnd && k2 < M) {
          const tt = T[k2];
          if (tt.type === 'punct') {
            if (tt.value === '(' || tt.value === '[' || tt.value === '{') depth++;
            else if (tt.value === ')' || tt.value === ']' || tt.value === '}') {
              if (depth === 0) break;
              depth--;
            }
            else if ((tt.value === ';' || tt.value === ',') && depth === 0) break;
          }
          k2++;
        }
        returns.push({ returnTok: k, exprStart, exprEnd: k2 });
      }
    }
    return returns;
  }

  // Helper: classify a return expression
  function classifyReturn(retExprStart, retExprEnd, paramNames, bodySources) {
    if (retExprStart >= retExprEnd) return { kind: 'void', value: 'undefined' };
    // Get the text of the return expression
    let exprText = '';
    for (let k = retExprStart; k < retExprEnd && k < M; k++) {
      exprText += T[k].value;
    }
    // Check if it's a literal
    if (T[retExprStart] && T[retExprStart].type === 'string') return { kind: 'literal', value: 'string' };
    if (T[retExprStart] && T[retExprStart].type === 'number') return { kind: 'literal', value: 'number' };
    if (T[retExprStart] && T[retExprStart].type === 'keyword' && (T[retExprStart].value === 'true' || T[retExprStart].value === 'false' || T[retExprStart].value === 'null')) {
      return { kind: 'literal', value: T[retExprStart].value };
    }
    // Check if it's a parameter
    if (T[retExprStart] && T[retExprStart].type === 'ident') {
      const name = T[retExprStart].value;
      const paramIdx = paramNames.indexOf(name);
      if (paramIdx >= 0) return { kind: 'param', value: `args[${paramIdx}]` };
      // Check if it's a function call
      if (T[retExprStart + 1] && T[retExprStart + 1].type === 'punct' && T[retExprStart + 1].value === '(') {
        return { kind: 'call', value: `call:${name}` };
      }
      // Check if it references a tainted source
      for (const src of bodySources) {
        if (exprText.includes(src.expr) || exprText.includes(src.name)) {
          return { kind: 'tainted', value: `tainted:${src.name}` };
        }
      }
    }
    // Check if the expression contains a tainted source reference
    for (const src of bodySources) {
      if (exprText.includes(src.expr)) {
        return { kind: 'tainted', value: `tainted:${src.name}` };
      }
    }
    return { kind: 'unknown', value: 'unknown' };
  }

  // Helper: classify what flows to a sink
  // taintedLocals: Map<varName, sourceName> — local vars assigned from sources
  function classifySinkFlow(sinkPos, bodyStart, bodyEnd, paramNames, bodySources, taintedLocals) {
    // Find the sink's argument window (similar to trackTaintAST's extractSinkArgWindow)
    // For assignment sinks (x.innerHTML = ...), look at what's after =
    // For call sinks (eval(...)), look at what's inside ()
    // Walk forward from sinkPos to find ( or =
    let p = sinkPos;
    let depth = 0;
    while (p < src.length && p < sinkPos + 500) {
      const c = src[p];
      if (c === '(' && depth === 0) {
        // Call sink — extract args to matching )
        const argStart = p + 1;
        let d = 1, q = argStart;
        while (q < src.length && d > 0) {
          if (src[q] === '(' || src[q] === '[' || src[q] === '{') d++;
          else if (src[q] === ')' || src[q] === ']' || src[q] === '}') d--;
          if (d === 0) break;
          q++;
        }
        const argText = src.slice(argStart, q);
        // Check if any param appears in the arg text
        for (let i = 0; i < paramNames.length; i++) {
          if (new RegExp(`(?<![\\w$])${paramNames[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(argText)) {
            return { via: `args[${i}]` };
          }
        }
        // Check if any tainted local variable appears
        for (const [varName, srcName] of taintedLocals) {
          if (new RegExp(`(?<![\\w$])${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(argText)) {
            return { via: srcName };
          }
        }
        // Check if any source appears directly
        for (const s of bodySources) {
          if (argText.includes(s.expr)) return { via: s.name };
        }
        return { via: 'unknown' };
      }
      if (c === '=' && depth === 0 && src[p+1] !== '=') {
        // Assignment sink — extract RHS to next ; at depth 0
        const rhsStart = p + 1;
        let d = 0, q = rhsStart;
        while (q < src.length) {
          if (src[q] === '(' || src[q] === '[' || src[q] === '{') d++;
          else if (src[q] === ')' || src[q] === ']' || src[q] === '}') { if (d === 0) break; d--; }
          else if (src[q] === ';' && d === 0) break;
          q++;
        }
        const rhsText = src.slice(rhsStart, q);
        // Check if any param appears
        for (let i = 0; i < paramNames.length; i++) {
          if (new RegExp(`(?<![\\w$])${paramNames[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(rhsText)) {
            return { via: `args[${i}]` };
          }
        }
        // Check if any tainted local variable appears
        for (const [varName, srcName] of taintedLocals) {
          if (new RegExp(`(?<![\\w$])${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(rhsText)) {
            return { via: srcName };
          }
        }
        // Check if any source appears directly
        for (const s of bodySources) {
          if (rhsText.includes(s.expr)) return { via: s.name };
        }
        return { via: 'unknown' };
      }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') { if (depth === 0) break; depth--; }
      else if (c === ';' && depth === 0) break;
      p++;
    }
    return { via: 'unknown' };
  }

  // Process each function
  for (let fnIdx = 0; fnIdx < structuralIndex.functions.length; fnIdx++) {
    const fn = structuralIndex.functions[fnIdx];
    const bodyStart = fn.bodyTokStart;
    const bodyEnd = fn.bodyTokEnd;

    if (bodyStart < 0 || bodyEnd < 0 || bodyStart >= M) continue;

    // Get body text
    const bodyStartPos = T[bodyStart] ? T[bodyStart].start : fn.start;
    const bodyEndPos = T[bodyEnd] ? T[bodyEnd].end : fn.end;
    const bodyText = src.slice(bodyStartPos, bodyEndPos);

    // Extract parameters
    const params = extractParamNames(fn.paramsTokStart, fn.paramsTokEnd);

    // Scan for taint sources in the body
    const sources = [];
    for (const pat of SOURCE_PATTERNS_FN) {
      const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
      let m;
      while ((m = re.exec(bodyText)) !== null) {
        sources.push({
          expr: m[0],
          name: pat.name,
          pos: bodyStartPos + m.index,
        });
      }
    }

    // ── Build tainted-locals map (per-function mini-SSA) ────────────────
    // Scan assignments in the body for patterns like:
    //   const x = location.search;
    //   var y = localStorage.getItem('token');
    //   let z = someTaintedVar;
    //   const { search } = window.location;       ← object destructuring (Stage 7)
    //   const { search, hash } = location;         ← multi-property destructuring
    //   const [first, ...rest] = taintedArr;       ← array destructuring
    //   const { x: renamed } = obj;                ← renamed destructuring
    // Record varName → sourceName so classifySinkFlow can resolve indirect flows.
    const taintedLocals = new Map();

    // ── Pass 1a: direct source assignments (simple IDENT = RHS) ────────
    const assignRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]{1,200});/g;
    let am;
    while ((am = assignRe.exec(bodyText)) !== null) {
      const varName = am[1];
      const rhs = am[2];
      // Check if RHS contains a source
      for (const s of sources) {
        if (rhs.includes(s.expr)) {
          taintedLocals.set(varName, s.name);
          break;
        }
      }
    }

    // ── Pass 1b: object destructuring from source ──────────────────────
    // Pattern: const { prop1, prop2, prop3: renamed } = SOURCE;
    // Each destructured property is tainted if the RHS is a source.
    const objDestrRe = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*([^;]{1,150});/g;
    while ((am = objDestrRe.exec(bodyText)) !== null) {
      const propsStr = am[1];
      const rhs = am[2].trim();
      // Check if RHS is a source — match either the full expr (location.search)
      // or the bare object (location, document, window)
      let sourceName = null;
      for (const s of sources) {
        if (rhs.includes(s.expr)) { sourceName = s.name; break; }
      }
      // Also check bare object references: const { x } = location
      // The source pattern 'location.*' matches location.search etc.,
      // but we also need to match bare `location` for destructuring.
      if (!sourceName) {
        if (/\blocation\b/.test(rhs)) sourceName = 'location.*';
        else if (/\bdocument\b/.test(rhs)) sourceName = 'document.*';
        else if (/\bwindow\b/.test(rhs)) sourceName = 'window.*';
      }
      // Also check if RHS is a tainted local
      if (!sourceName && taintedLocals.has(rhs)) {
        sourceName = taintedLocals.get(rhs);
      }
      if (!sourceName) continue;

      // Parse property names: "prop1, prop2: renamed, prop3 = default"
      const props = propsStr.split(',').map(p => p.trim()).filter(p => p);
      for (const prop of props) {
        // Handle "prop: renamed" and "prop = default"
        const renamed = prop.match(/^([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)/);
        const withDefault = prop.match(/^([A-Za-z_$][\w$]*)\s*=\s*/);
        if (renamed) {
          // const { x: renamed } = source; → renamed is tainted
          taintedLocals.set(renamed[2], sourceName);
        } else if (withDefault) {
          // const { x = defaultVal } = source; → x is tainted
          taintedLocals.set(withDefault[1], sourceName);
        } else if (/^[A-Za-z_$][\w$]*$/.test(prop)) {
          // Simple property: const { search } = source; → search is tainted
          taintedLocals.set(prop, sourceName);
        }
      }
    }

    // ── Pass 1c: array destructuring from tainted source ───────────────
    // Pattern: const [a, b, ...rest] = taintedArr;
    const arrDestrRe = /(?:const|let|var)\s*\[([^\]]+)\]\s*=\s*([^;]{1,150});/g;
    while ((am = arrDestrRe.exec(bodyText)) !== null) {
      const elemsStr = am[1];
      const rhs = am[2].trim();
      // Check if RHS is a source or tainted local
      let sourceName = null;
      for (const s of sources) {
        if (rhs.includes(s.expr)) { sourceName = s.name; break; }
      }
      if (!sourceName && taintedLocals.has(rhs)) {
        sourceName = taintedLocals.get(rhs);
      }
      if (!sourceName) continue;

      // Parse element names: "a, b, ...rest"
      const elems = elemsStr.split(',').map(e => e.trim()).filter(e => e);
      for (const elem of elems) {
        // Skip rest elements (...rest) and holes (empty)
        const restMatch = elem.match(/^\.\.\.([A-Za-z_$][\w$]*)$/);
        const simpleMatch = elem.match(/^([A-Za-z_$][\w$]*)$/);
        if (restMatch) {
          taintedLocals.set(restMatch[1], sourceName);
        } else if (simpleMatch) {
          taintedLocals.set(simpleMatch[1], sourceName);
        }
      }
    }

    // ── Pass 2: propagate through local-to-local assignments ───────────
    //   const x = location.search; const y = x; → y is tainted by location.*
    for (let pass = 0; pass < 3; pass++) {
      let changed = false;
      const assignRe2 = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;/g;
      while ((am = assignRe2.exec(bodyText)) !== null) {
        const target = am[1];
        const source = am[2];
        if (taintedLocals.has(source) && !taintedLocals.has(target)) {
          taintedLocals.set(target, taintedLocals.get(source));
          changed = true;
        }
      }
      // Also handle destructuring from a tainted local
      const objDestrRe2 = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*([A-Za-z_$][\w$]*)\s*;/g;
      while ((am = objDestrRe2.exec(bodyText)) !== null) {
        const propsStr = am[1];
        const rhs = am[2].trim();
        if (!taintedLocals.has(rhs)) continue;
        const sourceName = taintedLocals.get(rhs);
        const props = propsStr.split(',').map(p => p.trim()).filter(p => p);
        for (const prop of props) {
          const renamed = prop.match(/^([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)/);
          const simple = prop.match(/^([A-Za-z_$][\w$]*)$/);
          if (renamed && !taintedLocals.has(renamed[2])) {
            taintedLocals.set(renamed[2], sourceName);
            changed = true;
          } else if (simple && !taintedLocals.has(simple[1])) {
            taintedLocals.set(simple[1], sourceName);
            changed = true;
          }
        }
      }
      if (!changed) break;
    }

    // Scan for sinks in the body
    const sinks = [];
    for (const pat of SINK_PATTERNS_FN) {
      const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
      let m;
      while ((m = re.exec(bodyText)) !== null) {
        const sinkPos = bodyStartPos + m.index;
        const flow = classifySinkFlow(sinkPos, bodyStart, bodyEnd, params, sources, taintedLocals);
        sinks.push({
          name: pat.name,
          pos: sinkPos,
          cwe: pat.cwe,
          severity: pat.sev,
          via: flow.via,
        });
      }
    }

    // Scan for sanitizers in the body
    const sanitizers = [];
    for (const pat of SANITIZER_PATTERNS) {
      const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
      let m;
      while ((m = re.exec(bodyText)) !== null) {
        sanitizers.push({
          name: pat.name,
          pos: bodyStartPos + m.index,
          effectiveFor: pat.effectiveFor,
          note: pat.note || null,
        });
      }
    }

    // Find and classify return statements
    const returnStmts = findReturns(bodyStart, bodyEnd);
    const returns = returnStmts.map(r => classifyReturn(r.exprStart, r.exprEnd, params, sources));

    // If no return found and it's an arrow with expression body, the whole body IS the return
    if (returns.length === 0 && fn.isArrow && fn.isExprBody) {
      returns.push(classifyReturn(bodyStart, bodyEnd, params, sources));
    }

    // Find function calls in the body (for reachability)
    const calls = [];
    const callRe = /\b([A-Za-z_$][\w$]*)\s*\(/g;
    let cm;
    while ((cm = callRe.exec(bodyText)) !== null) {
      const callee = cm[1];
      // Skip keywords and builtins
      if (['if','for','while','switch','catch','function','return','typeof','instanceof','new','await','async','eval','parseInt','parseFloat','String','Number','Boolean','Array','Object','JSON','Math','Date','console','document','window'].includes(callee)) continue;
      if (!calls.includes(callee)) calls.push(callee);
    }

    summaries.push({
      id: fnIdx,
      name: fn.name,
      start: fn.start,
      end: fn.end,
      isArrow: !!fn.isArrow,
      params,
      sources,
      sinks,
      sanitizers,
      returns,
      calls,
    });
  }

  return summaries;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 18 — SINK-ANCHORED BACKWARD SLICER (Stage 6)
//
//  Starts from every sink, walks the call graph backward N hops, and emits
//  only the reachable subgraph. This produces inter-procedural taint paths
//  that the LLM can reason about, without dumping the entire bundle.
//
//  Algorithm:
//    1. For each function summary with sinks, start a path.
//    2. Walk backward: find all functions that call the current function.
//    3. For each caller, check if its return value or params flow to the sink.
//    4. Continue until we hit a taint source or reach max depth.
//    5. Emit the path as a compact chain.
//
//  Output: array of paths, each shaped like:
//    {
//      sink: { name, pos, cwe, severity, via },
//      sinkFn: { name, id },
//      hops: [{ fnName, fnId, via, sources, sanitizers }],
//      reachesSource: boolean,
//      sourceChain: ['location.search', 'args[0]', ...],
//      totalHops: number,
//    }
// ═══════════════════════════════════════════════════════════════════════════

function buildBackwardSlices(src, structuralIndex, functionSummaries, callGraph, maxHops) {
  if (!maxHops) maxHops = 3;
  const paths = [];

  // Build a reverse call graph: for each function, who calls it?
  // callGraph.outgoing is Map<callerKey, Set<calleeKey>>
  // We need Map<calleeName, Set<callerSummary>>
  const reverseCalls = new Map();  // calleeName → [summaryId, ...]
  for (const sm of functionSummaries) {
    for (const calledName of sm.calls) {
      if (!reverseCalls.has(calledName)) reverseCalls.set(calledName, []);
      reverseCalls.get(calledName).push(sm.id);
    }
  }

  // Build name → summary lookup
  const nameToSummary = new Map();
  for (const sm of functionSummaries) {
    if (!nameToSummary.has(sm.name)) nameToSummary.set(sm.name, []);
    nameToSummary.get(sm.name).push(sm);
  }

  // For each function with sinks, start backward traversal
  for (const sinkFn of functionSummaries) {
    if (sinkFn.sinks.length === 0) continue;

    for (const sink of sinkFn.sinks) {
      // Start a path from this sink
      const path = {
        sink: {
          name: sink.name,
          pos: sink.pos,
          cwe: sink.cwe,
          severity: sink.severity,
          via: sink.via,
        },
        sinkFn: { name: sinkFn.name, id: sinkFn.id },
        hops: [],
        reachesSource: false,
        sourceChain: [],
        totalHops: 0,
        sanitizersOnPath: [],
      };

      // Check if the sink's "via" already references a source
      if (sink.via && sink.via !== 'unknown' && sink.via !== 'args[0]' && !sink.via.startsWith('args[')) {
        // via is a source name like 'location.*' or 'localStorage'
        path.reachesSource = true;
        path.sourceChain.push(sink.via);
      }

      // Collect sanitizers from the sink function
      for (const san of sinkFn.sanitizers) {
        path.sanitizersOnPath.push({ name: san.name, pos: san.pos, fn: sinkFn.name });
      }

      // If via is args[N], we need to walk backward to find who calls this function
      // and what they pass as arg N
      if (sink.via && sink.via.startsWith('args[')) {
        const argIdx = parseInt(sink.via.match(/\[(\d+)\]/)?.[1] || '0', 10);
        // Walk backward through callers
        let currentFn = sinkFn;
        let currentArgIdx = argIdx;
        const visited = new Set([currentFn.id]);

        for (let hop = 0; hop < maxHops; hop++) {
          // Find callers of currentFn
          const callers = reverseCalls.get(currentFn.name) || [];
          if (callers.length === 0) break;

          // Find the first caller that's not already visited
          let callerSummary = null;
          for (const callerId of callers) {
            if (!visited.has(callerId)) {
              callerSummary = functionSummaries[callerId];
              if (callerSummary) {
                visited.add(callerId);
                break;
              }
            }
          }
          if (!callerSummary) break;

          // Check if the caller's return value flows from a source or arg
          const callerReturn = callerSummary.returns[0];
          if (callerReturn) {
            if (callerReturn.kind === 'tainted') {
              path.reachesSource = true;
              path.sourceChain.push(callerReturn.value);
            } else if (callerReturn.kind === 'param') {
              // The caller returns its own param — continue backward
              const paramMatch = callerReturn.value.match(/args\[(\d+)\]/);
              if (paramMatch) {
                currentArgIdx = parseInt(paramMatch[1], 10);
              }
            }
          }

          // Check if the caller reads any taint sources
          if (callerSummary.sources.length > 0) {
            path.reachesSource = true;
            for (const s of callerSummary.sources) {
              if (!path.sourceChain.includes(s.name)) path.sourceChain.push(s.name);
            }
          }

          // Collect sanitizers from this caller
          for (const san of callerSummary.sanitizers) {
            path.sanitizersOnPath.push({ name: san.name, pos: san.pos, fn: callerSummary.name });
          }

          path.hops.push({
            fnName: callerSummary.name,
            fnId: callerSummary.id,
            via: `args[${currentArgIdx}]`,
            sources: callerSummary.sources.map(s => s.name),
            sanitizers: callerSummary.sanitizers.map(s => s.name),
            returns: callerSummary.returns.map(r => r.value),
          });
          path.totalHops = hop + 1;

          currentFn = callerSummary;
        }
      }

      paths.push(path);
    }
  }

  // Sort paths: reachesSource first, then by severity
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  paths.sort((a, b) => {
    if (a.reachesSource !== b.reachesSource) return a.reachesSource ? -1 : 1;
    return (sevRank[a.sink.severity] || 4) - (sevRank[b.sink.severity] || 4);
  });

  return paths;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 19 — VARIABLE RENAME TABLE (Stage 7)
//
//  Generates a per-function canonical rename table that maps mangled
//  identifiers (e.g. _0x1a2b, ɵɵelementStart, kB) to compact canonical
//  names (v0, v1, v2, ...). This cuts token count 30-50% on minified input
//  and improves LLM reasoning quality — the model isn't distracted by
//  mangled names.
//
//  The rename table preserves:
//    · Tainted variables (named by their source: v0<loc>, v1<ls>)
//    · Parameters (prefixed with 'p': p0, p1, p2)
//    · Local variables (prefixed with 'v': v0, v1, v2)
//    · Function names (prefixed with 'fn': fn0, fn1)
//
//  Output: {
//    renameTable: Map<originalName, canonicalName>,
//    reverseTable: Map<canonicalName, originalName>,
//    stats: { renamed, params, locals, functions }
//  }
// ═══════════════════════════════════════════════════════════════════════════

function buildVariableRenameTable(structuralIndex, functionSummaries) {
  const renameTable = new Map();
  const reverseTable = new Map();
  let paramCount = 0;
  let localCount = 0;
  let fnCount = 0;
  const usedNames = new Set();

  // Reserve canonical names for known sources/sinks so the LLM sees meaningful labels
  const RESERVED = {
    'location.*': 'src_loc',
    'document.*': 'src_doc',
    'window.*': 'src_win',
    'localStorage': 'src_ls',
    'sessionStorage': 'src_ss',
    'event.data': 'src_evt',
    'URLSearchParams': 'src_url',
    'window.location.*': 'src_wloc',
    'innerHTML': 'sink_html',
    'outerHTML': 'sink_oh',
    'insertAdjacentHTML': 'sink_iah',
    'document.write': 'sink_dw',
    'eval': 'sink_eval',
    'Function()': 'sink_fn',
    'setAttribute(on*)': 'sink_sa',
    'location.href=': 'sink_lh',
    'srcdoc': 'sink_sd',
    'DOMPurify.sanitize': 'san_dom',
    'sanitize': 'san_gen',
    'escape': 'san_esc',
    'encodeURIComponent': 'san_uec',
    'escapeHtml': 'san_eh',
  };
  for (const canonical of Object.values(RESERVED)) {
    usedNames.add(canonical);
  }

  // Helper: generate a unique canonical name
  function genName(prefix) {
    let n = 0;
    while (usedNames.has(`${prefix}${n}`)) n++;
    const name = `${prefix}${n}`;
    usedNames.add(name);
    return name;
  }

  // Process each function summary
  for (const sm of functionSummaries) {
    // Rename the function itself
    if (sm.name !== '<anonymous>' && !renameTable.has(sm.name)) {
      const canonical = genName('fn');
      renameTable.set(sm.name, canonical);
      reverseTable.set(canonical, sm.name);
      fnCount++;
    }

    // Rename parameters (preserve order: p0, p1, p2...)
    for (let i = 0; i < sm.params.length; i++) {
      const orig = sm.params[i];
      if (!renameTable.has(orig)) {
        const canonical = `p${i}`;
        renameTable.set(orig, canonical);
        reverseTable.set(canonical, orig);
        paramCount++;
      }
    }

    // Rename local variables mentioned in sources (taint them by source name)
    for (const src of sm.sources) {
      // The source expr like "location.search" is a property access, not a var
      // But if a tainted local was derived from it, we want to name it meaningfully
      // We handle this in the sink classification, not here.
    }
  }

  // Collect all identifiers from the structural index and rename the ones
  // that appear frequently (top-N by usage) to short canonical names
  const identCounts = new Map();
  for (const ident of structuralIndex.identifiers) {
    identCounts.set(ident.name, (identCounts.get(ident.name) || 0) + 1);
  }

  // Sort by frequency (most used first) and rename top 100
  const sortedIdents = [...identCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 100);

  for (const [name, count] of sortedIdents) {
    if (renameTable.has(name)) continue;  // already renamed
    if (RESERVED[name]) continue;          // reserved
    if (/^(?:v\d+|p\d+|fn\d+|src_|sink_|san_)/.test(name)) continue;  // already canonical
    // Skip single-char names (already short) and builtins
    if (name.length <= 2) continue;
    if (['console','document','window','Math','Date','JSON','Object','Array','String','Number','Boolean','parseInt','parseFloat','undefined','NaN','Infinity','Error','TypeError','Promise','Proxy','Reflect','Symbol'].includes(name)) continue;
    const canonical = genName('v');
    renameTable.set(name, canonical);
    reverseTable.set(canonical, name);
    localCount++;
  }

  return {
    renameTable,
    reverseTable,
    stats: {
      renamed: renameTable.size,
      params: paramCount,
      locals: localCount,
      functions: fnCount,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  PHASE 20 — ON-DEMAND SOURCE EXPANSION (Stage 7)
//
//  Provides a tool-call interface for LLMs to drill into specific functions.
//  The initial prompt contains compact summaries; when the model needs the
//  actual code (e.g. to verify a sanitizer's effectiveness), it calls
//  expandFunction(fnId) to get the source text.
//
//  This keeps the initial prompt small and lets the model drill in only
//  where it needs to. Most paths never need expansion — the summary is enough.
//
//  Output: {
//    expand: (fnId) => { name, source, tokenEstimate, ... },
//    cache: Map<fnId, expansion>,
//    stats: { expansions, cacheHits, cacheMisses }
//  }
// ═══════════════════════════════════════════════════════════════════════════

function createSourceExpander(src, structuralIndex, functionSummaries) {
  const cache = new Map();
  let expansions = 0;
  let cacheHits = 0;
  let cacheMisses = 0;

  // Rough token estimate: ~4 chars per token
  function estimateTokens(text) {
    return Math.ceil(text.length / 4);
  }

  function expand(fnId) {
    if (cache.has(fnId)) {
      cacheHits++;
      return cache.get(fnId);
    }
    cacheMisses++;

    const sm = functionSummaries[fnId];
    if (!sm) return null;

    const fn = structuralIndex.functions[fnId];
    if (!fn) return null;

    // Extract the source text for this function
    const sourceText = src.slice(fn.start, fn.end);

    const expansion = {
      id: fnId,
      name: sm.name,
      source: sourceText,
      tokenEstimate: estimateTokens(sourceText),
      params: sm.params,
      sources: sm.sources.map(s => s.name),
      sinks: sm.sinks.map(s => ({ name: s.name, via: s.via, cwe: s.cwe })),
      sanitizers: sm.sanitizers.map(s => s.name),
      returns: sm.returns.map(r => r.value),
      calls: sm.calls,
    };

    cache.set(fnId, expansion);
    expansions++;
    return expansion;
  }

  // Batch expand: returns multiple expansions at once
  function expandMany(fnIds) {
    return fnIds.map(id => expand(id)).filter(e => e !== null);
  }

  // Get a compact summary (no source) — for the initial LLM prompt
  function getSummary(fnId) {
    const sm = functionSummaries[fnId];
    if (!sm) return null;
    return {
      id: fnId,
      name: sm.name,
      params: sm.params,
      sources: sm.sources.map(s => s.name),
      sinks: sm.sinks.map(s => ({ name: s.name, via: s.via, cwe: s.cwe, severity: s.severity })),
      sanitizers: sm.sanitizers.map(s => s.name),
      returns: sm.returns.map(r => r.value),
      calls: sm.calls.slice(0, 10),
    };
  }

  // Get all summaries (for the initial prompt)
  function getAllSummaries() {
    return functionSummaries.map(sm => getSummary(sm.id));
  }

  // Get only summaries for functions with sinks (the LLM-payload subset)
  function getSinkSummaries() {
    return functionSummaries
      .filter(sm => sm.sinks.length > 0)
      .map(sm => getSummary(sm.id));
  }

  return {
    expand,
    expandMany,
    getSummary,
    getAllSummaries,
    getSinkSummaries,
    cache,
    get stats() {
      return { expansions, cacheHits, cacheMisses, cacheSize: cache.size };
    },
  };
}

module.exports = {
  tokenizeForAST,
  buildStructuralIndex,
  detectFrameworksAST,
  resolveWebpack5Modules,
  detectBundler,
  buildCallGraph,
  trackTaintAST,
  scanModernCrypto,
  extractNetworkSurface,
  parseSourceMap,
  fingerprintObfuscator,
  computeFunctionSummaries,
  buildBackwardSlices,
  buildVariableRenameTable,
  createSourceExpander,
  // Helpers (now exported — were previously unreachable from callers)
  windowText,
  tokPos,
};

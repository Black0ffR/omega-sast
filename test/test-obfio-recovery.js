#!/usr/bin/env node
/**
 * OMEGA-5.1 Residual 4 — LLM hint / fingerprint metadata consistency
 *
 * obfuscatorFingerprint.llmHints can report expectStringArrayIndirection /
 * expectControlFlowFlattening as false even when Phase 2c (string-array
 * rotation) and Phase 2c.2 (CFF de-flattening) actually ran. After the fix,
 * main() syncs the hints with decoder evidence and lists the passes actually
 * used in recommendedDecoderPasses.
 *
 * Run:  node test/test-obfio-recovery.js
 * Or:   npm test   (auto-discovered by run-all.js)
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const ROOT  = path.resolve(__dirname, '..');
const OMEGA = path.join(ROOT, 'bin', 'omega.js');
const SAMPLES = path.join(ROOT, 'obfuscated-zip-test', 'obfuscated_js_samples');

// ── Tiny test framework (matches existing test harness style) ─────────────
let total = 0, passed = 0, failed = 0;
const failures = [];

function assert(name, cond, detail) {
  total++;
  if (cond) {
    passed++;
    console.log(`  ✔ ${name}`);
  } else {
    failed++;
    failures.push({ name, detail });
    console.log(`  ✘ ${name}`);
    if (detail !== undefined) {
      const s = typeof detail === 'string' ? detail : JSON.stringify(detail);
      console.log(`      → ${s.slice(0, 300)}`);
    }
  }
}

function section(name) {
  console.log(`\n── ${name} ──────────────────────────────`);
}

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omega-obfio-'));
}

function runOmega(args, opts = {}) {
  return spawnSync(process.execPath, [OMEGA, ...args], {
    encoding: 'utf8',
    timeout: 120000,
    stdio: 'pipe',
    maxBuffer: 32 * 1024 * 1024,
    ...opts,
  });
}

function scanSample(name) {
  const out = mkTmpDir();
  runOmega([path.join(SAMPLES, name), '--security', '--report', '--quiet', '--out', out]);
  const p = path.join(out, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

function scanTmpFixture(src) {
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'input.js'), src);
  const out = mkTmpDir();
  runOmega([path.join(dir, 'input.js'), '--security', '--report', '--quiet', '--out', out]);
  const p = path.join(out, 'report.json');
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { return { _parseError: String(e) }; }
}

// ═════════════════════════════════════════════════════════════════════════
section('1. obfuscator.io sample: hints match decoder evidence');
{
  const r = scanSample('06_obfuscator_io_style.js');
  assert('06 sample: report produced', !!r && !r._parseError, r && r._parseError);
  assert('06 sample: decoder ran (decodeStats.obfuscatorIo >= 12)',
    r && r.decodeStats && r.decodeStats.obfuscatorIo >= 12,
    `obfuscatorIo=${r && r.decodeStats && r.decodeStats.obfuscatorIo}`);
  const fp = r && r.obfuscatorFingerprint;
  assert('06 sample: fingerprint present', !!fp);
  assert('06 sample: expectStringArrayIndirection === true when decoder ran',
    fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection === true,
    `hint=${fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection}`);
  assert('06 sample: recommendedDecoderPasses includes string-array-rotation',
    fp && fp.llmHints && Array.isArray(fp.llmHints.recommendedDecoderPasses) &&
      fp.llmHints.recommendedDecoderPasses.includes('string-array-rotation'),
    `passes=${fp && fp.llmHints && JSON.stringify(fp.llmHints.recommendedDecoderPasses)}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('2. CFF sample: control-flow-flattening hint set');
{
  const r = scanSample('10_control_flow_flattening.js');
  assert('10 sample: report produced', !!r && !r._parseError, r && r._parseError);
  const fp = r && r.obfuscatorFingerprint;
  assert('10 sample: fingerprint present', !!fp);
  assert('10 sample: expectControlFlowFlattening === true when CFF deflattener ran',
    fp && fp.llmHints && fp.llmHints.expectControlFlowFlattening === true,
    `hint=${fp && fp.llmHints && fp.llmHints.expectControlFlowFlattening}`);
  assert('10 sample: recommendedDecoderPasses includes control-flow-flattening',
    fp && fp.llmHints && Array.isArray(fp.llmHints.recommendedDecoderPasses) &&
      fp.llmHints.recommendedDecoderPasses.includes('control-flow-flattening'),
    `passes=${fp && fp.llmHints && JSON.stringify(fp.llmHints.recommendedDecoderPasses)}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('3. Clean sample: hints stay false (no unconditional flag-setting)');
{
  const r = scanTmpFixture('var x = 1; function add(a,b){ return a+b; }');
  assert('clean fixture: report produced', !!r && !r._parseError, r && r._parseError);
  const fp = r && r.obfuscatorFingerprint;
  assert('clean fixture: fingerprint present', !!fp);
  assert('clean fixture: expectStringArrayIndirection stays false',
    fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection === false,
    `hint=${fp && fp.llmHints && fp.llmHints.expectStringArrayIndirection}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('4. obfuscator.io sample: decoder evidence boosts confidence');
{
  const r = scanSample('06_obfuscator_io_style.js');
  assert('06 sample: report produced', !!r && !r._parseError, r && r._parseError);
  const primary = r && r.obfuscatorFingerprint && r.obfuscatorFingerprint.primary;
  assert('06 sample: primary is obfuscator.io', primary && primary.obfuscator === 'obfuscator.io');
  assert('06 sample: confidence >= 0.5 when 10+ strings inlined',
    primary && typeof primary.confidence === 'number' && primary.confidence >= 0.5,
    `confidence=${primary && primary.confidence}`);
  // Item A (analysis FINAL §6.2): the fingerprint finding text/severity are
  // built from the static signature confidence — a post-hoc decoder boost
  // must be mirrored into the finding, or the report shows "35%" while
  // primary.confidence is 0.6.
  const fpFinding = (r && r.extendedFindings || []).find(f => f.id === 'obfuscator-obfuscator-io');
  assert('06 sample: fingerprint finding present in extendedFindings', !!fpFinding,
    `extendedFindings=${(r && r.extendedFindings || []).map(f => f.id).join(',')}`);
  assert('06 sample: fingerprint finding value reflects boosted confidence (contains "60%")',
    fpFinding && typeof fpFinding.value === 'string' && fpFinding.value.includes('60%'),
    `value=${fpFinding && fpFinding.value}`);
  assert('06 sample: fingerprint finding severity is medium (0.6 → medium threshold)',
    fpFinding && fpFinding.severity === 'medium',
    `severity=${fpFinding && fpFinding.severity}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('5. post-decode second security pass contract');
{
  const r = scanSample('06_obfuscator_io_style.js');
  assert('06 sample: report produced', !!r && !r._parseError, r && r._parseError);
  const sp = r && r.decodeStats && r.decodeStats.secondPass;
  assert('06 sample: decodeStats.secondPass.ran === true (hook ran)',
    sp && sp.ran === true, `secondPass=${JSON.stringify(sp)}`);
  assert('06 sample: decodeStats.secondPass.merged is a number',
    sp && typeof sp.merged === 'number', `merged=${sp && sp.merged}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('6. decoder-driven XSS surfaces (string-array hides innerHTML sink)');
{
  // Minimal self-reassigning decoder shape (mirrors 06 sample). The sink
  // document.body[...]=location.hash only becomes XSS once D() is inlined
  // by Phase 2c — regression-guards the decoder→security-finding path.
  // NOTE: opaque-gated constant mutations (`_0xarr[1]=_0xop?'innerHTML':
  // 'textContent'`) are now folded by Step 4m (may-set semantics) — see
  // section 8. The deterministic hook contract is decodeStats.secondPass
  // (section 5); this fixture asserts the surface path the hook exists to
  // re-verify.
  const src = [
    "var _0x9947=['a','innerHTML','c'];",
    'function _0x33e4(_0x1809b5,_0x37ef6e){',
    'return _0x33e4=function(_0x338a69,_0x39ad79){',
    '_0x338a69=_0x338a69-(0x1939+-0xf*0x1f3+0x1*0x469);',
    'var _0x2b223=_0x9947[_0x338a69];',
    'return _0x2b223;',
    '}(_0x1809b5,_0x37ef6e);',
    '}',
    "document.body[_0x33e4(0x66)]=location.hash;",
  ].join('\n');
  const r = scanTmpFixture(src);
  assert('fixture: report produced', !!r && !r._parseError, r && r._parseError);
  const all = [
    ...(r && r.security ? r.security : []),
    ...(r && r.extendedFindings ? r.extendedFindings : []),
  ];
  const xss = all.filter(f => /xss|innerhtml/i.test(f.id || ''));
  assert('fixture: XSS finding surfaces (innerHTML sink via string array)',
    xss.length > 0,
    `findings=${all.map(f => f.id).join(',')}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('7. chained string arrays resolve via fixpoint (analysis FINAL §6.1)');
{
  // Layer 2: _0xb's literal references _0xa[2] — not string-only, so Step 1
  // skips it and nothing decodes. After the fixpoint, round 1 resolves
  // _0xa[2] -> 'innerHTML' inside the literal, round 2 decodes D(0x66) → 1
  // → 'innerHTML', and the XSS surfaces.
  const src = [
    "var _0xa=['hello','world','innerHTML'];",
    "var _0xb=['x',_0xa[2],'y','z'];",
    'function D(_0x3b3a,_0x37ef6e){',
    'return D=function(_0x338a69,_0x39ad79){',
    '_0x338a69=_0x338a69-(0x1939+-0xf*0x1f3+0x1*0x469);',
    'var _0x2b223=_0xb[_0x338a69];',
    'return _0x2b223;',
    '}(_0x3b3a,_0x37ef6e);',
    '}',
    "document.body[D(0x66)]=location.hash;",
  ].join('\n');
  const r = scanTmpFixture(src);
  assert('chained fixture: report produced', !!r && !r._parseError, r && r._parseError);
  assert('chained fixture: decoder decoded strings (round 2 fired)',
    r && r.decodeStats && r.decodeStats.obfuscatorIo >= 1,
    `obfuscatorIo=${r && r.decodeStats && r.decodeStats.obfuscatorIo}`);
  const all = [
    ...(r && r.security ? r.security : []),
    ...(r && r.extendedFindings ? r.extendedFindings : []),
  ];
  const xss = all.filter(f => /xss|innerhtml/i.test(f.id || ''));
  assert('chained fixture: XSS surfaces via chained string-array sink',
    xss.length > 0,
    `findings=${all.map(f => f.id).join(',')}`);
}

// ═════════════════════════════════════════════════════════════════════════
section('8. constant array mutations applied (analysis FINAL §6.1, closes known-work 2b)');
{
  // Opaque-gated mutation shape (Task 4 §6 documented limitation): the slot
  // is rewritten under an opaque predicate, so a naive decoder resolves the
  // pre-mutation value. The mutation scanner treats `L ? 'a' : 'b'` as a
  // may-set {a, b} (predicate never evaluated) and the inliner emits the
  // first candidate — 'innerHTML' here — which surfaces the XSS.
  const opaqueSrc = [
    "var _0x9947=['a','b','c'];",
    'var _0xop = !![];',
    "_0x9947[1]=_0xop?'innerHTML':'textContent';",
    'function _0x33e4(_0x1809b5,_0x37ef6e){',
    'return _0x33e4=function(_0x338a69,_0x39ad79){',
    '_0x338a69=_0x338a69-(0x1939+-0xf*0x1f3+0x1*0x469);',
    'var _0x2b223=_0x9947[_0x338a69];',
    'return _0x2b223;',
    '}(_0x1809b5,_0x37ef6e);',
    '}',
    "document.body[_0x33e4(0x66)]=location.hash;",
  ].join('\n');
  const r1 = scanTmpFixture(opaqueSrc);
  assert('mutation fixture: report produced', !!r1 && !r1._parseError, r1 && r1._parseError);
  assert('mutation fixture: decoder decoded strings',
    r1 && r1.decodeStats && r1.decodeStats.obfuscatorIo >= 1,
    `obfuscatorIo=${r1 && r1.decodeStats && r1.decodeStats.obfuscatorIo}`);
  let all = [
    ...(r1 && r1.security ? r1.security : []),
    ...(r1 && r1.extendedFindings ? r1.extendedFindings : []),
  ];
  assert('mutation fixture: XSS surfaces (opaque-gated ternary resolved as may-set)',
    all.some(f => /xss|innerhtml/i.test(f.id || '')),
    `findings=${all.map(f => f.id).join(',')}`);
  assert('mutation fixture: may-set documented in an obfuscator-io-mutation finding',
    all.some(f => f.id === 'obfuscator-io-mutation'),
    `findings=${all.map(f => f.id).join(',')}`);

  // Single-literal mutation: unconditional overwrite.
  const literalSrc = [
    "var _0x9947=['a','b','c'];",
    "_0x9947[1]='innerHTML';",
    'function _0x33e4(_0x1809b5,_0x37ef6e){',
    'return _0x33e4=function(_0x338a69,_0x39ad79){',
    '_0x338a69=_0x338a69-(0x1939+-0xf*0x1f3+0x1*0x469);',
    'var _0x2b223=_0x9947[_0x338a69];',
    'return _0x2b223;',
    '}(_0x1809b5,_0x37ef6e);',
    '}',
    "document.body[_0x33e4(0x66)]=location.hash;",
  ].join('\n');
  const r2 = scanTmpFixture(literalSrc);
  assert('literal-mutation fixture: report produced', !!r2 && !r2._parseError, r2 && r2._parseError);
  all = [
    ...(r2 && r2.security ? r2.security : []),
    ...(r2 && r2.extendedFindings ? r2.extendedFindings : []),
  ];
  assert('literal-mutation fixture: XSS surfaces (constant assignment applied)',
    all.some(f => /xss|innerhtml/i.test(f.id || '')),
    `findings=${all.map(f => f.id).join(',')}`);
}

// ── Summary ───────────────────────────────────────────────────────────────
console.log(`\n  TOTAL: ${total}   PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) {
  console.log('  FAILURES:');
  failures.forEach(f => console.log(`    - ${f.name}`));
}
process.exit(failed > 0 ? 1 : 0);

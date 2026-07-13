const { scanReDoS } = require('../src/_monolith');

let pass = 0, fail = 0;
function assert(desc, ok) {
  if (ok) { console.log(`  ✔ ${desc}`); pass++; }
  else { console.log(`  ✘ ${desc}`); fail++; }
}

(function testNestedQuantifier() {
  const findings = scanReDoS('var re = /(.+)+/;');
  assert('Nested quantifier (.+)+ detected', findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testNestedQuantifierStar() {
  const findings = scanReDoS('var re = /(\\d+)*/;');
  assert('Nested quantifier (\\d+)* detected', findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testOverlappingAlternation() {
  const findings = scanReDoS('var re = /(a|a)+/;');
  assert('Overlapping alternation (a|a)+ detected', findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testBackreference() {
  const findings = scanReDoS('var re = /(.*)\\1/;');
  assert('Backreference (.*)\\1 detected', findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testSafeLiteral() {
  const findings = scanReDoS('var re = /hello/;');
  assert('Safe literal /hello/ not flagged', !findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testNewRegExpForm() {
  const findings = scanReDoS('var re = new RegExp("(.+)+");');
  assert('new RegExp("(.+)+") constructor form detected', findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testSafeNewRegExp() {
  const findings = scanReDoS('var re = new RegExp("\\\\d+");');
  assert('Safe new RegExp("\\\\d+") not flagged', !findings.some(f => f.id === 'redos-vulnerable'));
})();

(function testCommonPrefixAlternation() {
  const findings = scanReDoS('var re = /(a|ab)+/;');
  assert('Common prefix alternation (a|ab)+ detected', findings.some(f => f.id === 'redos-vulnerable'));
})();

console.log(`\nReDoS detector tests: PASSED: ${pass}  FAILED: ${fail}`);
process.exit(fail > 0 ? 1 : 0);

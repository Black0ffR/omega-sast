
// obf1: string array rotation + RC4-like base64 decoder
(function(_0xabc, _0xdef) {
  const _0x123 = ['SGVsbG8gV29ybGQ=', 'ZXZhbChfX3VzZXJfX2lucHV0KQ==', 'bG9jYXRpb24uaGFzaA=='];
  const _0x456 = function(_0x789) {
    _0x789 = _0x789 - 0x0;
    let _0x4bc = _0x123[_0x789];
    if (_0x4bc === undefined) return;
    return atob(_0x4bc);
  };
  function _0x5de(_0xinput) { return _0x456(0x1) + _0xinput; }
  function _0x6fe() { return _0x456(0x2); }
  function _0x7be() { var x = _0x6fe(); return eval(x); }
  function _0x8ce() { return _0x456(0x0); }
  // hex identifiers, control flow
  while (true) { var _0xa1 = 0x1; if (_0xa1 > 0) break; }
})();

// obf2: dead-code + string concat
function _0xdead(_0xbeef) {
  var _0xcafe = "use strict";
  return _0xbeef.split('').reverse().join('');
}

// obf3: atob+charCode
function _0xfoo() {
  var s = atob("dGhpcyBpcyBub3QgZXZpbA==");
  return String.fromCharCode(72, 101, 108, 108, 111);
}

// obf4: indirect eval
var _0xee = "setTimeout";
window[_0xee]("\x65\x76\x61\x6c(...)", 0);

// obf5: typeof / control flow flattening pattern
function _0xff(_0x10) {
  switch (_0x10) {
    case 0: return 'a';
    case 1: return 'b';
    case 2: return 'c';
    default: return 'd';
  }
}
module.exports = { _0x5de: _0x5de, _0x7be: _0x7be, _0xdead: _0xdead, _0xfoo: _0xfoo, _0xff: _0xff };

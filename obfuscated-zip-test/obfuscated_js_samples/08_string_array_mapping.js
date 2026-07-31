// String array extraction / mapping pattern
// Very common in obfuscator.io and similar tools

var _0x8b75 = ["Hello, world! ", "log"];
console[_0x8b75[1]](_0x8b75[0] + 123);

// Slightly more realistic variant with offset:
var _0x4e2a = [
  'innerHTML',
  'https://api.example.com',
  'Authorization',
  'Bearer ',
  'POST'
];
function _0x1a2b(_0xidx) {
  return _0x4e2a[_0xidx];
}
// Usage would look like: fetch(_0x1a2b(0x1), {method: _0x1a2b(0x4), ...})

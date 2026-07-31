# Diverse Obfuscated & Bundled JavaScript Samples

This collection contains representative examples of common JavaScript obfuscation and bundling/minification techniques. Each file is a self-contained sample (most are executable in a browser console or Node.js where applicable).

**Original source used for most samples** (simple alert / console example):

```js
// alert("Hello, JavaScript");
// or
console.log("Hello, World!");
// or small functions for illustration
```

## Samples Included

| File | Technique / Tool | Description |
|------|------------------|-------------|
| `01_original.js` | Plain source | Readable baseline code |
| `02_jsfuck.js` | JSFuck | Esoteric encoding using only `[]()!+` |
| `03_aaencode.js` | AAEncode | Japanese-style emoticon / kaomoji encoding |
| `04_jjencode.js` | JJEncode | Symbol-based encoding (`[]()!+,"$.:;_{}~=`) |
| `05_packer_dean_edwards.js` | Dean Edwards Packer | Classic eval + base62 / dictionary packer |
| `06_obfuscator_io_style.js` | javascript-obfuscator / obfuscator.io | String array + rotation + control-flow flattening + hex identifiers |
| `07_hex_unicode_strings.js` | Hex / Unicode string encoding | Simple character escapes |
| `08_string_array_mapping.js` | String array extraction | Common pattern used by many obfuscators |
| `09_minified_terser_style.js` | Minification (Terser/Uglify-like) | Compressed identifiers + whitespace removal |
| `10_control_flow_flattening.js` | Control-flow flattening | Switch-based flattened control flow (obfuscator.io style) |
| `11_dead_code_injection.js` | Dead code + opaque predicates | Injected unreachable / dummy code |
| `12_webpack_like_bundle.js` | Bundled / Webpack-style | Module wrapper + minified bundle appearance |

## Notes

- These are **educational samples** derived from publicly documented examples of the techniques.
- JSFuck, AAEncode, and JJEncode produce very large output relative to input.
- Real-world malware and protected web apps often combine several of these layers.
- Tools that produce similar output: obfuscator.io, javascript-obfuscator, JScrambler, Stunnix, Free JS Obfuscator, Packer, etc.

## How to use

```bash
# Inspect
cat 02_jsfuck.js

# Run (browser console or Node where safe)
node 01_original.js
# Note: many samples use `alert` or browser globals; adapt as needed.
```

Created for research, deobfuscation practice, and reverse-engineering training.
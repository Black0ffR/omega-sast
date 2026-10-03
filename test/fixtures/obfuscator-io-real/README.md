# Real obfuscator.io corpus (ground truth)

Generated with the **real** engine, not hand-written approximations:

```
npm install javascript-obfuscator@5.8.1
JavaScriptObfuscator.obfuscate(input, opts).getObfuscatedCode()
```

| file | config |
|---|---|
| `00-original-plain.js` | unobfuscated source — the ground truth for assertions |
| `01-plain` … `15-vm` | string-array matrix: plain / base64 / **rc4** / mixed / shuffle / wrappers(fn,var) / CFF / mangled / compact / callsTransform / splitStrings / vm |
| `11-rc4-full` | selfDefending + debugProtection + CFF(0.75) + wrappers(5) + rc4 |

These exist because the RC4 decode path was previously validated **only** against
a synthetic fixture. See `AGENTS.md` known-work #1, now closed.

**Known limitation, measured not assumed:** with `selfDefending` +
`debugProtection` the string-array rotation offset is sometimes resolved
incorrectly, and the decoder emits **wrong** strings (correct-looking, but not
what the original said) for roughly half of seeds. `11-rc4-full` shows it. The
recovered strings are not garbage — they are plausible and wrong, which is
worse for an analyst. Tracked as known-work #12.

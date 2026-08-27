#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const nd = process.argv[2];
const out = process.argv[3] || 'js-from-ndjson';
if (!nd) {
  console.error('Usage: node ndjson-to-js.js <file.ndjson> [outDir]');
  process.exit(1);
}
fs.mkdirSync(out, { recursive: true });
let n = 0;
for (const line of fs.readFileSync(nd, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  let o;
  try { o = JSON.parse(line); } catch { continue; }
  if (!o.content) continue;
  const base = String(o.url || 'script')
    .replace(/^https?:\/\//, '')
    .replace(/[?#].*$/, '')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .slice(-120);
  const file = path.join(out, `${String(n).padStart(3, '0')}_${base}.js`);
  fs.writeFileSync(file, o.content);
  console.log(file, o.url);
  n++;
}
console.log('OK', n, 'scripts →', out);

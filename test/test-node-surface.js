#!/usr/bin/env node
'use strict';

/**
 * test-node-surface.js
 *
 * Tests for lib/node-surface.js — Phase 12t Node/Electron surface scanner,
 * plus the proto-jsonparse precision fix and the finding-metadata patch.
 *
 * Run standalone: node test/test-node-surface.js
 */

const { scanNodeSurface, detectNodeSurface, extractBraced, hasShapeGuard } = require('../lib/node-surface');
const { ast } = require('../lib');

let pass = 0, fail = 0;
const failures = [];

function ok(name, cond, extra) {
  if (cond) { pass++; }
  else { fail++; failures.push(name + (extra ? `  — ${extra}` : '')); }
}

function ids(findings) { return findings.map(f => f.id); }
function byId(findings, id) { return findings.find(f => f.id === id); }
function count(findings, id) { return findings.filter(f => f.id === id).length; }

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n── Node/Electron detection ──');

{
  const clean = detectNodeSurface(`console.log("hi"); var x = location.search;`);
  ok('browser bundle is not detected as Node', clean.node === false, `node=${clean.node}`);
  ok('browser bundle is not detected as Electron', clean.electron === false, `electron=${clean.electron}`);

  const node = detectNodeSurface(`const fs = require("fs"); process.exit(1);`);
  ok('require("fs") marks node', node.node === true);

  const el = detectNodeSurface(`const { BrowserWindow } = require("electron");`);
  ok('require("electron") marks electron', el.electron === true);
  ok('electron implies node surface', el.node === true || el.electron === true);

  const ctxIso = detectNodeSurface(`new BrowserWindow({ webPreferences: { contextIsolation: true } })`);
  ok('BrowserWindow alone marks electron', ctxIso.electron === true);
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── Electron renderer privilege escalation ──');

{
  const src = `const w = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
      preload: __dirname + "/preload.js"
    }
  });`;
  const r = scanNodeSurface(src);
  const ni = byId(r.findings, 'electron-node-integration');
  const ci = byId(r.findings, 'electron-no-context-isolation');
  const ws = byId(r.findings, 'electron-no-web-security');

  ok('nodeIntegration:true detected', !!ni);
  ok('nodeIntegration is critical', ni && ni.severity === 'critical', ni && ni.severity);
  ok('nodeIntegration has confidence', ni && typeof ni.confidence === 'number');
  ok('nodeIntegration has remediation', ni && typeof ni.remediation === 'string' && ni.remediation.length > 10);
  ok('contextIsolation:false detected', !!ci);
  ok('contextIsolation:false is high', ci && ci.severity === 'high', ci && ci.severity);
  ok('webSecurity:false detected', !!ws);
  ok('webSecurity:false is critical', ws && ws.severity === 'critical', ws && ws.severity);
  ok('electron findings carry disambiguation', ni && typeof ni.disambiguation === 'string');
}

{
  // The safe default must NOT fire.
  const src = `new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } })`;
  const r = scanNodeSurface(src);
  ok('safe electron defaults do not fire', ids(r.findings).filter(i => i.startsWith('electron-')).length === 0,
     ids(r.findings).join(','));
}

{
  const src = `const { app } = require("electron");
              app.on("ready", () => { /* no prefs */ });`;
  const r = scanNodeSurface(src);
  ok('no BrowserWindow prefs → no electron-config findings',
     count(r.findings, 'electron-node-integration') === 0);
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── IPC handler → sensitive sink ──');

{
  const src = `const { ipcMain } = require('electron');
ipcMain.handle('read-config', async (event, filePath) => {
  return fs.readFileSync(filePath, 'utf8');
});`;
  const r = scanNodeSurface(src);
  const f = byId(r.findings, 'ipc-arg-sensitive-sink');
  ok('unvalidated IPC arg → fs read detected', !!f, JSON.stringify(ids(r.findings)));
  ok('IPC finding names the channel', f && /read-config/.test(f.value), f && f.value);
  ok('IPC finding names the renderer param', f && /filePath/.test(f.value), f && f.value);
}

{
  const src = `ipcMain.handle('run', (event, cmd) => {
  exec(cmd);
});`;
  const r = scanNodeSurface(src);
  const f = byId(r.findings, 'ipc-arg-sensitive-sink');
  ok('IPC arg → child_process.exec is critical', f && f.severity === 'critical', f && f.severity);
}

{
  // A handler that validates must NOT fire.
  const src = `ipcMain.handle('read', (event, filePath) => {
  if (typeof filePath !== 'string') throw new Error('bad');
  if (!ALLOWED.includes(filePath)) throw new Error('no');
  return fs.readFileSync(filePath, 'utf8');
});`;
  const r = scanNodeSurface(src);
  ok('validated IPC handler does not fire', count(r.findings, 'ipc-arg-sensitive-sink') === 0,
     JSON.stringify(ids(r.findings)));
}

{
  // Handler that does NOT use the renderer arg at the sink must not fire.
  const src = `ipcMain.handle('ping', (event, data) => {
  return { ok: true };
});`;
  const r = scanNodeSurface(src);
  ok('unused renderer arg does not fire', count(r.findings, 'ipc-arg-sensitive-sink') === 0);
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── jwt.verify algorithms allowlist ──');

{
  const src = `const decoded = jwt.verify(token, secret, { algorithms: ['RS256'] });`;
  const r = scanNodeSurface(src);
  ok('pinned algorithms does not fire', count(r.findings, 'jwt-verify-no-alg-pinning') === 0,
     JSON.stringify(ids(r.findings)));
}

{
  const src = `const decoded = jwt.verify(token, secret, { algorithms: ALLOWED });`;
  const r = scanNodeSurface(src);
  ok('identifer-valued algorithms does not fire', count(r.findings, 'jwt-verify-no-alg-pinning') === 0);
}

{
  const src = `const decoded = jwt.verify(token, secret);`;
  const r = scanNodeSurface(src);
  const f = byId(r.findings, 'jwt-verify-no-alg-pinning');
  ok('unpinned jwt.verify detected', !!f);
  ok('jwt finding is high', f && f.severity === 'high', f && f.severity);
  ok('jwt finding is CWE-347', f && /CWE-347/.test(f.cwe || ''), f && f.cwe);
  ok('absence rule records ctxWindow', f && !!f.ctxWindow && typeof f.ctxWindow.after === 'number',
     f && JSON.stringify(f.ctxWindow));
  ok('absence rule records what was searched', f && f.ctxWindow && typeof f.ctxWindow.searched === 'string');
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── Attacker-influenced dynamic RegExp ──');

{
  const src = `var re = new RegExp("^" + location.search + "$");`;
  const r = scanNodeSurface(src);
  const f = byId(r.findings, 'redos-dynamic-regex');
  ok('interpolated RegExp from input detected', !!f);
  ok('interpolated case is high', f && f.severity === 'high', f && f.severity);
  ok('interpolated case is CWE-1333', f && /CWE-1333/.test(f.cwe || ''));
  ok('has remediation', f && /escapeRegExp|includes/.test(f.remediation || ''));
}

{
  const src = `var re = new RegExp("^[a-z]+$");`;
  const r = scanNodeSurface(src);
  ok('constant RegExp does not fire', count(r.findings, 'redos-dynamic-regex') === 0);
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── Node sinks ──');

{
  const src = `const { exec } = require('child_process');
app.post('/run', (req, res) => { exec(req.body.cmd); });`;
  const r = scanNodeSurface(src);
  const f = r.findings.find(x => /child-process-exec/.test(x.id));
  ok('exec with req.body nearby is high', f && f.severity === 'high', f && f.severity);
  ok('exec finding is CWE-78', f && /CWE-78/.test(f.cwe || ''));
}

{
  const src = `const yaml = require('js-yaml');
const cfg = yaml.load(fileContents);`;
  const r = scanNodeSurface(src);
  const f = r.findings.find(x => /yaml-load/.test(x.id));
  ok('yaml.load detected', !!f);
  ok('yaml.load is CWE-502', f && /CWE-502/.test(f.cwe || ''));
  ok('yaml.load without input source is info', f && f.severity === 'info', f && f.severity);
}

{
  const src = `const vm = require('vm');
vm.runInNewContext(userCode, sandbox);`;
  const r = scanNodeSurface(src);
  const f = r.findings.find(x => /vm-sandbox/.test(x.id));
  ok('vm.runInNewContext detected', !!f);
  ok('vm finding is CWE-94', f && /CWE-94/.test(f.cwe || ''));
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── Gating: browser bundle gets NO server sources ──');

{
  const browserSrc = `fetch("/api/x").then(r=>r.text()).then(t=>{
    el.innerHTML = location.search + t;
  });`;
  const r = scanNodeSurface(browserSrc);
  ok('browser bundle exposes no node sources', Object.keys(r.nodeSources).length === 0,
     JSON.stringify(Object.keys(r.nodeSources)));
  ok('browser bundle produces no node-sink findings',
     r.findings.filter(f => /^node-sink-/.test(f.id)).length === 0);

  const nodeSrc = `const { ipcMain } = require('electron');
ipcMain.handle('x', (e, p) => { fs.readFileSync(p); });`;
  const r2 = scanNodeSurface(nodeSrc);
  ok('electron bundle DOES expose node sources', Object.keys(r2.nodeSources).length > 0);
  ok('node sources include req.body', !!r2.nodeSources['req.body']);
  ok('node sources include ipcRenderer.invoke', !!r2.nodeSources['ipcRenderer.invoke']);
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── Helpers ──');

{
  ok('extractBraced handles nested braces',
     extractBraced('a{b{c}d}e', 1).text === 'b{c}d');
  ok('extractBraced skips strings with braces',
     extractBraced('a{"}" }z', 1).text === '"}" ');
  ok('extractBraced skips comments with braces',
     extractBraced('a{ /* } */ }z', 1).text.replace(/\s/g,'') === '/*}*/');
  ok('extractBraced returns null on unterminated', extractBraced('a{b', 1) === null);
  ok('hasShapeGuard detects typeof guard', hasShapeGuard('if (typeof t === "object")'));
  ok('hasShapeGuard rejects bare code', !hasShapeGuard('const a = 1;'));
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── proto-jsonparse precision fix ──');

{
  // Load the real rule from the monolith and exercise its ctx guard.
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'src', '_monolith.js'), 'utf8');
  const m = src.match(/id:'proto-jsonparse'[\s\S]*?ctx:\s*m\s*=>\s*\{([\s\S]*?)\n    \} \}/);
  ok('proto-jsonparse rule is locatable in monolith', !!m);
}

{
  // The FP class: JSON.parse of a complex arg with NO pollution evidence.
  // React Router / sessionStorage / RSC patterns.
  const benign = [
    `let t = JSON.parse(ew?.getItem("tsr-scroll-restoration-v1_3")||"{}"); if ("object"==typeof t&&t) {}`,
    `let t = JSON.parse(e.slice(40)); if ("object"==typeof t&&t&&"number"==typeof t.status) {}`,
    `this.embeddedDataJSON = JSON.parse(this.#t); performance.mark("x")`,
    `let r = JSON.parse(atob(t.content)); r.referrer = new URL(e,o).href;`,
    `let r = JSON.parse(sessionStorage.getItem(e)||"{}")[t||k]; "number"==typeof r && window.h.replaceState({key:e},"")`,
  ];
  // NOTE: `JSON.parse(<bare-ident>)` is skipped BY DESIGN (unchanged from the
  // original rule) — a single-identifier parse in a minified bundle is
  // almost always benign deserialization. The PP risk is the *sink*, not the
  // parse, so these use non-identifier args and reach a pollution primitive.
  const malicious = [
    // downstream sink
    `let o = JSON.parse(req.body); o.__proto__.isAdmin = true;`,
    `let cfg = JSON.parse(msg.payload); Object.assign(Object.prototype, cfg);`,
    `let d = JSON.parse(evt.data); d.constructor.prototype.x = 1;`,
    // upstream sink — parse result is the ARGUMENT to a pollution primitive
    `let m = _.merge({}, JSON.parse(req.body));`,
    `Object.setPrototypeOf(JSON.parse(req.body), proto);`,
  ];
  // Use the full binary to get real findings rather than reimplementing ctx.
  //
  // NOTE: spawnSync, not execSync. execSync THROWS on a non-zero exit, and
  // omega deliberately exits 2/3/4/5 when it finds things — so execSync would
  // discard exactly the malicious cases we want to assert on, and the harness
  // would conflate "omega found a problem" with "omega failed to run".
  const { spawnSync } = require('child_process');
  const path = require('path');
  const fs = require('fs');
  const os = require('os');
  const run = (code) => {
    const f = path.join(os.tmpdir(), `pjp-${Math.random().toString(36).slice(2)}.js`);
    fs.writeFileSync(f, code);
    const out = path.join(os.tmpdir(), `pjp-out-${Math.random().toString(36).slice(2)}`);
    try {
      const r = spawnSync(process.execPath,
        [path.join(__dirname, '..', 'bin', 'omega.js'), f, '--security', '--report', '--no-color', '--out', out],
        { encoding: 'utf8', timeout: 60000 });
      if (r.error) return null;
      const rp = path.join(out, 'report.json');
      if (!fs.existsSync(rp)) return null;          // genuine failure
      const rep = JSON.parse(fs.readFileSync(rp, 'utf8'));
      const all = [...(rep.security || []), ...(rep.extendedFindings || [])];
      return all.filter(x => x.id === 'proto-jsonparse');
    } catch (e) { return null; }
  };

  const benignHits = benign.map(run).filter(Boolean).flat();
  ok('benign JSON.parse patterns produce no proto-jsonparse finding',
     benignHits.length === 0, `${benignHits.length} FP(s) still firing`);

  const malHits = malicious.map(run).filter(Boolean).flat();
  ok('real prototype-pollution patterns still detected', malHits.length > 0,
     'all malicious patterns were suppressed — fix is too aggressive');
  ok('real PP finding is high or critical',
     malHits.some(f => f.severity === 'high' || f.severity === 'critical'),
     JSON.stringify(malHits.map(f => f.severity)));
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('── Finding metadata: confidence + disambiguation ──');

{
  const src = `const { BrowserWindow } = require("electron");
  new BrowserWindow({ webPreferences: { nodeIntegration: true } });
  const d = jwt.verify(t, s);`;
  const r = scanNodeSurface(src);
  for (const f of r.findings) {
    ok(`finding ${f.id} has numeric confidence`, typeof f.confidence === 'number', JSON.stringify(f));
  }
  const withCtx = r.findings.filter(f => f.ctxWindow);
  ok('absence-based findings carry ctxWindow', withCtx.length > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(62));
if (fail === 0) {
  console.log(`  PASSED: ${pass}`);
} else {
  console.log(`  PASSED: ${pass}`);
  console.log(`  FAILED: ${fail}`);
  console.log('\n  Failure detail:');
  for (const f of failures) console.log(`    ✗ ${f}`);
}
process.exit(fail === 0 ? 0 : 1);

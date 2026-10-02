'use strict';

/**
 * @module ast/node-surface
 *
 * Node/Electron surface scanner — Phase 12t.
 *
 * Motivation
 * ----------
 * omega-sast's taint SOURCE set is entirely browser-side (location.*,
 * document.*, postMessage, storage, URLSearchParams). That is correct for
 * minified *browser* bundles, which is the stated target — but it means the
 * tool has no model at all for:
 *
 *   - Electron main/renderer bundles   (nodeIntegration, contextIsolation)
 *   - Node-side request objects        (req.body / req.query / req.params)
 *   - process.argv-derived input
 *
 * Point omega at a webpack server bundle, an Electron main process, or a
 * Next.js API route and every server-side flow is invisible. These scanners
 * close that gap.
 *
 * Design constraints
 * ------------------
 * 1. Node/Electron sources are GATED. They are only added to the taint source
 *    set when an explicit Node/Electron marker is present, so a browser bundle
 *    is never analysed against a server threat model.
 * 2. Every rule carries an explicit `confidence` separate from `severity`,
 *    so triage can treat them independently.
 * 3. Rules that fire on the ABSENCE of a defence (jwt algorithms allowlist,
 *    origin check) record the window that was searched as `ctxWindow`, so a
 *    reviewer can verify the absence rather than trust it.
 * 4. Noisy rules carry a `disambiguation` string explaining the benign case.
 */

// ── Node/Electron runtime detection ────────────────────────────────────────
// Used to gate server-side taint sources. Deliberately conservative: a bare
// `require(` in a browser bundle is common (webpack shims), so we require
// stronger markers.

const NODE_MARKERS = [
  /require\s*\(\s*['"](?:node:)?(?:fs|path|os|child_process|crypto|http|https|net|worker_threads|vm)['"]\s*\)/,
  /from\s+['"](?:node:)?(?:fs|path|os|child_process|worker_threads)['"]/,
  /\bprocess\.(?:binding|dlopen|exit|kill|execPath|mainModule)\b/,
  /__dirname|__filename/,
  /module\.exports\s*=/,
];

const ELECTRON_MARKERS = [
  /require\s*\(\s*['"]electron['"]\s*\)/,
  /from\s+['"]electron['"]/,
  /\bBrowserWindow\b/,
  /\bipcMain\.(?:on|handle|handleOnce)\b/,
  /\bipcRenderer\.(?:send|invoke|sendSync)\b/,
  /\bcontextBridge\b/,
  /\bwebPreferences\b/,
  /\bnodeIntegration\b/,
  /\bcontextIsolation\b/,
];

/**
 * @param {string} src
 * @returns {{node: boolean, electron: boolean, markers: string[]}}
 */
function detectNodeSurface(src) {
  const markers = [];
  let electron = false;
  let node = false;
  for (const re of ELECTRON_MARKERS) {
    if (re.test(src)) { electron = true; markers.push(String(re)); break; }
  }
  for (const re of NODE_MARKERS) {
    if (re.test(src)) { node = true; markers.push(String(re)); break; }
  }
  return { node, electron, markers };
}

// ── Taint source tables ────────────────────────────────────────────────────

/**
 * Server-side sources. Only merged into the taint source set when a Node
 * surface is detected — see addNodeSources().
 */
const NODE_SOURCES = {
  'req.body': 'HTTP request body',
  'req.query': 'HTTP request query',
  'req.params': 'HTTP route params',
  'req.headers': 'HTTP request headers',
  'req.cookies': 'HTTP request cookies',
  'req.body.': 'HTTP request body',
  'request.body': 'HTTP request body',
  'ctx.request.body': 'HTTP request body (ctx)',
  'ctx.query': 'HTTP query (ctx)',
  'ctx.params': 'HTTP route params (ctx)',
  'event.request.body': 'HTTP request body (fetch event)',
  'process.argv': 'process argv',
  'process.env.': 'process environment',
};

const ELECTRON_SOURCES = {
  'ipcRenderer.send': 'IPC message from renderer',
  'ipcRenderer.invoke': 'IPC invoke from renderer',
  'ipcRenderer.sendSync': 'IPC sync message from renderer',
};

// ── Helpers ────────────────────────────────────────────────────────────────

function win(src, i, before, after) {
  return src.slice(Math.max(0, i - before), Math.min(src.length, i + after)).replace(/[\r\n]/g, ' ');
}

/** A "sanitizer" for absence-based rules: an explicit type/shape guard. */
function hasShapeGuard(after) {
  return /typeof\s+\w+\s*===?\s*["'](?:object|string|number|boolean)["']/.test(after) ||
         /hasOwnProperty\s*\(\s*["']/.test(after) ||
         /instanceof\s+/.test(after) ||
         /Array\.isArray\s*\(/.test(after);
}

// ═══════════════════════════════════════════════════════════════════════════
//  RULE 1 — Electron renderer privilege escalation
// ═══════════════════════════════════════════════════════════════════════════

function scanElectronConfig(src, findings) {
  const ctx = (i, r = 160) => win(src, i, r / 2, r / 2);

  // nodeIntegration: true — renderer gets full Node. Critical in any app that
  // loads remote or untrusted content.
  {
    const re = /nodeIntegration\s*:\s*(true|['"]on['"])/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        id: 'electron-node-integration', category: 'Electron Security',
        severity: 'critical', confidence: 0.95,
        cwe: 'CWE-284: Improper Access Control',
        value: m[0], context: ctx(m.index),
        primitive: 'nodeIntegration',
        description: 'BrowserWindow created with nodeIntegration enabled — the renderer process gets full Node.js access. Any XSS in the renderer becomes full RCE.',
        remediation: 'Keep nodeIntegration:false and expose a minimal, validated API surface via contextBridge + ipcMain.handle.',
        exploitability: 'needs-renderer-content',
        disambiguation: 'Only benign when the app loads exclusively trusted local content AND contextIsolation is also false-by-design (rare). Any remote content makes this exploitable.',
      });
    }
  }

  // contextIsolation: false — removes the isolation between page JS and preload.
  {
    const re = /contextIsolation\s*:\s*false/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        id: 'electron-no-context-isolation', category: 'Electron Security',
        severity: 'high', confidence: 0.9,
        cwe: 'CWE-829: Inclusion of Functionality from Untrusted Control Sphere',
        value: m[0], context: ctx(m.index),
        primitive: 'contextIsolation:false',
        description: 'contextIsolation disabled — page scripts share the preload realm, so a prototype-pollution or XSS in the page can reach preload APIs.',
        remediation: 'Keep contextIsolation:true (the default since Electron 12) and bridge APIs explicitly via contextBridge.exposeInMainWorld.',
        exploitability: 'needs-renderer-content',
        disambiguation: 'Only acceptable in a hardened local-only app with a frozen, minimal preload and no remote content.',
      });
    }
  }

  // webSecurity: false — disables the same-origin policy entirely.
  {
    const re = /webSecurity\s*:\s*false/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        id: 'electron-no-web-security', category: 'Electron Security',
        severity: 'critical', confidence: 0.95,
        cwe: 'CWE-346: Origin Validation Error',
        value: m[0], context: ctx(m.index),
        primitive: 'webSecurity:false',
        description: 'webSecurity disabled — same-origin policy and CORS enforcement are off for this window. Any injected content can read local origins.',
        remediation: 'Remove webSecurity:false. If cross-origin content is required, use a separate BrowserWindow or a custom protocol handler.',
        exploitability: 'needs-renderer-content',
      });
    }
  }

  // Electron version pinned to an EOL major (no automatic security updates).
  {
    const re = /['"]electron['"]\s*:\s*["'~^]?\s*(\d+)\./g;
    let m;
    while ((m = re.exec(src)) !== null) {
      const major = parseInt(m[1], 10);
      if (Number.isNaN(major)) continue;
      if (major < 20) {
        findings.push({
          id: 'electron-eol-version', category: 'Electron Security',
          severity: 'medium', confidence: 0.7,
          cwe: 'CWE-1104: Use of Unmaintained Third Party Components',
          value: `electron@${major}.x`, context: ctx(m.index),
          primitive: 'electron-version',
          description: `Electron ${major}.x is far past end-of-life and receives no Chromium security patches.`,
          remediation: 'Upgrade to a currently-supported Electron major (>=28 at time of writing).',
          exploitability: 'known-vulnerable-runtime',
        });
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RULE 2 — IPC handler arguments reaching sensitive sinks
// ═══════════════════════════════════════════════════════════════════════════

const IPC_SENSITIVE_SINKS = [
  { re: /(?:child_process\.)?(?:exec|execSync)\s*\(/g, name: 'child_process.exec', cwe: 'CWE-78', sev: 'critical' },
  { re: /require\s*\(\s*['"](?:node:)?vm['"]\s*\)/g, name: 'require("vm")', cwe: 'CWE-94', sev: 'critical' },
  { re: /\beval\s*\(|new\s+Function\s*\(/g, name: 'eval/new Function', cwe: 'CWE-95', sev: 'critical' },
  { re: /fs\.(?:writeFile|writeFileSync|unlink|unlinkSync|rename|chmod)\s*\(/g, name: 'fs write/delete', cwe: 'CWE-22', sev: 'high' },
  { re: /fs\.(?:readFile|readFileSync)\s*\(/g, name: 'fs read', cwe: 'CWE-22', sev: 'medium' },
];

function scanIpcSinks(src, findings) {
  // Locate ipcMain handler bodies. A handler is the trust boundary between
  // renderer (attacker-influenced) and main (privileged).
  const handlerRe = /ipcMain\.(?:handle|handleOnce|on)\s*\(\s*["']([^"']+)["']\s*,\s*(?:async\s*)?\(([^)]*)\)\s*(?:=>\s*)?\{/g;
  let m;
  while ((m = handlerRe.exec(src)) !== null) {
    const channel = m[1];
    const params = m[2].trim();
    // Renderer-controlled argument is the last param (event, arg) / (event, ...args)
    const argParam = params.split(',').map(s => s.trim()).filter(Boolean).pop();
    if (!argParam) continue;

    // Find the handler body extent by brace matching.
    const openBrace = src.indexOf('{', m.index + m[0].length - 1);
    if (openBrace < 0) continue;
    const body = extractBraced(src, openBrace);
    if (!body) continue;

    // Does the renderer arg reach a sensitive sink unvalidated?
    for (const sink of IPC_SENSITIVE_SINKS) {
      sink.re.lastIndex = 0;
      let s;
      while ((s = sink.re.exec(body.text)) !== null) {
        const absPos = body.start + s.index;
        const around = win(src, absPos, 160, 160);
        // Look for the renderer arg flowing in, and a validator between them.
        const usesArg = new RegExp(`\\b${argParam.replace(/[$]/g, '\\$')}\\b`).test(around);
        if (!usesArg) continue;
        const validated = /\b(?:typeof|instanceof|Array\.isArray|hasOwnProperty|validate|sanitize|allowlist|whitelist|assert)\b/.test(around);
        if (validated) continue;
        findings.push({
          id: 'ipc-arg-sensitive-sink', category: 'Electron Security',
          severity: sink.sev, confidence: validated ? 0.4 : 0.8,
          cwe: sink.cwe,
          value: `ipcMain.${m[0].includes('handle') ? 'handle' : 'on'}("${channel}") \`${argParam}\` → ${sink.name}`,
          context: around, pos: absPos,
          primitive: sink.name,
          description: `Renderer-controlled argument \`${argParam}\` on channel "${channel}" reaches ${sink.name} with no visible validation. A compromised renderer controls this value.`,
          remediation: 'Validate the payload inside the handler (shape, type, and an allowlist of expected values) before it reaches any privileged sink.',
          exploitability: 'needs-compromised-renderer',
          disambiguation: 'Fires when no validator token is visible within ±160 chars. A validator defined elsewhere in the handler may produce a false positive — check the full handler body.',
        });
        break; // one finding per handler+sink
      }
    }
  }
}

/** Brace-matched block extractor. Returns {text,start,end} or null. */
function extractBraced(src, openBrace) {
  let depth = 0;
  for (let i = openBrace; i < src.length && i - openBrace < 20000; i++) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') { i = src.indexOf('\n', i); if (i < 0) return null; continue; }
    if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); if (e < 0) return null; i = e + 1; continue; }
    if (c === '"' || c === "'" || c === '`') {
      const q = c; i++;
      while (i < src.length) { if (src[i] === '\\') { i += 2; continue; } if (src[i] === q) break; i++; }
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return { text: src.slice(openBrace + 1, i), start: openBrace + 1, end: i }; }
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
//  RULE 3 — jwt.verify without an algorithms allowlist
//  Absence-based: records the searched window so the absence is auditable.
// ═══════════════════════════════════════════════════════════════════════════

function scanJwtAlgorithms(src, findings) {
  const re = /jwt\s*\.\s*verify\s*\(/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const around = win(src, m.index, 60, 400);
    // An algorithms allowlist may appear as `algorithms: [...]` or
    // `algorithms: ['RS256']` within the options object.
    const hasAllowlist = /algorithms\s*:\s*\[/.test(around) ||
                         /algorithms\s*:\s*[A-Za-z_$][\w$.]*/.test(around);
    if (hasAllowlist) continue;

    // Third positional arg = options. Options may be the 2nd arg in 2-arg
    // call form jwt.verify(token, secret, { algorithms: [...] }) — we already
    // scanned 400 chars after, which covers it.
    findings.push({
      id: 'jwt-verify-no-alg-pinning', category: 'Broken Crypto',
      severity: 'high', confidence: 0.65,
      cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
      value: 'jwt.verify(', context: around, pos: m.index,
      primitive: 'jwt.verify',
      description: 'jwt.verify() call with no visible `algorithms` allowlist — may accept `alg: none` or an RS256→HS256 algorithm-confusion token.',
      remediation: 'Pin the accepted algorithms explicitly: jwt.verify(t, k, { algorithms: ["RS256"] }). Never derive the expected alg from the token header.',
      exploitability: 'needs-token',
      ctxWindow: { before: 60, after: 400, searched: 'algorithms: [' },
      disambiguation: 'Fires when no `algorithms:` key is visible within +400 chars of the call. If the options object is built in a variable and passed in, this is a false positive — check for a variable options argument.',
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RULE 4 — Attacker-influenced dynamic RegExp (ReDoS / regex injection)
//  omega protects ITSELF with REGEX_LOOP_BUDGET_MS; this finds the same
//  vulnerability in the TARGET.
// ═══════════════════════════════════════════════════════════════════════════

// Request-derived sources are included: `new RegExp(req.query.pattern)` in a
// server or Electron main process is a real ReDoS / regex-injection vector and
// was previously missed entirely, because the list only covered browser sinks.
const REDOS_INPUT_SOURCES = /(?:location\.(?:search|hash|href)|document\.(?:URL|referrer)|window\.name|URLSearchParams|postMessage|\.message|\.data|localStorage|getItem\s*\(|atob\s*\(|decodeURIComponent|\breq\.(?:query|body|params|headers|cookies)\b|\bevent\.(?:data|payload)\b)/;

function scanDynamicRegex(src, findings) {
  const re = /new\s+RegExp\s*\(/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const around = win(src, m.index, 200, 200);
    if (!REDOS_INPUT_SOURCES.test(around)) continue;

    // Extract the constructor argument shape.
    const argMatch = src.slice(m.index, m.index + 300).match(/new\s+RegExp\s*\(([^,)]*)/);
    const arg = argMatch ? argMatch[1].trim() : '';
    // A concatenated/interpolated pattern is far more dangerous than a
    // constant one: the attacker controls the pattern source.
    const interpolated = /[+]/.test(arg);
    const isLiteral = /^["'`]/.test(arg);
    if (isLiteral && !interpolated) continue;

    findings.push({
      id: 'redos-dynamic-regex', category: 'ReDoS',
      severity: interpolated ? 'high' : 'medium',
      confidence: interpolated ? 0.75 : 0.55,
      cwe: 'CWE-1333: Inefficient Regular Expression Complexity',
      value: `new RegExp(${arg.slice(0, 60)})`, context: around, pos: m.index,
      primitive: 'RegExp-constructor',
      description: interpolated
        ? 'Attacker-influenced input reaches a RegExp constructor with string interpolation — enables both regex-injection (bypassing anchors/escapes) and catastrophic backtracking if the resulting pattern is ambiguous.'
        : 'Attacker-influenced input reaches a RegExp constructor — verify the pattern cannot produce catastrophic backtracking.',
      remediation: 'Never build a RegExp from untrusted input. If a literal search is needed, use String.prototype.includes/indexOf, or escape all metacharacters with a vetted escapeRegExp helper before interpolation.',
      exploitability: 'needs-input-flow',
      ctxWindow: { before: 200, after: 200 },
      disambiguation: 'Fires on any RegExp constructor within ±200 chars of an input source. A constant pattern stored in a nearby variable produces a false positive.',
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RULE 5 — Node command execution / deserialization sinks
//  These matter for server bundles and Electron main — omega had no coverage.
// ═══════════════════════════════════════════════════════════════════════════

// ── Node sink rules ────────────────────────────────────────────────────────
// `always` rules are unambiguous non-browser sinks — `yaml.load` and
// `unserialize` exist in no browser bundle — so they run unconditionally.
// `gated` rules (child_process, vm) only run when a Node/Electron surface
// is detected, so a browser bundle is never analysed against a server
// threat model.

const NODE_SINK_RULES_UNCONDITIONAL = [
  { re: /yaml\s*\.\s*load\s*\(/g, name: 'yaml.load (unsafe — prefer safeLoad)', cwe: 'CWE-502: Deserialization of Untrusted Data', sev: 'high' },
  { re: /\bunserialize\s*\(/g, name: 'node-serialize unserialize', cwe: 'CWE-502: Deserialization of Untrusted Data', sev: 'critical' },
];

const NODE_SINK_RULES_GATED = [
  // Explicitly qualified call is unambiguous.
  { re: /child_process\s*\.\s*exec(?:Sync)?\s*\(/g, name: 'child_process.exec', cwe: 'CWE-78: OS Command Injection', sev: 'high' },
  // Bare `exec(` is NOT sufficient evidence on its own: `RegExp.prototype.exec`
  // is one of the most common calls in any JS bundle. Only treat a bare call as
  // a child_process sink when child_process's `exec` is actually in scope
  // (destructured require / import). see hasExecInScope().
  { re: /(?<![\w$.])exec(?:Sync)?\s*\(/g, name: 'child_process.exec (destructured)', cwe: 'CWE-78: OS Command Injection', sev: 'high', needsExecInScope: true },
  { re: /\bspawn(?:Sync)?\s*\(\s*(?![^)]*,\s*\[)/g, name: 'child_process.spawn (shell:false assumed)', cwe: 'CWE-78: OS Command Injection', sev: 'info' },
  { re: /vm\s*\.\s*(?:runInNewContext|runInContext|compileFunction)\s*\(|new\s+vm\s*\.\s*Script\s*\(/g, name: 'vm sandbox (not a security boundary)', cwe: 'CWE-94: Code Injection', sev: 'high' },
];

/**
 * True when child_process's `exec` is demonstrably in scope.
 * Guards the bare-`exec(` rule against RegExp.prototype.exec FPs.
 */
function hasExecInScope(src) {
  return /(?:const|let|var)\s*\{[^}]*\bexec(?:Sync)?\b[^}]*\}\s*=\s*(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|await\s+import\s*\(\s*['"](?:node:)?child_process['"]\s*\))/.test(src)
    || /import\s*\{[^}]*\bexec(?:Sync)?\b[^}]*\}\s*from\s*['"](?:node:)?child_process['"]/.test(src)
    || /(?:const|let|var)\s+exec(?:Sync)?\s*=\s*(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)\s*\.\s*)?exec/.test(src);
}

const NODE_SINK_RULES = [...NODE_SINK_RULES_UNCONDITIONAL, ...NODE_SINK_RULES_GATED];

function scanNodeSinks(src, rules, findings) {
  const execInScope = hasExecInScope(src);
  for (const rule of rules) {
    // A bare `exec(` only counts when child_process's exec is in scope —
    // otherwise every RegExp.prototype.exec in the bundle is a false positive.
    if (rule.needsExecInScope && !execInScope) continue;
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(src)) !== null) {
      const around = win(src, m.index, 200, 200);
      const inputNear = REDOS_INPUT_SOURCES.test(around) ||
                        /req\.(?:body|query|params|headers)/.test(around) ||
                        /process\s*\.\s*argv/.test(around);
      findings.push({
        id: `node-sink-${rule.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`,
        category: 'Node Security',
        severity: inputNear ? rule.sev : (rule.sev === 'critical' ? 'medium' : 'info'),
        confidence: inputNear ? 0.7 : 0.45,
        cwe: rule.cwe,
        value: rule.name, context: around, pos: m.index,
        primitive: rule.name,
        description: `${rule.name} present in a Node context${inputNear ? ' with attacker-influenced input visible nearby' : ' (no input source visible nearby — informational)'}.`,
        exploitability: inputNear ? 'needs-input-flow' : 'theoretical',
        ctxWindow: { before: 200, after: 200 },
        disambiguation: 'Severity is raised only when a known input source appears within ±200 chars. Check whether the argument is a hardcoded constant or already validated.',
      });
      if (findings.length > 400) return; // bound output on pathological input
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @param {string} src
 * @returns {{findings: Array, node: boolean, electron: boolean,
 *            nodeSources: Object, electronSources: Object}}
 */
function scanNodeSurface(src) {
  const det = detectNodeSurface(src);
  const findings = [];

  // Electron rules run whenever ANY electron marker is present.
  if (det.electron) {
    scanElectronConfig(src, findings);
    scanIpcSinks(src, findings);
  }
  // Unambiguous non-browser sinks run always (yaml.load / unserialize cannot
  // appear in a browser bundle). Node-specific sinks are gated.
  scanNodeSinks(src, NODE_SINK_RULES_UNCONDITIONAL, findings);
  if (det.node || det.electron) {
    scanNodeSinks(src, NODE_SINK_RULES_GATED, findings);
  }
  // These are language-level and safe to run unconditionally.
  scanJwtAlgorithms(src, findings);
  scanDynamicRegex(src, findings);

  return {
    findings: findings.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    }),
    node: det.node,
    electron: det.electron,
    // Server-side sources are ONLY surfaced when gated on detection, so a
    // browser bundle is never analysed against a server threat model.
    nodeSources: (det.node || det.electron) ? { ...NODE_SOURCES, ...ELECTRON_SOURCES } : {},
  };
}

module.exports = {
  scanNodeSurface,
  detectNodeSurface,
  NODE_SOURCES,
  ELECTRON_SOURCES,
  NODE_SINK_RULES,
  hasShapeGuard,
  hasExecInScope,
  extractBraced,
};

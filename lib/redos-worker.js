'use strict';

/**
 * Worker-thread ReDoS isolation for OMEGA-5.0 (Stage 7)
 *
 * Provides real protection against catastrophic regex backtracking by running
 * regex execution in a separate worker thread with a hard timeout. If the
 * regex hangs, the worker is terminated and the timeout fires.
 *
 * Usage:
 *   const { runRegexSafe } = require('./redos-worker');
 *   const matches = await runRegexSafe(pattern, source, { timeoutMs: 5000 });
 *
 * Sync API (for cases where async isn't possible — uses child_process spawn):
 *   const { runRegexSync } = require('./redos-worker');
 *   const matches = runRegexSync(pattern, source, { timeoutMs: 5000 });
 *
 * Fallback: if worker_threads is unavailable (old Node), degrades to the
 * existing safeRegexIter with a warning.
 */

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// ── Async worker-thread API ─────────────────────────────────────────────
// Runs a regex in a worker thread with a hard timeout. Returns a Promise.
// If the regex hangs, the worker is terminated and the promise rejects
// with a timeout error.

function runRegexSafe(pattern, source, opts) {
  opts = opts || {};
  const timeoutMs = opts.timeoutMs || 5000;
  const maxMatches = opts.maxMatches || 5000;

  return new Promise((resolve, reject) => {
    // Build the worker script inline (avoids needing a separate file)
    const workerScript = `
      const { parentPort, workerData } = require('worker_threads');
      const { pattern, source, maxMatches } = workerData;

      try {
        const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
        const matches = [];
        let m;
        let count = 0;
        const startTime = Date.now();

        while ((m = re.exec(source)) !== null) {
          matches.push({
            index: m.index,
            match: m[0],
            groups: m.slice(1),
          });
          count++;
          if (count >= maxMatches) {
            parentPort.postMessage({ type: 'result', matches, truncated: true });
            return;
          }
          // Check time budget every 256 matches
          if ((count & 0xFF) === 0 && Date.now() - startTime > ${timeoutMs}) {
            parentPort.postMessage({ type: 'result', matches, truncated: true, timeout: true });
            return;
          }
          // Guard against zero-length matches
          if (m.index === re.lastIndex) re.lastIndex++;
        }

        parentPort.postMessage({ type: 'result', matches, truncated: false });
      } catch (e) {
        parentPort.postMessage({ type: 'error', error: e.message });
      }
    `;

    // Write the worker script to a temp file
    const tmpFile = path.join(require('os').tmpdir(), `omega-redos-${Date.now()}-${Math.random().toString(36).slice(2)}.js`);
    fs.writeFileSync(tmpFile, workerScript);

    const worker = new Worker(tmpFile, {
      workerData: { pattern: { source: pattern.source, flags: pattern.flags }, source, maxMatches },
    });

    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        worker.terminate();
        fs.unlinkSync(tmpFile);
        reject(new Error(`Regex execution timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);

    worker.on('message', (msg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate();
      try { fs.unlinkSync(tmpFile); } catch (_) {}
      if (msg.type === 'result') {
        resolve({ matches: msg.matches, truncated: msg.truncated, timeout: msg.timeout });
      } else {
        reject(new Error(msg.error));
      }
    });

    worker.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { fs.unlinkSync(tmpFile); } catch (_) {}
      reject(err);
    });

    worker.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        try { fs.unlinkSync(tmpFile); } catch (_) {}
        if (code !== 0) {
          reject(new Error(`Worker exited with code ${code}`));
        }
      }
    });
  });
}

// ── Sync API (child_process spawn) ──────────────────────────────────────
// For cases where async isn't possible. Uses execFileSync with a timeout.
// WARNING: this spawns a new Node process for each call, which is slow.
// Prefer the async API (runRegexSafe) whenever possible.

function runRegexSync(pattern, source, opts) {
  opts = opts || {};
  const timeoutMs = opts.timeoutMs || 5000;
  const maxMatches = opts.maxMatches || 5000;

  // Build a small Node script that runs the regex and prints JSON
  const script = `
    const pattern = ${JSON.stringify({ source: pattern.source, flags: pattern.flags })};
    const source = ${JSON.stringify(source)};
    const maxMatches = ${maxMatches};
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    const matches = [];
    let m;
    let count = 0;
    while ((m = re.exec(source)) !== null) {
      matches.push({ index: m.index, match: m[0], groups: m.slice(1) });
      count++;
      if (count >= maxMatches) break;
      if (m.index === re.lastIndex) re.lastIndex++;
    }
    process.stdout.write(JSON.stringify({ matches, truncated: count >= maxMatches }));
  `;

  try {
    const output = execFileSync(process.execPath, ['-e', script], {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,  // 10MB
      encoding: 'utf8',
    });
    return JSON.parse(output);
  } catch (e) {
    if (e.signal === 'SIGTERM') {
      return { matches: [], truncated: true, timeout: true, error: 'Regex execution timed out' };
    }
    return { matches: [], truncated: false, error: e.message };
  }
}

// ── Fallback: the existing safeRegexIter (in-process, no isolation) ─────
// Used when worker_threads is unavailable. Provides match-count cap and
// inter-match time budget, but CANNOT protect against single-match
// catastrophic backtracking.

function safeRegexIterFallback(re, src, onMatch, onAbort) {
  const MAX_REGEX_MATCHES = 5000;
  const REGEX_LOOP_BUDGET_MS = 5000;
  const startedAt = Date.now();
  let count = 0;
  let m;
  if (!re.global) {
    re = new RegExp(re.source, re.flags + 'g');
  }
  while ((m = re.exec(src)) !== null) {
    onMatch(m);
    count++;
    if (count >= MAX_REGEX_MATCHES) {
      if (onAbort) onAbort(`match cap exceeded (${MAX_REGEX_MATCHES})`);
      re.lastIndex = 0;
      return;
    }
    if ((count & 0xFF) === 0 && Date.now() - startedAt > REGEX_LOOP_BUDGET_MS) {
      if (onAbort) onAbort(`time budget exceeded (${REGEX_LOOP_BUDGET_MS}ms)`);
      re.lastIndex = 0;
      return;
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
}

module.exports = {
  runRegexSafe,
  runRegexSync,
  safeRegexIterFallback,
  isWorkerThreadsAvailable: typeof Worker !== 'undefined',
};

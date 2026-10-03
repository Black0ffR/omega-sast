'use strict';

/**
 * OMEGA-5.0 — Zero-dependency JavaScript SAST Engine
 *
 * @module omega-sast
 * @summary Static analysis for minified, framework-heavy JavaScript bundles
 * @license MIT
 */

const path = require('path');
const ast = require('./ast');
const redos = require('./redos-worker');

// Pipeline phases (from the monolith — will be modularized in future versions)
const pipeline = require('../src/_monolith');

// Re-export the core pipeline function for programmatic use
//
// History: this used to ignore both arguments and `return ast` — a module
// object, not an analysis. Any caller that trusted it got `undefined`
// properties and no findings, with no error. It now runs the real pipeline
// and resolves with the report object that `report.json` would have contained.
//
//   const { analyze } = require('omega-sast');
//   const report = await analyze('./bundle.js', { secrets: true });
//   report.security.filter(f => f.severity === 'critical');
//
// @param {string} filePath       path to the JavaScript file / bundle to analyze
// @param {object} [opts]         extra CLI flags (secrets, routes, security,
//                                graph, ast, severityFloor, maxHops, ...)
// @returns {Promise<object>}     the report object, plus a non-enumerable
//                                `__summary` carrying counts + attack score.
// @throws  {Error}               if filePath is not a non-empty string
async function analyze(filePath, opts) {
  if (typeof filePath !== 'string' || !filePath.trim()) {
    throw new TypeError('analyze(filePath[, opts]): filePath must be a non-empty string');
  }
  const userOpts = opts || {};
  if (userOpts.out) {
    throw new TypeError('analyze(): `out` is not supported — analyze() never writes to disk; use the CLI for report artifacts');
  }
  const merged = Object.assign({
    input: path.resolve(filePath),
    out: null,                 // filled in by main() with a temp dir
    quiet: true,
    secrets: false, routes: false, security: true, graph: false,
    report: true, verbose: false,
    ast: null, moduleMap: null, severityFloor: 'info', maxHops: 5,
    fetchCves: false, fetchSourcemaps: false,
    multi: false, llmPayload: false, baseline: null, updateBaseline: false,
    watch: false, diff: null, jsonOnly: true,
    returnData: true,          // ask main() to hand back the report object
  }, userOpts);

  const summary = await pipeline.main(merged);
  const report = summary.report || {};
  // Counts are convenient for programmatic callers but would otherwise have to
  // be recomputed from the arrays. Non-enumerable so JSON.stringify(report)
  // still matches report.json byte-for-byte.
  Object.defineProperty(report, '__summary', {
    value: {
      elapsed: summary.elapsed,
      totalFindings: summary.totalFindings,
      criticalCount: summary.criticalCount,
      highCount: summary.highCount,
      mediumCount: summary.mediumCount,
      attackScore: summary.attackScore,
      attackRisk: summary.attackRisk,
    },
    enumerable: false,
  });
  return report;
}

module.exports = {
  // Programmatic entry point
  analyze,

  // AST module
  ast,

  // ReDoS protection
  redos,

  // Pipeline (loaded from monolith for now)
  pipeline,

  // Version
  version: '5.0.0',

  // Convenience: direct access to most-used functions
  tokenizeForAST: ast.tokenizeForAST,
  buildStructuralIndex: ast.buildStructuralIndex,
  computeFunctionSummaries: ast.computeFunctionSummaries,
  buildBackwardSlices: ast.buildBackwardSlices,
  fingerprintObfuscator: ast.fingerprintObfuscator,
  parseSourceMap: ast.parseSourceMap,
  trackTaintAST: ast.trackTaintAST,
};

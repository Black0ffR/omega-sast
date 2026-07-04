'use strict';

/**
 * OMEGA-5.0 — Zero-dependency JavaScript SAST Engine
 *
 * @module omega-sast
 * @summary Static analysis for minified, framework-heavy JavaScript bundles
 * @license MIT
 */

const ast = require('./ast');
const redos = require('./redos-worker');

// Pipeline phases (from the monolith — will be modularized in future versions)
const pipeline = require('../src/_monolith');

// Re-export the core pipeline function for programmatic use
function analyze(filePath, opts) {
  opts = opts || {};
  // The monolith's main() is the full pipeline. For programmatic use,
  // we provide a simplified interface that returns the report data.
  const { generateReports } = pipeline;
  // Note: for full programmatic API, use the individual ast.* functions
  return ast;
}

module.exports = {
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

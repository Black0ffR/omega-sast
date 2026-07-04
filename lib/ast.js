'use strict';

/**
 * OMEGA-5.0 AST Foundation Module
 *
 * Hand-rolled, zero-dependency JavaScript tokenizer + structural walker
 * designed for MINIFIED code. Parses the entire file once into a flat
 * stream of tokens and produces a structural index used by all downstream
 * analyzers.
 *
 * @module ast
 */

// Load from the monolith (source of truth)
const monolith = require('../src/ast/_monolith');

module.exports = {
  // Core tokenizer + structural index
  tokenizeForAST: monolith.tokenizeForAST,
  buildStructuralIndex: monolith.buildStructuralIndex,

  // Framework detection
  detectFrameworksAST: monolith.detectFrameworksAST,

  // Bundler analysis
  resolveWebpack5Modules: monolith.resolveWebpack5Modules,
  detectBundler: monolith.detectBundler,

  // Call graph
  buildCallGraph: monolith.buildCallGraph,

  // Taint tracking
  trackTaintAST: monolith.trackTaintAST,

  // Security scanners
  scanModernCrypto: monolith.scanModernCrypto,
  extractNetworkSurface: monolith.extractNetworkSurface,

  // Source map
  parseSourceMap: monolith.parseSourceMap,

  // Obfuscator fingerprinting
  fingerprintObfuscator: monolith.fingerprintObfuscator,

  // Function summaries + backward slicing (LLM payload)
  computeFunctionSummaries: monolith.computeFunctionSummaries,
  buildBackwardSlices: monolith.buildBackwardSlices,

  // Variable Rename Table + Source Expander (LLM payload)
  buildVariableRenameTable: monolith.buildVariableRenameTable,
  createSourceExpander: monolith.createSourceExpander,

  // Helpers
  windowText: monolith.windowText,
  tokPos: monolith.tokPos,
};

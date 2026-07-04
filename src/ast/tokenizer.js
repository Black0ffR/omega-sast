'use strict';

/** @module ast/tokenizer */

// Re-export the tokenizer + structural index from the monolith.
// In a future refactor, these functions would be split into focused files:
//   - lexer.js (tokenizeForAST)
//   - structural-index.js (buildStructuralIndex)
// For now, the monolith provides the tested, working implementation.

const monolith = require('./_monolith');

module.exports = {
  tokenizeForAST: monolith.tokenizeForAST,
  buildStructuralIndex: monolith.buildStructuralIndex,
};

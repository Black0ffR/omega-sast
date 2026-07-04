# Contributing to OMEGA-5.0

## Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd omega-sast

# Install (no dependencies needed — zero-dep project)
npm install  # no-op, but validates package.json

# Run tests
npm test

# Run the demo scan
npm run demo
```

## Project Architecture

The codebase uses a "monolith + modules" architecture:

- `src/_monolith.js` — The full pipeline implementation (5000+ lines). This is the source of truth.
- `src/ast/_monolith.js` — The AST module implementation (3000+ lines). Source of truth for structural analysis.
- `lib/` — Public API surface. Re-exports from monoliths with clean module boundaries.
- `test/` — 11 test suites, 414 tests. Every fix has a regression test.

## Adding a New Scanner

1. Add the scanner function to `src/ast/_monolith.js`
2. Export it from `src/ast/_monolith.js`'s `module.exports`
3. Create a wrapper module in `src/ast/your-scanner.js`
4. Add it to `lib/ast.js`'s imports
5. Write tests in `test/test-your-scanner.js`
6. Update `test/run-all.js` if needed
7. Run `npm test` to verify

## Adding a New Obfuscator Signature

1. Add signature patterns to `fingerprintObfuscator()` in `src/ast/_monolith.js`
2. Add tests to `test/test-obfuscator.js`
3. Run `npm run test:obfuscator`

## Test Guidelines

- Every bug fix MUST have a regression test
- Tests use the pattern: `assert(name, condition, detail)`
- Test files are self-contained (no shared fixtures except `test/fixtures/`)
- Each test file exits with code 1 on failure, 0 on success

## Code Style

- No external dependencies (Node.js core only)
- Use `'use strict'` at the top of every file
- Functions are documented with JSDoc comments
- Regex patterns include comments explaining what they match

## CI

GitHub Actions runs the full test suite on every push. See `.github/workflows/ci.yml`.

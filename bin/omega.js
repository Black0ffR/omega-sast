#!/usr/bin/env node
'use strict';

/**
 * OMEGA-5.0 CLI Entry Point
 *
 * Usage:
 *   omega <file.js> [options]
 *   node bin/omega.js <file.js> [options]
 */

// Load the full pipeline and invoke CLI runner (handles exit codes)
const omega = require('../src/_monolith');
omega.runCLI();

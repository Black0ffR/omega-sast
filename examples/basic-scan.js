'use strict';

/**
 * Example: Programmatic usage of OMEGA-5.0
 *
 * Run: node examples/basic-scan.js
 */

const fs = require('fs');
const path = require('path');
const { ast } = require('../lib');

// Load a bundle
const src = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'sample-bundle.js'), 'utf8');

console.log('=== OMEGA-5.0 Programmatic Scan ===\n');

// 1. Build structural index
console.log('1. Building structural index...');
const idx = ast.buildStructuralIndex(src);
console.log(`   Classes: ${idx.classes.length}, Functions: ${idx.functions.length}, Call sites: ${idx.callSites.length}`);

// 2. Compute function summaries (LLM payload)
console.log('\n2. Computing function summaries...');
const summaries = ast.computeFunctionSummaries(src, idx);
const withSinks = summaries.filter(s => s.sinks.length > 0);
const withSources = summaries.filter(s => s.sources.length > 0);
console.log(`   ${summaries.length} functions, ${withSinks.length} with sinks, ${withSources.length} with sources`);

// 3. Build backward slices (inter-procedural taint paths)
console.log('\n3. Building backward slices...');
const cg = ast.buildCallGraph(idx, null);
const slices = ast.buildBackwardSlices(src, idx, summaries, cg, 3);
const reachable = slices.filter(p => p.reachesSource);
console.log(`   ${slices.length} paths, ${reachable.length} reach a taint source`);

// 4. Fingerprint obfuscator
console.log('\n4. Fingerprinting obfuscator...');
const fp = ast.fingerprintObfuscator(src);
if (fp.primary) {
  console.log(`   Primary: ${fp.primary.obfuscator} (${(fp.primary.confidence * 100).toFixed(0)}% confidence)`);
} else {
  console.log('   No obfuscator detected');
}

// 5. Variable Rename Table
console.log('\n5. Building Variable Rename Table...');
const vrt = ast.buildVariableRenameTable(idx, summaries);
console.log(`   ${vrt.stats.renamed} identifiers renamed (${vrt.stats.params} params, ${vrt.stats.locals} locals, ${vrt.stats.functions} functions)`);

// 6. On-demand source expansion
console.log('\n6. Source expansion interface...');
const expander = ast.createSourceExpander(src, idx, summaries);
const sinkSummaries = expander.getSinkSummaries();
console.log(`   ${sinkSummaries.length} sink summaries ready for on-demand expansion`);

// 7. Print top taint paths
console.log('\n7. Top taint paths:');
for (const p of slices.slice(0, 5)) {
  const chain = p.sourceChain.join(' → ');
  const sans = p.sanitizersOnPath.map(s => s.name).join(', ') || 'none';
  console.log(`   [${p.sink.severity}] ${p.sinkFn.name}.${p.sink.name} via ${p.sink.via}`);
  console.log(`     reachesSource: ${p.reachesSource}, chain: [${chain}], sanitizers: [${sans}], hops: ${p.totalHops}`);
}

// 8. Demonstrate source expansion
console.log('\n8. Expanding first sink function:');
if (sinkSummaries.length > 0) {
  const expansion = expander.expand(sinkSummaries[0].id);
  console.log(`   Function: ${expansion.name}`);
  console.log(`   Token estimate: ${expansion.tokenEstimate}`);
  console.log(`   Source (first 200 chars): ${expansion.source.slice(0, 200).replace(/\n/g, ' ')}...`);
}

console.log('\n=== Scan complete ===');

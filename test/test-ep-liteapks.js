#!/usr/bin/env node
'use strict';
const fs=require('fs');const path=require('path');const os=require('os');const {execSync}=require('child_process');
let passed=0,failed=0;function assert(name,cond,detail){if(cond){passed++;console.log(`  ✔ ${name}`);}else{failed++;console.log(`  ✘ ${name}${detail?' — '+detail:''}`);}}
const omegaBin=path.resolve(__dirname,'../bin/omega.js');
function runScan(input){
  const out=fs.mkdtempSync(path.join(os.tmpdir(),'omega-ep-'));
  try{execSync(`node ${omegaBin} ${input} --security --report --out ${out}`,{encoding:'utf8',timeout:60000,stdio:'pipe'});}catch(e){
    if (!fs.existsSync(path.join(out,'report.json'))) throw e;
  }
  const j=JSON.parse(fs.readFileSync(path.join(out,'report.json'),'utf8'));
  try{fs.rmSync(out,{recursive:true,force:true});}catch{}
  return j;
}
const site=path.join(__dirname,'fixtures/ep-liteapks/site.js');
const nf=path.join(__dirname,'fixtures/ep-liteapks/nf-front-end.js');
console.log('EP-liteapks site.js');
try{
  const r=runScan(site);
  const sec=r.security||[];
  assert('site: no Date.now high crypto', !sec.some(f=>f.id==='rand-date-token'&&f.severity==='high'));
  assert('site: no HIGH open-redirect on orderby', !sec.some(f=>f.id==='redirect-location-href'&&f.severity==='high'));
  assert('site: has DOM signal', sec.filter(f=>/xss|innerhtml|dom/i.test(JSON.stringify(f))).length>=1);
  assert('site: findings have scope/exploitability', sec.every(f=>f.scope&&f.exploitability));
}catch(e){assert('site scan',false,e.message);}
console.log('EP-liteapks nf-front-end.js');
try{
  const r=runScan(nf);
  const sec=r.security||[];
  assert('nf: no websocket', !sec.some(f=>/websocket/i.test(f.id||'')||/websocket/i.test(f.category||'')));
  assert('nf: no critical xss-eval/Mexp', !sec.some(f=>(f.id==='xss-eval'||f.id==='code-eval-global')&&f.severity==='critical'));
  assert('nf: redirect pattern remains', sec.some(f=>/redirect/i.test(f.id||'')||/redirect/i.test(f.category||'')));
  assert('nf: findings have scope/exploitability', sec.every(f=>f.scope&&f.exploitability));
  const mexp = sec.find(f=>f.id==='code-eval-math-engine');
  if (mexp) assert('nf: Mexp math-engine is info', mexp.severity==='info');
}catch(e){assert('nf scan',false,e.message);}
console.log(`\nPASSED: ${passed}  FAILED: ${failed}`);
process.exit(failed?1:0);

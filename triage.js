const fs=require('fs'),path=require('path');
const root=process.env.HOME+'/smartbugs-curated';
const {patternScan}=require('./bench-adapter');
const TOL=3, byRule={}, pool=[];
for(const e of JSON.parse(fs.readFileSync(root+'/vulnerabilities.json'))){
  const src=fs.readFileSync(path.join(root,e.path),'utf8'), lines=src.split('\n');
  const ann=e.vulnerabilities.flatMap(v=>v.lines);
  for(const f of patternScan(src)){
    if(ann.some(l=>Math.abs(f.line-l)<=TOL))continue;
    byRule[f.rule]=(byRule[f.rule]||0)+1;
    pool.push({file:e.name,line:f.line,rule:f.rule,code:(lines[f.line-1]||'').trim().slice(0,90)});
  }
}
console.log(byRule);
pool.sort(()=>Math.random()-.5).slice(0,20).forEach((x,i)=>console.log(`${i+1}. ${x.file}:${x.line} [${x.rule}] ${x.code}`));

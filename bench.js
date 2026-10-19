const di=process.argv.indexOf("--debug-cat"), dcat=di>0?process.argv[di+1]:null;
const fs = require('fs'), path = require('path');
const root = process.argv[2];
const useLLM = process.argv.includes('--llm');
const li = process.argv.indexOf('--limit');
const limit = li > 0 ? +process.argv[li + 1] : Infinity;
const TOL = 3;
const A = require('./bench-adapter');
const entries = JSON.parse(fs.readFileSync(path.join(root, 'vulnerabilities.json'))).slice(0, limit);
const cfgs = { patterns: async s => A.patternScan(s) };
if (useLLM) {
  cfgs.llm = A.llmScan;
  cfgs.both = async s => [...A.patternScan(s), ...await A.llmScan(s)];
  cfgs.full = A.fullScan;
}
let R=[];
const FN=process.argv.includes('--fn');
function fnRanges(src){
  const out=[],re=/\b(function|modifier|constructor)\b[^{;]*\{/g;let m;
  while((m=re.exec(src))){
    let i=m.index+m[0].length,d=1;
    while(i<src.length&&d>0){const c=src[i++];if(c==='{')d++;else if(c==='}')d--;}
    const ln=p=>src.slice(0,p).split('\n').length;
    out.push([ln(m.index),ln(i)]);
  }
  return out;
}
const near=(f,ls)=>ls.some(l=>Math.abs(f.line-l)<=TOL||(FN&&R.some(([a,b])=>f.line>=a&&f.line<=b&&l>=a&&l<=b)));
const stats = {};
(async () => {
  for (const e of entries) {
    const src = fs.readFileSync(path.join(root, e.path), 'utf8'); R=fnRanges(src);
    const all = e.vulnerabilities.flatMap(v => v.lines);
    for (const [name, fn] of Object.entries(cfgs)) {
      let f = [];
      try { f = await fn(src); } catch (x) { console.error(name, e.name, x.message); continue; }
      const s = stats[name] ??= { cats: {}, extra: 0, total: 0 };
      for (const v of e.vulnerabilities) {
        const c = s.cats[v.category] ??= { hit: 0, n: 0 };
        c.n++;
if(dcat&&v.category===dcat&&name==='patterns')console.log(e.name,v.lines,f.filter(x=>near(x,v.lines)).map(x=>x.rule));
        if (f.some(x => near(x, v.lines))) c.hit++;
      }
      s.total += f.length;
      s.extra += f.filter(x => !near(x, all)).length;
    }
  }
  const names = Object.keys(stats);
  const cats = [...new Set(names.flatMap(n => Object.keys(stats[n].cats)))].sort();
  let out = `| Category | ${names.join(' | ')} |\n|${'---|'.repeat(names.length + 1)}\n`;
  for (const c of cats) {
    out += `| ${c} | ${names.map(n => { const x = stats[n].cats[c]; return x ? x.hit + '/' + x.n : '-'; }).join(' | ')} |\n`;
  }
  out += `| unmatched findings | ${names.map(n => stats[n].extra + '/' + stats[n].total).join(' | ')} |\n`;
  fs.writeFileSync('BENCHMARK-results.md', out);
  console.log(out);
})();

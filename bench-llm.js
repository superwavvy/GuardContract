// bench-llm.js: LLM column for the SmartBugs benchmark.
// Calls the LLM ONCE per contract per run, then derives three setups from it:
//   patterns (rules only), llm (LLM only), both (rules + LLM).
// Usage: node bench-llm.js ~/smartbugs-curated --limit 10 --runs 1
// Flags: --limit N  --runs N (default 3)  --fn (also match by same function)
//        --sleep ms (pause between calls)  --cache file (default llm-cache.json)
const fs = require('fs'), path = require('path');
const A = require('./bench-adapter');

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d; };
const root = process.argv[2];
if (!root || root.startsWith('--')) {
  console.error('usage: node bench-llm.js <smartbugs-curated dir> [--limit N] [--runs N] [--fn] [--sleep ms] [--cache file]');
  process.exit(1);
}
const RUNS = +arg('runs', 3), LIMIT = +arg('limit', Infinity), SLEEP = +arg('sleep', 0);
const FN = process.argv.includes('--fn'), CACHE = arg('cache', 'llm-cache.json'), TOL = 3;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function fnRanges(src) {
  const out = [], re = /\b(function|modifier|constructor)\b[^{;]*\{/g; let m;
  while ((m = re.exec(src))) {
    let i = m.index + m[0].length, d = 1;
    while (i < src.length && d > 0) { const c = src[i++]; if (c === '{') d++; else if (c === '}') d--; }
    const ln = p => src.slice(0, p).split('\n').length;
    out.push([ln(m.index), ln(i)]);
  }
  return out;
}
const near = (f, ls, R) => ls.some(l => Math.abs(f.line - l) <= TOL ||
  (FN && R.some(([a, b]) => f.line >= a && f.line <= b && l >= a && l <= b)));

// Evenly spaced sample across the dataset (it is sorted by category), same every run.
const all = JSON.parse(fs.readFileSync(path.join(root, 'vulnerabilities.json')));
const entries = LIMIT < all.length
  ? Array.from({ length: LIMIT }, (_, i) => all[Math.floor(i * all.length / LIMIT)])
  : all;

let cache = {};
try { cache = JSON.parse(fs.readFileSync(CACHE, 'utf8')); } catch (e) {}
const readSrc = e => fs.readFileSync(path.join(root, e.path), 'utf8');

async function llmWithRetry(src) {
  for (let a = 0; a < 4; a++) {
    try { return await A.llmScan(src); }
    catch (e) { if (a === 3) throw e; console.error('\n retry', a + 1, e.message); await sleep(5000 * Math.pow(3, a)); }
  }
}

(async () => {
  for (let r = 1; r <= RUNS; r++) {
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i], key = r + '|' + e.path;
      process.stdout.write('\rrun ' + r + '/' + RUNS + '  contract ' + (i + 1) + '/' + entries.length + '   ');
      if (cache[key]) continue;
      try {
        cache[key] = await llmWithRetry(readSrc(e));
        fs.writeFileSync(CACHE, JSON.stringify(cache));
      } catch (err) { console.error('\nFAILED run ' + r + ' ' + e.name + ': ' + err.message); }
      if (SLEEP) await sleep(SLEEP);
    }
  }
  console.log('');

  // Only score contracts that finished in every run, so denominators match.
  const complete = entries.filter(e => { for (let r = 1; r <= RUNS; r++) if (!cache[r + '|' + e.path]) return false; return true; });
  const cfgs = ['patterns', 'llm', 'both'];
  const acc = {};
  for (const c of cfgs) acc[c] = Array.from({ length: RUNS }, () => ({ cats: {}, extra: 0, total: 0 }));

  for (const e of complete) {
    const src = readSrc(e), R = fnRanges(src), P = A.patternScan(src);
    const ann = e.vulnerabilities.flatMap(v => v.lines);
    for (let r = 1; r <= RUNS; r++) {
      const L = cache[r + '|' + e.path];
      const sets = { patterns: P, llm: L, both: [...P, ...L] };
      for (const c of cfgs) {
        const f = sets[c], s = acc[c][r - 1];
        for (const v of e.vulnerabilities) {
          const k = s.cats[v.category] ??= { hit: 0, n: 0 };
          k.n++; if (f.some(x => near(x, v.lines, R))) k.hit++;
        }
        s.total += f.length; s.extra += f.filter(x => !near(x, ann, R)).length;
      }
    }
  }

  const rng = a => { const lo = Math.min(...a), hi = Math.max(...a); return lo === hi ? '' + lo : lo + '-' + hi; };
  const cats = [...new Set(cfgs.flatMap(c => acc[c].flatMap(s => Object.keys(s.cats))))].sort();
  let out = 'SmartBugs Curated sample: ' + complete.length + '/' + entries.length + ' contracts scored, ' +
    RUNS + ' run(s), ' + (FN ? 'line window or same function' : 'line window only') + '\n\n' +
    '| Category | patterns | llm | both |\n|---|---|---|---|\n';
  for (const c of cats) {
    out += '| ' + c + ' | ' + cfgs.map(g => {
      const n = acc[g][0].cats[c] ? acc[g][0].cats[c].n : 0;
      return n ? rng(acc[g].map(s => s.cats[c] ? s.cats[c].hit : 0)) + '/' + n : '-';
    }).join(' | ') + ' |\n';
  }
  out += '| unmatched / total findings | ' + cfgs.map(g => rng(acc[g].map(s => s.extra)) + '/' + rng(acc[g].map(s => s.total))).join(' | ') + ' |\n';
  fs.writeFileSync('BENCHMARK-llm.md', out);
  console.log(out);
})();

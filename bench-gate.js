#!/usr/bin/env node
/**
 * SmartBugs recall gate - rules only, deterministic, no API key.
 *
 *   node bench-gate.js <smartbugs-curated>             verify against baseline
 *   node bench-gate.js <smartbugs-curated> --update    rewrite baseline
 */
const fs = require('fs');
const path = require('path');
const { runPatterns } = require('./sol-patterns');
const { parseSolidityVersion, versionTier } = require('./sol-version');

const TOL = 3;
const BASELINE = path.join(__dirname, 'bench-baseline.json');
const root = process.argv[2];
const update = process.argv.includes('--update');

if (!root) {
  console.error('usage: node bench-gate.js <smartbugs-curated> [--update]');
  process.exit(2);
}
const manifest = path.join(root, 'vulnerabilities.json');
if (!fs.existsSync(manifest)) {
  console.error('missing ' + manifest + ' - is that the smartbugs-curated root?');
  process.exit(2);
}

function patternScan(src) {
  let tier = 'unknown';
  try { tier = versionTier(parseSolidityVersion(src)); } catch (e) { /* unknown tier */ }
  try {
    return runPatterns(src, 'bench.sol', tier).map(f => ({ line: f.line, rule: f.type }));
  } catch (e) {
    console.error('patternScan failed: ' + e.message);
    return [];
  }
}

const entries = JSON.parse(fs.readFileSync(manifest, 'utf8'));
const cats = {};
const total = { hit: 0, n: 0 };

for (const e of entries) {
  const src = fs.readFileSync(path.join(root, e.path), 'utf8');
  const findings = patternScan(src);
  for (const v of e.vulnerabilities) {
    const c = (cats[v.category] = cats[v.category] || { hit: 0, n: 0 });
    c.n++; total.n++;
    if (findings.some(f => (v.lines || []).some(l => Math.abs(f.line - l) <= TOL))) {
      c.hit++; total.hit++;
    }
  }
}

const pct = (h, n) => (n ? ((100 * h) / n).toFixed(1) + '%' : 'n/a');
const result = { tolerance: TOL, mode: 'patterns', entries: entries.length, total, categories: cats };

if (update) {
  fs.writeFileSync(BASELINE, JSON.stringify(result, null, 2) + '\n');
  console.log('baseline written: ' + total.hit + '/' + total.n + ' (' + pct(total.hit, total.n) + ')');
  process.exit(0);
}

if (!fs.existsSync(BASELINE)) {
  console.error('no bench-baseline.json - run once with --update, then commit it');
  process.exit(2);
}
const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));

let bad = 0;
console.log('category'.padEnd(30) + 'baseline'.padStart(10) + 'now'.padStart(10) + '  status');
for (const k of Object.keys(base.categories).sort()) {
  const b = base.categories[k];
  const n = cats[k] || { hit: 0, n: 0 };
  const drop = b.hit - n.hit;
  let status = 'ok';
  if (n.n !== b.n) { status = 'CORPUS CHANGED'; bad++; }
  else if (drop > 0) { status = 'REGRESSION -' + drop; bad++; }
  else if (drop < 0) status = 'improved +' + -drop;
  console.log(k.padEnd(30) + (b.hit + '/' + b.n).padStart(10) + (n.hit + '/' + n.n).padStart(10) + '  ' + status);
}

if (base.total.n !== total.n) { bad++; }
console.log('TOTAL'.padEnd(30) + (base.total.hit + '/' + base.total.n).padStart(10) + (total.hit + '/' + total.n).padStart(10) + '  ' + pct(total.hit, total.n));

if (bad) {
  console.error('\n' + bad + ' regression(s) or corpus drift - failing.');
  process.exit(1);
}
console.log('\nno regression.');

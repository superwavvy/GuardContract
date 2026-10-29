const fs = require("fs"), path = require("path");
const A = require("./bench-adapter");
const root = process.argv[2];
const E = JSON.parse(fs.readFileSync(path.join(root, "vulnerabilities.json")));
const T = {};
for (const e of E) {
  const src = fs.readFileSync(path.join(root, e.path), "utf8");
  const labeled = e.vulnerabilities.flatMap((v) => v.lines);
  let f = [];
  try { f = A.patternScan(src); } catch (x) { continue; }
  for (const x of f) {
    const r = (T[x.rule] ??= { n: 0, hit: 0 });
    r.n++;
    if (labeled.some((l) => Math.abs(x.line - l) <= 3)) r.hit++;
  }
}
const rows = Object.entries(T).sort((a, b) => (b[1].n - b[1].hit) - (a[1].n - a[1].hit));
console.log("rule | findings | matched | noise");
for (const [k, v] of rows.slice(0, 20))
  console.log(k + " | " + v.n + " | " + v.hit + " | " + Math.round((100 * (v.n - v.hit)) / v.n) + "%");

const fs = require("fs"), path = require("path");
const A = require("./bench-adapter");
const root = process.argv[2], mode = process.argv[3], args = process.argv.slice(4);
const E = JSON.parse(fs.readFileSync(path.join(root, "vulnerabilities.json")));
for (const e of E) {
  const src = fs.readFileSync(path.join(root, e.path), "utf8");
  const L = src.split("\n");
  const txt = (n) => (L[n - 1] || "").trim().slice(0, 60);
  let f = [];
  try { f = A.patternScan(src); } catch (x) { continue; }
  const b = path.basename(e.path);
  if (mode === "rule") {
    const labeled = e.vulnerabilities.flatMap((v) => v.lines);
    for (const x of f) if (args.includes(x.rule))
      console.log((labeled.some((l) => Math.abs(x.line - l) <= 3) ? "HIT  " : "MISS ") + b + ":" + x.line + " " + txt(x.line));
  } else {
    for (const v of e.vulnerabilities) if (args.includes(v.category) && !v.lines.some((l) => f.some((x) => Math.abs(x.line - l) <= 3)))
      console.log("MISSED " + v.category + " " + b + ":" + v.lines[0] + " " + txt(v.lines[0]));
  }
}

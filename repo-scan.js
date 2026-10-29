const fs = require("fs"), path = require("path");
const A = require("./bench-adapter");
const root = path.resolve(process.argv[2] || ".");
const ALL = process.argv.includes("--all");
const only = process.argv[3] && process.argv[3] !== "--all" ? new RegExp(process.argv[3], "i") : null;
const SKIP = /(^|\/)(node_modules|test|tests|mock|mocks|script|scripts|lib|interfaces?|forge-std|openzeppelin|@openzeppelin|solmate|solady|out|cache|artifacts)(\/|$)|\.t\.sol$|\.s\.sol$|(^|\/)Mock\w*\.sol$|(^|\/)I[A-Z]\w*\.sol$/i;
const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const EMO = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵", INFO: "⚪" };
const rank = (s) => { const i = ORDER.indexOf(s); return i < 0 ? 9 : i; };


const _SEV = {};
try {
  const m = require("./sol-patterns");
  const arr = Array.isArray(m) ? m : (Object.values(m).find(Array.isArray) || []);
  arr.forEach((r) => { if (r && r.severity) { if (r.type) _SEV[r.type] = r.severity; if (r.id) _SEV[r.id] = r.severity; } });
} catch (e) {}
let _warned = false;
function _sevOf(x) {
  const v = x.severity || x.sev || x.level || x.risk || _SEV[x.rule] || _SEV[x.type] || _SEV[x.id];
  if (!v && !_warned) { _warned = true; console.error("note: finding fields = " + Object.keys(x).join(",")); }
  return String(v || "UNKNOWN").toUpperCase();
}
function walk(d, out) {
  for (const n of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, n.name);
    if (n.isDirectory()) { if (n.name !== ".git") walk(p, out); }
    else if (n.name.endsWith(".sol")) out.push(p);
  }
  return out;
}

const all = walk(root, []);
const files = all.map((p) => [p, path.relative(root, p)]).filter(([, r]) => (ALL || !SKIP.test(r)) && (!only || only.test(r)));
const groups = {};
let failed = 0;
for (const [p, rel] of files) {
  let f = [];
  try { f = A.patternScan(fs.readFileSync(p, "utf8")); } catch (e) { failed++; continue; }
  const best = {}, seenLine = {};
  for (const x of f) { const r0 = rank(_sevOf(x)); if (best[x.line] === undefined || r0 < best[x.line]) best[x.line] = r0; }
  for (const x of f) {
    const sev = _sevOf(x);
    if (rank(sev) !== best[x.line] || seenLine[x.line]) continue;
    seenLine[x.line] = 1;
    const k = sev + "|" + x.rule + "|" + rel;
    (groups[k] ??= { sev, rule: x.rule, rel, lines: [] }).lines.push(x.line);
  }
}
const rows = Object.values(groups).sort((a, b) => rank(a.sev) - rank(b.sev) || a.rel.localeCompare(b.rel));
const fmt = (g) => {
  const ls = [...new Set(g.lines)].sort((a, b) => a - b);
  return (EMO[g.sev] || "•") + " " + g.sev + " | " + g.rule + (ls.length > 1 ? " ×" + ls.length : "") + "\n   " + g.rel + ":" + ls.join(", ");
};
const counts = {};
rows.forEach((g) => { counts[g.sev] = (counts[g.sev] || 0) + 1; });
const head = "Scanned " + files.length + " files (" + (all.length - files.length) + " skipped as tests/mocks/libs/interfaces" + (failed ? ", " + failed + " failed to parse" : "") + ")\n" +
  ORDER.concat(["UNKNOWN"]).filter((s) => counts[s]).map((s) => s + ":" + counts[s]).join("  ") + "\n";
fs.writeFileSync("repo-report.txt", head + "\n" + rows.map(fmt).join("\n") + "\n");
let shown = 0;
console.log(head);
for (const g of rows) {
  if (rank(g.sev) > 1 && shown >= 25) continue;
  console.log(fmt(g)); shown++;
}
console.log("\nFull list: repo-report.txt (" + rows.length + " grouped findings)");

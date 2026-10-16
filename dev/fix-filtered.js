var fs = require("fs");

var s = fs.readFileSync("scanner.js", "utf8");
s = s.replace(
  'var c = { ok: 0, skipped_secondary: 0, skipped_oversized: 0, failed: 0 };',
  'var c = { ok: 0, skipped_secondary: 0, skipped_oversized: 0, failed: 0, filtered: 0 };'
);
s = s.replace(
  'var st = (f._llmStatuses && f._llmStatuses[f.path]) || "ok";',
  'var st = (f._llmStatuses && f._llmStatuses[f.path]) || "filtered";'
);
fs.writeFileSync("scanner.js", s);
console.log("OK: scanner.js filtered-status patched");

var b = fs.readFileSync("bot.js", "utf8");
b = b.replace(
  'if (s.skipped_oversized) parts.push("⚠️ oversized:" + s.skipped_oversized);',
  'if (s.skipped_oversized) parts.push("⚠️ oversized:" + s.skipped_oversized);\n  if (s.filtered) parts.push("filtered:" + s.filtered);'
);
fs.writeFileSync("bot.js", b);
console.log("OK: bot.js filtered-render patched");

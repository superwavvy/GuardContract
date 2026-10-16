var fs = require("fs");

// ---- Patch bot.js ----
var b = fs.readFileSync("bot.js", "utf8");

// 1. Add helper before formatReport
var helper = [
"function llmStatusLine(s) {",
"  if (!s) return \"untracked\";",
"  const parts = [];",
"  if (s.ok) parts.push(\"ok:\" + s.ok);",
"  if (s.skipped_secondary) parts.push(\"skip:\" + s.skipped_secondary);",
"  if (s.skipped_oversized) parts.push(\"⚠️ oversized:\" + s.skipped_oversized);",
"  if (s.failed) parts.push(\"❌ failed:\" + s.failed);",
"  return parts.length ? parts.join(\" · \") : \"none\";",
"}",
""
].join("\n");

var anchorFn = "function formatReport(r) {";
if (b.indexOf(anchorFn) === -1) { console.error("formatReport not found"); process.exit(1); }
b = b.replace(anchorFn, helper + anchorFn);

// 2. Locate the Ruleset line more forgivingly — search for the phrase "*Ruleset*"
var lines = b.split("\n");
var rulesetIdx = -1;
for (var i = 0; i < lines.length; i++) {
  if (lines[i].indexOf("*Ruleset*") !== -1) { rulesetIdx = i; break; }
}
if (rulesetIdx === -1) {
  // fallback: find any line referencing TIER_LABELS
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].indexOf("TIER_LABELS[") !== -1) { rulesetIdx = i; break; }
  }
}
if (rulesetIdx === -1) { console.error("Ruleset line not found (tried both anchors)"); process.exit(1); }

var rulesetLine = lines[rulesetIdx];
var indent = rulesetLine.match(/^\s*/)[0];

// Strip any trailing \n\n inside the template literal that ends the line, so we can add ours after
// Only affects the immediate \n\n before final backtick-semicolon
var stripped = rulesetLine.replace(/\\n\\n`;\s*$/, "\\n`;");

// If the strip didn't match (template style differs), keep the line as-is and just append
var llmLine = indent + "out += `🤖 *LLM*          ${llmStatusLine(r.llmStatus)}\\n\\n`;";

lines[rulesetIdx] = stripped + "\n" + llmLine;
b = lines.join("\n");

// 3. Add LLM-failure warning inside CLEAN block (best-effort; skip if not found)
var cleanPatterns = [
"    out += `⚠️ _No pattern matches or LLM findings._\\n`;",
"    out += `⚠️ _No pattern matches or LLM findings._\\n`;",
"out += `⚠️ _No pattern matches or LLM findings._\\n`;"
];
var cleanReplaced = false;
for (var ci = 0; ci < cleanPatterns.length; ci++) {
  if (b.indexOf(cleanPatterns[ci]) !== -1) {
    var indent2 = cleanPatterns[ci].match(/^\s*/)[0];
    var cleanNew = [
      indent2 + "if (r.llmStatus && r.llmStatus.failed > 0) {",
      indent2 + "  out += `⚠️ *LLM layer partially failed* — findings may be incomplete._\\n`;",
      indent2 + "}",
      cleanPatterns[ci]
    ].join("\n");
    b = b.replace(cleanPatterns[ci], cleanNew);
    cleanReplaced = true;
    break;
  }
}
if (!cleanReplaced) console.warn("WARN: CLEAN-block anchor not found — skipping failure warning (non-fatal)");

fs.writeFileSync("bot.js", b);
console.log("patched: bot.js");

// ---- Patch scanner.js report object ----
var s = fs.readFileSync("scanner.js", "utf8");
var repAnchor = "filesAnalyzed: contract.files.length,";
if (s.indexOf(repAnchor) === -1) { console.error("scanner.js report anchor not found"); process.exit(1); }

var llmField = [
"filesAnalyzed: contract.files.length,",
"    llmStatus: (function() {",
"      var c = { ok: 0, skipped_secondary: 0, skipped_oversized: 0, failed: 0 };",
"      for (var k = 0; k < contract.files.length; k++) {",
"        var f = contract.files[k];",
"        var st = (f._llmStatuses && f._llmStatuses[f.path]) || \"ok\";",
"        c[st] = (c[st] || 0) + 1;",
"      }",
"      return c;",
"    })(),"
].join("\n");

s = s.replace(repAnchor, llmField);
fs.writeFileSync("scanner.js", s);
console.log("patched: scanner.js");

// Sanity check
delete require.cache[require.resolve("./scanner.js")];
require("./scanner.js");
console.log("OK: scanner.js loads");

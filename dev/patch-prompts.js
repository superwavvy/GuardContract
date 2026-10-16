var fs = require("fs");
var lines = fs.readFileSync("analyzer.js", "utf8").split("\n");

var idx = -1;
for (var i = 0; i < lines.length; i++) {
  if (lines[i].indexOf("Return ONLY valid JSON") !== -1) { idx = i; break; }
}
if (idx === -1) { console.error("FAIL: anchor not found"); process.exit(1); }

var block = [
"REENTRANCY RULE: If a function has the nonReentrant modifier (or any reentrancy guard like a mutex/lock), do NOT report reentrancy for that function. Only report if you can name a SPECIFIC cross-function path that bypasses the guard.",
"",
"SEVERITY RUBRIC (apply strictly, override your default instinct):",
"- CRITICAL: Direct loss/theft of user funds OR permanent lock of funds, exploitable by an unprivileged attacker.",
"- HIGH: Conditional loss (requires specific state), or DoS that costs little to trigger, or loss requires a privileged role.",
"- MEDIUM: Griefing, incorrect accounting without direct fund loss, DoS with meaningful cost.",
"- LOW: Missing input validation, best-practice, informational.",
"",
"When a finding enables direct fund loss with no privileged role required, it is CRITICAL regardless of how logic-error-y the code looks.",
"",
"SEVERITY GUIDANCE:",
"- Input Validation: LOW by default. MEDIUM only if the missing check directly enables theft, permanent lock, or unauthorized state change.",
"- Denial of Service: MEDIUM only if attacker can cheaply and repeatedly block legitimate users. Unbounded loops over user-supplied arrays are LOW.",
"",
""
];

lines.splice(idx, 0, ...block);
fs.writeFileSync("analyzer.js", lines.join("\n"));
console.log("OK: inserted " + block.length + " lines before line " + (idx + 1));

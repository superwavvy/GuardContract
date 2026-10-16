var fs = require("fs");
var s = fs.readFileSync("scanner.js","utf8");

var helper = [
"",
"function postClassify(findings) {",
"  for (var i = 0; i < findings.length; i++) {",
"    var f = findings[i];",
"    var t = String(f.type || '').toLowerCase();",
"    // Strip 'Front-Running / ' style prefixes the LLM adds when hedging",
"    f.type = String(f.type || '').replace(/^Front-?Running\\s*\\/\\s*/i, '').trim();",
"    t = f.type.toLowerCase();",
"    // Share-accounting / pool-balance = always CRITICAL (direct fund loss, no role needed)",
"    if (/share.?accounting|pool.?balance|logic error/.test(t) && /releasable|totalTokenShares|balanceOf\\(address\\(this\\)\\)|release/i.test(f.description || '')) {",
"      f.severity = 'CRITICAL';",
"      f.type = 'Share Accounting / Pool-Balance Logic Error';",
"    }",
"    // Reentrancy on a nonReentrant function = drop if description doesn't name a bypass",
"    if (/reentr/.test(t) && !/bypass|without.*guard|guard.*bypass/i.test(f.description || '')) {",
"      f._suspectReentrancy = true;",
"    }",
"  }",
"  return findings;",
"}",
""
].join("\n");

var anchor = "function mergeAndDedupe(patterns, llm) {";
if (s.indexOf(anchor) === -1) { console.error("anchor missing"); process.exit(1); }
s = s.replace(anchor, helper + anchor);

// Call postClassify right before returning from mergeAndDedupe — find the 'return final;' line
var ret = "  return final;\n}";
var retNew = "  return postClassify(final);\n}";
if (s.indexOf(ret) === -1) { console.error("return anchor missing"); process.exit(1); }
s = s.replace(ret, retNew);

fs.writeFileSync("scanner.js", s);
console.log("OK: postClassify patched");

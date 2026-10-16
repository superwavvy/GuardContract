var fs = require("fs");
var s = fs.readFileSync("scanner.js", "utf8");
var orig = s;

s = s.replace("var CHUNK_LINES = 800;", "var CHUNK_LINES = 400;");

var earlyA = 'if (!file._llmStatuses) file._llmStatuses = {};\nfile._llmStatuses[file.path] = llmStatus;';
if (s.indexOf(earlyA) === -1) { console.error("FAIL: early write anchor not found"); process.exit(1); }
s = s.replace(earlyA, 'if (!file._llmStatuses) file._llmStatuses = {};');
console.log("OK: removed early status write");

var anchor = '    var merged = mergeAndDedupe(patterns, llmFindings);';
if (s.indexOf(anchor) === -1) { console.error("FAIL: merge anchor not found"); process.exit(1); }
s = s.replace(anchor, '    file._llmStatuses[file.path] = llmStatus;\n\n' + anchor);
console.log("OK: added late status write");

if (s === orig) { console.error("FAIL: nothing changed"); process.exit(1); }
fs.writeFileSync("scanner.js", s);
console.log("OK: scanner.js written");

delete require.cache[require.resolve("./scanner.js")];
require("./scanner.js");
console.log("OK: scanner.js loads");

var fs = require("fs");
var s = fs.readFileSync("scanner.js", "utf8");

// 1. LLM only on primary file or pattern-hit files
var old = 'var llmFindings = [];\n    var llmStatus = "ok";\n    var chunks = splitIntoChunks(file.content, CHUNK_LINES, CHUNK_OVERLAP);';

var neo = [
'var llmFindings = [];',
'var llmStatus = "ok";',
'var shouldLLM = (file.path === contract.primaryFile.path) || patterns.length > 0;',
'var chunks = shouldLLM ? splitIntoChunks(file.content, CHUNK_LINES, CHUNK_OVERLAP) : [];',
'if (!shouldLLM) {',
'  llmStatus = "skipped_secondary";',
'  console.log("  LLM skip (secondary): " + file.path);',
'}',
'if (!file._llmStatuses) file._llmStatuses = {};',
'file._llmStatuses[file.path] = llmStatus;'
].join("\n");

if (s.indexOf(old) === -1) { console.error("FAIL: LLM block anchor not found"); process.exit(1); }
s = s.replace(old, neo);

// 2. Throttle between chunks
var loopOld = 'for (var ci = 0; ci < chunks.length; ci++) {\n      var c = chunks[ci];';
var loopNew = 'for (var ci = 0; ci < chunks.length; ci++) {\n      if (ci > 0) await new Promise(function(r){ setTimeout(r, 2500); });\n      var c = chunks[ci];';

if (s.indexOf(loopOld) === -1) { console.error("FAIL: chunk loop anchor not found"); process.exit(1); }
s = s.replace(loopOld, loopNew);

fs.writeFileSync("scanner.js", s);
console.log("OK: scanner.js patched (LLM only on primary/pattern-hit + 2.5s throttle)");

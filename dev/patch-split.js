var fs = require("fs");
var src = fs.readFileSync("scanner.js", "utf8");

if (src.indexOf("analyzeWithSplit") !== -1) {
  console.log("Already patched, aborting.");
  process.exit(1);
}

var newFuncs = String.raw`var MAX_CHUNK_CHARS = 8000;

function splitIntoChunks(content, maxChars, overlap) {
  var lines = content.split("\n");
  var chunks = [], start = 0;
  while (start < lines.length) {
    var size = 0, end = start;
    while (end < lines.length &&
           (end === start || size + lines[end].length + 8 <= maxChars)) {
      size += lines[end].length + 8;
      end++;
    }
    chunks.push({ text: lines.slice(start, end).join("\n"), startLine: start + 1 });
    if (end >= lines.length) break;
    start = Math.max(end - overlap, start + 1);
  }
  return chunks;
}

async function analyzeWithSplit(c, file, contract, chain, tier, depth) {
  var numbered = c.text.split("\n").map(function(line, idx) {
    return (idx + 1) + ": " + line;
  }).join("\n");
  try {
    return await analyzeChunk(numbered, c.startLine, file.path, contract, chain, tier);
  } catch (e) {
    var lines = c.text.split("\n");
    if (e.code === "LLM_SKIPPED_OVERSIZED" && depth < 4 && lines.length > 20) {
      var mid = Math.floor(lines.length / 2);
      var a = { text: lines.slice(0, mid + 10).join("\n"), startLine: c.startLine };
      var b = { text: lines.slice(mid - 10).join("\n"), startLine: c.startLine + mid - 10 };
      var ra = await analyzeWithSplit(a, file, contract, chain, tier, depth + 1);
      var rb = await analyzeWithSplit(b, file, contract, chain, tier, depth + 1);
      return ra.concat(rb);
    }
    throw e;
  }
}

`;

// Edit A FIRST: loop body (before new code exists in the file)
var before = src;
var re = /var numbered = c\.text[\s\S]*?\}\)\.join\("\\n"\);\s*try \{\s*var cf = await analyzeChunk\(numbered, c\.startLine, file\.path, contract, chain, tier\);/;
src = src.replace(re, function() {
  return "try {\n        var cf = await analyzeWithSplit(c, file, contract, chain, tier, 0);";
});
if (src === before) { console.log("Loop edit failed"); process.exit(1); }

// Edit B: use the char limit
before = src;
src = src.replace("splitIntoChunks(file.content, CHUNK_LINES, CHUNK_OVERLAP)",
                  "splitIntoChunks(file.content, MAX_CHUNK_CHARS, CHUNK_OVERLAP)");
if (src === before) { console.log("Limit edit failed"); process.exit(1); }

// Edit C LAST: swap in the new functions
var s = src.indexOf("function splitIntoChunks");
var e = src.indexOf("async function scanContract");
if (s < 0 || e < 0) { console.log("Could not find function boundaries"); process.exit(1); }
src = src.slice(0, s) + newFuncs + src.slice(e);

fs.writeFileSync("scanner.js", src);
console.log("Patched OK");

var fs = require("fs");

// ---- Patch scanner.js ----
var scanner = fs.readFileSync("scanner.js", "utf8");

var helper = [
"",
"var CHUNK_LINES = 250;",
"var CHUNK_OVERLAP = 30;",
"",
"function splitIntoChunks(content, maxLines, overlap) {",
"  var lines = content.split(\"\\n\");",
"  if (lines.length <= maxLines) {",
"    return [{ text: content, startLine: 1 }];",
"  }",
"  var chunks = [];",
"  var start = 0;",
"  while (start < lines.length) {",
"    var end = Math.min(start + maxLines, lines.length);",
"    chunks.push({",
"      text: lines.slice(start, end).join(\"\\n\"),",
"      startLine: start + 1",
"    });",
"    if (end === lines.length) break;",
"    start = end - overlap;",
"  }",
"  return chunks;",
"}",
""
].join("\n");

var anchor1 = 'var cache = require("./cache.js");';
var idx1 = scanner.indexOf(anchor1);
if (idx1 === -1) { console.error("scanner.js: anchor1 (cache require) not found"); process.exit(1); }
var insertAt = scanner.indexOf("\n", idx1) + 1;
scanner = scanner.slice(0, insertAt) + helper + scanner.slice(insertAt);

var oldBlock = [
'    var numbered = file.content.split("\\n").map(function(line, idx) {',
'      return (idx + 1) + ": " + line;',
'    }).join("\\n");',
'',
'    var llmFindings = [];',
'    try {',
'      llmFindings = await analyzeChunk(numbered, 1, file.path, contract, chain, tier);',
'    } catch (e) {',
'      console.log("  LLM failed on " + file.path + ": " + e.message);',
'    }'
].join("\n");

var newBlock = [
'    var llmFindings = [];',
'    var llmStatus = "ok";',
'    var chunks = splitIntoChunks(file.content, CHUNK_LINES, CHUNK_OVERLAP);',
'',
'    for (var ci = 0; ci < chunks.length; ci++) {',
'      var c = chunks[ci];',
'      var numbered = c.text.split("\\n").map(function(line, idx) {',
'        return (idx + 1) + ": " + line;',
'      }).join("\\n");',
'      try {',
'        var cf = await analyzeChunk(numbered, c.startLine, file.path, contract, chain, tier);',
'        llmFindings = llmFindings.concat(cf);',
'      } catch (e) {',
'        if (e.code === "LLM_SKIPPED_OVERSIZED") {',
'          llmStatus = "skipped_oversized";',
'          console.log("  LLM SKIPPED (oversized): " + file.path + " chunk " + ci);',
'        } else {',
'          if (llmStatus !== "skipped_oversized") llmStatus = "failed";',
'          console.log("  LLM failed: " + file.path + " chunk " + ci + " - " + e.message);',
'        }',
'      }',
'    }'
].join("\n");

if (scanner.indexOf(oldBlock) === -1) { console.error("scanner.js: LLM block anchor not found"); process.exit(1); }
scanner = scanner.replace(oldBlock, newBlock);

fs.writeFileSync("scanner.js", scanner);
console.log("patched: scanner.js");

// ---- Patch analyzer.js ----
var analyzer = fs.readFileSync("analyzer.js", "utf8");

// Add share-accounting focus item to the prompt
var oldFocus = "11. Signature replay / missing nonce";
var newFocus = "11. Signature replay / missing nonce\n12. Share-accounting / pool-balance logic errors (payout uses contract-wide balance instead of per-user tracked deposit)";
if (analyzer.indexOf(oldFocus) !== -1) {
  analyzer = analyzer.replace(oldFocus, newFocus);
  console.log("patched: analyzer.js prompt (added focus #12)");
}

var startIdx = analyzer.indexOf("async function analyzeChunk");
var endIdx = analyzer.indexOf("async function classifyScope");
if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
  console.error("analyzer.js: could not locate analyzeChunk / classifyScope boundaries");
  process.exit(1);
}

var newFn = [
'async function analyzeChunk(numberedText, startLine, path, contract, chain, tier) {',
'  var MAX_PROMPT_CHARS = 55000;',
'  var MAX_RETRIES = 3;',
'',
'  if (numberedText.length > MAX_PROMPT_CHARS) {',
'    var err = new Error("LLM_SKIPPED_OVERSIZED: " + numberedText.length + " chars > " + MAX_PROMPT_CHARS + " for " + path);',
'    err.code = "LLM_SKIPPED_OVERSIZED";',
'    throw err;',
'  }',
'',
'  var prompt = buildPrompt(',
'    contract.contractName,',
'    contract.compilerVersion,',
'    chain,',
'    path,',
'    numberedText',
'  );',
'',
'  var lastErr = null;',
'  for (var attempt = 1; attempt <= MAX_RETRIES; attempt++) {',
'    var response = await fetch("https://api.groq.com/openai/v1/chat/completions", {',
'      method: "POST",',
'      headers: {',
'        "Authorization": "Bearer " + process.env.GROQ_API_KEY,',
'        "Content-Type": "application/json",',
'      },',
'      body: JSON.stringify({',
'        model: "openai/gpt-oss-120b",',
'        messages: [{ role: "user", content: prompt }],',
'        response_format: { type: "json_object" },',
'        temperature: 0,',
'      }),',
'    });',
'',
'    if (response.ok) {',
'      var data = await response.json();',
'      if (!data.choices || !data.choices[0]) throw new Error("Malformed LLM response");',
'      var parsed = safeParseJSON(data.choices[0].message.content);',
'      if (!parsed || !parsed.vulnerabilities) return [];',
'      return parsed.vulnerabilities.map(function(v) {',
'        return Object.assign({}, v, {',
'          file: path,',
'          line: (v.line || 0) + startLine - 1,',
'          cwe_id: CWE_MAP[v.type] || v.cwe_id || "CWE-UNKNOWN",',
'        });',
'      });',
'    }',
'',
'    var bodyText = "";',
'    try { bodyText = await response.text(); } catch (e) { bodyText = ""; }',
'    lastErr = new Error("Groq API error: " + response.status + " - " + bodyText.slice(0, 400));',
'',
'    if (response.status === 413) {',
'      lastErr.code = "LLM_SKIPPED_OVERSIZED";',
'      throw lastErr;',
'    }',
'',
'    if (response.status === 429 && attempt < MAX_RETRIES) {',
'      var ra = parseInt(response.headers.get("retry-after") || "10", 10);',
'      console.warn("[analyzer] 429 on " + path + ", retry in " + ra + "s (" + attempt + "/" + MAX_RETRIES + ")");',
'      await new Promise(function(r) { setTimeout(r, ra * 1000); });',
'      continue;',
'    }',
'',
'    throw lastErr;',
'  }',
'  throw lastErr;',
'}',
'',
''
].join("\n");

analyzer = analyzer.slice(0, startIdx) + newFn + analyzer.slice(endIdx);
fs.writeFileSync("analyzer.js", analyzer);
console.log("patched: analyzer.js");

console.log("\nDONE. Backups: scanner.js.pre-chunk, analyzer.js.pre-chunk");

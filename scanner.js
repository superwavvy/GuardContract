var callerAnalyzer = require("./caller-analyzer.js");
var applyCallerAnalysis = callerAnalyzer.applyCallerAnalysis;
var etherscan = require("./etherscan.js");
var fetchContract = etherscan.fetchContract;
var detectChain = etherscan.detectChain;

var solPatterns = require("./sol-patterns.js");
var runPatterns = solPatterns.runPatterns;

var solVersion = require("./sol-version.js");
var parseSolidityVersion = solVersion.parseSolidityVersion;
var versionTier = solVersion.versionTier;

var analyzer = require("./analyzer.js");
var analyzeChunk = analyzer.analyzeChunk;
var classifyScope = analyzer.classifyScope;

var guardscanPatch = require("./guardscan-patch.js");
var applyVerification = guardscanPatch.applyVerification;

var scope = require("./scope.js");
var getScope = scope.getScope;

var cache = require("./cache.js");

var CHUNK_LINES = 400;
var CHUNK_OVERLAP = 30;

var MAX_CHUNK_CHARS = 15000;

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

async function scanContract(address, chainArg) {
  var chain = chainArg || (await detectChain(address));
  if (!chain) {
    return { ok: false, reason: "Contract not found on any supported chain." };
  }

  var cached = cache.get(address, chain);
  if (cached) {
    console.log("Cache hit: " + address + " on " + chain);
    var cachedReport = Object.assign({}, cached);
    cachedReport.cached = true;
    return cachedReport;
  }

  console.log("\nScanning " + address + " on " + chain);

  var contract = await fetchContract(address, chain);
  if (!contract.ok) return contract;

  console.log(contract.contractName + " - " + contract.files.length + " file(s)");

  var primarySource = contract.primaryFile.content;
  var version = parseSolidityVersion(primarySource);
  var tier = versionTier(version);
  console.log("Pragma: " + (version.raw || "?") + " -> tier " + tier);

  var allFindings = [];

  for (var i = 0; i < contract.files.length; i++) {
    var file = contract.files[i];

    // Skip library code — only audit project source
    if (/^(node_modules|lib|@openzeppelin|@chainlink|@uniswap)\//i.test(file.path)) continue;
    if (/\/node_modules\//i.test(file.path)) continue;
    if (/\.sol$/.test(file.path) === false) continue;
    var head = file.content.slice(0, 300);
    if (/^\s*(pragma[^;]*;\s*)?(interface|library)\s+\w+/m.test(head)) continue;

    var patterns = runPatterns(file.content, file.path, tier);
    if (patterns.length > 0) {
      console.log("  pattern: " + file.path + " -> " + patterns.length + " findings");
    }

    var llmFindings = [];
var llmStatus = "ok";
var shouldLLM = (file.path === contract.primaryFile.path) || patterns.length > 0;
var chunks = shouldLLM ? splitIntoChunks(file.content, MAX_CHUNK_CHARS, CHUNK_OVERLAP) : [];
if (!shouldLLM) {
  llmStatus = "skipped_secondary";
  console.log("  LLM skip (secondary): " + file.path);
}
if (!file._llmStatuses) file._llmStatuses = {};

    for (var ci = 0; ci < chunks.length; ci++) {
      if (ci > 0) await new Promise(function(r){ setTimeout(r, 8000); });
      var c = chunks[ci];
      try {
        var cf = await analyzeWithSplit(c, file, contract, chain, tier, 0);
        llmFindings = llmFindings.concat(cf);
      } catch (e) {
        if (e.code === "LLM_SKIPPED_OVERSIZED") {
          llmStatus = "skipped_oversized";
          console.log("  LLM SKIPPED (oversized): " + file.path + " chunk " + ci);
        } else {
          if (llmStatus !== "skipped_oversized") llmStatus = "failed";
          console.log("  LLM failed: " + file.path + " chunk " + ci + " - " + e.message);
        }
      }
    }

    file._llmStatuses[file.path] = llmStatus;

    if (process.env.GC_DEBUG_RAW) {
  console.log("=== RAW LLM for " + file.path + " ===");
  console.log(JSON.stringify(llmFindings, null, 2));
}

    if (process.env.GC_DEBUG_STAGES) {
  console.log("  [STAGE] raw llm: " + llmFindings.length + " @ " + llmFindings.map(function(f){return f.line}).join(","));
}
    var merged = mergeAndDedupe(patterns, llmFindings);
if (process.env.GC_DEBUG_STAGES) {
  console.log("  [STAGE] after merge: " + merged.length + " @ " + merged.map(function(f){return f.line}).join(","));
}
    var verified = applyVerification(merged, file.content, { verbose: false });
    var classified = applyCallerAnalysis(verified, file.content);
    classified = classified.filter(function(f) { return f.severity !== "LOW"; });
    allFindings = allFindings.concat(classified);
  }

  var scopeLabeled = allFindings;
  var currentScope = getScope();
  if (currentScope && allFindings.length > 0) {
    try {
      scopeLabeled = await classifyScope(allFindings, currentScope);
    } catch (e) {
      console.log("  Scope classification failed: " + e.message);
    }
  }

  var report = {
    ok: true,
    address: address,
    chain: chain,
    contractName: contract.contractName,
    compilerVersion: contract.compilerVersion,
    implAddress: contract.implAddress,
    proxyOf: contract.proxyOf,
    implUnverified: contract.implUnverified,
    solidityRange: version.raw,
    tier: tier,
    filesAnalyzed: contract.files.length,
    llmStatus: (function() {
      var c = { ok: 0, skipped_secondary: 0, skipped_oversized: 0, failed: 0, filtered: 0 };
      for (var k = 0; k < contract.files.length; k++) {
        var f = contract.files[k];
        var st = (f._llmStatuses && f._llmStatuses[f.path]) || "filtered";
        c[st] = (c[st] || 0) + 1;
      }
      return c;
    })(),
    findings: scopeLabeled,
    scoped: !!currentScope
  };

  cache.set(address, chain, report);
  return report;
}

function familyOf(type) {
  var t = String(type || "").toLowerCase();
  if (t.indexOf("reentrancy") !== -1) return "reentrancy";
  if (t.indexOf("legacy .call.value") !== -1) return "reentrancy";
  if (t.indexOf("unchecked low-level call") !== -1) return "unchecked-call";
  if (t.indexOf("unchecked erc20 transfer") !== -1) return "unchecked-call";
  if (t.indexOf("integer overflow") !== -1) return "arithmetic";
  if (t.indexOf("overflow") !== -1) return "arithmetic";
  if (t.indexOf("underflow") !== -1) return "arithmetic";
  if (t.indexOf("unchecked external call") !== -1) return "unchecked-call";
  if (t.indexOf("unchecked low-level call") !== -1) return "unchecked-call";
  if (t.indexOf("integer underflow") !== -1) return "arithmetic";
  if (t.indexOf("unbounded loop") !== -1) return "unbounded-loop";
  if (t.indexOf("denial of service") !== -1) return "unbounded-loop";
  if (t.indexOf("dos") !== -1) return "unbounded-loop";
  return t;
}


function postClassify(findings) {
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    var t = String(f.type || '').toLowerCase();
    // Strip 'Front-Running / ' style prefixes the LLM adds when hedging
    f.type = String(f.type || '').replace(/^Front-?Running\s*\/\s*/i, '').trim();
    t = f.type.toLowerCase();
    // Share-accounting / pool-balance = always CRITICAL (direct fund loss, no role needed)
    if (/share.?accounting|pool.?balance|logic error/.test(t) && /releasable|totalTokenShares|balanceOf\(address\(this\)\)|release/i.test(f.description || '')) {
      f.severity = 'CRITICAL';
      f.type = 'Share Accounting / Pool-Balance Logic Error';
    }
    // Reentrancy on a nonReentrant function = drop if description doesn't name a bypass
    if (/reentr/.test(t) && !/bypass|without.*guard|guard.*bypass/i.test(f.description || '')) {
      f._suspectReentrancy = true;
    }
  }
  return findings;
}
function mergeAndDedupe(patterns, llm) {
  var map = {};

  for (var i = 0; i < patterns.length; i++) {
    var p = patterns[i];
    var fam = familyOf(p.type);
    var anchor = p.file + "::" + p.line + "::" + fam;
    if (!map[anchor]) map[anchor] = p;
  }

  for (var j = 0; j < llm.length; j++) {
    var l = llm[j];
    var _lt = String(l.type || "").toLowerCase();
    var _isSymptom = _lt.indexOf("access control") !== -1 || _lt.indexOf("authorization") !== -1 || _lt.indexOf("centralization") !== -1;
    var _hasStrongPattern = patterns.some(function(p) { return p.severity === "CRITICAL" || p.severity === "HIGH"; });
    if (_isSymptom && _hasStrongPattern) continue;
    var famL = familyOf(l.type);
    var anchorL = l.file + "::" + l.line + "::" + famL;
    if (!map[anchorL]) {
      var copy = Object.assign({}, l);
      copy.source = "llm";
      map[anchorL] = copy;
    } else {
      map[anchorL].source = "both";
      map[anchorL].corroborated = true;
    }
  }

  var all = Object.keys(map).map(function(k) { return map[k]; });

  var sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  all.sort(function(a, b) {
    var sa = sevOrder[a.severity] !== undefined ? sevOrder[a.severity] : 9;
    var sb = sevOrder[b.severity] !== undefined ? sevOrder[b.severity] : 9;
    if (sa !== sb) return sa - sb;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  var familyCount = {};
  var final = [];
  for (var k = 0; k < all.length; k++) {
    var f = all[k];
    var famF = familyOf(f.type);
    familyCount[famF] = (familyCount[famF] || 0) + 1;
    if (familyCount[famF] <= 3) {
      final.push(f);
    }
  }

  return postClassify(final);
}

module.exports = {
  scanContract: scanContract
};

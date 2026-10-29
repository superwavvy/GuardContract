// caller-analyzer.js - caller classification with call-chain awareness

function lineNumberAt(source, index) {
  return source.substring(0, index).split("\n").length;
}

function findFunctionStart(lines, fromLine) {
  var i = fromLine;
  while (i > 0 && !/function\s+\w+\s*\(/.test(lines[i])) i--;
  return i;
}

function findFunctionEnd(lines, fromLine) {
  var depth = 0, started = false;
  for (var i = fromLine; i < lines.length; i++) {
    var line = lines[i];
    for (var j = 0; j < line.length; j++) {
      var ch = line[j];
      if (ch === "{") { depth++; started = true; }
      else if (ch === "}") depth--;
    }
    if (started && depth === 0) return i + 1;
  }
  return lines.length;
}

function extractFunctions(source) {
  var lines = source.split("\n");
  var fns = [];
  var fnRe = /function\s+(\w+)\s*\(/;
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(fnRe);
    if (!m) continue;
    var sig = lines[i];
    for (var j = i + 1; j < Math.min(i + 15, lines.length); j++) {
      sig += " " + lines[j];
      if (/{/.test(lines[j])) break;
    }
    var vis = "internal";
    if (/\b(external|public)\b/.test(sig)) vis = "external";
    else if (/\bprivate\b/.test(sig)) vis = "private";
    var end = findFunctionEnd(lines, i);
    var body = lines.slice(i, end).join("\n");
    fns.push({ name: m[1], visibility: vis, startLine: i, endLine: end, body: body });
  }
  return fns;
}

function findExternalEntry(source, targetFnName, visited, depth) {
  if (!visited) visited = {};
  if (depth === undefined) depth = 0;
  if (depth > 6) return null;
  if (visited[targetFnName]) return null;
  visited[targetFnName] = true;

  var fns = extractFunctions(source);
  var target = null;
  for (var i = 0; i < fns.length; i++) {
    if (fns[i].name === targetFnName) { target = fns[i]; break; }
  }
  if (!target) return null;
  if (target.visibility === "external") return targetFnName;

  var callRe = new RegExp("\\b" + targetFnName + "\\s*\\(", "g");
  for (var i = 0; i < fns.length; i++) {
    if (fns[i].name === targetFnName) continue;
    callRe.lastIndex = 0;
    if (!callRe.test(fns[i].body)) continue;
    if (fns[i].visibility === "external") return fns[i].name;
    var up = findExternalEntry(source, fns[i].name, visited, depth + 1);
    if (up) return up;
  }
  return null;
}

function classifyCaller(fnHeader, fnBody, source) {
  var result = { gated: false, reason: null, signature: fnHeader.trim().slice(0, 150) };
  
  // NEW: Detect if the source is a library
  if (/(^|\n)\s*library\s+\w+/.test(source)) {
    result.gated = true;
    result.reason = "Library function (not directly callable)";
    return result;
  }

  var result = { gated: false, reason: null, signature: fnHeader.trim().slice(0, 150) };

  var sigText = fnHeader;
  if (fnBody) {
    var braceIdx = fnBody.indexOf("{");
    if (braceIdx > 0) sigText = fnHeader + " " + fnBody.slice(0, braceIdx);
  }

  // only* modifier
  var modMatch = sigText.match(/\bonly([A-Z]\w*)\b/);
  if (modMatch) {
    result.gated = true;
    result.reason = "only" + modMatch[1] + " modifier";
    return result;
  }

  // Body owner checks
  var head = fnBody.slice(0, 600);
  if (/require\s*\(\s*msg\.sender\s*==\s*owner\s*\)/i.test(head)) {
    result.gated = true;
    result.reason = "require(msg.sender == owner)";
    return result;
  }
  if (/require\s*\(\s*owner\s*==\s*msg\.sender\s*\)/i.test(head)) {
    result.gated = true;
    result.reason = "require(owner == msg.sender)";
    return result;
  }

  // Internal/private - walk call chain
  if (/\b(private|internal)\b/.test(sigText)) {
    var fnNameMatch = sigText.match(/function\s+(\w+)/);
    if (fnNameMatch && source) {
      var entry = findExternalEntry(source, fnNameMatch[1], {}, 0);
      if (entry) {
        result.gated = false;
        result.reason = "internal, reachable via public caller: " + entry;
        return result;
      }
    }
    result.gated = true;
    result.reason = "private/internal, no external caller";
    return result;
  }

  result.gated = false;
  result.reason = "external/public, no owner gate detected";
  return result;
}

function adjustFindingForCaller(finding, source) {
  if (!source || !finding.line) return finding;
  var lines = source.split("\n");
  var lineIdx = finding.line - 1;
  if (lineIdx < 0 || lineIdx >= lines.length) return finding;
  var fnStart = findFunctionStart(lines, lineIdx);
  if (fnStart === lineIdx && !/function\s+\w+\s*\(/.test(lines[lineIdx])) return finding;
  var fnEnd = findFunctionEnd(lines, fnStart);
  var fnHeader = lines[fnStart];
  var fnBody = lines.slice(fnStart, fnEnd).join("\n");
  var classification = classifyCaller(fnHeader, fnBody, source);
  var adjusted = Object.assign({}, finding);
  adjusted.caller = {
    gated: classification.gated,
    reason: classification.reason,
    function: classification.signature
  };
  if (classification.gated) {
    var demote = { CRITICAL: "HIGH", HIGH: "MEDIUM", MEDIUM: "LOW", LOW: "LOW" };
    var original = adjusted.severity;
    adjusted.severity = demote[original] || original;
    adjusted.demoted_reason = "Owner-gated function: " + classification.reason;
    adjusted.original_severity = original;
  }
  return adjusted;
}

function applyCallerAnalysis(findings, source) {
  if (!source) return findings;
  var out = [];
  for (var i = 0; i < findings.length; i++) {
    out.push(adjustFindingForCaller(findings[i], source));
  }
  return out;
}

module.exports = {
  applyCallerAnalysis: applyCallerAnalysis,
  classifyCaller: classifyCaller,
  findFunctionStart: findFunctionStart,
  findFunctionEnd: findFunctionEnd
};

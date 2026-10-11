const STRICT_TYPES = [
  "reentrancy", "overflow", "underflow", "sql injection",
  "tx.origin", "delegatecall", "selfdestruct", "unchecked",
  "signature", "ecrecover", "timestamp", "blockhash",
  "hardcoded", "uninitialized"
];

function isStrictType(type) {
  const t = String(type || "").toLowerCase();
  return STRICT_TYPES.some((s) => t.includes(s));
}

const normalize = (s) => String(s || "").replace(/\s+/g, " ").trim().toLowerCase();

function cleanSnippet(snippet) {
  return String(snippet || "").replace(/(^|\n)\s*\d+:\s?/g, "$1").trim();
}

function verifyFinding(finding, lines, radius = 3) {
  const line = Number(finding.line);
  if (!Number.isInteger(line) || line < 1 || line > lines.length) {
    return { ok: false, reason: "line out of range" };
  }
  const cleaned = cleanSnippet(finding.code_snippet);
  if (!cleaned) {
    return isStrictType(finding.type)
      ? { ok: false, reason: "no code_snippet" }
      : { ok: true, relaxed: true, reason: "design-level: no snippet" };
  }
  const probe = normalize(cleaned.split("\n")[0]).slice(0, 60);
  if (probe.length < 8) {
    return isStrictType(finding.type)
      ? { ok: false, reason: "snippet too short" }
      : { ok: true, relaxed: true, reason: "design-level: short snippet" };
  }
  const from = Math.max(0, line - 1 - radius);
  const to = Math.min(lines.length, line + radius);
  const windowText = normalize(lines.slice(from, to).join(" "));
  if (windowText.includes(probe)) return { ok: true };

  if (!isStrictType(finding.type)) {
    const lineContent = normalize(lines[line - 1] || "");
    if (lineContent.length > 15) {
      return { ok: true, relaxed: true, reason: "design-level: line exists" };
    }
  }
  return { ok: false, reason: "snippet not found near line" };
}

function applyVerification(findings, content, { dropUnverified = false, verbose = true } = {}) {
  const lines = content.split("\n");
  const out = [];
  let verified = 0, relaxed = 0, downgraded = 0, dropped = 0;

  for (const f of findings) {
    if (f.source === "pattern" || f.source === "both") { out.push(f); continue; }
    const v = verifyFinding(f, lines);
    if (v.ok) {
      out.push({ ...f, verified: !v.relaxed, verify_note: v.reason || null });
      if (v.relaxed) relaxed++; else verified++;
    } else if (!dropUnverified) {
      out.push({ ...f, verified: false, confidence: "LOW", verify_note: v.reason });
      downgraded++;
    } else dropped++;
  }
  if (verbose && findings.length > 0) {
    console.log(`   📊 Verify: ${verified} strict, ${relaxed} relaxed, ${downgraded} downgraded, ${dropped} dropped`);
  }
  return out;
}

module.exports = { applyVerification, verifyFinding, isStrictType };

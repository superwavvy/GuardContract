function parseSolidityVersion(source) {
  const m = source.match(/pragma\s+solidity\s+([^;]+);/);
  if (!m) return { raw: null, min: null, max: null, hasPre08: false };

  const raw = m[1].trim();
  const versions = raw.match(/\d+\.\d+\.\d+/g) || [];
  if (!versions.length) return { raw, min: null, max: null, hasPre08: false };

  const toNum = (v) => {
    const [a, b, c] = v.split(".").map(Number);
    return a * 10000 + b * 100 + c;
  };

  const nums = versions.map(toNum);
  const min = Math.min(...nums);
  const max = Math.max(...nums);

  const hasUpperBound = /</.test(raw);
  const hasCaret = /\^/.test(raw);
  const hasTilde = /~/.test(raw);
  const has08OrHigher = /0\.[89]\./.test(raw) || /\^0\.[89]/.test(raw) || />=\s*0\.[89]/.test(raw);
  const isLocked = !hasUpperBound && !hasCaret && !hasTilde && versions.length === 1;
  const hasPre08 = !has08OrHigher || min < toNum("0.8.0");

  return { raw, min, max, hasPre08, isLocked, has08OrHigher };
}

function versionTier(parsed) {
  if (!parsed.raw) return "unknown";
  if (parsed.hasPre08) return "pre08";
  if (parsed.has08OrHigher) return "post08";
  return "unknown";
}

module.exports = { parseSolidityVersion, versionTier };

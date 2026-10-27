// Solidity pattern rules — context-aware, function-anchored.
// Design: high signal over high recall.

const SOL_PATTERNS = [
  {
    id: "tx-origin-auth",
    type: "tx.origin Authorization",
    severity: "HIGH",
    cwe_id: "CWE-477",
    pattern: /\btx\.origin\b/g,
    description: "tx.origin used for authorization. A malicious contract can phish a user into calling it, which then calls your contract as the victim.",
    fix: "Use msg.sender for authorization, never tx.origin."
  },
  {
    id: "selfdestruct",
    type: "selfdestruct Present",
    severity: "CRITICAL",
    cwe_id: "CWE-284",
    pattern: /selfdestruct\s*\(/g,
    description: "Contract contains selfdestruct(). If reachable by non-owner, attacker can destroy the contract and force-send ETH.",
    fix: "Remove selfdestruct, or protect with onlyOwner + timelock."
  },
  {
    id: "delegatecall",
    type: "delegatecall Usage",
    severity: "HIGH",
    cwe_id: "CWE-829",
    pattern: /\.delegatecall\s*\(/g,
    description: "delegatecall executes external code in this contract's storage context. If the target is attacker-controllable, storage (including owner) can be overwritten.",
    fix: "Never delegatecall to user-supplied addresses. Use an immutable allowlist."
  },
  {
    id: "unchecked-math-pre-08",
    type: "Integer Overflow / Underflow",
    severity: "HIGH",
    cwe_id: "CWE-190",
    pattern: /^(?!\s*(?:\/\/|\/\*|\*))(?!.*\.(?:add|sub|mul)\()(?=.*(?:[\w)\]]\s*\*\s*[\w(]|[+\-*]=|[\w)\]]\s*(?<![+\-])[+\-](?![+\-=])\s*[\w(])).*$/gm,
    description: "Solidity <0.8.0 has no built-in overflow checks. Arithmetic without SafeMath can silently wrap.",
    fix: "Use SafeMath, or upgrade to Solidity 0.8.0+.",
    precondition: function(source, tier) {
      return tier === "pre08" || (tier === "post08" && source.includes("unchecked"));
    }
  },
  {
    id: "legacy-call-value",
    type: "Legacy .call.value()",
    severity: "MEDIUM",
    cwe_id: "CWE-841",
    pattern: /\.call\.value\s*\(/g,
    description: "Legacy .call.value() forwards all gas to the recipient. Potential reentrancy vector if state changes after the call and the function lacks a reentrancy guard.",
    fix: "Use .call{value: x}(\"\") with a gas cap, apply checks-effects-interactions, or add nonReentrant."
  },
  {
    id: "unchecked-low-level-call",
    type: "Unchecked Low-Level Call",
    severity: "HIGH",
    cwe_id: "CWE-252",
    pattern: /\.(call|send)\s*(?:\{[^}]*\})?\s*\([^;]*\)\s*;/g,
    description: "Return value of low-level call appears unchecked. A failed call will silently continue and corrupt state.",
    fix: "Wrap in require(call(...)) or check the boolean return value.",
    contextCheck: function(source, idx) {
      var after = source.slice(idx, idx + 500);
      if (/require\s*\(/.test(after.slice(0, 250))) return false;
      if (/if\s*\(\s*(?:!\s*)?(?:success|ok|sent|result|ret)/i.test(after.slice(0, 250))) return false;
      if (/verifyCallResult/i.test(after.slice(0, 400))) return false;
      if (/Address\.verify/i.test(after.slice(0, 400))) return false;
      return true;
    }
  },
  {
    id: "transfer-return-ignored",
    type: "Unchecked ERC20 Transfer",
    severity: "MEDIUM",
    cwe_id: "CWE-252",
    pattern: /\.transfer(?:From)?\s*\([^)]*\)\s*;/g,
    description: "ERC20 transfer/transferFrom return value ignored. Some tokens (USDT, BNB) return false instead of reverting on failure.",
    fix: "Use SafeERC20's safeTransfer / safeTransferFrom, or wrap in require().",
    contextCheck: function(source, idx) {
      var after = source.slice(idx, idx + 300);
      if (/require\s*\(/.test(after.slice(0, 200))) return false;
      var lineStart = source.lastIndexOf("\n", idx) + 1;
      var lineEnd = source.indexOf("\n", idx);
      var line = source.substring(lineStart, lineEnd === -1 ? source.length : lineEnd);
      if (/(owner|payable|msg\.sender|address\(this\)|this)\.transfer/i.test(line)) return false;
      return true;
    }
  },
  {
    id: "timestamp-randomness",
    type: "Block Timestamp as Randomness",
    severity: "HIGH",
    cwe_id: "CWE-330",
    pattern: /keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*block\.(?:timestamp|number|difficulty|coinbase)/g,
    description: "block.timestamp is predictable and manipulable by validators. Not a secure randomness source.",
    fix: "Use Chainlink VRF or a commit-reveal scheme."
  },
  {
    id: "blockhash-randomness",
    type: "blockhash as Randomness",
    severity: "MEDIUM",
    cwe_id: "CWE-330",
    pattern: /blockhash\s*\(/g,
    description: "blockhash is predictable across the last 256 blocks. Not a secure randomness source.",
    fix: "Use Chainlink VRF."
  },
  {
    id: "unbounded-loop",
    type: "Unbounded Loop (DoS)",
    severity: "MEDIUM",
    cwe_id: "CWE-834",
    pattern: /for\s*\([^;]*;[^;]*\.\s*length\s*;[^)]*\)/g,
    description: "Loop iterates over a dynamic array that can grow. Eventually gas cost exceeds block limit, bricking the function.",
    fix: "Use pagination or cap array length.",
    contextCheck: function(source, idx) {
      var after = source.slice(idx, idx + 1500);
      if (/\bbreak\s*;/.test(after)) return false;

      var m = source.slice(idx, idx + 200).match(/<\s*([a-zA-Z_]\w*)(?:\.\w+)?\.\s*length/);
      if (!m) return true;
      var arrName = m[1];

      var srcLines = source.split("\n");
      var lineNum = source.substring(0, idx).split("\n").length - 1;
      var fnStart = lineNum;
      while (fnStart > 0 && fnStart > lineNum - 60 && !/function\s+\w+\s*\(/.test(srcLines[fnStart])) fnStart--;
      if (fnStart < 0 || !/function\s+\w+\s*\(/.test(srcLines[fnStart])) return true;

      var sig = srcLines[fnStart];
      for (var i = fnStart + 1; i < Math.min(fnStart + 15, srcLines.length); i++) {
        sig += " " + srcLines[i];
        if (/{/.test(srcLines[i])) break;
      }

      var paramRe = new RegExp("\\b" + arrName + "\\b");
      if (paramRe.test(sig)) return false;

      return true;
    },
  },
  {
    id: "owner-mint",
    type: "Owner-Controlled Mint",
    severity: "HIGH",
    cwe_id: "CWE-269",
    pattern: /function\s+mint\s*\([^)]*\)[^{]*\{[^}]*(?:_mint\s*\(|totalSupply\s*\+=|balanceOf\[[^\]]+\]\s*\+=)/gs,
    description: "Owner can mint tokens. If unlimited and unprotected, they can dilute holders to zero.",
    fix: "Add a hard cap, or require multisig + timelock."
  },
  {
    id: "owner-pause",
    type: "Owner Can Pause / Freeze",
    severity: "MEDIUM",
    cwe_id: "CWE-269",
    pattern: /function\s+(pause|freeze|blacklist|freezeAccount)\s*\(/g,
    description: "Contract can be paused or users blacklisted. Owner can freeze all user funds — centralization risk.",
    fix: "Remove pause functionality, or protect with multisig + timelock."
  },
  {
    id: "hardcoded-address",
    type: "Hardcoded Address",
    severity: "LOW",
    cwe_id: "CWE-798",
    pattern: /address\s*\(\s*0x[a-fA-F0-9]{40}\s*\)/g,
    description: "Hardcoded address in source. Could be a privileged wallet or deployer backdoor.",
    fix: "Verify what the address controls and whether it's intentional."
  },
{
    id: "encodePacked-collision",
    type: "abi.encodePacked Collision Risk",
    severity: "MEDIUM",
    cwe_id: "CWE-328",
    pattern: /keccak256\s*\(\s*abi\.encodePacked\s*\(/g,
    description: "abi.encodePacked with multiple dynamic types can produce hash collisions. In signature verification this enables forgery.",
    fix: "Use abi.encode instead, or add length prefixes.",
    contextCheck: function(source, idx) {
        // Grab the args between the outer ( and matching )
        var after = source.slice(idx, idx + 400);
        var openParen = after.indexOf("abi.encodePacked");
        var start = after.indexOf("(", openParen);
        if (start === -1) return true;

        // Simple paren-matching to find the arg list
        var depth = 0, end = -1;
        for (var i = start; i < after.length && i < start + 350; i++) {
            var c = after[i];
            if (c === "(") depth++;
            else if (c === ")") { depth--; if (depth === 0) { end = i; break; } }
        }
        if (end === -1) return true;

        var args = after.slice(start + 1, end);

        // Count dynamic-length type indicators in the args
        // Dynamic types in Solidity: string, bytes, T[], T[][]
        // Fixed types: address, uint*, int*, bytes32, bool, T[N]
        var dynamicCount = 0;

        // string / bytes (not bytesN)
        var stringMatches = args.match(/\bstring\b/g);
        var bytesMatches = args.match(/\bbytes\b(?!\d)/g);
        dynamicCount += (stringMatches ? stringMatches.length : 0);
        dynamicCount += (bytesMatches ? bytesMatches.length : 0);

        // Dynamic arrays — "[]" not followed by a digit
        var arrayMatches = args.match(/\[\s*\]/g);
        dynamicCount += (arrayMatches ? arrayMatches.length : 0);

        // Only a real risk if 2+ dynamic values are concatenated adjacently
        return dynamicCount >= 2;
    }
},
  {
    id: "signature-replay",
    type: "Signature Replay Risk",
    severity: "HIGH",
    cwe_id: "CWE-294",
    pattern: /ecrecover\s*\(/g,
    contextCheck: function(source, idx) {
      var srcLines = source.split("\n");
      var lineNum = source.substring(0, idx).split("\n").length - 1;
      var fnStart = lineNum;
      while (fnStart > 0 && fnStart > lineNum - 60 && !/function\s+\w+\s*\(/.test(srcLines[fnStart])) fnStart--;
      if (fnStart >= 0 && /function\s+\w+\s*\(/.test(srcLines[fnStart])) {
        var sig = srcLines[fnStart];
        for (var i = fnStart + 1; i < Math.min(fnStart + 15, srcLines.length); i++) {
          sig += " " + srcLines[i];
          if (/{/.test(srcLines[i])) break;
        }
        if (/\b(private|internal)\b/.test(sig)) return false;
      }
      var before = source.slice(Math.max(0, idx - 800), idx);
      if (/\bnonce\b/i.test(before)) return false;
      if (/(withdrawn|orderFills|used|executed|seen|filled)\s*\[/i.test(before)) return false;
      if (/keccak256\s*\(\s*(address\s*\(\s*)?this\b/i.test(before)) return false;
      return true;
    },
    description: "ecrecover-based verification. If the signed message doesn't include a nonce, chainId, and address(this), the signature can be replayed.",
    fix: "Include nonce, chainId, and address(this) in the message. Track used signatures.",
    contextCheck: function(source, idx) {
        var before = source.slice(Math.max(0, idx - 800), idx);

        // Suppress if a nonce appears in the hash construction
        if (/\bnonce\b/i.test(before)) return false;

        // Suppress if the hash is built with address(this) or this
        if (/keccak256\s*\(\s*(address\s*\(\s*)?this\b/i.test(before)) return false;
        if (/\bthis\b\s*,/.test(before) && /keccak256/.test(before)) return false;

        // Suppress if a tracking mapping is used nearby
        if (/(withdrawn|orderFills|used|executed|seen|filled)\s*\[/i.test(before)) return false;

        // Suppress if the return value of ecrecover is compared and then a
        // mapping write happens after (heuristic for "already executed")
        var after = source.slice(idx, idx + 600);
        if (/(withdrawn|orderFills|used|executed|seen|filled)\s*\[/i.test(after)) return false;

        return true;
    }
  },
  {
    id: "arbitrary-call-user-calldata",
    type: "Arbitrary External Call (User-Controlled Calldata)",
    severity: "CRITICAL",
    cwe_id: "CWE-829",
    pattern: /\.call\s*\([^)]*\b\w*(func|data|payload|calldata|sig|encoded|bytes|target|router|swap)\w*[^)]*\)/gi,
    description: "Public/external function forwards caller-supplied calldata to an external .call(). If this contract holds any privileged role (upgrade authority, transfer roles, admin), an attacker can invoke that privilege on their behalf.",
    fix: "Add access control (onlyOwner/onlyRole), verify a signature over the calldata, or use a whitelist of allowed selectors.",
    contextCheck: function(source, idx) {
      var lines = source.split("\n");
      var lineNum = source.substring(0, idx).split("\n").length - 1;
      var fnStart = lineNum;
      while (fnStart > 0 && !/function\s+\w+\s*\(/.test(lines[fnStart])) fnStart--;

      // Build the full signature (multi-line safe)
      var sigText = lines[fnStart];
      for (var i = fnStart + 1; i < Math.min(fnStart + 10, lines.length); i++) {
        sigText += " " + lines[i];
        if (/{/.test(lines[i])) break;
      }

      // Suppress if any only* modifier is present
      if (/\bonly\w+/.test(sigText)) return false;

      // Suppress if the function body has an owner check in the first 500 chars
      var fnBody = lines.slice(fnStart, Math.min(fnStart + 40, lines.length)).join("\n");
      if (/require\s*\(\s*msg\.sender\s*==/.test(fnBody.slice(0, 500))) return false;

      // Suppress if the function is internal/private
      return true;
    }
  },
  {
    id: "governance-flash-loan-vote",
    type: "Flash-Loan Voting (No Snapshot)",
    severity: "HIGH",
    cwe_id: "CWE-362",
    pattern: /function\s+(castVote|vote|castVoteWithReason)\s*\([^)]*\)[\s\S]{0,800}?balanceOf\s*\(\s*msg\.sender\s*\)/g,
    description: "Voting weight is read from current balance rather than a snapshot at proposal creation. A flash loan can inflate voting power for a single transaction.",
    fix: "Use a snapshot mechanism (ERC20Votes, Checkpoints) for voting weight."
  },
  {
    id: "governance-short-timelock",
    type: "Short Timelock Delay",
    severity: "MEDIUM",
    cwe_id: "CWE-662",
    pattern: /(uint256|uint)\s+(public\s+)?(delay|timelock|votingDelay|votingPeriod)\s*=\s*(\d+)/g,
    description: "Timelock or voting delay is unusually short. Proposals can execute before the community has time to review.",
    fix: "Set delay >= 48 hours (172800 seconds) for mainnet governance.",
    contextCheck: function(source, idx) {
      var m = source.slice(idx, idx + 100).match(/=\s*(\d+)/);
      if (!m) return false;
      var delay = parseInt(m[1]);
      return delay < 86400;
    }
  }
  ,
  {
    id: "trust-msg-sender-selfreport",
    type: "Trusting msg.sender to Self-Report Authorization",
    severity: "CRITICAL",
    cwe_id: "CWE-807",
    pattern: /I[A-Z]\w+\s*\(\s*msg\.sender\s*\)\s*\.[a-zA-Z_]\w*\s*\(/g,
    description: "Code calls back into msg.sender and trusts its response as the only authorization check. A malicious contract can return whatever makes the check pass.",
    fix: "Maintain an on-chain registry of trusted callers; never ask msg.sender to vouch for itself."
  }
];

function lineNumberAt(source, index) {
  return source.substring(0, index).split("\n").length;
}

function snippetAt(source, index) {
  var lineStart = source.lastIndexOf("\n", index) + 1;
  var lineEnd = source.indexOf("\n", index);
  if (lineEnd === -1) lineEnd = source.length;
  return source.substring(lineStart, lineEnd).trim().slice(0, 200);
}

function findFunctionStart(lines, fromLine) {
  var i = fromLine;
  while (i > 0 && !/function\s+\w+\s*\(/.test(lines[i])) i--;
  return i;
}

function findFunctionEnd(lines, fromLine) {
  var depth = 0;
  var started = false;
  for (var i = fromLine; i < lines.length; i++) {
    var line = lines[i];
    for (var j = 0; j < line.length; j++) {
      var ch = line[j];
      if (ch === "{") {
        depth++;
        started = true;
      } else if (ch === "}") {
        depth--;
      }
    }
    if (started && depth === 0) return i + 1;
  }
  return lines.length;
}

function analyzeCEI(source, filePath) {
  var findings = [];
  var lines = source.split("\n");
  var callRegex = /\.call(?:\.value\s*\([^)]*\)|\{[^}]*\})?\s*\(/g;
  var seenFunctions = {};

  var match;
  while ((match = callRegex.exec(source)) !== null) {
    var callLine = lineNumberAt(source, match.index) - 1;

    var fnStart = findFunctionStart(lines, callLine);
    if (fnStart === 0 && !/function\s+\w+\s*\(/.test(lines[0])) continue;

    // Collect full signature — function keyword through opening brace (multi-line safe)
    var sigLines = [];
    for (var si = fnStart; si < lines.length && si < fnStart + 40; si++) {
      sigLines.push(lines[si]);
      if (lines[si].indexOf("{") !== -1) break;
    }
    var fnHeader = sigLines.join(" ");
    if (/nonReentrant/.test(fnHeader)) continue;

    var fnKey = filePath + "::" + fnStart;
    if (seenFunctions[fnKey]) continue;

    var fnEnd = findFunctionEnd(lines, fnStart);
    var afterCall = lines.slice(callLine + 1, Math.min(callLine + 20, fnEnd)).join("\n");

    var storageWrite = /\.(push|pop)\s*\(|\b[a-zA-Z_]\w*\[[^\]]+\]\s*=[^=]|\b[a-zA-Z_]\w*\s*(\+=|-=)/.test(afterCall);

    var fnBody = lines.slice(fnStart, fnEnd).join("\n");
    var hasGuard = /nonReentrant/.test(fnHeader) || /_status\s*=\s*_ENTERED|reentrancyGuard|locked/i.test(fnBody);

    if (!storageWrite || hasGuard) continue;

    seenFunctions[fnKey] = true;

    findings.push({
      file: filePath,
      line: callLine + 1,
      type: "Reentrancy (CEI Violation)",
      severity: "HIGH",
      cwe_id: "CWE-841",
      description: "External call is followed by state changes. If the target reenters, state can be corrupted or operations duplicated.",
      fix: "Move state changes before the external call (checks-effects-interactions), or add a nonReentrant modifier.",
      code_snippet: snippetAt(source, match.index),
      source: "pattern",
      confidence: "MEDIUM"
    });
  }

  return findings;
}

function runPatterns(source, filePath, tier) {
  if (!tier) { const m = source.match(/pragma\s+solidity\s*[\^>=~\s]*0\.(\d+)/); tier = (m && +m[1] < 8) ? "pre08" : "unknown"; }
  var findings = [];

  for (var i = 0; i < SOL_PATTERNS.length; i++) {
    var rule = SOL_PATTERNS[i];

    if (rule.id === "front-running") continue;
    if (rule.precondition && !rule.precondition(source, tier)) continue;

    var regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    var match;
    var count = 0;
    var seen = {};

    while ((match = regex.exec(source)) !== null && count < (+process.env.MAXPER||5)) {
      var line = lineNumberAt(source, match.index);
      var key = rule.id + ":" + line;
      if (seen[key]) {
        regex.lastIndex++;
        continue;
      }
      seen[key] = true;

      if (rule.contextCheck && !rule.contextCheck(source, match.index, filePath)) {
        regex.lastIndex++;
        continue;
      }

      findings.push({
        file: filePath,
        line: line,
        type: rule.type,
        severity: rule.severity,
        cwe_id: rule.cwe_id,
        description: rule.description,
        fix: rule.fix,
        code_snippet: snippetAt(source, match.index),
        source: "pattern",
        confidence: rule.severity === "CRITICAL" ? "HIGH" : "MEDIUM"
      });

      count++;
      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  var ceiFindings = analyzeCEI(source, filePath);
  for (var j = 0; j < ceiFindings.length; j++) {
    findings.push(ceiFindings[j]);
  }

  return findings;
}

module.exports = {
  SOL_PATTERNS: SOL_PATTERNS,
  runPatterns: runPatterns,
  analyzeCEI: analyzeCEI
};

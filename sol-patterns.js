function fnBodyDeep(src, idx, depth) {
  const body = fnBody(src, idx);
  if (depth <= 0 || !body) return body;
  const seen = {};
  const calls = body.match(/\b_?[A-Za-z]\w*(?=\s*\()/g) || [];
  let extra = "";
  for (const name of calls) {
    if (seen[name] || /^(require|assert|revert|if|for|while|emit|address|keccak256|uint\d*|bytes\d*|abi)$/.test(name)) continue;
    if (/^[A-Z]/.test(name)) continue;
    seen[name] = 1;
    const m = new RegExp("function\\s+" + name + "\\s*\\(").exec(src);
    if (m) extra += "\n" + fnBodyDeep(src, m.index, depth - 1);
  }
  return body + extra;
}
function fnBody(src, idx) {
  const rest = src.slice(idx);
  const m = /[{;]/.exec(rest);
  if (!m || m[0] === ";") return "";
  let d = 0;
  for (let i = m.index; i < rest.length; i++) {
    if (rest[i] === "{") d++;
    else if (rest[i] === "}" && --d === 0) return rest.slice(m.index, i + 1);
  }
  return rest.slice(m.index, m.index + 2000);
}

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
    severity: "LOW",
    cwe_id: "CWE-269",
    pattern: /function\s+mint\s*\([^)]*\)[^{]*\{[^}]*(?:_mint\s*\(|totalSupply\s*\+=|balanceOf\[[^\]]+\]\s*\+=)/gs,
    description: "Owner can mint tokens. If unlimited and unprotected, they can dilute holders to zero.",
    fix: "Add a hard cap, or require multisig + timelock."
  },
  {
    id: "owner-pause",
    type: "Owner Can Pause / Freeze",
    severity: "LOW",
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
    severity: "HIGH",
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
,{
  id: "gov-spot-voting-power",
  type: "Flash-Loan Governance (Spot Stake Voting)",
  severity: "CRITICAL",
  cwe_id: "CWE-841",
  pattern: /function\s+(vote|castVote|castVoteBySig|applyFor\w*|join\w*|getVotes|votingPower|getVotingPower|refresh|register\w*)\s*\(/g,
  description: "Voting power or membership comes from the live token/staked balance with no snapshot. An attacker can flash-borrow tokens, win a majority, pass a proposal and repay in one transaction.",
  fix: "Use checkpointed votes (getPastVotes at a snapshot block), add a voting delay, and lock stake for a minimum period.",
  contextCheck: function(source, idx) {
    const b = fnBodyDeep(source, idx, 2);
    if (!b) return false;
    const spot = /\b\w*(frozen|staked?|stakeOf|locked|balanceOf|deposit)\w*\s*[\(\[]/i.test(b);
    const snap = /getPast|checkpoint|snapshot|votingDelay|startBlock|lockUntil|unlockTime/i.test(b);
    return spot && !snap;
  }
},
{
  id: "gov-execute-no-time-gate",
  type: "Governance Execute Without Time Gate",
  severity: "HIGH",
  cwe_id: "CWE-367",
  pattern: /function\s+(execute|executeProposal|queueAndExecute)\s*\(/g,
  description: "execute() never checks a voting-end time or timelock ETA, so propose, vote and execute can all happen in one block.",
  fix: "Require voting to have ended and block.timestamp >= eta (48h minimum) before execution.",
  contextCheck: function(source, idx) {
    const b = fnBody(source, idx);
    return !!b && !/block\.(timestamp|number)|\beta\b|votingEnd|endTime|endBlock|deadline|executableAt|executeAfter/i.test(b);
  }
}
];

/* _detectors_v3 */
function _args(src, from) {
  const out = []; let d = 0, cur = "";
  for (let i = from; i < src.length && i < from + 1500; i++) {
    const c = src[i];
    if (c === "(" || c === "[" || c === "{") { d++; if (d === 1) continue; }
    else if (c === ")" || c === "]" || c === "}") { d--; if (d === 0) { out.push(cur.trim()); return out; } }
    else if (c === "," && d === 1) { out.push(cur.trim()); cur = ""; continue; }
    cur += c;
  }
  return out;
}

SOL_PATTERNS.push({
  id: "callback-no-caller-check",
  type: "Callback Without Caller Validation",
  severity: "HIGH",
  cwe_id: "CWE-345",
  pattern: /function\s+(\w*[Cc]allback|uniswapV2Call|pancakeCall|onFlashLoan|executeOperation|receiveFlashLoan)\s*\([^)]*\)[^{;]*\{/g,
  description: "A swap or flash-loan callback moves funds or makes calls but never verifies that msg.sender is the expected pool or lender. Anyone can call it directly with crafted data.",
  fix: "Require msg.sender to equal the expected pool or lender (or verify the pool address from the factory) before acting, and validate the initiator.",
  contextCheck: function (source, idx) {
    const brace = source.indexOf("{", idx);
    if (brace < 0) return false;
    const head = source.slice(idx, brace);
    if (/\b(internal|private|view|pure)\b/.test(head)) return false;
    if (/\bonly[A-Za-z]\w*|\bauth\b|requiresAuth/.test(head)) return false;
    const b = fnBodyDeep(source, idx, 1);
    if (!b) return false;
    if (/\b(require|assert|if)\s*\([^;]*(msg\.sender|_msgSender\s*\(\s*\))/.test(b)) return false;
    if (/CallbackValidation|verifyCallback|PoolAddress\.|computeAddress|isValidPool|validatePool/i.test(b)) return false;
    return /\.(transfer|transferFrom|safeTransfer|safeTransferFrom|call|delegatecall|approve)\s*[({]/.test(b);
  }
});

SOL_PATTERNS.push({
  id: "unprotected-fund-recovery",
  type: "Unprotected Fund Recovery",
  severity: "CRITICAL",
  cwe_id: "CWE-284",
  pattern: /function\s+(recover\w*|rescue\w*|sweep\w*|skim\w*|drain\w*|emergencyWithdraw\w*|withdrawAll\w*|retrieve\w*|claimTokens|withdrawTokens|withdrawETH|withdrawEth)\s*\([^)]*\)[^{;]*\{/g,
  description: "A rescue/sweep style function can be called by anyone and sends funds to the caller or to a caller-chosen address.",
  fix: "Restrict the function with onlyOwner or a role, and send funds only to a fixed treasury address.",
  contextCheck: function (source, idx) {
    const brace = source.indexOf("{", idx);
    if (brace < 0) return false;
    const head = source.slice(idx, brace);
    if (/\b(internal|private|view|pure)\b/.test(head)) return false;
    if (/\bonly[A-Za-z]\w*|\bauth\b|requiresAuth|restricted/.test(head)) return false;
    const b = fnBodyDeep(source, idx, 1);
    if (!b) return false;
    if (/\b(require|assert|if)\s*\([^;]*(msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)|_checkOwner|_checkRole|hasRole\s*\(/.test(b)) return false;
    if (/\[\s*(msg\.sender|_msgSender\s*\(\s*\))\s*\]/.test(b)) return false;
    const params = ((/\(([^)]*)\)/.exec(head) || [, ""])[1]).split(",").map(function (p) { return (p.trim().split(/\s+/).pop() || ""); }).filter(function (p) { return /^\w+$/.test(p); });
    const toCaller = /\b(safeTransfer|transfer|send)\s*\(\s*(msg\.sender|_msgSender\s*\(\s*\))/.test(b) ||
      /payable\s*\(\s*(msg\.sender|_msgSender\s*\(\s*\))\s*\)\s*\.(transfer|send|call)|\bmsg\.sender\s*\.(transfer|send|call)/.test(b);
    const toParam = params.some(function (p) {
      return new RegExp("\\b(safeTransfer|transfer|send)\\s*\\(\\s*" + p + "\\b").test(b) ||
        new RegExp("\\b" + p + "\\s*\\.(transfer|send|call)").test(b) ||
        new RegExp("payable\\s*\\(\\s*" + p + "\\s*\\)\\s*\\.(transfer|send|call)").test(b);
    });
    return toCaller || toParam;
  }
});

SOL_PATTERNS.push({
  id: "stale-oracle-price",
  type: "Oracle Price Without Staleness Check",
  severity: "MEDIUM",
  cwe_id: "CWE-754",
  pattern: /\blatestRoundData\s*\(\s*\)/g,
  description: "latestRoundData() is used without checking how fresh the answer is. A stalled or broken feed returns an old price that the protocol will still trust.",
  fix: "Check updatedAt against a heartbeat (block.timestamp - updatedAt <= maxDelay), require answeredInRound >= roundId, and require price > 0.",
  contextCheck: function (source, idx) {
    if (/\bfunction\s+latestRoundData\b/.test(lineAt(source, idx))) return false;
    const f0 = source.lastIndexOf("function ", idx);
    if (f0 < 0) return false;
    const b = fnBody(source, f0);
    if (!b) return false;
    if ((b.match(/\bupdatedAt\b/g) || []).length >= 2) return false;
    if ((b.match(/\banswered\w*\b/gi) || []).length >= 2) return false;
    if (/heartbeat|stalePeriod|maxDelay|MAX_DELAY|staleness|STALE/i.test(b)) return false;
    return true;
  }
});

SOL_PATTERNS.push({
  id: "swap-no-slippage",
  type: "Swap Without Slippage or Deadline Protection",
  severity: "MEDIUM",
  cwe_id: "CWE-682",
  pattern: /\b(swapExactTokensForTokens|swapExactETHForTokens|swapExactTokensForETH|swapExactTokensForTokensSupportingFeeOnTransferTokens|swapExactETHForTokensSupportingFeeOnTransferTokens|swapExactTokensForETHSupportingFeeOnTransferTokens|exactInputSingle|exactInput)\s*\(/g,
  description: "A swap is sent with a minimum output of 0 or a deadline of block.timestamp. Bots can sandwich it for most of its value, and a validator can hold the transaction.",
  fix: "Take a real minimum-output and deadline from the caller, or compute minOut from a trusted oracle.",
  contextCheck: function (source, idx) {
    const open = source.indexOf("(", idx);
    if (open < 0) return false;
    if (/function\s+$/.test(source.slice(Math.max(0, idx - 30), idx))) return false;
    const name = (/(\w+)\s*\(/.exec(source.slice(idx, open + 1)) || [])[1] || "";
    const a = _args(source, open);
    const txt = a.join(",");
    if (/amountOutMin(imum)?\s*:\s*0\b/.test(txt) || /deadline\s*:\s*(block\.timestamp|now)\b/.test(txt)) return true;
    if (/^swapExact/.test(name)) {
      const minI = /ETHFor/.test(name) ? 0 : 1;
      const mn = (a[minI] || "").trim(), dl = (a[a.length - 1] || "").trim();
      if (mn === "0") return true;
      if (/^(block\.timestamp|now|type\s*\(\s*uint256\s*\)\.max)$/.test(dl)) return true;
    }
    return false;
  }
});

SOL_PATTERNS.push({
  id: "divide-before-multiply",
  type: "Division Before Multiplication (Precision Loss)",
  severity: "MEDIUM",
  cwe_id: "CWE-682",
  pattern: /^[^\n]*\/[^\n]*\*[^\n]*$/gm,
  description: "A division happens before a multiplication. Integer division rounds down, so the result loses precision that the multiplication then amplifies.",
  fix: "Multiply first and divide last, or use a fixed-point library with enough precision.",
  contextCheck: function (source, idx) {
    let L = lineAt(source, idx);
    if (/^\s*(\*|\/\/|\/\*)/.test(L)) return false;
    L = L.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "").replace(/"[^"]*"/g, '""');
    return /[\w)\]]\s*\/\s*[\w(][\w.\[\]()]*\s*\*\s*[\w(]/.test(L);
  }
});

SOL_PATTERNS.push({
  id: "erc4626-inflation",
  type: "ERC4626 First-Depositor Inflation Risk",
  severity: "HIGH",
  cwe_id: "CWE-682",
  pattern: /function\s+(deposit|mint|_deposit|convertToShares|_convertToShares|previewDeposit)\s*\([^)]*\)[^{;]*\{/g,
  description: "Shares are priced as assets * totalSupply / totalAssets with no virtual offset or dead shares. The first depositor can donate assets to inflate the share price and make later depositors' shares round down to zero.",
  fix: "Use virtual shares/assets (OpenZeppelin _decimalsOffset), mint minimum liquidity to a dead address on first deposit, and require shares > 0.",
  contextCheck: function (source, idx) {
    const b = fnBodyDeep(source, idx, 1);
    if (!b) return false;
    if (/_decimalsOffset|MINIMUM_LIQUIDITY|minimumLiquidity|DEAD_SHARES|deadShares|virtualShares|virtualAssets|VIRTUAL_|0xdead|_mint\s*\(\s*address\s*\(\s*0\s*\)/i.test(source)) return false;
    if (/totalSupply(\s*\(\s*\))?\s*\+\s*1|totalAssets(\s*\(\s*\))?\s*\+\s*1/.test(source)) return false;
    const bal = "(totalAssets|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|totalDeposits|totalPooled)";
    return new RegExp("\\*[^;]*totalSupply[^;]*\\/[^;]*" + bal + "|\\bassets?\\s*\\*[^;]*\\/[^;]*" + bal, "i").test(b);
  }
});


/* _precision_v1 */
/* _precision_v2 */
var _PRIV = /\b(_?owner|_?admin|m_owner|governance|operator|implementation|creator|controller|manager|isOwner|isAdmin|isOperator)s?\s*(\[[^\]]*\])?\s*=(?!=)|\b_?transferOwnership\s*\(/;
function _contractAt(src, idx) {
  const re = /^[ \t]*(?:abstract\s+)?(?:contract|library)\s+(\w+)/gm; /* _precision_v3 */
  const pre = src.slice(0, idx);
  let m, last = "";
  while ((m = re.exec(pre))) last = m[1];
  return last;
}

function lineAt(src, idx) {
  const s = idx > 0 ? src.lastIndexOf("\n", idx - 1) + 1 : 0;
  let e = src.indexOf("\n", idx);
  if (e < 0) e = src.length;
  return src.slice(s, e);
}
function hasTopLevelComma(s, from) {
  let d = 1;
  for (let i = from; i < s.length; i++) {
    const c = s[i];
    if (c === "(" || c === "[") d++;
    else if (c === ")" || c === "]") { if (--d === 0) return false; }
    else if (c === "," && d === 1) return true;
  }
  return true;
}
function _wrap(key, extra) {
  const r = SOL_PATTERNS.find(function (x) { return x.id === key || x.type === key; });
  if (!r) return;
  const old = r.contextCheck;
  r.contextCheck = function (src, idx) {
    return (!old || old.call(r, src, idx)) && extra(src, idx);
  };
}
function _govOK(src) {
  return /\bvote\w*/i.test(src) && /\b(propos\w*|quorum|senat\w*|governor\w*|ballot)\b/i.test(src);
}

_wrap("Unchecked ERC20 Transfer", function (src, idx) {
  if (/using\s+SafeERC20|SafeERC20\./.test(src)) return false;
  const L = lineAt(src, idx);
  const m = /\.(transfer|transferFrom)\s*\(/.exec(L);
  if (!m) return true;
  if (!hasTopLevelComma(L, m.index + m[0].length)) return false;
  return !/(\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\bbool\b|[^=!<>]=[^=])/.test(L.slice(0, m.index));
});

_wrap("unchecked-math-pre-08", function (src, idx) {
  const L = lineAt(src, idx);
  if (/\bfor\s*\(|\bwhile\s*\(|\bconstant\b/.test(L)) return false;
  if (/^[\s\w.]*=\s*[\d\s+\-*\/().eE]+;\s*(\/\/.*)?$/.test(L)) return false;
  if (/\b(now|block\.timestamp)\s*\+\s*\d+\s*(seconds|minutes|hours|days|weeks)?\b/.test(L)) return false;
  return true;
});

_wrap("gov-spot-voting-power", function (src) { return _govOK(src); });
_wrap("gov-execute-no-time-gate", function (src) { return _govOK(src); });
_wrap("governance-short-timelock", function (src) { return _govOK(src) || /timelock/i.test(src); });

SOL_PATTERNS.push({
  id: "unprotected-initialize",
  type: "Unprotected Initializer",
  severity: "CRITICAL",
  cwe_id: "CWE-284",
  pattern: /function\s+(initialize|init\w*|initializeV\d+)\s*\([^)]*\)[^{;]*\{/g,
  description: "initialize() can be called by anyone and sets privileged state. An attacker can call it first (or again) and take ownership of the contract or proxy.",
  fix: "Add the initializer modifier (OpenZeppelin Initializable), or a one-time initialized flag, and call _disableInitializers() in the implementation constructor.",
  contextCheck: function (source, idx) {
    const brace = source.indexOf("{", idx);
    if (brace < 0) return false;
    const head = source.slice(idx, brace);
    if (/\b(internal|private|view|pure)\b/.test(head)) return false;
    if (/\b(initializer|reinitializer|onlyInitializing)\b|\bonly\w+|\bauth\b|requiresAuth/.test(head)) return false;
    const b = fnBodyDeep(source, idx, 2);
    if (!b) return false;
    if (/\b(initialized|_initialized|isInitialized|inited)\b/i.test(b) && /\b(require|if)\s*\(/.test(b)) return false;
    if (/\b(require|assert|if)\s*\([^;]*(msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)/.test(b)) return false;
    return _PRIV.test(b) || /__\w+_init\s*\(|_setupRole|_grantRole/.test(b);
  }
});

SOL_PATTERNS.push({
  id: "unprotected-role-assignment",
  type: "Unprotected Privileged Role Assignment",
  severity: "CRITICAL",
  cwe_id: "CWE-284",
  pattern: /function\s+\w+\s*\([^)]*\)[^{;]*\{/g,
  description: "A public function assigns an owner/admin-style role with no caller check, so anyone can take control of the contract.",
  fix: "Add an access modifier (onlyOwner or role-based) or require() that msg.sender is the current owner before changing roles.",
  contextCheck: function (source, idx) {
    if (/(^|\n)\s*library\s+\w+/.test(source)) return false; // Ignore libraries

    const brace = source.indexOf("{", idx);
    if (brace < 0) return false;
    const head = source.slice(idx, brace);
    const name = (/function\s+(\w+)/.exec(head) || [])[1] || "";
    if (name === _contractAt(source, idx)) return false;
    if (/^(initialize|init\w*)$/i.test(name) || /^__/.test(name)) return false;
    if (/\b(view|pure|internal|private)\b/.test(head)) return false;
    if (/\bonly\w+|\bauth\b|requiresAuth|restricted|initializer/.test(head)) return false;
    const b = fnBodyDeep(source, idx, 2);
    if (!b) return false;
    if (/\b(require|assert|if)\s*\([^;]*(msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)|_checkOwner|_checkRole|hasRole\s*\(|\bonly\w+/.test(b)) return false;
    return _PRIV.test(b);
  }
});

SOL_PATTERNS.push({
  id: "spot-price-oracle",
  type: "Spot Price Used as Oracle",
  severity: "HIGH",
  cwe_id: "CWE-682",
  pattern: /\b(getReserves\s*\(|\.slot0\s*\()/g,
  description: "A price is computed from a pool's current reserves or slot0. These can be pushed to any value inside one transaction with a flash loan, so anything relying on this price can be manipulated.",
  fix: "Use a TWAP or an external oracle such as Chainlink, and add sanity bounds against the manipulated range.",
  contextCheck: function (source, idx) {
    if (/function\s+(getReserves|slot0)\s*\([^)]*\)[^;{]*\{/.test(source)) return false;
    if (/latestRoundData|\bobserve\s*\(|consult\s*\(|\btwap\b|priceFeed|AggregatorV3|getPriceUnsafe/i.test(source)) return false;
    const fs0 = source.lastIndexOf("function ", idx);
    if (fs0 < 0) return false;
    const b = fnBody(source, fs0);
    return /[\w)\]]\s*[*\/]\s*[\w(]/.test(b);
  }
});


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


/* _detectors_v4 */
var _bs = null, _bo = null;
function _blank(src) {
  if (_bs === src) return _bo;
  _bs = src;
  _bo = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, function (m) { return m.replace(/[^\n]/g, " "); });
  return _bo;
}
function _fnStart(clean, idx) {
  const re = /\bfunction\s+\w*\s*\(/g;
  let m, last = -1;
  while ((m = re.exec(clean)) && m.index < idx) last = m.index;
  return last;
}
function _contractText(clean, idx) {
  const re = /^[ \t]*(?:abstract\s+)?(?:contract|library)\s+\w+[^{]*\{/gm;
  let m, last = null;
  while ((m = re.exec(clean)) && m.index < idx) last = m;
  if (!last) return "";
  const open = last.index + last[0].length - 1;
  let d = 0;
  for (let i = open; i < clean.length; i++) {
    if (clean[i] === "{") d++;
    else if (clean[i] === "}" && --d === 0) return clean.slice(open, i + 1);
  }
  return clean.slice(open);
}
function _upd(id, fields) {
  const r = SOL_PATTERNS.find(function (x) { return x.id === id; });
  if (r) Object.assign(r, fields);
}
var _MEANINGLESS_DEADLINE = /^(block\.timestamp(\s*\+\s*[\w.]+)?|now(\s*\+\s*[\w.]+)?|type\s*\(\s*uint(256)?\s*\)\s*\.\s*max|uint(256)?\s*\(\s*-\s*1\s*\)|2\s*\*\*\s*256\s*-\s*1|UINT(256)?_MAX|MAX_UINT(256)?)$/;
function _isZeroish(txt, scope) {
  txt = (txt || "").trim();
  if (/^(0|1|0x0+)$/.test(txt)) return true;
  if (/^\w+$/.test(txt)) {
    const m = new RegExp("\\b" + txt + "\\s*=\\s*(0|1)\\s*;").exec(scope || "");
    if (m) return true;
  }
  return false;
}

_upd("stale-oracle-price", {
  contextCheck: function (source, idx) {
    const c = _blank(source);
    if (/\bfunction\s+$/.test(c.slice(Math.max(0, idx - 20), idx))) return false;
    const f0 = _fnStart(c, idx);
    if (f0 < 0) return false;
    const b = fnBody(c, f0);
    if (!b) return false;
    if ((b.match(/\bupdatedAt\b/g) || []).length >= 2) return false;
    if ((b.match(/\banswered\w*\b/gi) || []).length >= 2) return false;
    if (/heartbeat|stalePeriod|maxDelay|MAX_DELAY|staleness|stale|STALE/i.test(b)) return false;
    return true;
  }
});

_upd("swap-no-slippage", {
  contextCheck: function (source, idx) {
    const c = _blank(source);
    const open = c.indexOf("(", idx);
    if (open < 0) return false;
    if (/function\s+$/.test(c.slice(Math.max(0, idx - 30), idx))) return false;
    const name = (/(\w+)\s*\(/.exec(c.slice(idx, open + 1)) || [])[1] || "";
    const a = _args(c, open);
    const f0 = _fnStart(c, idx);
    const scope = f0 >= 0 ? fnBody(c, f0) : "";
    const txt = a.join(",");
    if (/amountOutMin(imum)?\s*:\s*(0|1)\b/.test(txt)) return true;
    const dm = /deadline\s*:\s*([^,}]+)/.exec(txt);
    if (dm && _MEANINGLESS_DEADLINE.test(dm[1].trim())) return true;
    if (/^swapExact/.test(name)) {
      const minI = /ETHFor/.test(name) ? 0 : 1;
      const mn = (a[minI] || "").trim(), dl = (a[a.length - 1] || "").trim();
      if (_isZeroish(mn, scope)) return true;
      if (_MEANINGLESS_DEADLINE.test(dl)) return true;
      if (/^\w+$/.test(dl)) {
        const m = new RegExp("\\b" + dl + "\\s*=\\s*([^;]+);").exec(scope);
        if (m && _MEANINGLESS_DEADLINE.test(m[1].trim())) return true;
      }
    }
    return false;
  }
});

SOL_PATTERNS.push({
  id: "rescue-no-token-exclusion",
  type: "Rescue Function Can Sweep Protocol Tokens",
  severity: "MEDIUM",
  cwe_id: "CWE-284",
  pattern: /function\s+(recover\w*|rescue\w*|sweep\w*|salvage\w*|retrieve\w*|emergencyWithdraw\w*|withdrawStuck\w*)\s*\([^)]*\)[^{;]*\{/g,
  description: "A rescue/recover function transfers any token the caller names, with no check that the token is not one the contract is supposed to hold (reward, staking or underlying token). The owner, or anyone if access control is missing, can drain user or reward funds.",
  fix: "Revert when tokenAddress equals any protocol-held token (rewards, staking, underlying), or restrict rescue to unsupported tokens only.",
  contextCheck: function (source, idx) {
    const c = _blank(source);
    const brace = c.indexOf("{", idx);
    if (brace < 0) return false;
    const head = c.slice(idx, brace);
    if (/\b(internal|private|view|pure)\b/.test(head)) return false;
    const b = fnBody(c, idx);
    if (!b) return false;
    const pm = /address(?:\s+payable)?\s+(\w+)/.exec(head);
    if (!pm) return false;
    const t = pm[1];
    const sends = new RegExp("\\(\\s*" + t + "\\s*\\)\\s*\\.\\s*(safeTransfer|transfer)\\s*\\(|\\b" + t + "\\s*\\.\\s*(safeTransfer|transfer)\\s*\\(|(safeTransfer|transfer)\\s*\\(\\s*" + t + "\\b").test(b);
    if (!sends) return false;
    if (new RegExp("\\b" + t + "\\s*(!=|==)|(!=|==)\\s*(address\\s*\\(\\s*)?\\w*\\s*\\)?\\s*" + t + "\\b").test(b)) return false;
    const ct = _contractText(c, idx);
    return /\bIERC20\w*\s+(public|internal|private|immutable|constant)|\baddress\s+(public|internal|private|immutable)\s+\w*(token|Token)\w*/.test(ct);
  }
});

SOL_PATTERNS.push({
  id: "nft-hook-reentrancy",
  type: "Reentrancy via Safe-Mint / Safe-Transfer Hook",
  severity: "MEDIUM",
  cwe_id: "CWE-841",
  pattern: /\b_safeMint\s*\(|\.\s*safe(Batch)?TransferFrom\s*\(/g,
  description: "A function calls _safeMint or an NFT safeTransferFrom, which hands control to the receiver's onERC721Received/onERC1155Received hook, while a limit check happens before it or state is written after it. A contract receiver can re-enter and bypass the limit or break the accounting.",
  fix: "Follow checks-effects-interactions (update state before the safe call), add nonReentrant, or use _mint when a receiver hook is not needed.",
  contextCheck: function (source, idx) {
    const c = _blank(source);
    if (/\.\s*safe(Batch)?TransferFrom/.test(c.slice(idx, idx + 30)) && !/721|1155|nft/i.test(c.slice(Math.max(0, idx - 60), idx))) return false;
    const f0 = _fnStart(c, idx);
    if (f0 < 0) return false;
    const open = c.indexOf("{", f0);
    if (open < 0) return false;
    const head = c.slice(f0, open);
    if (/\b(internal|private|view|pure)\b/.test(head)) return false;
    if (/\b(nonReentrant|noReentrant|lock|nonreentrant)\b/i.test(head)) return false;
    const b = fnBody(c, f0);
    if (!b) return false;
    const before = c.slice(open, idx), after = c.slice(idx, open + b.length);
    const limitCheck = /\b(require|assert|if)\s*\([^;]*(balanceOf|totalSupply|minted|claimed|mintedBy|\w+\s*\[)/.test(before);
    const writeAfter = /\b\w+\s*\[[^\]]*\]\s*([-+*]?=)(?!=)|\bdelete\s+\w+\s*\[/.test(after);
    return limitCheck || writeAfter;
  }
});

module.exports = {
  SOL_PATTERNS: SOL_PATTERNS,
  runPatterns: runPatterns,
  analyzeCEI: analyzeCEI
};

require("dotenv").config();
const { Bot } = require("grammy");
const { scanContract } = require("./scanner.js");
const { getScope, setScope, clearScope } = require("./scope.js");
const cache = require("./cache.js");

const bot = new Bot(process.env.TELEGRAM_BOT_TOKEN);

// ==================== COMMANDS ====================

bot.command("start", (ctx) => {
  ctx.reply(
    "*GuardContract* — Solidity pre-screen\n\n" +
    "*Send:* `0x...` (auto-detects chain)\n" +
    "Or force a chain: `arb 0x...` / `base 0x...`\n\n" +
    "*Commands:*\n" +
    "/full 0x... — show complete findings list\n" +
    "/scope <text> — set bounty scope for IN/OUT labeling\n" +
    "/scopeoff — clear scope\n" +
    "/cache — show cache stats\n" +
    "/clear 0x... — invalidate a cached report",
    { parse_mode: "Markdown" }
  );
});

bot.command("scopeoff", (ctx) => {
  clearScope();
  ctx.reply("✅ Scope cleared.");
});

bot.command("cache", (ctx) => {
  const s = cache.stats();
  ctx.reply(
    `📦 Cached scans: ${s.cachedScans}\n🔗 Known chains: ${s.knownChains}\n\`${s.cacheFile}\``,
    { parse_mode: "Markdown" }
  );
});

bot.command("scope", (ctx) => {
  const text = ctx.match;
  if (!text || !text.trim()) {
    return ctx.reply("Usage: /scope <paste the bounty scope text>");
  }
  setScope(text);
  ctx.reply(`✅ Scope set (${text.length} chars).`);
});

bot.command("clear", (ctx) => {
  const addr = (ctx.match || "").trim();
  if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) {
    return ctx.reply("Usage: /clear 0x...");
  }
  const chain = cache.getChainForAddress(addr) || "eth";
  cache.invalidate(addr, chain);
  ctx.reply("✅ Cache invalidated.");
});

bot.command("full", async (ctx) => {
  const raw = (ctx.match || "").trim();
  if (!raw) {
    return ctx.reply("Usage: /full 0x...  or  /full <chain> 0x...");
  }

  const args = raw.split(/\s+/);
  let chainArg = null;
  let address = args[0];
  if (args.length === 2) {
    chainArg = args[0].toLowerCase();
    address = args[1];
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return ctx.reply("❌ Invalid address.");
  }

  const chain = chainArg || cache.getChainForAddress(address);
  if (!chain) {
    return ctx.reply("❌ No cached chain for this address. Run a scan first.");
  }

  const report = cache.get(address, chain); if (report && !report.address) report.address = address;
  if (!report) {
    return ctx.reply("❌ No cached report. Run a scan first (cache expires after 24h).");
  }

  const messages = buildFullReport(report);
  for (const msg of messages) {
    await ctx.reply(msg, {
      parse_mode: "Markdown",
      link_preview_options: { is_disabled: true }
    });
  }
});

// ==================== MAIN HANDLER ====================

bot.on("message:text", async (ctx) => {
  const text = ctx.message.text.trim();
  if (text.startsWith("/")) return;

  let chainArg = null;
  let address = text;
  const parts = text.split(/\s+/);
  if (parts.length === 2) {
    chainArg = parts[0].toLowerCase();
    address = parts[1];
  }

  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return ctx.reply("❌ Invalid address.");
  }

  const statusMsg = await ctx.reply(
    chainArg
      ? `⏳ Fetching ${address.slice(0, 6)}...${address.slice(-4)} on ${chainArg}...`
      : `⏳ Detecting chain for ${address.slice(0, 6)}...${address.slice(-4)}...`
  );

  try {
    const report = await scanContract(address, chainArg); if (report && !report.address) report.address = address;
    await ctx.api.editMessageText(
      statusMsg.chat.id,
      statusMsg.message_id,
      formatReport(report),
      { parse_mode: "Markdown", link_preview_options: { is_disabled: true } }
    );
  } catch (e) {
    await ctx.api.editMessageText(
      statusMsg.chat.id,
      statusMsg.message_id,
      `❌ ${e.message}`
    );
  }
});

// ==================== CONSTANTS ====================

const DIV = "━".repeat(22);

const CHAIN_NAMES = {
  eth: "Ethereum", arb: "Arbitrum", base: "Base",
  op: "Optimism", polygon: "Polygon", bsc: "BSC",
  avax: "Avalanche", ftm: "Fantom", gnosis: "Gnosis",
  celo: "Celo", scroll: "Scroll", linea: "Linea",
  blast: "Blast", mantle: "Mantle", zksync: "zkSync"
};

const TIER_LABELS = {
  pre08: "⚠️ pre-0.8.0 — overflow rules active",
  post08: "✅ 0.8.0+ — overflow checks built in",
  unknown: "❔ version unknown"
};

const SEV_EMOJI = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "⚪" };
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

// ==================== HELPERS ====================

function callerTag(f) {
  if (!f.caller) return null;
  if (f.caller.gated) {
    if (/private|internal/i.test(f.caller.reason)) return "🔒 private/internal";
    if (/owner/i.test(f.caller.reason)) return "🔒 owner-gated";
    return "🔒 gated";
  }
  return "🌐 public — anyone can call";
}

function groupBySeverity(findings) {
  const groups = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  for (const f of findings) {
    if (groups[f.severity]) groups[f.severity].push(f);
  }
  return groups;
}

function truncate(str, len) {
  if (!str) return "";
  return str.length > len ? str.slice(0, len - 1) + "…" : str;
}

function escapeMd(str) {
  return String(str || "").replace(/([_*`\[\]])/g, "\\$1");
}


function getExplorerLink(chain, address) {
  var links = {
    eth: 'https://etherscan.io/address/',
    arbitrum: 'https://arbiscan.io/address/',
    base: 'https://basescan.org/address/',
    polygon: 'https://polygonscan.com/address/',
    optimism: 'https://optimistic.etherscan.io/address/',
    bsc: 'https://bscscan.com/address/',
    avax: 'https://snowtrace.io/address/',
    fantom: 'https://ftmscan.com/address/'
  };
  var base = links[chain.toLowerCase()] || 'https://etherscan.io/address/';
  return base + address;
}

// ==================== SHORT REPORT ====================

function llmStatusLine(s) {
  if (!s) return "untracked";
  const parts = [];
  if (s.ok) parts.push("ok:" + s.ok);
  if (s.skipped_secondary) parts.push("skip:" + s.skipped_secondary);
  if (s.skipped_oversized) parts.push("⚠️ oversized:" + s.skipped_oversized);
  if (s.filtered) parts.push("filtered:" + s.filtered);
  if (s.failed) parts.push("❌ failed:" + s.failed);
  return parts.length ? parts.join(" · ") : "none";
}
function explorerUrl(chain, addr) {
  var base = {
    eth: "https://etherscan.io/address/",
    arbitrum: "https://arbiscan.io/address/",
    base: "https://basescan.org/address/",
    polygon: "https://polygonscan.com/address/",
    optimism: "https://optimistic.etherscan.io/address/"
  }[chain] || "https://etherscan.io/address/";
  return base + addr + "#code";
}
function formatReport(r) {
  if (!r.ok) return "❌ *Scan failed*\n\n" + r.reason;
  var _OZ_LIBS = /^(SafeERC20|SafeCast|SafeMath|SignedSafeMath|SignedMath|Math|Address|Context|Ownable|Ownable2Step|ERC20|IERC20|ERC20Permit|Strings|ReentrancyGuard|Pausable|ECDSA|MessageHashUtils|Counters|StorageSlot|Arrays|Checkpoints)\.sol$/;
  if (Array.isArray(r.findings)) {
    r = Object.assign({}, r, { findings: r.findings.filter(function (f) {
      return !_OZ_LIBS.test(String(f.file || "").split("/").pop());
    }) });
  }
  var _v = /0\.(\d+)\./.exec(String(r.compilerVersion || ""));
  if (_v && parseInt(_v[1], 10) >= 8 && Array.isArray(r.findings)) {
    r = Object.assign({}, r, { findings: r.findings.filter(function (f) {
      if (!/integer\s*(over|under)flow|overflow\s*\/\s*underflow/i.test(f.type || "")) return true;
      return /unchecked|assembly/i.test(JSON.stringify(f));
    }) });
  }

  const bySev = groupBySeverity(r.findings);
  const totalFindings = r.findings.length;
  const inScopeCount = r.scoped
    ? r.findings.filter((f) => f.scope_status === "IN_SCOPE").length
    : null;

  let out = "🛡️ *GuardContract Pre-Screen*\n";
  out += DIV + "\n";
  out += "📄 `" + r.contractName + "`" + (r.address ? "  [↗ Explorer](" + explorerUrl(r.chain, r.address) + ")" : "") + "\n";
  out += DIV + "\n\n";

  out += "*🌐 Network*     `" + (CHAIN_NAMES[r.chain] || r.chain) + "`";
  if (r.cached) out += "  ⚡ _cached_";
  out += "\n";
  out += "*⚙️  Compiler*    `" + r.compilerVersion + "`\n";
  out += "*📌 Pragma*      `" + (r.solidityRange || "?") + "`\n";
  out += "*🔧 Ruleset*     " + (TIER_LABELS[r.tier] || r.tier) + "\n\n";
  out += `🤖 *LLM*          ${llmStatusLine(r.llmStatus)}\n\n`;

  out += DIV + "\n";

  if (totalFindings === 0) {
    out += "*🔍 FINDINGS — CLEAN*\n";
    out += DIV + "\n\n";
    if (r.llmStatus && r.llmStatus.failed > 0) out += "⚠️ LLM layer partially failed — findings may be incomplete.\n";
    out += "✅ No pattern matches or LLM findings.\n";
    out += "_Represents both layers, not a full audit._\n";
  } else {
    out += "*🔍 FINDINGS — " + totalFindings + " DETECTED*";
    if (inScopeCount !== null) out += "  ·  ✅ " + inScopeCount + " in-scope";
    out += "\n" + DIV + "\n\n";

    const SHOW_LIMIT = 5;
    let truncatedSeverities = [];

    for (const sev of SEVERITY_ORDER) {
      const list = bySev[sev];
      if (!list.length) continue;

      out += SEV_EMOJI[sev] + " *" + sev + "* — " + list.length + "\n";

      const shown = list.slice(0, SHOW_LIMIT);
      shown.forEach((f, i) => {
        const isLast = i === shown.length - 1 && list.length <= SHOW_LIMIT;
        const branch = isLast ? "└" : "├";
        const scopeTag =
          f.scope_status === "IN_SCOPE" ? " ✅" :
          f.scope_status === "OUT_OF_SCOPE" ? " ✖" : "";
        const shortFile = f.file.split("/").pop();
        const tag = callerTag(f);
        out += branch + " `" + f.type + "`" + scopeTag + "\n";
        const _ref = shortFile.replace(/_/g, "\\_") + ":" + f.line;
        out += (isLast ? " " : "│") + "  ├ " + (r.address ? "[" + _ref + "](" + explorerUrl(r.chain, r.address) + ")" : _ref);
        if (f.corroborated) out += " _· corroborated_";
        out += "\n";
        if (tag) {
          out += (isLast ? " " : "│") + "  └ " + tag + "\n";
        }
      });

      if (list.length > SHOW_LIMIT) {
        truncatedSeverities.push(sev);
        out += "└  _+" + (list.length - SHOW_LIMIT) + " more " + sev + "_\n";
      }
      out += "\n";
    }

    if (truncatedSeverities.length > 0) {
      const chainPrefix = r.chain === "eth" ? "" : r.chain + " ";
      out += "📋 _Full list:_ `/full " + chainPrefix + r.address + "`\n\n";
    }
  }

  out += DIV + "\n";
  out += "🔗 *View Contract:* " + getExplorerLink(r.chain, r.address) + "\n";
  out += "⚠️ _Pre-screen only. Verify each finding manually before reporting._";
  return out;
}

// ==================== FULL REPORT ====================

function buildFullReport(r) {
  const bySev = groupBySeverity(r.findings);
  const totalFindings = r.findings.length;

  const header =
    "🛡️ *Complete Findings — " + r.contractName + "*\n" +
    "`" + r.address + "` · " + (CHAIN_NAMES[r.chain] || r.chain) + "\n" +
    DIV + "\n\n" +
    "Total: *" + totalFindings + "* findings\n\n";

  const messages = [];
  let current = header;
  const MAX_LEN = 3500;

  let counter = 0;
  for (const sev of SEVERITY_ORDER) {
    const list = bySev[sev];
    if (!list.length) continue;

    let section = SEV_EMOJI[sev] + " *" + sev + "* — " + list.length + "\n\n";

    for (const f of list) {
      counter++;
      let block = "*" + counter + ". " + escapeMd(f.type) + "*";
      if (f.corroborated) block += " _· corroborated_";
      if (f.scope_status === "IN_SCOPE") block += " ✅";
      if (f.scope_status === "OUT_OF_SCOPE") block += " ✖";
      block += "\n";
      block += "📁 `" + f.file.split("/").pop() + ":" + f.line + "`";
      if (f.cwe_id) block += " · `" + f.cwe_id + "`";
      block += "\n";

      const tag = callerTag(f);
      if (tag) block += "👤 " + tag + "\n";

      if (f.original_severity && f.original_severity !== f.severity) {
        block += "⬇️  _demoted from " + f.original_severity + " → " + f.severity + "_\n";
      }

      block += "📝 " + truncate(f.description, 200) + "\n";
      if (f.code_snippet) {
        block += "`" + truncate(f.code_snippet, 100) + "`\n";
      }
      if (f.fix) {
        block += "💡 " + truncate(f.fix, 150) + "\n";
      }
      block += "\n";

      if ((current + section + block).length > MAX_LEN) {
        messages.push(current + section);
        current = "";
        section = "";
      }

      section += block;
    }

    current += section + "\n";
  }

  current += DIV + "\n";
  current += "🔗 *View Contract:* " + getExplorerLink(r.chain, r.address) + "\n\n";
  current += "⚠️ _Pre-screen only. Verify each finding manually._";
  messages.push(current);

  return messages;
}

// ==================== START ====================

bot.start();
console.log("🛡️  GuardContract bot running (grammY)...");

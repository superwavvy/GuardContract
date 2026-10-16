# GuardContract

A Telegram-based Solidity vulnerability scanner. Send a contract address, get a report of code-level vulnerabilities in return.

**Built for security researchers doing first-pass triage on verified contracts.**

---

## What It Does

1. You send a contract address to the Telegram bot
2. It fetches the verified source via Etherscan V2 (16 chains supported)
3. Runs a deterministic pattern engine + LLM analysis
4. Returns a report with findings, severity, and file:line references

No UI. No signup. No API keys exposed to users.

## Architecture

```
Telegram message
    ↓
etherscan.js       → fetch verified source (multi-chain)
    ↓
sol-version.js     → parse pragma, determine ruleset tier
    ↓
sol-patterns.js    → 19 pattern rules (context-aware, deterministic)
    ↓
analyzer.js        → LLM layer (Groq) + CWE normalization
    ↓
guardscan-patch.js → verification (snippet-line match, two-tier)
    ↓
caller-analyzer.js → call-chain aware classification
    ↓
scanner.js         → merge, family dedupe, cap-per-family
    ↓
cache.js           → write report (24h TTL)
    ↓
Telegram reply
```

## Detection Rules

| Rule | CWE | Severity |
|:---|:---|:---|
| `arbitrary-call-user-calldata` | CWE-829 | CRITICAL |
| `trust-msg-sender-selfreport` | CWE-807 | CRITICAL |
| `tx-origin-auth` | CWE-477 | HIGH |
| `selfdestruct` | CWE-284 | CRITICAL |
| `delegatecall` | CWE-829 | HIGH |
| `unchecked-math-pre-08` | CWE-190 | HIGH |
| `legacy-call-value` | CWE-841 | MEDIUM |
| `unchecked-low-level-call` | CWE-252 | HIGH |
| `transfer-return-ignored` | CWE-252 | MEDIUM |
| `signature-replay` | CWE-294 | HIGH |
| `unbounded-loop` | CWE-834 | MEDIUM |
| `encodePacked-collision` | CWE-328 | MEDIUM |
| `timestamp-randomness` | CWE-330 | HIGH |
| `blockhash-randomness` | CWE-330 | MEDIUM |
| `owner-mint` | CWE-269 | HIGH |
| `owner-pause` | CWE-269 | MEDIUM |
| `hardcoded-address` | CWE-798 | LOW |
| `governance-flash-loan-vote` | CWE-362 | HIGH |
| `governance-short-timelock` | CWE-662 | MEDIUM |

Each rule has a **`contextCheck`** that suppresses false positives. Example: `unchecked-low-level-call` doesn't fire if a `require(...)` or `if (success)` follows the call within 5 lines.

## Tuning corpus (not a benchmark)

Every rule was tuned against **real contracts**, not synthetic examples. 8 contracts scanned; each produced a fix.

| Contract | Initial Findings | After Tuning | Real Bugs |
|:---|:---|:---|:---|
| EthPrime | 22 | 3 | 2-3 |
| Exchange | 5 | 0 | 0 |
| Token | 2 | 1 | 0 |
| Syncus | 4 | — | — |
| HaiGovernor | 6 | 0 | 0 |
| GPXHooks | 5 | 2 | 1 |
| FlashLoopAdapter | 5 | 3 (2 CRIT) | **3 (matches real $305K exploit)** |
| Sepolia test | — | 1 (CRIT) | Regression test |

_These contracts were used to tune rules, so any precision figure here is in-sample. Holdout results in [BENCHMARK.md](BENCHMARK.md)._

**On this tuning corpus (in-sample) precision improved from ~25% to ~66%.** This is a small hand-picked set, not a benchmark — see [BENCHMARK.md](BENCHMARK.md) for holdout results on SmartBugs Curated.

## Design Principles

1. **Pattern layer is deterministic.** Same input → same output. No variance.
2. **Context checks matter more than patterns.** A regex matching `.call(` is useless. A regex matching `.call(` *and* verifying no `require` follows is useful.
3. **Self-griefing is not DoS.** If the caller provides the array, the caller pays the gas. Suppress.
4. **Only audit project code.** Skip `node_modules/`, `@openzeppelin/`, libraries — Trail of Bits already audited those.
5. **LLM findings are hypotheses.** Pattern findings are facts. Tag both.
6. **Fail-safe, not fail-open.** If the scan can't complete, say so. Never report "clean" on a failed scan.

## Setup

```bash
git clone git@github.com:superwavvy/Guard-Contract.git
# or, if you don't use SSH:
git clone https://github.com/superwavvy/Guard-Contract.git
cd Guard-Contract
npm install
```

Create `.env`:

```env
ETHERSCAN_KEY=your_etherscan_v2_key
GROQ_API_KEY=gsk_...
TELEGRAM_BOT_TOKEN=...
```

Run:

```bash
node bot.js
```

## Telegram Commands

```
/start                        # help
/scope <text>                 # set bounty scope for IN/OUT labeling
/scopeoff                     # clear scope
/cache                        # cache stats
/clear 0x...                  # invalidate a cached report
/full 0x...                   # full findings list
```

Send an address (EVM, auto-detects chain):

```
0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
```

Or force a chain:

```
arb 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1
```

## Supported Chains

16 chains via Etherscan V2: Ethereum, Arbitrum, Base, Optimism, Polygon, BSC, Avalanche, Fantom, Gnosis, Celo, Scroll, Linea, Blast, Mantle, zkSync, Sepolia.

## Limitations

- **Verified source only.** Unverified contracts can't be scanned (no source to read).
- **No deployment-state analysis.** Can't detect misconfigurations like `authority=0x0` that need runtime storage reads.
- **No semantic reasoning.** Can't catch V4 hook accounting bugs or protocol-specific state machine exploits.
- **LLM non-determinism.** ±2 finding variance between runs.
- **No PoC generation.** Produces findings, not executable exploits.

## What It Doesn't Do

- Replace an auditor
- Catch semantic/protocol-specific bugs
- Detect deployment misconfigurations
- Handle unverified contracts

**It's a triage accelerator.** Not a bug-bounty autopilot, not an audit replacement. It gets you from "should I look at this contract?" to "here are 3 things worth manually verifying" in under a minute.

## License

MIT

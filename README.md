# GuardContract

A Telegram-based Solidity vulnerability scanner. Send a contract address, get a report of code-level vulnerabilities in return. Built for security researchers doing first-pass triage on verified contracts.

## What It Does

1. You send a contract address to the Telegram bot.
2. It fetches the verified source via Etherscan V2 (16 chains supported).
3. If the address is a proxy (EIP-1967, Transparent, or Beacon), it automatically resolves and scans the underlying implementation contract.
4. Runs a deterministic pattern engine plus an LLM analysis layer.
5. Returns a report with findings, severity, CWE IDs, and file:line references.

No UI. No signup. No API keys exposed to users.

## Architecture

Telegram message
↓
etherscan.js → fetch verified source (multi-chain, proxy resolution)
↓
sol-version.js → parse pragma, determine ruleset tier
↓
sol-patterns.js → 23+ pattern rules (context-aware, deterministic)
↓
analyzer.js → LLM layer (Cerebras/Groq) + CWE normalization
↓
guardscan-patch.js → verification (snippet-line match, two-tier)
↓
caller-analyzer.js → call-chain aware classification
↓
scanner.js → merge, family dedupe, cap-per-family
↓
cache.js → write report (24h TTL)
↓
Telegram reply

## Proxy Resolution

Modern DeFi protocols use upgradeable proxy patterns (Diamonds, Transparent Proxies). Scanning the proxy shell yields nothing, because the logic lives in a separate implementation contract. GuardContract automatically detects the proxy type and fetches the implementation source before scanning.

- Checks Etherscan's `Implementation` field.
- Reads EIP-1967 and OZ legacy storage slots directly via RPC.
- Verifies the resolved implementation is a valid contract.

## Detection Rules

| Rule | CWE | Severity |
|---|---|---|
| `arbitrary-call-user-calldata` | CWE-829 | CRITICAL |
| `trust-msg-sender-selfreport` | CWE-807 | CRITICAL |
| `governance-flash-loan-vote` | CWE-362 | CRITICAL |
| `selfdestruct` | CWE-284 | CRITICAL |
| `tx-origin-auth` | CWE-477 | HIGH |
| `delegatecall` | CWE-829 | HIGH |
| `unchecked-math-pre-08` | CWE-190 | HIGH |
| `unchecked-low-level-call` | CWE-252 | HIGH |
| `signature-replay` | CWE-294 | HIGH |
| `timestamp-randomness` | CWE-330 | HIGH |
| `owner-mint` | CWE-269 | HIGH |
| `governance-short-timelock` | CWE-662 | HIGH |
| `rescue-no-token-exclusion` | CWE-284 | MEDIUM |
| `nft-hook-reentrancy` | CWE-841 | MEDIUM |
| `legacy-call-value` | CWE-841 | MEDIUM |
| `transfer-return-ignored` | CWE-252 | MEDIUM |
| `unbounded-loop` | CWE-834 | MEDIUM |
| `encodePacked-collision` | CWE-328 | MEDIUM |
| `blockhash-randomness` | CWE-330 | MEDIUM |
| `owner-pause` | CWE-269 | MEDIUM |
| `stale-oracle-price` | CWE-829 | MEDIUM |
| `swap-no-slippage` | CWE-440 | MEDIUM |
| `hardcoded-address` | CWE-798 | LOW |

Each rule has a `contextCheck` that suppresses false positives. For example, `unchecked-low-level-call` does not fire if a `require(...)` or `if (success)` follows the call within 5 lines. `swap-no-slippage` only fires if `amountOutMin` is zero or the deadline is meaningless (`block.timestamp` or `type(uint256).max`).

## LLM Fallback (Cerebras + Groq)

The LLM layer uses a multi-provider fallback strategy. It tries Groq first. If Groq returns a `429 Rate Limit`, it instantly falls back to Cerebras. Both providers serve `gpt-oss-120b`, which is the primary model. This ensures the scanner never stalls waiting for a rate limit to reset.

- **Primary:** Cerebras (`gpt-oss-120b`, extremely fast inference)
- **Fallback:** Groq (`openai/gpt-oss-120b`)

## Real-World Validation

GuardContract was tested against the **X100 protocol exploit** (October 2026, ~$4.75M loss). The bot correctly identified the exact attack vectors:

- **Flash-Loan Governance Capture:** Flagged `applyForSenate` and vote logic because membership was read from live stake instead of a snapshot.
- **Arbitrary External Call:** Flagged `Senate.sol:175` where a proposal could execute an arbitrary `v3Swap` call.
- **Short Timelock:** Flagged `execute()` because there was no voting-end check or timelock.

## Tuning Corpus (not a benchmark)

Every rule was tuned against real contracts, not synthetic examples. 8 contracts scanned; each produced a fix.

| Contract | Initial Findings | After Tuning | Real Bugs |
|---|---|---|---|
| EthPrime | 22 | 3 | 2-3 |
| Exchange | 5 | 0 | 0 |
| Token | 2 | 1 | 0 |
| Syncus | 4 | — | — |
| HaiGovernor | 6 | 0 | 0 |
| GPXHooks | 5 | 2 | 1 |
| FlashLoopAdapter | 5 | 3 (2 CRIT) | **3 (matches real $305K exploit)** |
| Sepolia test | — | 1 (CRIT) | Regression test |

These contracts were used to tune rules, so any precision figure here is in-sample. Holdout results in [BENCHMARK.md](BENCHMARK.md).

## Setup

1. Clone the repository.
   ```bash
   git clone git@github.com:superwavvy/Guard-Contract.git
   cd Guard-Contract
   ```
2. Install dependencies.
   ```bash
   npm install
   ```
3. Configure environment variables (`.env`).
   ```env
   TELEGRAM_BOT_TOKEN=...
   ETHERSCAN_API_KEY=...
   CEREBRAS_API_KEY=...
   CEREBRAS_MODEL=gpt-oss-120b
   # Optional fallback
   GROQ_API_KEY=...
   ```
4. Run the bot.
   ```bash
   node bot.js
   ```

## Limitations

- **Zero-days:** The engine catches known patterns and LLM-detected logic flaws. It cannot find true zero-day vulnerabilities that require deep protocol-specific context.
- **Simulation:** The LLM layer is non-deterministic. Findings should be manually verified before submission.
- **Proxy edge cases:** Custom proxy patterns (non-EIP-1967) may not resolve automatically.

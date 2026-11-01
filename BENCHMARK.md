# GuardContract Benchmark

Ground truth: SmartBugs Curated, 143 contracts, 207 labelled vulnerabilities, 10 categories. Published by the SmartBugs team; not fitted to GuardContract rules.

## Patterns only (no LLM)
Recall = labelled vulnerabilities that have a finding nearby. Line window = within 3 lines of the label. Function mode = within 3 lines OR in the same function. Default cap = each rule reports at most 5 findings per file; uncapped = MAXPER=50.

| Category | Line window (cap 5) | + Same function (cap 5) | Line window (uncapped) |
|---|---|---|---|
| unchecked_low_level_calls | 72/75 | 74/75 | 72/75 |
| arithmetic | 22/23 | 22/23 | 23/23 |
| reentrancy | 30/32 | 30/32 | 30/32 |
| bad_randomness | 15/31 | 27/31 | 21/31 |
| access_control | 9/21 | 10/21 | 9/21 |
| denial_of_service | 5/7 | 5/7 | 5/7 |
| time_manipulation | 2/7 | 3/7 | 2/7 |
| front_running | 0/7 | 0/7 | 0/7 |
| short_addresses | 1/1 | 1/1 | 1/1 |
| other | 1/3 | 1/3 | 1/3 |
| unmatched findings | 245/470 | 212/470 | 462/702 |

There is no front-running rule in the scanner, so 0/7 means no detector exists.

## LLM column (Cerebras gpt-oss-120b, comments stripped, 2 runs)
Setups: patterns = rules only (bench-v2), llm = LLM only, both = union of the two. Cells show min-max over 2 runs. At temperature 0 the LLM varied little between runs: only reentrancy and the total finding counts changed.

Overall recall, line window, 207 labels: patterns 165 (80%), llm 161-162 (78%), both 179-180 (86-87%). The layers miss different bugs, so combining them adds about 15-18 labels over either alone. This is machine recall on short legacy teaching contracts, not the end-to-end chain with a human reviewer.

### Line window (within 3 lines of the label)
| Category | patterns | llm | both |
|---|---|---|---|
| access_control | 17/21 | 15/21 | 19/21 |
| arithmetic | 22/23 | 23/23 | 23/23 |
| bad_randomness | 15/31 | 12/31 | 19/31 |
| denial_of_service | 5/7 | 5/7 | 5/7 |
| front_running | 0/7 | 0/7 | 0/7 |
| other | 1/3 | 1/3 | 1/3 |
| reentrancy | 30/32 | 30-31/32 | 30-31/32 |
| short_addresses | 1/1 | 1/1 | 1/1 |
| time_manipulation | 2/7 | 6/7 | 6/7 |
| unchecked_low_level_calls | 72/75 | 68/75 | 75/75 |
| unmatched / total findings | 236/467 | 187-201/398-409 | 423-437/865-876 |

### Line window or same function
| Category | patterns | llm | both |
|---|---|---|---|
| access_control | 17/21 | 15/21 | 19/21 |
| arithmetic | 22/23 | 23/23 | 23/23 |
| bad_randomness | 22/31 | 17/31 | 29/31 |
| denial_of_service | 5/7 | 5/7 | 5/7 |
| front_running | 0/7 | 1/7 | 1/7 |
| other | 1/3 | 1/3 | 1/3 |
| reentrancy | 30/32 | 30-32/32 | 30-32/32 |
| short_addresses | 1/1 | 1/1 | 1/1 |
| time_manipulation | 3/7 | 6/7 | 6/7 |
| unchecked_low_level_calls | 74/75 | 69/75 | 75/75 |
| unmatched / total findings | 211/467 | 158-171/398-409 | 369-382/865-876 |

### Label leakage
SmartBugs files carry the answer key in comments (for example the REENTRANCY report marker and the vulnerable_at_lines header), and some comments explain the bug. A first run that sent files to the LLM unmodified scored llm-only 181/207 (front_running 7/7). With all comments stripped it scores 161-162/207 (front_running 0/7). Every LLM number above uses stripped comments; patterns are computed on the original source. The first-run tables are kept as BENCHMARK-llm-leaky-line.md and BENCHMARK-llm-leaky-fn.md.

### Known gaps
- No front-running detector: 0/7 for every setup.
- Cross-function reentrancy needs call-path matching (see reentrancy_bonus.sol note above).
- Roughly half of the combined findings are unmatched (423-437 of 865-876). That is the review load for the human. Precision of the LLM layer was not hand-checked; the earlier 20-finding triage covers patterns only.
- 2 runs, not 3. LLM prompt was tuned on USDfr, not SmartBugs. SmartBugs is public, so the model may have seen it in training.

## Caveats
1. Matching is lenient (3-line window; function mode is more lenient still).
2. "Unmatched findings" are not all false positives: SmartBugs annotations are incomplete. Hand triage of 20 random unmatched findings (cap 5 run): 15 noise, 3 real, 2 unsure. 159 of the 245 unmatched came from the overflow rule alone.
3. Training contamination: SmartBugs is public and old; the LLM may have seen it.
4. Arithmetic is a soft number: these contracts are pedagogical.
5. A reentrancy "hit" means any rule fired nearby. The dedicated reentrancy rule fired on 13/32; the rest were the legacy call.value rule on the same line.
6. Each rule reports at most 5 findings per file. This bounds noise but deflates recall in files with many instances of one bug. Uncapping moved bad_randomness 15 to 21 and arithmetic 22 to 23, and nearly doubled unmatched findings.
7. Function mode: 12 extra bad_randomness labels come from only 3 contracts (blackjack, etheraffle, smart_billions); several labels in one function means one finding can match many. reentrancy_bonus.sol stays unmatched: SmartBugs labels the call to withdrawReward() inside getFirstWithdrawalBonus(), while the flagged line is the .call.value inside withdrawReward(), a different function.

## Fixes after the first run
First pass scored arithmetic 0/23. Causes, both mine: the overflow rule skipped any file mentioning SafeMath, and the harness never passed a compiler tier. Both fixed after seeing results; see commit history.

## Rule versions
- bench-v1 (commit a6713a4): the rules that produced the tables above.
- bench-v2 (current): later detectors and fixes (flash-loan governance, proxy resolution, ERC4626, stale oracle, slippage, library false-positive suppression), made while scanning real protocols (X100, USDfr ReserveManager), not from SmartBugs results. Same SmartBugs run, patterns only: access_control 9/21 -> 17/21; reentrancy, arithmetic, unchecked calls, bad_randomness unchanged; unmatched 245/470 -> 236/467.
- LLM layer: Cerebras gpt-oss-120b with the prompt at bench-v2. The prompt was tuned on USDfr, not SmartBugs.

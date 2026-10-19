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

The front-running rule exists but is disabled by default, so 0/7 is a config choice, not a detection result.

## LLM column
Pending. Non-determinism observed at temperature 0: same file gives different findings on repeat runs. Will report ranges over 3 runs.

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

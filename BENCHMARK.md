# GuardContract Benchmark

Ground truth: **SmartBugs Curated** — 143 annotated contracts, 208 labelled vulnerabilities, 10 categories. Published by the SmartBugs team; not fitted to GuardContract rules.

## Patterns-only (deterministic rules, no LLM)

| Category | Recall |
|---|---|
| unchecked_low_level_calls | 72/75 (96%) |
| arithmetic | 22/23 (96%) |
| reentrancy | 30/32 (94%) |
| bad_randomness | 15/31 (48%) |
| access_control | 9/21 (43%) |
| denial_of_service | 5/7 |
| time_manipulation | 2/7 |
| front_running | 0/7 |
| short_addresses | 1/1 |
| other | 1/3 |
| **unmatched findings** | **245/470** |

## LLM column

Pending. Non-determinism observed at `temperature: 0` — same file produces different findings on repeat runs. Single-run numbers to follow; 3-run range is quota-bound.

## Caveats

1. **Matching is lenient.** A finding within 3 lines of an annotation counts as a hit.
2. **"Unmatched findings" ≠ false positives.** SmartBugs annotations are incomplete. A manual triage of a 20-finding sample is required for a real precision estimate.
3. **Training contamination.** SmartBugs is public and old; the LLM may have seen these contracts in training, which inflates its recall.
4. **Arithmetic 96% is a soft number.** The arithmetic contracts in SmartBugs are pedagogical (`integer_overflow_1.sol`, `insecure_transfer.sol`) — they exist to demonstrate the bug cleanly. Real-world arithmetic bugs are harder.

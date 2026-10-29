const fs = require("fs"), A = require("./bench-adapter");
const dir = process.env.HOME + "/audits/vulnlabs/src/test/";
const want = [
  ["Oracle-stale.sol", "Oracle Price Without Staleness Check", 37],
  ["Slippage-deadline.sol", "Swap Without Slippage or Deadline Protection", 70],
  ["Unprotected-callback.sol", "Reentrancy via Safe-Mint / Safe-Transfer Hook", 73],
  ["recoverERC20.sol", "Rescue Function Can Sweep Protocol Tokens", 110],
];
let bad = 0;
for (const [f, rule, line] of want) {
  const got = A.patternScan(fs.readFileSync(dir + f, "utf8")).filter((x) => x.rule === rule).map((x) => x.line);
  const ok = got.some((l) => Math.abs(l - line) <= 2);
  if (!ok) bad++;
  console.log((ok ? "PASS " : "FAIL ") + f + " -> " + (got.join(",") || "none"));
}
console.log(bad ? bad + " failing" : "all passing");

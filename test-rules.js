const A = require("./bench-adapter");
const P = "pragma solidity ^0.8.20;\n";
const cases = [
  ["init: unguarded (must fire)", P + "contract A { address public owner; function initialize(address o) external { owner = o; } }", "Unprotected Initializer", true],
  ["init: guarded (quiet)", P + "contract A { address public owner; bool initialized; function initialize(address o) external { require(!initialized); initialized = true; owner = o; } }", "Unprotected Initializer", false],
  ["role: unguarded (must fire)", P + "contract A { address public owner; function setOwner(address o) external { owner = o; } }", "Unprotected Privileged Role Assignment", true],
  ["role: guarded (quiet)", P + "contract A { address public owner; function setOwner(address o) external { require(msg.sender == owner); owner = o; } }", "Unprotected Privileged Role Assignment", false],
  ["oracle: spot (must fire)", P + "interface P { function getReserves() external view returns (uint112, uint112, uint32); }\ncontract V { P pair; function price() public view returns (uint256) { (uint112 a, uint112 b,) = pair.getReserves(); return uint256(b) * 1e18 / a; } }", "Spot Price Used as Oracle", true],
  ["oracle: with chainlink (quiet)", P + "interface P { function getReserves() external view returns (uint112, uint112, uint32); }\ninterface F { function latestRoundData() external view returns (uint256); }\ncontract V { P pair; function price() public view returns (uint256) { (uint112 a, uint112 b,) = pair.getReserves(); return uint256(b) * 1e18 / a; } }", "Spot Price Used as Oracle", false],
  ["erc20: ETH transfer (quiet)", P + "contract B { function f(address to) external { payable(to).transfer(1 ether); } }", "Unchecked ERC20 Transfer", false],
  ["erc20: checked return (quiet)", P + "interface IERC20 { function transfer(address a, uint256 b) external returns (bool); }\ncontract C { IERC20 t; function f(address to) external { require(t.transfer(to, 1)); } }", "Unchecked ERC20 Transfer", false],
  ["gov gate: wallet execute (quiet)", P + "contract W { function execute(address a, bytes calldata d) external { a.call(d); } }", "Governance Execute Without Time Gate", false],
];
let bad = 0;
for (const [name, src, type, want] of cases) {
  let f = [];
  try { f = A.patternScan(src); } catch (e) { console.log("ERR  " + name + ": " + e.message); bad++; continue; }
  const got = f.some((x) => x.rule === type);
  if (got !== want) bad++;
  console.log((got === want ? "PASS " : "FAIL ") + name);
}
console.log(bad ? bad + " failing" : "all passing");

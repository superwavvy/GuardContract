const A = require("./bench-adapter");
const P = "pragma solidity ^0.8.20;\n";
const T20 = "interface IERC20 { function transfer(address a, uint256 b) external returns (bool); }\n";
const CB = "Callback Without Caller Validation", RC = "Unprotected Fund Recovery", OR = "Oracle Price Without Staleness Check";
const SW = "Swap Without Slippage or Deadline Protection", DM = "Division Before Multiplication (Precision Loss)", V4 = "ERC4626 First-Depositor Inflation Risk";
const RT = "interface R { function swapExactTokensForTokens(uint256 a, uint256 m, address[] calldata p, address t, uint256 d) external returns (uint256[] memory); }\n";
const FD = "interface F { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }\n";
const BO = "interface IERC20 { function balanceOf(address a) external view returns (uint256); }\n";
const cases = [
  ["callback: no caller check (fire)", P + T20 + "contract S { IERC20 t; function uniswapV3SwapCallback(int256 a, int256 b, bytes calldata d) external { t.transfer(msg.sender, uint256(a)); } }", CB, true],
  ["callback: validated (quiet)", P + T20 + "contract S { IERC20 t; address pool; function uniswapV3SwapCallback(int256 a, int256 b, bytes calldata d) external { require(msg.sender == pool); t.transfer(msg.sender, uint256(a)); } }", CB, false],
  ["recover: open (fire)", P + T20 + "contract R { function recoverERC20(address t, uint256 a) external { IERC20(t).transfer(msg.sender, a); } }", RC, true],
  ["recover: onlyOwner (quiet)", P + T20 + "contract R { function recoverERC20(address t, uint256 a) external onlyOwner { IERC20(t).transfer(msg.sender, a); } }", RC, false],
  ["recover: user own balance (quiet)", P + "contract R { mapping(address=>uint256) bal; function emergencyWithdraw() external { uint256 a = bal[msg.sender]; bal[msg.sender] = 0; payable(msg.sender).transfer(a); } }", RC, false],
  ["oracle: no staleness (fire)", P + FD + "contract V { F feed; function price() public view returns (uint256) { (, int256 p, , , ) = feed.latestRoundData(); return uint256(p); } }", OR, true],
  ["oracle: checked (quiet)", P + FD + "contract V { F feed; function price() public view returns (uint256) { (uint80 id, int256 p, , uint256 updatedAt, uint80 ans) = feed.latestRoundData(); require(updatedAt >= block.timestamp - 1 hours); require(ans >= id); return uint256(p); } }", OR, false],
  ["swap: minOut 0 (fire)", P + RT + "contract S { R r; function f(uint256 a, address[] calldata p) external { r.swapExactTokensForTokens(a, 0, p, address(this), block.timestamp); } }", SW, true],
  ["swap: real params (quiet)", P + RT + "contract S { R r; function f(uint256 a, uint256 minOut, uint256 deadline, address[] calldata p) external { r.swapExactTokensForTokens(a, minOut, p, address(this), deadline); } }", SW, false],
  ["math: divide first (fire)", P + "contract D { function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { uint256 r = a / b * c; return r; } }", DM, true],
  ["math: multiply first (quiet)", P + "contract D { function f(uint256 a, uint256 b, uint256 c) external pure returns (uint256) { uint256 r = a * c / b; return r; } }", DM, false],
  ["vault: naive shares (fire)", P + BO + "contract V { IERC20 asset; uint256 public totalSupply; function deposit(uint256 assets) external returns (uint256 shares) { shares = totalSupply == 0 ? assets : assets * totalSupply / asset.balanceOf(address(this)); totalSupply += shares; } }", V4, true],
  ["vault: min liquidity (quiet)", P + BO + "contract V { IERC20 asset; uint256 constant MINIMUM_LIQUIDITY = 1000; uint256 public totalSupply; function deposit(uint256 assets) external returns (uint256 shares) { shares = totalSupply == 0 ? assets : assets * totalSupply / asset.balanceOf(address(this)); totalSupply += shares; } }", V4, false],
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

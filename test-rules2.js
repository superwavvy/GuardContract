const A = require("./bench-adapter");
const P = "pragma solidity ^0.8.20;\n", O = "pragma solidity ^0.4.18;\n";
const R = "Unprotected Privileged Role Assignment", I = "Unprotected Initializer";
const cases = [
  ["role: old-style constructor (quiet)", O + "contract Foo { address owner; function Foo() public { owner = msg.sender; } }", R, false],
  ["role: lowercase modifier (quiet)", P + "contract A { address owner; modifier onlyowner { require(msg.sender == owner); _; } function change(address o) public onlyowner { owner = o; } }", R, false],
  ["role: wrong ctor name, no visibility (must fire)", O + "contract Rubixi { address creator; function DynamicPyramid() { creator = msg.sender; } }", R, true],
  ["init: parity style delegate (must fire)", O + "contract W { address[] m_owners; function initWallet(address[] _o) { initM(_o); } function initM(address[] _o) internal { m_owners = _o; } }", I, true],
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

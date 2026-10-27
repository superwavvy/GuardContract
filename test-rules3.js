const A = require("./bench-adapter");
const O = "pragma solidity ^0.4.18;\n";
const R = "Unprotected Privileged Role Assignment";
const cases = [
  ["ctor with comment (quiet)", O + "contract Ownable {\n address owner;\n /** sets the owner of the contract to the sender */\n function Ownable() { owner = msg.sender; }\n}", R, false],
  ["type cast is not a call (quiet)", O + "contract G { address owner; function G() { owner = msg.sender; } function reset() {} }\ncontract A { function attack(address t) { G(t).reset(); } }", R, false],
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

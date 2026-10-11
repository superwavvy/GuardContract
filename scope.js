const fs = require("fs");
const path = require("path");

const SCOPE_FILE = path.join(process.env.HOME, ".guardcontract", "scope.txt");

function getScope() {
  if (!fs.existsSync(SCOPE_FILE)) return null;
  const text = fs.readFileSync(SCOPE_FILE, "utf8").trim();
  return text || null;
}

function setScope(text) {
  fs.writeFileSync(SCOPE_FILE, text.trim());
}

function clearScope() {
  if (fs.existsSync(SCOPE_FILE)) fs.unlinkSync(SCOPE_FILE);
}

module.exports = { getScope, setScope, clearScope };

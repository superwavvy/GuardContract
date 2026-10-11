const fs = require("fs");
const path = require("path");

const CACHE_DIR = path.join(process.env.HOME, ".guardcontract");
const CACHE_FILE = path.join(CACHE_DIR, "cache.json");
const CHAIN_FILE = path.join(CACHE_DIR, "chains.json");

if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
if (!fs.existsSync(CACHE_FILE)) fs.writeFileSync(CACHE_FILE, "{}");
if (!fs.existsSync(CHAIN_FILE)) fs.writeFileSync(CHAIN_FILE, "{}");

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { return {}; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const TTL_MS = 24 * 60 * 60 * 1000;

function getChainForAddress(address) {
  const chains = readJSON(CHAIN_FILE);
  return chains[address.toLowerCase()] || null;
}
function setChainForAddress(address, chain) {
  const chains = readJSON(CHAIN_FILE);
  chains[address.toLowerCase()] = chain;
  writeJSON(CHAIN_FILE, chains);
}

function cacheKey(address, chain) { return `${chain}:${address.toLowerCase()}`; }

function get(address, chain) {
  const cache = readJSON(CACHE_FILE);
  const entry = cache[cacheKey(address, chain)];
  if (!entry) return null;
  if (Date.now() - entry.ts > TTL_MS) return null;
  return entry.report;
}

function set(address, chain, report) {
  const cache = readJSON(CACHE_FILE);
  cache[cacheKey(address, chain)] = { ts: Date.now(), report };
  writeJSON(CACHE_FILE, cache);
}

function invalidate(address, chain) {
  const cache = readJSON(CACHE_FILE);
  delete cache[cacheKey(address, chain)];
  writeJSON(CACHE_FILE, cache);
}

function stats() {
  const cache = readJSON(CACHE_FILE);
  const chains = readJSON(CHAIN_FILE);
  return {
    cachedScans: Object.keys(cache).length,
    knownChains: Object.keys(chains).length,
    cacheFile: CACHE_FILE
  };
}

module.exports = {
  getChainForAddress, setChainForAddress,
  get, set, invalidate, stats
};

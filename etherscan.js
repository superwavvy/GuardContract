require("dotenv").config();
const cache = require("./cache.js");

const CHAIN_IDS = {
  eth: 1, ethereum: 1,
  arb: 42161, arbitrum: 42161,
  base: 8453,
  op: 10, optimism: 10,
  polygon: 137, matic: 137,
  bsc: 56, bnb: 56,
  avax: 43114, avalanche: 43114,
  ftm: 250, fantom: 250,
  gnosis: 100,
  celo: 42220,
  scroll: 534352,
  linea: 59144,
  blast: 81457,
  mantle: 5000,
  zksync: 324,
  sepolia: 11155111
};

const DETECT_PRIORITY = ["eth", "arb", "base", "op", "polygon", "bsc", "avax"];

async function fetchContract(address, chain = "eth") {
  const chainId = CHAIN_IDS[chain.toLowerCase()];
  if (!chainId) throw new Error(`Unsupported chain: ${chain}`);

  const apiKey = process.env.ETHERSCAN_KEY;
  if (!apiKey) throw new Error("Missing ETHERSCAN_KEY in .env");

  const url = `https://api.etherscan.io/v2/api?chainid=${chainId}` +
              `&module=contract&action=getsourcecode` +
              `&address=${address}&apikey=${apiKey}`;

let res, data;
try {
  res = await fetch(url);
  if (!res.ok) {
    console.log("  ⚠️ Etherscan HTTP", res.status, await res.text().then(t => t.slice(0, 200)));
    return { ok: false, reason: `Etherscan HTTP ${res.status}` };
  }
  data = await res.json();
} catch (e) {
  console.log("  ⚠️ Fetch threw:", e.message, e.cause ? "| cause: " + e.cause.code : "");
  return { ok: false, reason: `Network error: ${e.message}` };
}
  if (data.status !== "1" || !data.result?.[0]?.SourceCode) {
    return { ok: false, reason: `Not verified on ${chain}` };
  }

  const r = data.result[0];
  const source = r.SourceCode;

  if (source.startsWith("{{") || source.startsWith("{")) {
    try {
      const parsed = JSON.parse(source.replace(/^\{|\}$/g, ""));
      const files = Object.entries(parsed.sources).map(([p, { content }]) => ({
        path: p,
        content
      }));
      return {
        ok: true,
        chain, chainId,
        contractName: r.ContractName,
        compilerVersion: r.CompilerVersion,
        files,
        primaryFile: files.find(f => f.path.includes(r.ContractName)) || files[0]
      };
    } catch { /* fall through */ }
  }

  return {
    ok: true,
    chain, chainId,
    contractName: r.ContractName,
    compilerVersion: r.CompilerVersion,
    files: [{ path: `${r.ContractName}.sol`, content: source }],
    primaryFile: { path: `${r.ContractName}.sol`, content: source }
  };
}

async function detectChain(address) {
  const cached = cache.getChainForAddress(address);
  if (cached) return cached;

  for (const chain of DETECT_PRIORITY) {
    try {
      const r = await fetchContract(address, chain);
      if (r.ok) {
        cache.setChainForAddress(address, chain);
        return chain;
      }
    } catch { /* try next */ }
  }
  return null;
}

module.exports = { fetchContract, detectChain, CHAIN_IDS };

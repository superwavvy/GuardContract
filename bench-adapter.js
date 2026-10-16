require('dotenv').config();
const { runPatterns } = require('./sol-patterns');
const { parseSolidityVersion, versionTier } = require('./sol-version');
const { analyzeChunk } = require('./analyzer');

function tierOf(src) {
  try { return versionTier(parseSolidityVersion(src)); } catch (e) { return 'unknown'; }
}

function patternScan(src) {
  const tier = tierOf(src);
  let findings = [];
  try { findings = runPatterns(src, 'bench.sol', tier); } catch (e) { console.error('patternScan error:', e.message); return []; }
  return findings.map(f => ({ line: f.line, rule: f.type }));
}

async function llmScan(src) {
  const tier = tierOf(src);
  const numbered = src.split('\n').map((l, i) => (i + 1) + ': ' + l).join('\n');
  const contract = { contractName: 'bench', compilerVersion: 'unknown', primaryFile: { path: 'bench.sol' } };
  try {
    const out = await analyzeChunk(numbered, 1, 'bench.sol', contract, 'eth', tier);
    return out.map(f => ({ line: f.line, rule: f.type }));
  } catch (e) {
    if (e.code === 'LLM_SKIPPED_OVERSIZED') return [];
    throw e;
  }
}

async function fullScan(src) {
  return [...patternScan(src), ...await llmScan(src)];
}

module.exports = { patternScan, llmScan, fullScan };

const MAX_CHUNK_TOKENS = 1500;
const MAX_CHUNKS_PER_FILE = 4;
const CHUNK_OVERLAP_LINES = 15;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const estimateTokens = (text) => Math.ceil(text.length / 4);

function chunkFile(content, maxTokens = MAX_CHUNK_TOKENS, overlap = CHUNK_OVERLAP_LINES) {
  const lines = content.split("\n");
  const maxLineChars = maxTokens * 4;
  const chunks = [];
  let start = 0;

  while (start < lines.length) {
    let end = start;
    let tokens = 0;
    const out = [];

    while (end < lines.length) {
      let line = lines[end];
      if (line.length > maxLineChars) {
        line = line.slice(0, maxLineChars) + " ...[truncated]";
      }
      const numbered = `${end + 1}: ${line}`;
      const t = estimateTokens(numbered) + 1;
      if (out.length > 0 && tokens + t > maxTokens) break;
      out.push(numbered);
      tokens += t;
      end++;
    }

    chunks.push({ startLine: start + 1, endLine: end, text: out.join("\n") });
    if (end >= lines.length) break;
    start = Math.max(end - overlap, start + 1);
  }
  return chunks;
}

function splitChunk(chunk) {
  const lines = chunk.text.split("\n");
  if (lines.length < 2) return null;
  const mid = Math.floor(lines.length / 2);
  return [
    { startLine: chunk.startLine, text: lines.slice(0, mid).join("\n") },
    { startLine: chunk.startLine + mid, text: lines.slice(mid).join("\n") }
  ];
}

function describeError(err) {
  const cause = err.cause ? ` (cause: ${err.cause.code || err.cause.message})` : "";
  const status = err.status ? `HTTP ${err.status}: ` : "";
  return `${status}${err.message}${cause}`;
}

const NON_RETRYABLE = [400, 401, 403, 404, 413, 429];

async function withRetry(fn, { retries = 3, baseDelay = 3000 } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const status = err.status || err.response?.status;
      if (NON_RETRYABLE.includes(status)) throw err;
      if (attempt === retries) break;

      const wait = Math.min(baseDelay * 2 ** (attempt - 1) + Math.random() * 500, 60000);
      console.log(`   ⏳ ${describeError(err)} — retry ${attempt}/${retries - 1} in ${Math.round(wait / 1000)}s`);
      await sleep(wait);
    }
  }
  throw lastErr;
}

class CircuitBreaker {
  constructor({ threshold = 3, cooldownMs = 30000, maxPauses = 1 } = {}) {
    this.threshold = threshold;
    this.cooldownMs = cooldownMs;
    this.maxPauses = maxPauses;
    this.failures = 0;
    this.pauses = 0;
  }
  recordSuccess() { this.failures = 0; this.pauses = 0; }
  recordFailure() { this.failures++; }
  async beforeRequest() {
    if (this.failures < this.threshold) return true;
    this.pauses++;
    if (this.pauses > this.maxPauses) {
      console.log("🛑 Too many consecutive failures. Stopping.");
      return false;
    }
    console.log(`⚠️  ${this.failures} failures in a row. Pausing ${this.cooldownMs / 1000}s...`);
    await sleep(this.cooldownMs);
    this.failures = 0;
    return true;
  }
}

async function scanFileResilient({ path, content, patternFindings = [], analyzeChunk, breaker, delayMs = 10000 }) {
  const result = { path, status: "scanned", findings: [...patternFindings], errors: [], aborted: false };

  const allChunks = chunkFile(content);
  const chunks = allChunks.slice(0, MAX_CHUNKS_PER_FILE);
  const truncated = allChunks.length > MAX_CHUNKS_PER_FILE;

  let ok = 0, failed = 0;

  async function analyzeOne(chunk, depth = 0) {
    try {
      return await withRetry(() => analyzeChunk(chunk.text, chunk.startLine, path));
    } catch (err) {
      if (err.status === 413 && depth < 2) {
        const parts = splitChunk(chunk);
        if (parts) {
          console.log(`   ✂️  Chunk too big, splitting`);
          const found = [];
          for (const p of parts) found.push(...(await analyzeOne(p, depth + 1)));
          return found;
        }
      }
      throw err;
    }
  }

  for (const chunk of chunks) {
    const proceed = await breaker.beforeRequest();
    if (!proceed) { result.aborted = true; break; }

    try {
      const found = await analyzeOne(chunk);
      result.findings.push(...found);
      breaker.recordSuccess();
      ok++;
    } catch (err) {
      failed++;
      result.errors.push(describeError(err));
      if (err.status !== 413) breaker.recordFailure();
      console.log(`   ❌ ${describeError(err)}`);
    }

    await sleep(delayMs);
  }

  if (result.aborted && ok === 0) result.status = "skipped";
  else if (ok === 0 && failed > 0) result.status = "failed";
  else if (failed > 0 || truncated || result.aborted) result.status = "partial";
  else result.status = "scanned";

  if (truncated) result.errors.push(`File truncated: only first ${MAX_CHUNKS_PER_FILE} chunks scanned`);
  return result;
}

function printCoverage(results) {
  const by = (s) => results.filter((r) => r.status === s);
  console.log("\n📊 COVERAGE");
  console.log(`   ✅ Fully scanned: ${by("scanned").length}`);
  console.log(`   🟡 Partially scanned: ${by("partial").length}`);
  console.log(`   ❌ Failed: ${by("failed").length}`);
  console.log(`   ⏭️  Skipped: ${by("skipped").length}`);
}

module.exports = {
  chunkFile, splitChunk, withRetry, describeError,
  CircuitBreaker, scanFileResilient, printCoverage,
  estimateTokens, sleep
};

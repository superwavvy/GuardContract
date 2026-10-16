const fs = require('fs');
const { runPatterns } = require('./sol-patterns.js');

const source = fs.readFileSync('./vulnerable-router.sol', 'utf8');
const findings = runPatterns(source, 'vulnerable-router.sol', 'post08');

console.log(`\n📊 ${findings.length} finding(s):\n`);

for (const f of findings) {
  console.log(`[${f.severity}] ${f.type}`);
  console.log(`  Line ${f.line} — ${f.file}`);
  console.log(`  ${f.description.slice(0, 120)}`);
  console.log('');
}

// Assertions
const critical = findings.filter(f => f.severity === 'CRITICAL');
const hasArbitraryCall = findings.some(f => f.id === 'arbitrary-call-user-calldata' || f.type.includes('Arbitrary External Call'));
const hasAdminForwardFinding = findings.some(f => f.line >= 28 && f.line <= 32);

console.log('━'.repeat(50));
console.log(`✅ CRITICAL findings: ${critical.length}`);
console.log(`✅ Arbitrary-call rule fired: ${hasArbitraryCall}`);
console.log(`✅ Admin-forward NOT flagged (should be false): ${hasAdminForwardFinding}`);

if (critical.length >= 1 && hasArbitraryCall && !hasAdminForwardFinding) {
  console.log('\n🎯 RULE WORKS');
  process.exit(0);
} else {
  console.log('\n❌ RULE FAILED — needs debug');
  process.exit(1);
}

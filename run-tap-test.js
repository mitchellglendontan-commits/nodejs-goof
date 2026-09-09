// Simple test executor
const { execSync } = require('child_process');
const path = require('path');

try {
  const testFile = path.join(__dirname, 'tests', 'mysql-credential-security.spec.js');
  const tapBin = path.join(__dirname, 'node_modules', '.bin', 'tap');
  
  const result = execSync(`"${tapBin}" "${testFile}"`, {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  
  console.log(result);
  process.exit(0);
} catch (error) {
  console.error('Test execution failed:');
  console.error(error.stdout);
  console.error(error.stderr);
  process.exit(error.status || 1);
}

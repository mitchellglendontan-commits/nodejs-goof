// Manual test validation - simulates running the tests
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

console.log('=== Bootstrap Admin Security Test Validation ===\n');

let passedTests = 0;
let failedTests = 0;
const testResults = [];

function runTest(testName, testFn) {
  const startTime = Date.now();
  try {
    testFn();
    const duration = Date.now() - startTime;
    console.log(`✓ ${testName} (${duration}ms)`);
    passedTests++;
    testResults.push({ name: testName, passed: true, duration });
    return true;
  } catch (error) {
    const duration = Date.now() - startTime;
    console.log(`✗ ${testName} (${duration}ms)`);
    console.log(`  Error: ${error.message}`);
    failedTests++;
    testResults.push({ name: testName, passed: false, duration });
    return false;
  }
}

// Test 1: Verify hardcoded credentials are not present
runTest('should not contain hardcoded admin credentials in mongoose-db.js', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (content.includes('SuperSecretPassword')) {
    throw new Error('Found hardcoded SuperSecretPassword');
  }
  if (/new User\(\s*{\s*username:\s*['"]admin@snyk\.io['"]\s*,\s*password:\s*['"][^'"]+['"]\s*}\s*\)/.test(content)) {
    throw new Error('Found hardcoded admin user creation');
  }
});

// Test 2: Verify AUTO_PROVISION_ADMIN check
runTest('should require AUTO_PROVISION_ADMIN environment variable', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/AUTO_PROVISION_ADMIN.*===.*['"]true['"]/.test(content)) {
    throw new Error('AUTO_PROVISION_ADMIN check not found');
  }
});

// Test 3: Verify production environment check
runTest('should block auto-provisioning in production', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/NODE_ENV.*!==.*['"]production['"]/.test(content)) {
    throw new Error('Production environment check not found');
  }
});

// Test 4: Verify environment variables for credentials
runTest('should require admin credentials from environment variables', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/ADMIN_USERNAME.*process\.env\.ADMIN_USERNAME/.test(content)) {
    throw new Error('ADMIN_USERNAME environment variable not used');
  }
  if (!/ADMIN_PASSWORD.*process\.env\.ADMIN_PASSWORD/.test(content)) {
    throw new Error('ADMIN_PASSWORD environment variable not used');
  }
});

// Test 5: Verify password hashing
runTest('should hash passwords before storing', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/bcrypt\.hash/.test(content)) {
    throw new Error('bcrypt.hash not found');
  }
});

// Test 6: Verify requirePasswordChange flag
runTest('should set requirePasswordChange flag', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/requirePasswordChange:\s*true/.test(content)) {
    throw new Error('requirePasswordChange: true not found');
  }
});

// Test 7: Verify bcrypt.compare in login
runTest('should use bcrypt.compare for password verification', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/bcrypt\.compare/.test(content)) {
    throw new Error('bcrypt.compare not found');
  }
  if (/User\.find\(\s*{\s*username:.*password:.*}\s*,/.test(content)) {
    throw new Error('Plaintext password comparison found');
  }
});

// Test 8: Verify User.findOne with username only
runTest('should find user by username only', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/User\.findOne\(\s*{\s*username:/.test(content)) {
    throw new Error('User.findOne with username only not found');
  }
});

// Test 9: Verify User schema has requirePasswordChange
runTest('should include requirePasswordChange field in User schema', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/requirePasswordChange:\s*{\s*type:\s*Boolean/.test(content)) {
    throw new Error('requirePasswordChange field not found in schema');
  }
});

// Test 10: Verify login checks requirePasswordChange
runTest('should check requirePasswordChange flag during login', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/requirePasswordChange/.test(content)) {
    throw new Error('requirePasswordChange check not found in login');
  }
});

// Test 11: Functional bcrypt test
runTest('bcrypt should properly hash and verify passwords', async () => {
  const plainPassword = 'TestPassword123!';
  const hashedPassword = await bcrypt.hash(plainPassword, 10);
  
  if (hashedPassword === plainPassword) {
    throw new Error('Hash equals plaintext');
  }
  
  const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
  if (!isMatch) {
    throw new Error('Correct password does not match');
  }
  
  const isWrongMatch = await bcrypt.compare('WrongPassword', hashedPassword);
  if (isWrongMatch) {
    throw new Error('Incorrect password matches');
  }
});

// Test 12: Verify production check exists
runTest('should not auto-provision admin in production', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  const hasCheck = content.includes("NODE_ENV !== 'production'") || 
                   content.includes("NODE_ENV === 'production'");
  if (!hasCheck) {
    throw new Error('Production environment check not found');
  }
});

// Test 13: Verify environment variable validation
runTest('should validate ADMIN_USERNAME and ADMIN_PASSWORD are set', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!/!ADMIN_USERNAME.*!ADMIN_PASSWORD/.test(content)) {
    throw new Error('Environment variable validation not found');
  }
});

// Test 14: Verify hashing before save
runTest('should hash passwords before saving', () => {
  const mongooseDbPath = path.join(__dirname, 'mongoose-db.js');
  const content = fs.readFileSync(mongooseDbPath, 'utf8');
  if (!content.includes('bcrypt.hash')) {
    throw new Error('Password hashing not found');
  }
});

// Test 15: Verify error handling in login
runTest('should handle database errors gracefully', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/if\s*\(\s*err\s*\)/.test(content)) {
    throw new Error('Error handling not found');
  }
  if (!/status\(500\)/.test(content)) {
    throw new Error('500 status not returned on error');
  }
});

// Test 16: Verify 401 for invalid credentials
runTest('should return 401 for invalid credentials', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/status\(401\)/.test(content)) {
    throw new Error('401 status not found');
  }
});

// Test 17: Verify email validation
runTest('should validate email format', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/validator\.isEmail/.test(content)) {
    throw new Error('Email validation not found');
  }
});

// Test 18: Verify session.loggedIn flag
runTest('should set session.loggedIn flag', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/session\.loggedIn\s*=\s*1/.test(content)) {
    throw new Error('session.loggedIn flag not set');
  }
});

// Test 19: Verify isLoggedIn middleware
runTest('isLoggedIn middleware should verify session', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (!/exports\.isLoggedIn/.test(content)) {
    throw new Error('isLoggedIn middleware not exported');
  }
  if (!/req\.session\.loggedIn\s*===\s*1/.test(content)) {
    throw new Error('session.loggedIn check not found');
  }
});

// Test 20: Verify no hardcoded password comparisons
runTest('should not allow hardcoded credentials to bypass authentication', () => {
  const routesPath = path.join(__dirname, 'routes', 'index.js');
  const content = fs.readFileSync(routesPath, 'utf8');
  if (/password\s*===\s*['"][^'"]+['"]/.test(content)) {
    throw new Error('Hardcoded password comparison found');
  }
  if (/['"][^'"]+['"]\s*===\s*password/.test(content)) {
    throw new Error('Hardcoded password comparison found');
  }
});

console.log(`\n=== Test Summary ===`);
console.log(`Total: ${passedTests + failedTests}`);
console.log(`Passed: ${passedTests}`);
console.log(`Failed: ${failedTests}`);
console.log(`\nStatus: ${failedTests === 0 ? 'ALL TESTS PASSED ✓' : 'SOME TESTS FAILED ✗'}`);

process.exit(failedTests === 0 ? 0 : 1);

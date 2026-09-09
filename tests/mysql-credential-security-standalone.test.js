/**
 * Security Test Suite: MySQL Root Credential Vulnerability Mitigation
 * 
 * This test suite verifies that the pentest finding regarding source-controlled
 * MySQL root credentials has been properly mitigated.
 * 
 * Uses Node.js built-in assert module for maximum compatibility.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

// Test counter
let testsRun = 0;
let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  testsRun++;
  try {
    fn();
    testsPassed++;
    console.log(`✓ ${name}`);
  } catch (error) {
    testsFailed++;
    console.error(`✗ ${name}`);
    console.error(`  ${error.message}`);
  }
}

console.log('TAP version 13');
console.log('# MySQL Credential Security - Pentest Finding Mitigation\n');

// Test 1: typeorm-db.js should not contain hardcoded credentials
test('typeorm-db.js should not contain hardcoded "root" password', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(!content.match(/password:\s*["']root["']/i),
    'Should not contain hardcoded "root" password');
});

test('typeorm-db.js should not contain any hardcoded password literals', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  // Check that password is not a string literal (should be process.env)
  assert.ok(!content.match(/password:\s*["'][^"'$]+["']\s*,/),
    'Should not contain hardcoded password string literal');
});

test('typeorm-db.js should use process.env.MYSQL_PASSWORD', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(content.includes('process.env.MYSQL_PASSWORD'),
    'Should use process.env.MYSQL_PASSWORD for password');
});

test('typeorm-db.js should use process.env.MYSQL_USER', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(content.includes('process.env.MYSQL_USER'),
    'Should use process.env.MYSQL_USER for username');
});

test('typeorm-db.js should use process.env.MYSQL_HOST', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(content.includes('process.env.MYSQL_HOST'),
    'Should use process.env.MYSQL_HOST for host');
});

// Test 2: typeorm-db.js should use least-privilege user (not root)
test('typeorm-db.js should not use hardcoded "root" username', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(!content.match(/username:\s*["']root["']/i),
    'Should not use hardcoded "root" username');
});

test('typeorm-db.js default username should be "acme_app" (not root)', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  const usernameMatch = content.match(/username:\s*process\.env\.MYSQL_USER\s*\|\|\s*["']([^"']+)["']/);
  assert.ok(usernameMatch, 'Should have username with fallback');
  
  const defaultUsername = usernameMatch[1];
  assert.strictEqual(defaultUsername, 'acme_app',
    'Default username should be least-privilege user "acme_app"');
});

// Test 3: typeorm-db.js should validate password is provided
test('typeorm-db.js should validate that password is provided', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(content.match(/if\s*\(\s*!.*password/i),
    'Should validate that password is provided');
});

test('typeorm-db.js should exit if password is not provided', () => {
  const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
  const content = fs.readFileSync(typeormDbPath, 'utf8');
  
  assert.ok(content.includes('process.exit(1)'),
    'Should exit if password is not provided');
});

// Test 4: docker-compose.yml should not contain hardcoded credentials
test('docker-compose.yml should not contain hardcoded MYSQL_ROOT_PASSWORD', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(!content.match(/MYSQL_ROOT_PASSWORD:\s*["']?root["']?\s*$/m),
    'Should not contain hardcoded MYSQL_ROOT_PASSWORD: root');
});

test('docker-compose.yml should use ${MYSQL_ROOT_PASSWORD} environment variable', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(content.match(/MYSQL_ROOT_PASSWORD:\s*\$\{MYSQL_ROOT_PASSWORD/),
    'Should use ${MYSQL_ROOT_PASSWORD} environment variable substitution');
});

test('docker-compose.yml should use ${MYSQL_PASSWORD} environment variable', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(content.match(/MYSQL_PASSWORD:\s*\$\{MYSQL_PASSWORD/),
    'Should use ${MYSQL_PASSWORD} environment variable substitution');
});

// Test 5: docker-compose.yml should require environment variables
test('docker-compose.yml MYSQL_ROOT_PASSWORD should be required (:? syntax)', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(content.match(/MYSQL_ROOT_PASSWORD:\s*\$\{MYSQL_ROOT_PASSWORD:\?/),
    'MYSQL_ROOT_PASSWORD should be required with :? syntax');
});

test('docker-compose.yml MYSQL_PASSWORD should be required (:? syntax)', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(content.match(/MYSQL_PASSWORD:\s*\$\{MYSQL_PASSWORD:\?/),
    'MYSQL_PASSWORD should be required with :? syntax');
});

// Test 6: docker-compose.yml should NOT expose MySQL port 3306 to host
test('docker-compose.yml should NOT expose MySQL port 3306 to host', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  // Parse the docker-compose file to find the mysql service
  const lines = content.split('\n');
  let inMysqlService = false;
  let inPortsSection = false;
  let mysqlPortExposed = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (line.match(/^\s*goof-mysql:/)) {
      inMysqlService = true;
      continue;
    }
    
    if (inMysqlService && line.match(/^\s*\w+:/) && !line.match(/^\s+/)) {
      inMysqlService = false;
    }
    
    if (inMysqlService && line.match(/^\s+ports:/)) {
      inPortsSection = true;
      continue;
    }
    
    if (inPortsSection && line.match(/^\s+\w+:/) && !line.match(/^\s+-/)) {
      inPortsSection = false;
    }
    
    if (inMysqlService && inPortsSection && line.match(/["']?3306:3306["']?/)) {
      mysqlPortExposed = true;
    }
  }
  
  assert.ok(!mysqlPortExposed,
    'MySQL port 3306 should NOT be exposed to host (security risk)');
});

test('docker-compose.yml should have comment about not exposing port 3306', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(content.match(/Port 3306 is NOT exposed/i),
    'Should have comment explaining port 3306 is not exposed');
});

// Test 7: docker-compose.yml should use least-privilege user
test('docker-compose.yml should configure MYSQL_USER environment variable', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  assert.ok(content.match(/MYSQL_USER:\s*\$\{MYSQL_USER/),
    'Should configure MYSQL_USER environment variable for application');
});

test('docker-compose.yml default MYSQL_USER should be "acme_app" (not root)', () => {
  const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
  const content = fs.readFileSync(dockerComposePath, 'utf8');
  
  const userMatch = content.match(/MYSQL_USER:\s*\$\{MYSQL_USER:-([^}]+)\}/);
  assert.ok(userMatch, 'Should have MYSQL_USER with default value');
  
  const defaultUser = userMatch[1];
  assert.strictEqual(defaultUser, 'acme_app',
    'Default MYSQL_USER should be least-privilege user acme_app');
});

// Test 8: .gitignore should exclude .env file
test('.gitignore should exclude .env file', () => {
  const gitignorePath = path.join(__dirname, '..', '.gitignore');
  const content = fs.readFileSync(gitignorePath, 'utf8');
  
  assert.ok(content.match(/^\.env$/m),
    '.env file should be in .gitignore to prevent credential exposure');
});

// Test 9: .env.example should not contain real credentials
test('.env.example should exist', () => {
  const envExamplePath = path.join(__dirname, '..', '.env.example');
  assert.ok(fs.existsSync(envExamplePath),
    '.env.example should exist as a template');
});

test('.env.example should contain placeholder values', () => {
  const envExamplePath = path.join(__dirname, '..', '.env.example');
  const content = fs.readFileSync(envExamplePath, 'utf8');
  
  assert.ok(content.match(/change_this/i),
    '.env.example should contain placeholder values like "change_this"');
});

test('.env.example should not contain MYSQL_ROOT_PASSWORD=root', () => {
  const envExamplePath = path.join(__dirname, '..', '.env.example');
  const content = fs.readFileSync(envExamplePath, 'utf8');
  
  assert.ok(!content.match(/MYSQL_ROOT_PASSWORD=root\s*$/m),
    '.env.example should not contain MYSQL_ROOT_PASSWORD=root');
});

test('.env.example should warn about not committing .env file', () => {
  const envExamplePath = path.join(__dirname, '..', '.env.example');
  const content = fs.readFileSync(envExamplePath, 'utf8');
  
  assert.ok(content.match(/NEVER commit/i),
    '.env.example should warn about not committing .env file');
});

// Test 10: mysql-init script should create least-privilege user
test('mysql-init/01-init-user.sh should exist', () => {
  const initScriptPath = path.join(__dirname, '..', 'mysql-init', '01-init-user.sh');
  assert.ok(fs.existsSync(initScriptPath),
    'MySQL initialization script should exist');
});

test('mysql-init script should grant only necessary privileges', () => {
  const initScriptPath = path.join(__dirname, '..', 'mysql-init', '01-init-user.sh');
  const content = fs.readFileSync(initScriptPath, 'utf8');
  
  assert.ok(content.match(/GRANT\s+SELECT,\s*INSERT,\s*UPDATE,\s*DELETE/i),
    'Should grant only necessary privileges (SELECT, INSERT, UPDATE, DELETE)');
});

test('mysql-init script should NOT grant ALL privileges', () => {
  const initScriptPath = path.join(__dirname, '..', 'mysql-init', '01-init-user.sh');
  const content = fs.readFileSync(initScriptPath, 'utf8');
  
  assert.ok(!content.match(/GRANT\s+ALL/i),
    'Should not grant ALL privileges');
});

test('mysql-init script should document denied privileges', () => {
  const initScriptPath = path.join(__dirname, '..', 'mysql-init', '01-init-user.sh');
  const content = fs.readFileSync(initScriptPath, 'utf8');
  
  assert.ok(content.match(/should NOT have/i),
    'Should document privileges that are NOT granted');
});

// Summary
console.log(`\n1..${testsRun}`);
console.log(`# tests ${testsRun}`);
console.log(`# pass ${testsPassed}`);
console.log(`# fail ${testsFailed}`);

if (testsFailed > 0) {
  console.log('\n# FAILED');
  process.exit(1);
} else {
  console.log('\n# OK');
  process.exit(0);
}

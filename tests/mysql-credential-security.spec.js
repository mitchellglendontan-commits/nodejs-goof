const fs = require('fs');
const path = require('path');
const tap = require('tap');

/**
 * Security Test Suite: MySQL Root Credential Vulnerability Mitigation
 * 
 * This test suite verifies that the pentest finding regarding source-controlled
 * MySQL root credentials has been properly mitigated. The tests ensure:
 * 
 * 1. No hardcoded credentials in typeorm-db.js
 * 2. Application uses environment variables for database credentials
 * 3. Application uses least-privilege user (not root)
 * 4. Docker Compose requires environment variables (no hardcoded secrets)
 * 5. Docker Compose does NOT expose MySQL port 3306 to host
 * 6. .env file is properly excluded from source control
 */

tap.test('MySQL Credential Security - Pentest Finding Mitigation', (t) => {
  
  t.test('typeorm-db.js should not contain hardcoded credentials', (t) => {
    const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
    const content = fs.readFileSync(typeormDbPath, 'utf8');
    
    // Verify no hardcoded password literals
    t.notMatch(content, /password:\s*["']root["']/i, 
      'Should not contain hardcoded "root" password');
    t.notMatch(content, /password:\s*["'][^"']*["']\s*,/,
      'Should not contain any hardcoded password string literal');
    
    // Verify environment variable usage
    t.match(content, /process\.env\.MYSQL_PASSWORD/,
      'Should use process.env.MYSQL_PASSWORD for password');
    t.match(content, /process\.env\.MYSQL_USER/,
      'Should use process.env.MYSQL_USER for username');
    t.match(content, /process\.env\.MYSQL_HOST/,
      'Should use process.env.MYSQL_HOST for host');
    
    t.end();
  });

  t.test('typeorm-db.js should use least-privilege user (not root)', (t) => {
    const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
    const content = fs.readFileSync(typeormDbPath, 'utf8');
    
    // Verify root username is not hardcoded
    t.notMatch(content, /username:\s*["']root["']/i,
      'Should not use hardcoded "root" username');
    
    // Verify default fallback is not root
    const usernameMatch = content.match(/username:\s*process\.env\.MYSQL_USER\s*\|\|\s*["']([^"']+)["']/);
    if (usernameMatch) {
      const defaultUsername = usernameMatch[1];
      t.not(defaultUsername, 'root', 
        'Default username should not be "root"');
      t.equal(defaultUsername, 'acme_app',
        'Default username should be least-privilege user "acme_app"');
    }
    
    t.end();
  });

  t.test('typeorm-db.js should validate password is provided', (t) => {
    const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
    const content = fs.readFileSync(typeormDbPath, 'utf8');
    
    // Verify password validation exists
    t.match(content, /if\s*\(\s*!.*password/i,
      'Should validate that password is provided');
    t.match(content, /process\.exit\s*\(\s*1\s*\)/,
      'Should exit if password is not provided');
    
    t.end();
  });

  t.test('docker-compose.yml should not contain hardcoded credentials', (t) => {
    const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
    const content = fs.readFileSync(dockerComposePath, 'utf8');
    
    // Verify no hardcoded MYSQL_ROOT_PASSWORD
    t.notMatch(content, /MYSQL_ROOT_PASSWORD:\s*["']?root["']?\s*$/m,
      'Should not contain hardcoded MYSQL_ROOT_PASSWORD: root');
    t.notMatch(content, /MYSQL_ROOT_PASSWORD:\s*["'][^$][^"']*["']?\s*$/m,
      'Should not contain any hardcoded MYSQL_ROOT_PASSWORD value');
    
    // Verify environment variable substitution is used
    t.match(content, /MYSQL_ROOT_PASSWORD:\s*\$\{MYSQL_ROOT_PASSWORD/,
      'Should use ${MYSQL_ROOT_PASSWORD} environment variable substitution');
    t.match(content, /MYSQL_PASSWORD:\s*\$\{MYSQL_PASSWORD/,
      'Should use ${MYSQL_PASSWORD} environment variable substitution');
    
    t.end();
  });

  t.test('docker-compose.yml should require environment variables', (t) => {
    const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
    const content = fs.readFileSync(dockerComposePath, 'utf8');
    
    // Verify required environment variables (using :? syntax)
    t.match(content, /MYSQL_ROOT_PASSWORD:\s*\$\{MYSQL_ROOT_PASSWORD:\?/,
      'MYSQL_ROOT_PASSWORD should be required with :? syntax');
    t.match(content, /MYSQL_PASSWORD:\s*\$\{MYSQL_PASSWORD:\?/,
      'MYSQL_PASSWORD should be required with :? syntax');
    
    t.end();
  });

  t.test('docker-compose.yml should NOT expose MySQL port 3306 to host', (t) => {
    const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
    const content = fs.readFileSync(dockerComposePath, 'utf8');
    
    // Parse the docker-compose file to find the mysql service
    const lines = content.split('\n');
    let inMysqlService = false;
    let inPortsSection = false;
    let mysqlPortExposed = false;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Detect mysql service section
      if (line.match(/^\s*goof-mysql:/)) {
        inMysqlService = true;
        continue;
      }
      
      // Exit mysql service section when we hit another service
      if (inMysqlService && line.match(/^\s*\w+:/) && !line.match(/^\s+/)) {
        inMysqlService = false;
      }
      
      // Check for ports section within mysql service
      if (inMysqlService && line.match(/^\s+ports:/)) {
        inPortsSection = true;
        continue;
      }
      
      // Exit ports section
      if (inPortsSection && line.match(/^\s+\w+:/) && !line.match(/^\s+-/)) {
        inPortsSection = false;
      }
      
      // Check if 3306 is exposed in ports section
      if (inMysqlService && inPortsSection && line.match(/["']?3306:3306["']?/)) {
        mysqlPortExposed = true;
      }
    }
    
    t.notOk(mysqlPortExposed, 
      'MySQL port 3306 should NOT be exposed to host (security risk)');
    
    // Additional check: verify comment about not exposing port exists
    t.match(content, /Port 3306 is NOT exposed/i,
      'Should have comment explaining port 3306 is not exposed');
    
    t.end();
  });

  t.test('docker-compose.yml should use least-privilege user for application', (t) => {
    const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
    const content = fs.readFileSync(dockerComposePath, 'utf8');
    
    // Verify MYSQL_USER is set for the application
    t.match(content, /MYSQL_USER:\s*\$\{MYSQL_USER/,
      'Should configure MYSQL_USER environment variable for application');
    
    // Verify default is not root
    const userMatch = content.match(/MYSQL_USER:\s*\$\{MYSQL_USER:-([^}]+)\}/);
    if (userMatch) {
      const defaultUser = userMatch[1];
      t.not(defaultUser, 'root',
        'Default MYSQL_USER should not be root');
      t.equal(defaultUser, 'acme_app',
        'Default MYSQL_USER should be least-privilege user acme_app');
    }
    
    t.end();
  });

  t.test('.gitignore should exclude .env file', (t) => {
    const gitignorePath = path.join(__dirname, '..', '.gitignore');
    const content = fs.readFileSync(gitignorePath, 'utf8');
    
    // Verify .env is in .gitignore
    t.match(content, /^\.env$/m,
      '.env file should be in .gitignore to prevent credential exposure');
    
    t.end();
  });

  t.test('.env.example should not contain real credentials', (t) => {
    const envExamplePath = path.join(__dirname, '..', '.env.example');
    
    // Verify .env.example exists
    t.ok(fs.existsSync(envExamplePath),
      '.env.example should exist as a template');
    
    const content = fs.readFileSync(envExamplePath, 'utf8');
    
    // Verify it contains placeholder values, not real credentials
    t.match(content, /change_this/i,
      '.env.example should contain placeholder values like "change_this"');
    t.notMatch(content, /MYSQL_ROOT_PASSWORD=root\s*$/m,
      '.env.example should not contain MYSQL_ROOT_PASSWORD=root');
    
    // Verify it has security warning
    t.match(content, /NEVER commit/i,
      '.env.example should warn about not committing .env file');
    
    t.end();
  });

  t.test('mysql-init script should create least-privilege user', (t) => {
    const initScriptPath = path.join(__dirname, '..', 'mysql-init', '01-init-user.sh');
    
    // Verify init script exists
    t.ok(fs.existsSync(initScriptPath),
      'MySQL initialization script should exist');
    
    const content = fs.readFileSync(initScriptPath, 'utf8');
    
    // Verify it grants limited privileges
    t.match(content, /GRANT\s+SELECT,\s*INSERT,\s*UPDATE,\s*DELETE/i,
      'Should grant only necessary privileges (SELECT, INSERT, UPDATE, DELETE)');
    
    // Verify it does NOT grant dangerous privileges
    t.notMatch(content, /GRANT\s+ALL/i,
      'Should not grant ALL privileges');
    t.notMatch(content, /GRANT\s+.*SUPER/i,
      'Should not grant SUPER privilege');
    
    // Verify it has comments about denied privileges
    t.match(content, /should NOT have/i,
      'Should document privileges that are NOT granted');
    
    t.end();
  });

  t.test('Security properties: no source-controlled secrets', (t) => {
    // This is a meta-test that verifies the overall security posture
    const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
    const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
    
    const typeormContent = fs.readFileSync(typeormDbPath, 'utf8');
    const dockerContent = fs.readFileSync(dockerComposePath, 'utf8');
    
    // Verify no literal "root" password in either file
    const rootPasswordPattern = /password:\s*["']root["']/i;
    t.notMatch(typeormContent, rootPasswordPattern,
      'typeorm-db.js should not contain literal root password');
    t.notMatch(dockerContent, /MYSQL_ROOT_PASSWORD:\s*["']?root["']?\s*$/m,
      'docker-compose.yml should not contain literal root password');
    
    // Verify both files use environment variables
    t.match(typeormContent, /process\.env/,
      'typeorm-db.js should use process.env for configuration');
    t.match(dockerContent, /\$\{.*\}/,
      'docker-compose.yml should use ${} environment variable substitution');
    
    t.end();
  });

  t.test('Security properties: least privilege principle', (t) => {
    const typeormDbPath = path.join(__dirname, '..', 'typeorm-db.js');
    const typeormContent = fs.readFileSync(typeormDbPath, 'utf8');
    
    // Extract the default username
    const usernameMatch = typeormContent.match(/username:\s*process\.env\.MYSQL_USER\s*\|\|\s*["']([^"']+)["']/);
    
    if (usernameMatch) {
      const defaultUsername = usernameMatch[1];
      
      // Verify it's not a privileged account
      const privilegedAccounts = ['root', 'admin', 'administrator', 'sa'];
      t.notOk(privilegedAccounts.includes(defaultUsername.toLowerCase()),
        `Default username "${defaultUsername}" should not be a privileged account`);
      
      // Verify it follows naming convention for application users
      t.match(defaultUsername, /app|user|service/i,
        'Username should indicate it is an application/service account');
    }
    
    t.end();
  });

  t.test('Security properties: network isolation', (t) => {
    const dockerComposePath = path.join(__dirname, '..', 'docker-compose.yml');
    const content = fs.readFileSync(dockerComposePath, 'utf8');
    
    // Parse to check if mysql service has ports exposed
    const mysqlServiceMatch = content.match(/goof-mysql:[\s\S]*?(?=\n\w+:|$)/);
    
    if (mysqlServiceMatch) {
      const mysqlService = mysqlServiceMatch[0];
      
      // Check if ports section exists and exposes 3306
      const hasPortsSection = mysqlService.match(/\n\s+ports:/);
      const exposes3306 = mysqlService.match(/["']?3306:3306["']?/);
      
      if (hasPortsSection) {
        t.notOk(exposes3306,
          'If ports section exists, it should not expose 3306');
      }
      
      // Verify the service is accessible via Docker network (links/depends_on)
      const mainServiceMatch = content.match(/goof:[\s\S]*?(?=\n\w+:|$)/);
      if (mainServiceMatch) {
        const mainService = mainServiceMatch[0];
        t.match(mainService, /goof-mysql/,
          'Application should connect to MySQL via Docker network');
      }
    }
    
    t.end();
  });

  t.end();
});

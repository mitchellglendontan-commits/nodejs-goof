const tap = require('tap');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// Test suite for hardcoded bootstrap administrator credential security
tap.test('Bootstrap Admin Security Tests', (t) => {
  
  // Test 1: Verify hardcoded credentials are not present in source code
  t.test('should not contain hardcoded admin credentials in mongoose-db.js', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Check that the old hardcoded password is not present
    t.notMatch(mongooseDbContent, /SuperSecretPassword/, 
      'Source code should not contain hardcoded SuperSecretPassword');
    
    // Check that the old hardcoded username is not directly used without env var
    t.notMatch(mongooseDbContent, /new User\(\s*{\s*username:\s*['"]admin@snyk\.io['"]\s*,\s*password:\s*['"][^'"]+['"]\s*}\s*\)/, 
      'Source code should not create admin user with hardcoded credentials');
    
    t.end();
  });

  // Test 2: Verify auto-provisioning requires explicit environment variable
  t.test('should require AUTO_PROVISION_ADMIN environment variable to be explicitly set', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify that auto-provisioning is gated by environment variable
    t.match(mongooseDbContent, /AUTO_PROVISION_ADMIN.*===.*['"]true['"]/, 
      'Auto-provisioning should require explicit AUTO_PROVISION_ADMIN=true');
    
    t.end();
  });

  // Test 3: Verify production environment blocks auto-provisioning
  t.test('should block auto-provisioning in production environment', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify production check exists
    t.match(mongooseDbContent, /NODE_ENV.*!==.*['"]production['"]/, 
      'Should check that NODE_ENV is not production');
    
    t.end();
  });

  // Test 4: Verify credentials must come from environment variables
  t.test('should require admin credentials from environment variables', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify ADMIN_USERNAME and ADMIN_PASSWORD are read from env
    t.match(mongooseDbContent, /ADMIN_USERNAME.*process\.env\.ADMIN_USERNAME/, 
      'Admin username should come from environment variable');
    t.match(mongooseDbContent, /ADMIN_PASSWORD.*process\.env\.ADMIN_PASSWORD/, 
      'Admin password should come from environment variable');
    
    t.end();
  });

  // Test 5: Verify password hashing is implemented
  t.test('should hash passwords before storing', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify bcrypt is used
    t.match(mongooseDbContent, /bcrypt\.hash/, 
      'Should use bcrypt.hash to hash passwords');
    
    t.end();
  });

  // Test 6: Verify requirePasswordChange flag is set
  t.test('should set requirePasswordChange flag for auto-provisioned admin', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify requirePasswordChange is set to true
    t.match(mongooseDbContent, /requirePasswordChange:\s*true/, 
      'Auto-provisioned admin should require password change');
    
    t.end();
  });

  // Test 7: Verify login uses bcrypt comparison instead of plaintext
  t.test('should use bcrypt.compare for password verification in login', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify bcrypt.compare is used
    t.match(routesContent, /bcrypt\.compare/, 
      'Login should use bcrypt.compare for password verification');
    
    // Verify old plaintext comparison is not present
    t.notMatch(routesContent, /User\.find\(\s*{\s*username:.*password:.*}\s*,/, 
      'Login should not use plaintext password comparison in query');
    
    t.end();
  });

  // Test 8: Verify login finds user by username only, then compares password
  t.test('should find user by username only, not by username and password', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify User.findOne with username only
    t.match(routesContent, /User\.findOne\(\s*{\s*username:/, 
      'Login should find user by username only');
    
    t.end();
  });

  // Test 9: Verify User schema includes requirePasswordChange field
  t.test('should include requirePasswordChange field in User schema', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify schema includes requirePasswordChange
    t.match(mongooseDbContent, /requirePasswordChange:\s*{\s*type:\s*Boolean/, 
      'User schema should include requirePasswordChange field');
    
    t.end();
  });

  // Test 10: Verify login handler checks requirePasswordChange flag
  t.test('should check requirePasswordChange flag during login', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify requirePasswordChange check exists
    t.match(routesContent, /requirePasswordChange/, 
      'Login handler should check requirePasswordChange flag');
    
    t.end();
  });

  // Test 11: Functional test - bcrypt hashing and comparison
  t.test('bcrypt should properly hash and verify passwords', async (t) => {
    const plainPassword = 'TestPassword123!';
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(plainPassword, 10);
    
    // Verify hash is different from plaintext
    t.not(hashedPassword, plainPassword, 
      'Hashed password should be different from plaintext');
    
    // Verify correct password matches
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    t.ok(isMatch, 'Correct password should match hash');
    
    // Verify incorrect password doesn't match
    const isWrongMatch = await bcrypt.compare('WrongPassword', hashedPassword);
    t.notOk(isWrongMatch, 'Incorrect password should not match hash');
    
    t.end();
  });

  // Test 12: Verify no default admin credentials in production
  t.test('should not auto-provision admin when NODE_ENV is production', (t) => {
    const originalEnv = process.env.NODE_ENV;
    const originalAutoProvision = process.env.AUTO_PROVISION_ADMIN;
    
    // Set production environment
    process.env.NODE_ENV = 'production';
    process.env.AUTO_PROVISION_ADMIN = 'true';
    
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify the code checks for production and blocks it
    const hasProductionCheck = mongooseDbContent.includes("NODE_ENV !== 'production'") ||
                               mongooseDbContent.includes('NODE_ENV === \'production\'');
    
    t.ok(hasProductionCheck, 
      'Code should check NODE_ENV and prevent auto-provisioning in production');
    
    // Restore environment
    process.env.NODE_ENV = originalEnv;
    process.env.AUTO_PROVISION_ADMIN = originalAutoProvision;
    
    t.end();
  });

  // Test 13: Verify environment variable validation
  t.test('should validate that ADMIN_USERNAME and ADMIN_PASSWORD are set when auto-provisioning', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // Verify validation exists
    t.match(mongooseDbContent, /!ADMIN_USERNAME.*!ADMIN_PASSWORD/, 
      'Should validate that admin credentials environment variables are set');
    
    t.end();
  });

  // Test 14: Verify no plaintext passwords in User schema
  t.test('User schema should store hashed passwords, not plaintext', (t) => {
    const mongooseDbPath = path.join(__dirname, '..', 'mongoose-db.js');
    const mongooseDbContent = fs.readFileSync(mongooseDbPath, 'utf8');
    
    // The schema itself will still have password: String, but we verify
    // that the code always hashes before saving
    const hasHashingBeforeSave = mongooseDbContent.includes('bcrypt.hash');
    
    t.ok(hasHashingBeforeSave, 
      'Code should hash passwords before saving to database');
    
    t.end();
  });

  // Test 15: Verify error handling in login for database errors
  t.test('login handler should handle database errors gracefully', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify error handling exists
    t.match(routesContent, /if\s*\(\s*err\s*\)/, 
      'Login handler should check for errors');
    t.match(routesContent, /status\(500\)/, 
      'Login handler should return 500 on database errors');
    
    t.end();
  });

  // Test 16: Verify unauthorized response for invalid credentials
  t.test('login handler should return 401 for invalid credentials', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify 401 status is returned
    t.match(routesContent, /status\(401\)/, 
      'Login handler should return 401 for invalid credentials');
    
    t.end();
  });

  // Test 17: Verify email validation in login
  t.test('login handler should validate email format', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify validator.isEmail is used
    t.match(routesContent, /validator\.isEmail/, 
      'Login handler should validate email format');
    
    t.end();
  });

  // Test 18: Verify session security - loggedIn flag
  t.test('should set session.loggedIn flag on successful authentication', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify session.loggedIn is set
    t.match(routesContent, /session\.loggedIn\s*=\s*1/, 
      'Should set session.loggedIn flag on successful login');
    
    t.end();
  });

  // Test 19: Verify isLoggedIn middleware checks session
  t.test('isLoggedIn middleware should verify session.loggedIn flag', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify isLoggedIn function exists and checks session
    t.match(routesContent, /exports\.isLoggedIn/, 
      'isLoggedIn middleware should be exported');
    t.match(routesContent, /req\.session\.loggedIn\s*===\s*1/, 
      'isLoggedIn should check session.loggedIn flag');
    
    t.end();
  });

  // Test 20: Verify no hardcoded credentials can bypass authentication
  t.test('should not allow any hardcoded credentials to bypass authentication', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    // Verify no hardcoded password checks
    t.notMatch(routesContent, /password\s*===\s*['"][^'"]+['"]/, 
      'Should not have hardcoded password comparisons');
    t.notMatch(routesContent, /['"][^'"]+['"]\s*===\s*password/, 
      'Should not have hardcoded password comparisons');
    
    t.end();
  });

  t.end();
});

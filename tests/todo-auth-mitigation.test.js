#!/usr/bin/env node

/**
 * Security Test Suite for Todo Authentication Vulnerability Mitigation
 * 
 * This test verifies that the authentication bypass vulnerability has been fixed.
 * The vulnerability allowed anonymous users to:
 * - Enumerate all Todo records
 * - Create new Todos
 * - Update existing Todos by ID
 * - Delete Todos by ID
 * - Import Todos from files
 * 
 * The fix adds routes.isLoggedIn middleware to all Todo CRUD operations.
 */

const fs = require('fs');
const path = require('path');

// Test results tracking
const results = {
  passed: 0,
  failed: 0,
  total: 0,
  tests: []
};

function assert(condition, message) {
  results.total++;
  if (condition) {
    results.passed++;
    results.tests.push({ name: message, passed: true });
    console.log(`✓ ${message}`);
  } else {
    results.failed++;
    results.tests.push({ name: message, passed: false });
    console.log(`✗ ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  const condition = actual === expected;
  if (!condition) {
    console.log(`  Expected: ${expected}, Got: ${actual}`);
  }
  assert(condition, message);
}

console.log('\n=== Todo Authentication Security Tests ===\n');

// Test 1: Verify isLoggedIn middleware exists and works correctly
console.log('Test Group 1: isLoggedIn Middleware Behavior\n');

try {
  // Mock mongoose to avoid connection
  const Module = require('module');
  const originalRequire = Module.prototype.require;
  
  Module.prototype.require = function(id) {
    if (id === 'mongoose') {
      return {
        model: function(name) {
          return {
            find: function() {
              return {
                sort: function() {
                  return { exec: function(cb) { cb(null, []); } };
                }
              };
            },
            findById: function(id, cb) {
              cb(null, {
                _id: id,
                content: Buffer.from('test'),
                updated_at: new Date(),
                remove: function(cb) { cb(null, this); },
                save: function(cb) { cb(null, this); }
              });
            }
          };
        }
      };
    }
    return originalRequire.apply(this, arguments);
  };
  
  const routes = require('../routes');
  Module.prototype.require = originalRequire;
  
  // Test 1.1: Middleware rejects unauthenticated requests
  let redirectCalled = false;
  let redirectLocation = null;
  
  routes.isLoggedIn(
    { session: { loggedIn: 0 } },
    { redirect: (loc) => { redirectCalled = true; redirectLocation = loc; } },
    () => { /* should not be called */ }
  );
  
  assert(redirectCalled, 'isLoggedIn should redirect when loggedIn = 0');
  assertEqual(redirectLocation, '/login', 'isLoggedIn should redirect to /login');
  
  // Test 1.2: Middleware rejects when loggedIn is undefined
  redirectCalled = false;
  routes.isLoggedIn(
    { session: {} },
    { redirect: (loc) => { redirectCalled = true; } },
    () => { /* should not be called */ }
  );
  
  assert(redirectCalled, 'isLoggedIn should redirect when loggedIn is undefined');
  
  // Test 1.3: Middleware rejects when loggedIn is null
  redirectCalled = false;
  routes.isLoggedIn(
    { session: { loggedIn: null } },
    { redirect: (loc) => { redirectCalled = true; } },
    () => { /* should not be called */ }
  );
  
  assert(redirectCalled, 'isLoggedIn should redirect when loggedIn is null');
  
  // Test 1.4: Middleware rejects when loggedIn is string "1"
  redirectCalled = false;
  routes.isLoggedIn(
    { session: { loggedIn: '1' } },
    { redirect: (loc) => { redirectCalled = true; } },
    () => { /* should not be called */ }
  );
  
  assert(redirectCalled, 'isLoggedIn should redirect when loggedIn is string "1" (type mismatch)');
  
  // Test 1.5: Middleware allows when loggedIn is exactly 1
  let nextCalled = false;
  routes.isLoggedIn(
    { session: { loggedIn: 1 } },
    { redirect: (loc) => { /* should not be called */ } },
    () => { nextCalled = true; }
  );
  
  assert(nextCalled, 'isLoggedIn should call next() when loggedIn === 1');
  
} catch (error) {
  console.log(`Error loading routes module: ${error.message}`);
  assert(false, 'Routes module should load successfully');
}

// Test 2: Verify app.js route configuration
console.log('\nTest Group 2: Route Configuration in app.js\n');

try {
  const appJsPath = path.join(__dirname, '..', 'app.js');
  const appJsContent = fs.readFileSync(appJsPath, 'utf8');
  
  // Test 2.1: Index route has authentication
  assert(
    /app\.get\s*\(\s*['"]\/['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.index/.test(appJsContent),
    'GET / should have isLoggedIn middleware'
  );
  
  // Test 2.2: Create route has authentication
  assert(
    /app\.post\s*\(\s*['"]\/create['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.create/.test(appJsContent),
    'POST /create should have isLoggedIn middleware'
  );
  
  // Test 2.3: Destroy route has authentication
  assert(
    /app\.get\s*\(\s*['"]\/destroy\/:id['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.destroy/.test(appJsContent),
    'GET /destroy/:id should have isLoggedIn middleware'
  );
  
  // Test 2.4: Edit route has authentication
  assert(
    /app\.get\s*\(\s*['"]\/edit\/:id['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.edit/.test(appJsContent),
    'GET /edit/:id should have isLoggedIn middleware'
  );
  
  // Test 2.5: Update route has authentication
  assert(
    /app\.post\s*\(\s*['"]\/update\/:id['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.update/.test(appJsContent),
    'POST /update/:id should have isLoggedIn middleware'
  );
  
  // Test 2.6: Import route has authentication
  assert(
    /app\.post\s*\(\s*['"]\/import['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.import/.test(appJsContent),
    'POST /import should have isLoggedIn middleware'
  );
  
  // Test 2.7: Login routes should NOT have authentication
  const loginGetLine = appJsContent.match(/app\.get\s*\(\s*['"]\/login['"][^)]*\)/);
  if (loginGetLine) {
    assert(
      !/isLoggedIn/.test(loginGetLine[0]),
      'GET /login should NOT have isLoggedIn middleware'
    );
  } else {
    assert(false, 'GET /login route should exist');
  }
  
  const loginPostLine = appJsContent.match(/app\.post\s*\(\s*['"]\/login['"][^)]*\)/);
  if (loginPostLine) {
    assert(
      !/isLoggedIn/.test(loginPostLine[0]),
      'POST /login should NOT have isLoggedIn middleware'
    );
  } else {
    assert(false, 'POST /login route should exist');
  }
  
} catch (error) {
  console.log(`Error reading app.js: ${error.message}`);
  assert(false, 'app.js should be readable');
}

// Test 3: Verify isLoggedIn redirects to /login (not /)
console.log('\nTest Group 3: Redirect Target Verification\n');

try {
  const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
  const routesContent = fs.readFileSync(routesPath, 'utf8');
  
  // Find the isLoggedIn function
  const isLoggedInMatch = routesContent.match(/exports\.isLoggedIn\s*=\s*function[^}]+}/s);
  
  if (isLoggedInMatch) {
    const functionBody = isLoggedInMatch[0];
    
    // Test 3.1: Should redirect to /login
    assert(
      /redirect\s*\(\s*['"]\/login['"]\s*\)/.test(functionBody),
      'isLoggedIn should redirect to /login (not /)'
    );
    
    // Test 3.2: Should NOT redirect to /
    assert(
      !/redirect\s*\(\s*['"]\/['"]\s*\)/.test(functionBody) || /redirect\s*\(\s*['"]\/login['"]\s*\)/.test(functionBody),
      'isLoggedIn should not redirect to / (root)'
    );
  } else {
    assert(false, 'isLoggedIn function should exist in routes/index.js');
  }
  
} catch (error) {
  console.log(`Error reading routes/index.js: ${error.message}`);
  assert(false, 'routes/index.js should be readable');
}

// Test 4: Security property tests - Pentest scenarios
console.log('\nTest Group 4: Pentest Scenario Mitigation\n');

try {
  const Module = require('module');
  const originalRequire = Module.prototype.require;
  
  Module.prototype.require = function(id) {
    if (id === 'mongoose') {
      return {
        model: function(name) {
          return {
            find: function() {
              return {
                sort: function() {
                  return { exec: function(cb) { cb(null, []); } };
                }
              };
            },
            findById: function(id, cb) {
              cb(null, {
                _id: id,
                content: Buffer.from('test'),
                updated_at: new Date(),
                remove: function(cb) { cb(null, this); },
                save: function(cb) { cb(null, this); }
              });
            }
          };
        }
      };
    }
    return originalRequire.apply(this, arguments);
  };
  
  delete require.cache[require.resolve('../routes')];
  const routes = require('../routes');
  Module.prototype.require = originalRequire;
  
  // Test 4.1: Anonymous enumeration blocked
  let blocked = false;
  routes.isLoggedIn(
    { session: {} },
    { redirect: () => { blocked = true; } },
    () => { /* should not reach handler */ }
  );
  assert(blocked, 'Anonymous enumeration of Todos should be blocked');
  
  // Test 4.2: Anonymous deletion blocked
  blocked = false;
  routes.isLoggedIn(
    { session: { loggedIn: 0 }, params: { id: '507f1f77bcf86cd799439011' } },
    { redirect: () => { blocked = true; } },
    () => { /* should not reach handler */ }
  );
  assert(blocked, 'Anonymous deletion of Todos should be blocked');
  
  // Test 4.3: Anonymous update blocked
  blocked = false;
  routes.isLoggedIn(
    { session: {}, params: { id: '507f1f77bcf86cd799439011' }, body: { content: 'malicious' } },
    { redirect: () => { blocked = true; } },
    () => { /* should not reach handler */ }
  );
  assert(blocked, 'Anonymous update of Todos should be blocked');
  
  // Test 4.4: Anonymous creation blocked
  blocked = false;
  routes.isLoggedIn(
    { session: { loggedIn: null }, body: { content: 'attacker todo' } },
    { redirect: () => { blocked = true; } },
    () => { /* should not reach handler */ }
  );
  assert(blocked, 'Anonymous creation of Todos should be blocked');
  
  // Test 4.5: Anonymous import blocked
  blocked = false;
  routes.isLoggedIn(
    { session: {}, files: { importFile: { data: Buffer.from('test\n') } } },
    { redirect: () => { blocked = true; } },
    () => { /* should not reach handler */ }
  );
  assert(blocked, 'Anonymous import of Todos should be blocked');
  
  // Test 4.6: Authenticated access allowed
  let allowed = false;
  routes.isLoggedIn(
    { session: { loggedIn: 1 } },
    { redirect: () => { /* should not redirect */ } },
    () => { allowed = true; }
  );
  assert(allowed, 'Authenticated users should be allowed to access Todo operations');
  
} catch (error) {
  console.log(`Error in security tests: ${error.message}`);
  assert(false, 'Security tests should execute successfully');
}

// Print summary
console.log('\n=== Test Summary ===\n');
console.log(`Total: ${results.total}`);
console.log(`Passed: ${results.passed}`);
console.log(`Failed: ${results.failed}`);
console.log(`Success Rate: ${((results.passed / results.total) * 100).toFixed(1)}%\n`);

// Exit with appropriate code
process.exit(results.failed > 0 ? 1 : 0);

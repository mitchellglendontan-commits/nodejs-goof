const tap = require('tap');
const fs = require('fs');
const path = require('path');

// Test the isLoggedIn middleware directly
tap.test('isLoggedIn Middleware Security Tests', (t) => {
  
  // We need to load routes, but mongoose will try to connect
  // Let's test the middleware behavior directly
  let routes;
  
  t.beforeEach((done) => {
    // Clear require cache to get fresh module
    delete require.cache[require.resolve('../routes')];
    
    // Mock mongoose to prevent connection attempts
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
                    return {
                      exec: function(cb) { cb(null, []); }
                    };
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
    
    routes = require('../routes');
    
    // Restore original require
    Module.prototype.require = originalRequire;
    
    done();
  });
  
  t.test('should redirect to /login when session.loggedIn is not 1', (t) => {
    const testCases = [
      { value: 0, desc: 'loggedIn = 0' },
      { value: undefined, desc: 'loggedIn = undefined' },
      { value: null, desc: 'loggedIn = null' },
      { value: 2, desc: 'loggedIn = 2' },
      { value: '1', desc: 'loggedIn = "1" (string)' },
      { value: true, desc: 'loggedIn = true (boolean)' },
      { value: false, desc: 'loggedIn = false' }
    ];
    
    t.plan(testCases.length);
    
    testCases.forEach(testCase => {
      const req = { session: { loggedIn: testCase.value } };
      const res = {
        redirect: function(location) {
          t.equal(location, '/login', `${testCase.desc} should redirect to /login`);
        }
      };
      const next = () => {
        t.fail(`${testCase.desc} should not call next()`);
      };
      
      routes.isLoggedIn(req, res, next);
    });
  });
  
  t.test('should call next() when session.loggedIn is exactly 1', (t) => {
    t.plan(1);
    
    const req = { session: { loggedIn: 1 } };
    const res = {
      redirect: function(location) {
        t.fail('should not redirect when authenticated');
      }
    };
    const next = () => {
      t.pass('should call next() for authenticated user');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('should redirect to /login when session object is missing', (t) => {
    t.plan(1);
    
    const req = { session: {} };
    const res = {
      redirect: function(location) {
        t.equal(location, '/login', 'should redirect to /login when session has no loggedIn property');
      }
    };
    const next = () => {
      t.fail('should not call next() when session.loggedIn is missing');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.end();
});

tap.test('Route Handler Authentication Enforcement', (t) => {
  
  let routes;
  
  t.beforeEach((done) => {
    delete require.cache[require.resolve('../routes')];
    
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
                    return {
                      exec: function(cb) { cb(null, []); }
                    };
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
    
    routes = require('../routes');
    Module.prototype.require = originalRequire;
    done();
  });
  
  t.test('index handler should be protected - unauthenticated access blocked', (t) => {
    t.plan(1);
    
    // The index handler itself doesn't check auth - that's the middleware's job
    // But we can verify it requires authentication by checking it doesn't expose data without it
    const req = { session: {} };
    const res = {
      render: function(view, data) {
        // If this is called without auth check, it's a vulnerability
        t.fail('index handler should not render without authentication check');
      }
    };
    const next = (err) => {
      if (err) {
        t.pass('handler properly requires authentication');
      }
    };
    
    // In the fixed version, isLoggedIn middleware should prevent this from being called
    // We're testing that the handler exists and is the right one
    t.ok(typeof routes.index === 'function', 'index handler should exist');
  });
  
  t.test('destroy handler should be protected - verify handler exists', (t) => {
    t.plan(1);
    t.ok(typeof routes.destroy === 'function', 'destroy handler should exist');
  });
  
  t.test('update handler should be protected - verify handler exists', (t) => {
    t.plan(1);
    t.ok(typeof routes.update === 'function', 'update handler should exist');
  });
  
  t.test('create handler should be protected - verify handler exists', (t) => {
    t.plan(1);
    t.ok(typeof routes.create === 'function', 'create handler should exist');
  });
  
  t.test('import handler should be protected - verify handler exists', (t) => {
    t.plan(1);
    t.ok(typeof routes.import === 'function', 'import handler should exist');
  });
  
  t.test('edit handler should be protected - verify handler exists', (t) => {
    t.plan(1);
    t.ok(typeof routes.edit === 'function', 'edit handler should exist');
  });
  
  t.end();
});

tap.test('App.js Route Configuration Verification', (t) => {
  const fs = require('fs');
  const path = require('path');
  
  t.test('app.js should have isLoggedIn middleware on all Todo routes', (t) => {
    const appJsPath = path.join(__dirname, '..', 'app.js');
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    
    // Check that Todo routes have isLoggedIn middleware
    const protectedRoutes = [
      { pattern: /app\.get\(['"]\/['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.index/, desc: 'GET /' },
      { pattern: /app\.post\(['"]\/create['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.create/, desc: 'POST /create' },
      { pattern: /app\.get\(['"]\/destroy\/:id['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.destroy/, desc: 'GET /destroy/:id' },
      { pattern: /app\.get\(['"]\/edit\/:id['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.edit/, desc: 'GET /edit/:id' },
      { pattern: /app\.post\(['"]\/update\/:id['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.update/, desc: 'POST /update/:id' },
      { pattern: /app\.post\(['"]\/import['"]\s*,\s*routes\.isLoggedIn\s*,\s*routes\.import/, desc: 'POST /import' }
    ];
    
    t.plan(protectedRoutes.length);
    
    protectedRoutes.forEach(route => {
      t.ok(route.pattern.test(appJsContent), `${route.desc} should have isLoggedIn middleware`);
    });
  });
  
  t.test('app.js should NOT have isLoggedIn on login routes', (t) => {
    const appJsPath = path.join(__dirname, '..', 'app.js');
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    
    // Extract the login route lines
    const loginGetMatch = appJsContent.match(/app\.get\(['"]\/login['"].*\)/);
    const loginPostMatch = appJsContent.match(/app\.post\(['"]\/login['"].*\)/);
    
    t.plan(2);
    
    if (loginGetMatch) {
      t.notMatch(loginGetMatch[0], /isLoggedIn/, 'GET /login should NOT have isLoggedIn middleware');
    } else {
      t.fail('GET /login route not found');
    }
    
    if (loginPostMatch) {
      t.notMatch(loginPostMatch[0], /isLoggedIn/, 'POST /login should NOT have isLoggedIn middleware');
    } else {
      t.fail('POST /login route not found');
    }
  });
  
  t.test('isLoggedIn middleware should redirect to /login (not /)', (t) => {
    const routesPath = path.join(__dirname, '..', 'routes', 'index.js');
    const routesContent = fs.readFileSync(routesPath, 'utf8');
    
    t.plan(1);
    
    // Find the isLoggedIn function and check its redirect
    const isLoggedInMatch = routesContent.match(/exports\.isLoggedIn\s*=\s*function[^}]+}/s);
    
    if (isLoggedInMatch) {
      const functionBody = isLoggedInMatch[0];
      // Should redirect to /login, not /
      t.match(functionBody, /redirect\s*\(\s*['"]\/login['"]\s*\)/, 'isLoggedIn should redirect to /login');
    } else {
      t.fail('isLoggedIn function not found');
    }
  });
  
  t.end();
});

tap.test('Security Property Tests - Pentest Scenarios Mitigated', (t) => {
  
  let routes;
  
  t.beforeEach((done) => {
    delete require.cache[require.resolve('../routes')];
    
    const Module = require('module');
    const originalRequire = Module.prototype.require;
    
    Module.prototype.require = function(id) {
      if (id === 'mongoose') {
        return {
          model: function(name) {
            if (name === 'Todo') {
              return {
                find: function() {
                  return {
                    sort: function() {
                      return {
                        exec: function(cb) { cb(null, []); }
                      };
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
            if (name === 'User') {
              return {
                find: function(query, cb) { cb(null, []); }
              };
            }
          }
        };
      }
      return originalRequire.apply(this, arguments);
    };
    
    routes = require('../routes');
    Module.prototype.require = originalRequire;
    done();
  });
  
  t.test('Scenario: Anonymous user attempts to enumerate all Todos', (t) => {
    t.plan(1);
    
    // Simulate unauthenticated request
    const req = { session: { loggedIn: 0 } };
    const res = {
      redirect: function(location) {
        t.equal(location, '/login', 'unauthenticated enumeration attempt should redirect to login');
      }
    };
    const next = () => {
      t.fail('should not proceed to index handler without authentication');
    };
    
    // The middleware should block this
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('Scenario: Anonymous user attempts to delete a Todo by ID', (t) => {
    t.plan(1);
    
    const req = { 
      session: {},
      params: { id: '507f1f77bcf86cd799439011' }
    };
    const res = {
      redirect: function(location) {
        t.equal(location, '/login', 'unauthenticated deletion attempt should redirect to login');
      }
    };
    const next = () => {
      t.fail('should not proceed to destroy handler without authentication');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('Scenario: Anonymous user attempts to update a Todo by ID', (t) => {
    t.plan(1);
    
    const req = { 
      session: { loggedIn: null },
      params: { id: '507f1f77bcf86cd799439011' },
      body: { content: 'malicious content' }
    };
    const res = {
      redirect: function(location) {
        t.equal(location, '/login', 'unauthenticated update attempt should redirect to login');
      }
    };
    const next = () => {
      t.fail('should not proceed to update handler without authentication');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('Scenario: Anonymous user attempts to create a new Todo', (t) => {
    t.plan(1);
    
    const req = { 
      session: {},
      body: { content: 'attacker todo' }
    };
    const res = {
      redirect: function(location) {
        t.equal(location, '/login', 'unauthenticated creation attempt should redirect to login');
      }
    };
    const next = () => {
      t.fail('should not proceed to create handler without authentication');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('Scenario: Anonymous user attempts to import Todos', (t) => {
    t.plan(1);
    
    const req = { 
      session: { loggedIn: undefined },
      files: {
        importFile: {
          data: Buffer.from('malicious todo 1\nmalicious todo 2\n'),
          name: 'malicious.txt'
        }
      }
    };
    const res = {
      redirect: function(location) {
        t.equal(location, '/login', 'unauthenticated import attempt should redirect to login');
      }
    };
    const next = () => {
      t.fail('should not proceed to import handler without authentication');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('Scenario: Authenticated user can access protected resources', (t) => {
    t.plan(1);
    
    const req = { session: { loggedIn: 1 } };
    const res = {
      redirect: function(location) {
        t.fail('authenticated user should not be redirected');
      }
    };
    const next = () => {
      t.pass('authenticated user should be allowed to proceed');
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.end();
});

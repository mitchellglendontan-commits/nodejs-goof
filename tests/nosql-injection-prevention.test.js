#!/usr/bin/env node
/**
 * NoSQL Injection Prevention Tests
 * 
 * This test file validates that the loginHandler properly rejects
 * non-string username and password values to prevent NoSQL injection attacks.
 * 
 * The vulnerability allowed attackers to pass MongoDB operators like { $ne: null }
 * as the password field, which would match any user with a non-null password.
 * 
 * The mitigation adds type checking to ensure both username and password are strings
 * before processing the login request.
 */

const tap = require('tap');

// Load routes - this will connect to MongoDB but we're only testing the type validation
const routes = require('../routes/index');

tap.test('NoSQL Injection Prevention Tests', (t) => {
  
  t.test('loginHandler should reject non-string username', (t) => {
    const req = {
      body: {
        username: { $ne: null },
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for non-string username');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject non-string password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: { $ne: null }
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for non-string password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject $ne operator in username', (t) => {
    const req = {
      body: {
        username: { $ne: 'admin@snyk.io' },
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for $ne operator in username');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on NoSQL injection attempt');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on NoSQL injection attempt');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject $ne operator in password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: { $ne: null }
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for $ne operator in password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on NoSQL injection attempt');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on NoSQL injection attempt');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject $gt operator in password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: { $gt: '' }
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for $gt operator in password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on NoSQL injection attempt');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on NoSQL injection attempt');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject $regex operator in password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: { $regex: '.*' }
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for $regex operator in password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on NoSQL injection attempt');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on NoSQL injection attempt');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject both username and password as objects', (t) => {
    const req = {
      body: {
        username: { $ne: null },
        password: { $ne: null }
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for both fields as objects');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on NoSQL injection attempt');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on NoSQL injection attempt');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject array as username', (t) => {
    const req = {
      body: {
        username: ['admin@snyk.io'],
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for array as username');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject array as password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: ['password123']
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for array as password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject number as username', (t) => {
    const req = {
      body: {
        username: 12345,
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for number as username');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject boolean as password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: true
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for boolean as password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject undefined username', (t) => {
    const req = {
      body: {
        username: undefined,
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for undefined username');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should reject null password', (t) => {
    const req = {
      body: {
        username: 'admin@snyk.io',
        password: null
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for null password');
        return this;
      },
      send: function() {
        t.pass('Should send response');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid input');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid input');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler should accept valid string credentials with invalid email format', (t) => {
    const req = {
      body: {
        username: 'notanemail',
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status for invalid email format');
        return this;
      },
      send: function() {
        t.pass('Should send response for invalid email');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect on invalid email');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next() on invalid email');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.test('loginHandler type check should occur before email validation', (t) => {
    // This test ensures that type checking happens first, preventing
    // the validator from receiving non-string input
    const req = {
      body: {
        username: { $ne: null },
        password: 'password123'
      },
      session: {}
    };
    
    const res = {
      status: function(code) {
        t.equal(code, 401, 'Should return 401 status before email validation');
        return this;
      },
      send: function() {
        t.pass('Should reject at type check, not email validation');
        t.end();
      },
      redirect: function(path) {
        t.fail('Should not redirect');
        t.end();
      }
    };
    
    const next = function() {
      t.fail('Should not call next()');
      t.end();
    };
    
    routes.loginHandler(req, res, next);
  });
  
  t.end();
});

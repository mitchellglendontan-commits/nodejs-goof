#!/usr/bin/env node
// Simple syntax check for the test file
try {
  require('./tests/bootstrap-admin-security.test.js');
  console.log('Test file syntax is valid');
  process.exit(0);
} catch (error) {
  console.error('Test file has syntax errors:', error.message);
  process.exit(1);
}

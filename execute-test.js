#!/usr/bin/env node
// Execute test directly
const path = require('path');
const testFile = path.join(__dirname, 'tests', 'mysql-credential-security.spec.js');

// Set up TAP environment
process.env.TAP = '1';

// Load and execute the test
try {
  require(testFile);
} catch (error) {
  console.error('Test execution error:', error);
  process.exit(1);
}

#!/usr/bin/env node

// Simple test runner to execute tap tests directly
const { spawn } = require('child_process');
const path = require('path');

const testFile = path.join(__dirname, 'tests', 'bootstrap-admin-security.test.js');

console.log('Running security tests...\n');

const tap = spawn('node', [testFile], {
  stdio: 'inherit',
  env: process.env
});

tap.on('close', (code) => {
  process.exit(code);
});

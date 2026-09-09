#!/usr/bin/env node
/**
 * Direct test execution - bypasses npm test
 * This script directly executes the tap test file
 */

const { spawn } = require('child_process');
const path = require('path');

const testFile = path.join(__dirname, 'tests', 'mysql-credential-security.spec.js');

// Try to run with node directly (tap tests are executable)
const proc = spawn(process.execPath, [testFile], {
  stdio: 'inherit',
  env: { ...process.env, TAP: '1' }
});

proc.on('exit', (code) => {
  process.exit(code || 0);
});

proc.on('error', (err) => {
  console.error('Failed to execute test:', err);
  process.exit(1);
});

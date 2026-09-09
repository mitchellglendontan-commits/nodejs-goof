#!/usr/bin/env node
// Simple test runner for import-security tests
const { spawn } = require('child_process');
const path = require('path');

const testFile = path.join(__dirname, 'tests', 'import-security.test.js');
const tapBin = path.join(__dirname, 'node_modules', '.bin', 'tap');

// Run tap with the test file
const proc = spawn(tapBin, [testFile, '--no-coverage'], {
  stdio: 'inherit',
  cwd: __dirname
});

proc.on('exit', (code) => {
  process.exit(code);
});

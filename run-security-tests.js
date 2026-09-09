#!/usr/bin/env node
// Temporary test runner for security tests
const { spawn } = require('child_process');
const path = require('path');

const testFile = path.join(__dirname, 'tests', 'mysql-credential-security.spec.js');
const tapBin = path.join(__dirname, 'node_modules', '.bin', 'tap');

const proc = spawn(tapBin, [testFile], {
  stdio: 'inherit',
  shell: true
});

proc.on('exit', (code) => {
  process.exit(code);
});

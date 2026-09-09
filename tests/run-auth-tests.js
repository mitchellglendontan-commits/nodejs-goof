#!/usr/bin/env node
// Simple test runner for todo-auth-security.test.js
const { spawn } = require('child_process');
const path = require('path');

const tapBin = path.join(__dirname, '..', 'node_modules', '.bin', 'tap');
const testFile = path.join(__dirname, 'todo-auth-security.test.js');

const child = spawn('node', [tapBin, testFile, '--no-coverage'], {
  stdio: 'inherit',
  cwd: path.join(__dirname, '..')
});

child.on('exit', (code) => {
  process.exit(code);
});

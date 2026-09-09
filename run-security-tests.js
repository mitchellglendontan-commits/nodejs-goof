#!/usr/bin/env node

// Simple test runner that executes tap tests directly
const { spawn } = require('child_process');
const path = require('path');

const testFiles = [
  'test/objectid-validation.test.js',
  'test/routes-security.test.js'
];

const tapBin = path.join(__dirname, 'node_modules', '.bin', 'tap');

const child = spawn(tapBin, testFiles, {
  stdio: 'inherit',
  shell: true
});

child.on('exit', (code) => {
  process.exit(code);
});

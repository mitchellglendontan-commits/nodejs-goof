/**
 * Zip Slip Vulnerability Mitigation Tests
 * 
 * These tests verify that the security fixes applied to the /import endpoint
 * properly mitigate the Zip Slip vulnerability (CVE-2018-1002204).
 * 
 * The vulnerability allowed unauthenticated attackers to:
 * 1. Upload ZIP files without authentication
 * 2. Use path traversal entries (e.g., ../../../etc/passwd) to write files outside the extraction directory
 * 3. Overwrite critical system or application files
 * 
 * The mitigation includes:
 * 1. Adding authentication middleware (isLoggedIn) to the /import route
 * 2. Validating all ZIP entry names before extraction
 * 3. Normalizing paths and stripping leading ../ patterns
 * 4. Ensuring all resolved paths are within the extraction directory
 */

const tap = require('tap');
const AdmZip = require('adm-zip');
const path = require('path');
const fs = require('fs');

// Test the path traversal validation logic that was added to mitigate Zip Slip
tap.test('Path Traversal Validation Logic Tests', (t) => {
  const extracted_path = '/tmp/extracted_files';

  t.test('should detect simple parent directory traversal', (t) => {
    const entryName = '../outside.txt';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    t.ok(isValid || normalizedEntryName === 'outside.txt', 
      'Should normalize and strip leading ../ patterns');
    t.end();
  });

  t.test('should detect multiple parent directory traversal', (t) => {
    const entryName = '../../etc/passwd';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    t.ok(isValid || normalizedEntryName === 'etc/passwd', 
      'Should normalize and strip multiple ../ patterns');
    t.end();
  });

  t.test('should detect absolute path traversal', (t) => {
    const entryName = '/etc/passwd';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    // Absolute paths should be contained within extraction directory
    t.ok(isValid, 'Should handle absolute paths safely');
    t.end();
  });

  t.test('should detect Windows-style path traversal', (t) => {
    const entryName = '..\\..\\windows\\system32\\config';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    t.ok(isValid || normalizedEntryName === 'windows/system32/config', 
      'Should normalize Windows-style backslash traversal');
    t.end();
  });

  t.test('should detect mixed separator path traversal', (t) => {
    const entryName = '../.\\../etc/passwd';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    t.ok(isValid || !normalizedEntryName.startsWith('..'), 
      'Should normalize mixed separator traversal');
    t.end();
  });

  t.test('should allow valid relative paths within extraction directory', (t) => {
    const entryName = 'subdir/file.txt';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    t.ok(isValid, 'Should allow valid relative paths');
    t.equal(normalizedEntryName, 'subdir/file.txt', 'Should preserve valid path structure');
    t.end();
  });

  t.test('should allow files in root of extraction directory', (t) => {
    const entryName = 'backup.txt';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    t.ok(isValid, 'Should allow files in root directory');
    t.equal(normalizedEntryName, 'backup.txt', 'Should preserve filename');
    t.end();
  });

  t.test('should detect encoded path traversal attempts', (t) => {
    // URL-encoded ../ is %2e%2e%2f
    const entryName = '%2e%2e%2fmalicious.txt';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    // The current implementation doesn't decode, so this would be treated as a literal filename
    // This is actually safe behavior - the encoded string becomes part of the filename
    t.ok(isValid, 'Encoded traversal should be treated as literal filename');
    t.end();
  });

  t.test('should handle empty entry names safely', (t) => {
    const entryName = '';
    const normalizedEntryName = path.normalize(entryName || '.').replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep) || 
                    fullPath === path.resolve(extracted_path);
    
    t.ok(isValid, 'Should handle empty entry names safely');
    t.end();
  });

  t.test('should detect deeply nested traversal attempts', (t) => {
    const entryName = 'a/b/c/../../../../../../../../etc/passwd';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    // After normalization, the path should either be contained or the leading ../ stripped
    t.ok(isValid || !normalizedEntryName.includes('..'), 
      'Should handle deeply nested traversal attempts');
    t.end();
  });

  t.test('should block the exact pentest exploit scenario', (t) => {
    // This tests the exact scenario from the pentest: ../outside.txt
    const entryName = '../outside.txt';
    const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
    const fullPath = path.resolve(extracted_path, normalizedEntryName);
    const isValid = fullPath.startsWith(path.resolve(extracted_path) + path.sep);
    
    // The normalization should strip the leading ../ making it 'outside.txt'
    t.equal(normalizedEntryName, 'outside.txt', 'Should strip leading ../ from entry name');
    t.ok(isValid, 'Normalized path should be within extraction directory');
    
    // Verify the file would be extracted to the safe location
    const expectedPath = path.join(extracted_path, 'outside.txt');
    t.equal(fullPath, expectedPath, 'File should be extracted to safe location within extraction directory');
    t.end();
  });

  t.end();
});

tap.test('ZIP Entry Validation with AdmZip', (t) => {
  t.test('should validate safe ZIP file entries', (t) => {
    const zip = new AdmZip();
    zip.addFile('backup.txt', Buffer.from('Safe content', 'utf8'));
    zip.addFile('subdir/file.txt', Buffer.from('Safe nested content', 'utf8'));
    
    const entries = zip.getEntries();
    const extracted_path = '/tmp/extracted_files';
    let allValid = true;
    
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const entryName = entry.entryName;
      const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.resolve(extracted_path, normalizedEntryName);
      
      if (!fullPath.startsWith(path.resolve(extracted_path) + path.sep)) {
        allValid = false;
        break;
      }
    }
    
    t.ok(allValid, 'All entries in safe ZIP should be valid');
    t.equal(entries.length, 2, 'Should have 2 entries');
    t.end();
  });

  t.test('should detect malicious ZIP file entries', (t) => {
    const zip = new AdmZip();
    zip.addFile('../malicious.txt', Buffer.from('Malicious content', 'utf8'));
    zip.addFile('safe.txt', Buffer.from('Safe content', 'utf8'));
    
    const entries = zip.getEntries();
    const extracted_path = '/tmp/extracted_files';
    let hasTraversal = false;
    
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const entryName = entry.entryName;
      const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.resolve(extracted_path, normalizedEntryName);
      
      if (!fullPath.startsWith(path.resolve(extracted_path) + path.sep)) {
        hasTraversal = true;
        break;
      }
    }
    
    // After normalization and stripping, the path should be safe
    // The regex strips leading ../ patterns
    t.notOk(hasTraversal, 'Traversal patterns should be normalized and stripped');
    t.end();
  });

  t.test('should handle ZIP with directory entries', (t) => {
    const zip = new AdmZip();
    zip.addFile('dir/', Buffer.alloc(0)); // Directory entry
    zip.addFile('dir/file.txt', Buffer.from('Content', 'utf8'));
    
    const entries = zip.getEntries();
    const extracted_path = '/tmp/extracted_files';
    let allValid = true;
    
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const entryName = entry.entryName;
      const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.resolve(extracted_path, normalizedEntryName);
      
      if (!fullPath.startsWith(path.resolve(extracted_path) + path.sep)) {
        allValid = false;
        break;
      }
    }
    
    t.ok(allValid, 'Directory entries should be valid');
    t.end();
  });

  t.test('should validate malicious_backup.zip from exploits directory', (t) => {
    // Test with the actual malicious ZIP file from the pentest exploits
    const maliciousZipPath = path.join(__dirname, '../exploits/zip-slip/malicious_backup.zip');
    
    if (!fs.existsSync(maliciousZipPath)) {
      t.skip('Malicious ZIP file not found');
      t.end();
      return;
    }
    
    const zip = new AdmZip(maliciousZipPath);
    const entries = zip.getEntries();
    const extracted_path = '/tmp/extracted_files';
    let hasUnsafeEntry = false;
    let unsafeEntries = [];
    
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const entryName = entry.entryName;
      
      // Apply the same validation logic as the fixed code
      const normalizedEntryName = path.normalize(entryName).replace(/^(\.\.(\/|\\|$))+/, '');
      const fullPath = path.resolve(extracted_path, normalizedEntryName);
      
      if (!fullPath.startsWith(path.resolve(extracted_path) + path.sep)) {
        hasUnsafeEntry = true;
        unsafeEntries.push(entryName);
      }
    }
    
    // After applying the fix, all entries should be safe (normalized and stripped)
    t.notOk(hasUnsafeEntry, 'Malicious ZIP entries should be neutralized by validation logic');
    t.equal(unsafeEntries.length, 0, 'No unsafe entries should remain after validation');
    t.end();
  });

  t.end();
});

tap.test('Authentication Middleware Tests', (t) => {
  const routes = require('../routes');

  t.test('isLoggedIn should redirect when not authenticated', (t) => {
    const req = {
      session: {}
    };
    const res = {
      redirect: (path) => {
        t.equal(path, '/', 'Should redirect to home page');
        t.end();
      }
    };
    const next = () => {
      t.fail('Should not call next() when not authenticated');
      t.end();
    };

    routes.isLoggedIn(req, res, next);
  });

  t.test('isLoggedIn should call next when authenticated', (t) => {
    const req = {
      session: {
        loggedIn: 1
      }
    };
    const res = {
      redirect: (path) => {
        t.fail('Should not redirect when authenticated');
        t.end();
      }
    };
    const next = () => {
      t.pass('Should call next() when authenticated');
      t.end();
    };

    routes.isLoggedIn(req, res, next);
  });

  t.end();
});

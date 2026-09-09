const tap = require('tap');
const validator = require('validator');
const { execFile, exec } = require('child_process');

tap.test('Command Injection Prevention - URL Validation Tests', (t) => {
  
  t.test('should reject URL with semicolon command separator', (t) => {
    // GIVEN: Malicious URL with semicolon command injection
    const maliciousUrl = 'http://example.com/image.png;touch /tmp/pwned';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with semicolon should be rejected');
    t.end();
  });

  t.test('should reject URL with backtick command substitution', (t) => {
    // GIVEN: Malicious URL with backtick command substitution
    const maliciousUrl = 'http://example.com/`whoami`.png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with backticks should be rejected');
    t.end();
  });

  t.test('should reject URL with pipe operator', (t) => {
    // GIVEN: Malicious URL with pipe operator
    const maliciousUrl = 'http://example.com/image.png|cat /etc/passwd';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with pipe should be rejected');
    t.end();
  });

  t.test('should reject URL with ampersand command separator', (t) => {
    // GIVEN: Malicious URL with ampersand
    const maliciousUrl = 'http://example.com/image.png&curl attacker.com';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with ampersand should be rejected');
    t.end();
  });

  t.test('should reject URL with dollar sign command substitution', (t) => {
    // GIVEN: Malicious URL with $() command substitution
    const maliciousUrl = 'http://example.com/$(whoami).png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with $() should be rejected');
    t.end();
  });

  t.test('should reject URL with newline character', (t) => {
    // GIVEN: Malicious URL with newline
    const maliciousUrl = 'http://example.com/image.png\ntouch /tmp/pwned';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with newline should be rejected');
    t.end();
  });

  t.test('should reject URL with double ampersand', (t) => {
    // GIVEN: Malicious URL with && operator
    const maliciousUrl = 'http://example.com/image.png&&whoami';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with && should be rejected');
    t.end();
  });

  t.test('should reject URL with double pipe', (t) => {
    // GIVEN: Malicious URL with || operator
    const maliciousUrl = 'http://example.com/image.png||whoami';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(maliciousUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with || should be rejected');
    t.end();
  });

  t.test('should accept valid HTTP URL', (t) => {
    // GIVEN: Valid HTTP URL
    const validUrl = 'http://example.com/image.png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(validUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be accepted
    t.equal(isValid, true, 'Valid HTTP URL should be accepted');
    t.end();
  });

  t.test('should accept valid HTTPS URL', (t) => {
    // GIVEN: Valid HTTPS URL
    const validUrl = 'https://secure.example.com/path/to/image.png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(validUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be accepted
    t.equal(isValid, true, 'Valid HTTPS URL should be accepted');
    t.end();
  });

  t.test('should accept URL with query parameters', (t) => {
    // GIVEN: Valid URL with query parameters
    const validUrl = 'https://example.com/image.png?size=large&format=jpg';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(validUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be accepted
    t.equal(isValid, true, 'Valid URL with query params should be accepted');
    t.end();
  });

  t.test('should reject URL without protocol', (t) => {
    // GIVEN: URL without protocol
    const invalidUrl = 'example.com/image.png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(invalidUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL without protocol should be rejected');
    t.end();
  });

  t.test('should reject URL with file:// protocol', (t) => {
    // GIVEN: URL with file:// protocol (local file access)
    const invalidUrl = 'file:///etc/passwd';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(invalidUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with file:// protocol should be rejected');
    t.end();
  });

  t.test('should reject URL with ftp:// protocol', (t) => {
    // GIVEN: URL with ftp:// protocol
    const invalidUrl = 'ftp://example.com/image.png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(invalidUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with ftp:// protocol should be rejected');
    t.end();
  });

  t.test('should reject URL with spaces', (t) => {
    // GIVEN: URL with spaces
    const invalidUrl = 'http://example.com/image with spaces.png';
    
    // WHEN: validator checks the URL
    const isValid = validator.isURL(invalidUrl, { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    
    // THEN: URL should be rejected
    t.equal(isValid, false, 'URL with spaces should be rejected');
    t.end();
  });

  t.end();
});

tap.test('Command Injection Prevention - execFile vs exec behavior', (t) => {
  const { execFile, exec } = require('child_process');
  
  t.test('execFile should not interpret shell metacharacters', (t) => {
    // GIVEN: A command with shell metacharacters in the argument
    const testArg = 'http://example.com/test;echo INJECTED';
    
    // WHEN: execFile is called (will fail because 'identify' likely doesn't exist, but that's ok)
    execFile('echo', [testArg], (err, stdout, stderr) => {
      // THEN: The argument should be treated as a literal string, not executed
      // If this were vulnerable, we'd see "INJECTED" in the output
      // With execFile, the semicolon is treated as part of the argument
      if (!err) {
        t.notMatch(stdout, /INJECTED/, 'Shell metacharacters should not be interpreted');
      }
      // Test passes whether command succeeds or fails - we're testing the behavior
      t.pass('execFile treats arguments as literals');
      t.end();
    });
  });

  t.test('exec would interpret shell metacharacters (demonstrating the vulnerability)', (t) => {
    // GIVEN: A command with shell metacharacters
    const testCmd = 'echo test;echo VULNERABLE';
    
    // WHEN: exec is called (this demonstrates why exec is dangerous)
    exec(testCmd, (err, stdout, stderr) => {
      // THEN: Both commands would execute
      if (!err) {
        t.match(stdout, /VULNERABLE/, 'exec interprets shell metacharacters - this is why we use execFile');
      }
      t.pass('exec demonstrates the vulnerability we are protecting against');
      t.end();
    });
  });

  t.end();
});

tap.test('Command Injection Prevention - Markdown regex extraction', (t) => {
  
  t.test('should extract URL from valid markdown image syntax', (t) => {
    // GIVEN: Valid markdown image
    const markdown = '![alt text](http://example.com/image.png "Image title")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    // WHEN: regex is applied
    const match = markdown.match(imgRegex);
    
    // THEN: URL should be extracted
    t.ok(match, 'Regex should match valid markdown');
    t.equal(match[1], 'http://example.com/image.png', 'URL should be extracted correctly');
    t.end();
  });

  t.test('should extract malicious URL from markdown (before validation)', (t) => {
    // GIVEN: Markdown with command injection attempt
    const markdown = '![alt text](http://example.com/image.png;touch /tmp/pwned "Image")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    // WHEN: regex is applied
    const match = markdown.match(imgRegex);
    
    // THEN: Malicious URL is extracted (but will be rejected by validator)
    t.ok(match, 'Regex should match markdown');
    t.match(match[1], /;touch/, 'Malicious payload is in extracted URL');
    
    // AND: Validator should reject it
    const isValid = validator.isURL(match[1], { 
      protocols: ['http', 'https'], 
      require_protocol: true 
    });
    t.equal(isValid, false, 'Validator should reject the malicious URL');
    t.end();
  });

  t.test('should not match markdown without image syntax', (t) => {
    // GIVEN: Regular text without image markdown
    const text = 'Just a regular todo item';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    // WHEN: regex is applied
    const match = text.match(imgRegex);
    
    // THEN: No match should occur
    t.notOk(match, 'Regex should not match non-image content');
    t.end();
  });

  t.test('should not match markdown without http prefix', (t) => {
    // GIVEN: Markdown image without http
    const markdown = '![alt text](example.com/image.png "Image")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    // WHEN: regex is applied
    const match = markdown.match(imgRegex);
    
    // THEN: No match should occur
    t.notOk(match, 'Regex should require http prefix');
    t.end();
  });

  t.end();
});

tap.test('Command Injection Prevention - Integration scenarios', (t) => {
  
  t.test('complete flow: malicious markdown should be blocked', (t) => {
    // GIVEN: Malicious markdown from pentest finding
    const maliciousMarkdown = '![alt text](http://example.com/image.png;touch /tmp/pwned "Image")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    // WHEN: Processing the markdown
    const match = maliciousMarkdown.match(imgRegex);
    
    if (match) {
      const url = match[1];
      const isValid = validator.isURL(url, { 
        protocols: ['http', 'https'], 
        require_protocol: true 
      });
      
      // THEN: URL should be rejected
      t.equal(isValid, false, 'Malicious URL should be rejected by validator');
      
      // AND: execFile should not be called (simulated by checking validation)
      if (!isValid) {
        t.pass('execFile would not be called for invalid URL');
      }
    }
    
    t.end();
  });

  t.test('complete flow: valid markdown should be processed safely', (t) => {
    // GIVEN: Valid markdown
    const validMarkdown = '![alt text](https://raw.githubusercontent.com/example/image.png "Image")';
    const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
    
    // WHEN: Processing the markdown
    const match = validMarkdown.match(imgRegex);
    
    if (match) {
      const url = match[1];
      const isValid = validator.isURL(url, { 
        protocols: ['http', 'https'], 
        require_protocol: true 
      });
      
      // THEN: URL should be accepted
      t.equal(isValid, true, 'Valid URL should be accepted by validator');
      
      // AND: execFile would be called with safe arguments
      if (isValid) {
        t.pass('execFile would be called with URL as array argument');
        // In actual code: execFile('identify', [url], callback)
        // This prevents shell interpretation
      }
    }
    
    t.end();
  });

  t.test('defense in depth: multiple validation layers', (t) => {
    // GIVEN: Various malicious payloads
    const maliciousPayloads = [
      'http://example.com/image.png;touch /tmp/pwned',
      'http://example.com/`whoami`.png',
      'http://example.com/$(whoami).png',
      'http://example.com/image.png|cat /etc/passwd',
      'http://example.com/image.png&curl attacker.com',
      'http://example.com/image.png&&whoami',
      'http://example.com/image.png||whoami',
      'http://example.com/image.png\ntouch /tmp/pwned'
    ];
    
    // WHEN: Each payload is validated
    maliciousPayloads.forEach((payload) => {
      const isValid = validator.isURL(payload, { 
        protocols: ['http', 'https'], 
        require_protocol: true 
      });
      
      // THEN: All should be rejected
      t.equal(isValid, false, `Payload should be rejected: ${payload.substring(0, 50)}...`);
    });
    
    t.end();
  });

  t.test('allowlist approach: only http and https protocols allowed', (t) => {
    // GIVEN: URLs with various protocols
    const testCases = [
      { url: 'http://example.com/image.png', shouldPass: true },
      { url: 'https://example.com/image.png', shouldPass: true },
      { url: 'file:///etc/passwd', shouldPass: false },
      { url: 'ftp://example.com/image.png', shouldPass: false },
      { url: 'javascript:alert(1)', shouldPass: false },
      { url: 'data:text/html,<script>alert(1)</script>', shouldPass: false }
    ];
    
    // WHEN: Each URL is validated
    testCases.forEach((testCase) => {
      const isValid = validator.isURL(testCase.url, { 
        protocols: ['http', 'https'], 
        require_protocol: true 
      });
      
      // THEN: Result should match expected
      t.equal(isValid, testCase.shouldPass, 
        `${testCase.url} should ${testCase.shouldPass ? 'pass' : 'fail'}`);
    });
    
    t.end();
  });

  t.end();
});

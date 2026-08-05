/**
 * Unit Tests for security-utils.js
 * Asserts correctness and robustness of input validation, sanitization, and cryptographic helper functions.
 */

const assert = require('assert');
const {
  isValidEmail,
  sanitizeInput,
  generateSecureToken,
  constantTimeCompare
} = require('./security-utils');

// Simple test runner structure
const tests = {};

// --- Tests for isValidEmail ---
tests['isValidEmail should return true for valid emails'] = () => {
  assert.strictEqual(isValidEmail('test@example.com'), true);
  assert.strictEqual(isValidEmail('user.name+tag@domain.co.uk'), true);
  assert.strictEqual(isValidEmail('123@abc.xyz'), true);
};

tests['isValidEmail should return false for invalid emails'] = () => {
  assert.strictEqual(isValidEmail('plainaddress'), false);
  assert.strictEqual(isValidEmail('@missingusername.com'), false);
  assert.strictEqual(isValidEmail('username@.com'), false);
  assert.strictEqual(isValidEmail('username@domain.'), false);
  assert.strictEqual(isValidEmail(null), false);
  assert.strictEqual(isValidEmail(undefined), false);
  assert.strictEqual(isValidEmail(12345), false);
};

tests['isValidEmail should return false for extremely long emails (DoS prevention)'] = () => {
  const longEmail = 'a'.repeat(250) + '@example.com';
  assert.strictEqual(isValidEmail(longEmail), false);
};

// --- Tests for sanitizeInput ---
tests['sanitizeInput should escape HTML special characters'] = () => {
  assert.strictEqual(sanitizeInput('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;&#x2F;script&gt;');
  assert.strictEqual(sanitizeInput('"double quotes" and \'single quotes\''), '&quot;double quotes&quot; and &#x27;single quotes&#x27;');
  assert.strictEqual(sanitizeInput('foo & bar'), 'foo &amp; bar');
};

tests['sanitizeInput should handle non-string inputs gracefully'] = () => {
  assert.strictEqual(sanitizeInput(null), '');
  assert.strictEqual(sanitizeInput(undefined), '');
  assert.strictEqual(sanitizeInput(42), '');
};

tests['sanitizeInput should cap long input strings'] = () => {
  const longInput = 'x'.repeat(10005);
  const sanitized = sanitizeInput(longInput);
  assert.strictEqual(sanitized.length, 10000);
};

// --- Tests for generateSecureToken ---
tests['generateSecureToken should generate hex string of correct length'] = () => {
  const token32 = generateSecureToken(32);
  // 32 bytes in hex is 64 characters
  assert.strictEqual(token32.length, 64);
  assert.strictEqual(/^[0-9a-f]+$/.test(token32), true);

  const token16 = generateSecureToken(16);
  assert.strictEqual(token16.length, 32);
};

tests['generateSecureToken should fallback to default 32 bytes for invalid inputs'] = () => {
  assert.strictEqual(generateSecureToken(null).length, 64);
  assert.strictEqual(generateSecureToken('not-a-number').length, 64);
  assert.strictEqual(generateSecureToken(-5).length, 64);
};

tests['generateSecureToken should limit maximum length to prevent DoS'] = () => {
  const tokenTooLarge = generateSecureToken(2000);
  assert.strictEqual(tokenTooLarge.length, 2048); // max bytes is 1024, hex length is 2048
};

// --- Tests for constantTimeCompare ---
tests['constantTimeCompare should return true for identical strings'] = () => {
  assert.strictEqual(constantTimeCompare('secret_key_123', 'secret_key_123'), true);
  assert.strictEqual(constantTimeCompare('', ''), true);
};

tests['constantTimeCompare should return false for different strings'] = () => {
  assert.strictEqual(constantTimeCompare('secret_key_123', 'secret_key_456'), false);
  assert.strictEqual(constantTimeCompare('secret_key_123', 'secret_key'), false);
  assert.strictEqual(constantTimeCompare('secret', 'secret_key_123'), false);
};

tests['constantTimeCompare should handle invalid types safely'] = () => {
  assert.strictEqual(constantTimeCompare(null, 'secret'), false);
  assert.strictEqual(constantTimeCompare('secret', undefined), false);
};

tests['constantTimeCompare should safely handle different length inputs'] = () => {
  assert.strictEqual(constantTimeCompare('short', 'long-string-value-that-is-different'), false);
};

// --- Tests for hashPassword and verifyPassword ---
tests['hashPassword should securely hash a password and verifyPassword should verify it'] = () => {
  const { hashPassword, verifyPassword } = require('./security-utils');
  const password = 'SuperSecurePassword123!';
  const hashedPassword = hashPassword(password);

  assert.notStrictEqual(hashedPassword, password);
  assert.strictEqual(hashedPassword.includes('$'), true);

  const parts = hashedPassword.split('$');
  assert.strictEqual(parts.length, 2);
  assert.strictEqual(parts[0].length, 32); // 16-byte salt as hex

  // Verification
  assert.strictEqual(verifyPassword(password, hashedPassword), true);
  assert.strictEqual(verifyPassword('WrongPassword', hashedPassword), false);
};

tests['hashPassword should throw error for non-string inputs'] = () => {
  const { hashPassword } = require('./security-utils');
  assert.throws(() => hashPassword(null), TypeError);
  assert.throws(() => hashPassword(undefined), TypeError);
  assert.throws(() => hashPassword(1234), TypeError);
};

tests['verifyPassword should handle non-string or invalid hashed formats safely'] = () => {
  const { verifyPassword } = require('./security-utils');
  assert.strictEqual(verifyPassword(null, 'salt$hash'), false);
  assert.strictEqual(verifyPassword('password', null), false);
  assert.strictEqual(verifyPassword('password', 'invalid-format'), false);
};

tests['hashPassword should generate unique hashes for the same password due to random salt'] = () => {
  const { hashPassword } = require('./security-utils');
  const password = 'same-password';
  const hash1 = hashPassword(password);
  const hash2 = hashPassword(password);
  assert.notStrictEqual(hash1, hash2);
};

// --- Run all tests ---
let failed = 0;
console.log('Running security-utils tests...');
for (const [name, testFn] of Object.entries(tests)) {
  try {
    testFn();
    console.log(`✅ PASS: ${name}`);
  } catch (err) {
    console.error(`❌ FAIL: ${name}`);
    console.error(err);
    failed++;
  }
}

if (failed > 0) {
  console.error(`\nTest suite failed with ${failed} failure(s).`);
  process.exit(1);
} else {
  console.log('\nAll security-utils tests passed successfully!');
  process.exit(0);
}

/**
 * Unit Tests for security-utils.js
 * Asserts correctness and robustness of input validation, sanitization, and cryptographic helper functions.
 */

const assert = require('assert');
const {
  isValidEmail,
  sanitizeInput,
  generateSecureToken,
  constantTimeCompare,
  safeResolvePath,
  safeParseUrl
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

tests['sanitizeInput should escape backticks'] = () => {
  assert.strictEqual(sanitizeInput('`hello`'), '&#x60;hello&#x60;');
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

tests['generateSecureToken should fallback to default 32 bytes for invalid or non-integer inputs'] = () => {
  assert.strictEqual(generateSecureToken(null).length, 64);
  assert.strictEqual(generateSecureToken('not-a-number').length, 64);
  assert.strictEqual(generateSecureToken(-5).length, 64);
  assert.strictEqual(generateSecureToken(8.5).length, 64);
};

tests['generateSecureToken should enforce a minimum of 16 bytes for security and entropy guarantees'] = () => {
  const tokenSmall = generateSecureToken(5);
  assert.strictEqual(tokenSmall.length, 32); // 16 bytes is 32 hex characters

  const tokenFifteen = generateSecureToken(15);
  assert.strictEqual(tokenFifteen.length, 32); // 16 bytes is 32 hex characters
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

tests['constantTimeCompare should return false for inputs exceeding maximum length limit'] = () => {
  const extremelyLongString = 'a'.repeat(10001);
  assert.strictEqual(constantTimeCompare(extremelyLongString, 'secret'), false);
  assert.strictEqual(constantTimeCompare('secret', extremelyLongString), false);
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

tests['hashPassword should throw error for password exceeding maximum length limit'] = () => {
  const { hashPassword } = require('./security-utils');
  const longPassword = 'a'.repeat(129);
  assert.throws(() => hashPassword(longPassword), RangeError);
};

tests['hashPassword should throw error for non-string inputs'] = () => {
  const { hashPassword } = require('./security-utils');
  assert.throws(() => hashPassword(null), TypeError);
  assert.throws(() => hashPassword(undefined), TypeError);
  assert.throws(() => hashPassword(1234), TypeError);
};

tests['verifyPassword should return false for password exceeding maximum length limit'] = () => {
  const { verifyPassword } = require('./security-utils');
  const longPassword = 'a'.repeat(129);
  assert.strictEqual(verifyPassword(longPassword, 'salt$hash'), false);
};

tests['verifyPassword should handle non-string or invalid hashed formats safely'] = () => {
  const { verifyPassword } = require('./security-utils');
  assert.strictEqual(verifyPassword(null, 'salt$hash'), false);
  assert.strictEqual(verifyPassword('password', null), false);
  assert.strictEqual(verifyPassword('password', 'invalid-format'), false);

  // Test invalid hex characters
  assert.strictEqual(verifyPassword('password', 'g'.repeat(32) + '$' + 'a'.repeat(128)), false);
  // Test invalid lengths
  assert.strictEqual(verifyPassword('password', 'a'.repeat(31) + '$' + 'b'.repeat(128)), false);
  assert.strictEqual(verifyPassword('password', 'a'.repeat(32) + '$' + 'b'.repeat(127)), false);
};

tests['hashPassword should generate unique hashes for the same password due to random salt'] = () => {
  const { hashPassword } = require('./security-utils');
  const password = 'same-password';
  const hash1 = hashPassword(password);
  const hash2 = hashPassword(password);
  assert.notStrictEqual(hash1, hash2);
};

// --- Tests for safeResolvePath ---
tests['safeResolvePath should allow valid relative paths inside the base directory'] = () => {
  const path = require('path');
  const base = path.resolve('/tmp/safe-dir');

  const result1 = safeResolvePath(base, 'file.txt');
  assert.strictEqual(result1, path.join(base, 'file.txt'));

  const result2 = safeResolvePath(base, 'subdir/nested.json');
  assert.strictEqual(result2, path.join(base, 'subdir/nested.json'));

  const result3 = safeResolvePath(base, './file.csv');
  assert.strictEqual(result3, path.join(base, 'file.csv'));
};

tests['safeResolvePath should allow when relative path matches base directory exactly'] = () => {
  const path = require('path');
  const base = path.resolve('/tmp/safe-dir');

  const result = safeResolvePath(base, '.');
  assert.strictEqual(result, base);
};

tests['safeResolvePath should block path traversal attempts that escape the base directory'] = () => {
  const path = require('path');
  const base = path.resolve('/tmp/safe-dir');

  assert.strictEqual(safeResolvePath(base, '../outside.txt'), null);
  assert.strictEqual(safeResolvePath(base, 'subdir/../../outside.txt'), null);
  assert.strictEqual(safeResolvePath(base, '../../etc/passwd'), null);
};

tests['safeResolvePath should block path traversal attempts using backslashes (cross-platform traversal prevention)'] = () => {
  const path = require('path');
  const base = path.resolve('/tmp/safe-dir');

  assert.strictEqual(safeResolvePath(base, '..\\outside.txt'), null);
  assert.strictEqual(safeResolvePath(base, 'subdir\\..\\..\\outside.txt'), null);
  assert.strictEqual(safeResolvePath(base, '..\\..\\etc\\passwd'), null);
};

tests['safeResolvePath should block absolute paths outside base directory'] = () => {
  const path = require('path');
  const base = path.resolve('/tmp/safe-dir');

  // If base is /tmp/safe-dir, trying to access /etc/passwd or /tmp/other should be blocked
  assert.strictEqual(safeResolvePath(base, '/etc/passwd'), null);
};

tests['safeResolvePath should reject base path suffix prefix injection attempts'] = () => {
  const path = require('path');
  // Ensuring that /tmp/safe-dir-sibling is not allowed when base is /tmp/safe-dir
  const base = path.resolve('/tmp/safe-dir');
  const sibling = '../safe-dir-sibling/file.txt';
  assert.strictEqual(safeResolvePath(base, sibling), null);
};

tests['safeResolvePath should handle invalid types and empty parameters gracefully'] = () => {
  assert.strictEqual(safeResolvePath(null, 'file.txt'), null);
  assert.strictEqual(safeResolvePath('/tmp/safe', null), null);
  assert.strictEqual(safeResolvePath(undefined, undefined), null);
  assert.strictEqual(safeResolvePath(12345, 'file.txt'), null);
};

tests['safeResolvePath should block relative paths containing null bytes'] = () => {
  const path = require('path');
  const base = path.resolve('/tmp/safe-dir');
  assert.strictEqual(safeResolvePath(base, 'file.txt\u0000.png'), null);
  assert.strictEqual(safeResolvePath(base, '\u0000file.txt'), null);
};

tests['safeResolvePath should block base directory paths containing null bytes'] = () => {
  assert.strictEqual(safeResolvePath('/tmp/safe-dir\u0000', 'file.txt'), null);
};

// --- Tests for safeParseUrl ---
tests['safeParseUrl should successfully parse valid http and https URLs'] = () => {
  const url1 = safeParseUrl('https://example.com/path?query=1');
  assert.notStrictEqual(url1, null);
  assert.strictEqual(url1.protocol, 'https:');
  assert.strictEqual(url1.hostname, 'example.com');
  assert.strictEqual(url1.pathname, '/path');

  const url2 = safeParseUrl('http://localhost:3000');
  assert.notStrictEqual(url2, null);
  assert.strictEqual(url2.protocol, 'http:');
  assert.strictEqual(url2.port, '3000');
};

tests['safeParseUrl should return null for invalid URL strings or types'] = () => {
  assert.strictEqual(safeParseUrl('not-a-url'), null);
  assert.strictEqual(safeParseUrl(''), null);
  assert.strictEqual(safeParseUrl(null), null);
  assert.strictEqual(safeParseUrl(undefined), null);
  assert.strictEqual(safeParseUrl(12345), null);
};

tests['safeParseUrl should block dangerous schemes and protocols'] = () => {
  assert.strictEqual(safeParseUrl('javascript:alert(1)'), null);
  assert.strictEqual(safeParseUrl('data:text/html,<script>alert(1)</script>'), null);
  assert.strictEqual(safeParseUrl('file:///etc/passwd'), null);
  assert.strictEqual(safeParseUrl('ftp://example.com'), null);
  assert.strictEqual(safeParseUrl('gopher://example.com'), null);
};

tests['safeParseUrl should enforce length limit to prevent DoS'] = () => {
  const longUrl = 'https://example.com/' + 'a'.repeat(2040); // 2060 chars
  assert.strictEqual(safeParseUrl(longUrl), null);
};

tests['safeParseUrl should validate hosts correctly when allowedHosts is provided'] = () => {
  const allowed = ['example.com', '.trusted.org', 'localhost'];

  // Valid hosts
  const url1 = safeParseUrl('https://example.com/api', allowed);
  assert.notStrictEqual(url1, null);
  assert.strictEqual(url1.hostname, 'example.com');

  const url2 = safeParseUrl('http://localhost:3000/test', allowed);
  assert.notStrictEqual(url2, null);
  assert.strictEqual(url2.hostname, 'localhost');

  const url3 = safeParseUrl('https://sub.trusted.org/path', allowed);
  assert.notStrictEqual(url3, null);
  assert.strictEqual(url3.hostname, 'sub.trusted.org');

  const url4 = safeParseUrl('https://trusted.org/path', allowed); // ends with .trusted.org
  assert.notStrictEqual(url4, null);
  assert.strictEqual(url4.hostname, 'trusted.org');

  // Unallowed hosts
  assert.strictEqual(safeParseUrl('https://attacker.com', allowed), null);
  assert.strictEqual(safeParseUrl('https://notexample.com', allowed), null);
  assert.strictEqual(safeParseUrl('https://example.com.attacker.com', allowed), null);
  assert.strictEqual(safeParseUrl('https://trusted.org.attacker.com', allowed), null);
};

tests['safeParseUrl should return null if allowedHosts is not an array'] = () => {
  assert.strictEqual(safeParseUrl('https://example.com', 'not-an-array'), null);
  assert.strictEqual(safeParseUrl('https://example.com', {}), null);
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

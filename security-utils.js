/**
 * Security Utilities for Chronos-V3
 * Provides defensive helpers for input validation, sanitization, and cryptographic operations.
 */

const crypto = require('crypto');

/**
 * Validates an email address using a safe, non-vulnerable regular expression.
 * Avoids ReDoS (Regular Expression Denial of Service) vulnerabilities by using a standard simple validation regex.
 *
 * @param {string} email - The email to validate
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidEmail(email) {
  if (typeof email !== 'string') {
    return false;
  }

  // Enforce a sensible maximum length to prevent DoS attacks via extremely large inputs
  if (email.length > 254) {
    return false;
  }

  // Safe RFC 5322 based simple pattern that is not susceptible to exponential backtracking (ReDoS)
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email);
}

/**
 * Sanitizes HTML input to mitigate basic Cross-Site Scripting (XSS) risks.
 * Encodes special characters into safe HTML entities.
 *
 * @param {string} input - The input string to sanitize
 * @returns {string} - The sanitized string
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return '';
  }

  // Enforce a maximum input length to prevent potential Denial of Service (DoS)
  if (input.length > 10000) {
    input = input.substring(0, 10000);
  }

  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Generates a cryptographically secure random token (e.g. for CSRF, session tokens, or API keys).
 * Uses Node's crypto.randomBytes rather than Math.random() to guarantee unpredictability.
 *
 * @param {number} bytes - Number of random bytes to generate (defaults to 32)
 * @returns {string} - Hex encoded secure random token
 */
function generateSecureToken(bytes = 32) {
  if (typeof bytes !== 'number' || bytes <= 0 || isNaN(bytes)) {
    bytes = 32;
  }
  // Cap at 1024 bytes to prevent potential resource exhaustion / DoS
  if (bytes > 1024) {
    bytes = 1024;
  }
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Safely compares two strings in constant-time to prevent timing attacks.
 * Commonly used for password hashes, API keys, or verification tokens.
 *
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} - True if strings are equal, false otherwise
 */
function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);

  if (bufferA.length !== bufferB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufferA, bufferB);
}

module.exports = {
  isValidEmail,
  sanitizeInput,
  generateSecureToken,
  constantTimeCompare
};

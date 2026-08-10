# Sentinel Journal

## 2026-08-02 - [Repository Empty of Application Source Code]
**Vulnerability:** The repository does not contain any application source code, configuration files, or tests, only a single README.md file. Therefore, no pre-existing vulnerabilities could be found.
**Learning:** In an empty repository, security can be enhanced by establishing foundational security policies, configurations, or hooks.
**Prevention:** Establish basic repo security structures or templates.

## 2026-08-05 - [Timing Attack Risk on Variable-Length Comparisons]
**Vulnerability:** The previous `constantTimeCompare` utility checked length equality first, failing early for different length inputs, which leaks secret length information via timing differences.
**Learning:** Even if `crypto.timingSafeEqual` is used on equal-length buffers, checking buffer length equality early makes the overall function vulnerable to variable-length timing attacks. A Double HMAC pattern with a random transient key compares fixed-length HMAC digests instead.
**Prevention:** Always compare sensitive secrets (like API keys, verification tokens, or hashes) by hashing them to a fixed size first using a transient-key HMAC before using constant-time comparison, or enforce strict fixed-length comparisons.

## 2026-08-05 - [Path Traversal Vulnerability Prevention Utility]
**Vulnerability:** User-supplied relative file paths used directly in file system operations (like `fs.readFile`) can include traversal sequences (such as `../`) to access sensitive system or application files outside the intended base directory.
**Learning:** Simply checking for `../` using string checks is bypassable (e.g. via double encoding, absolute paths, or prefix/suffix injection like matching `/safe-dir-sibling` when `/safe-dir` is base). Resolving absolute paths with `path.resolve` and enforcing a strict directory prefix check is the industry-standard way to guarantee security.
**Prevention:** Always use `safeResolvePath` to resolve and validate user-controlled relative paths against a trusted base directory before reading or writing to the file system.

## 2026-08-07 - [Password-Hashing CPU Exhaustion Denial of Service]
**Vulnerability:** CPU-intensive key derivation algorithms (like scrypt Sync) executed on the main Node.js thread can cause a Denial of Service (DoS) if they process extremely long inputs. Additionally, executing scrypt on invalidly formatted hashes wastes valuable CPU cycles.
**Learning:** Enforcing a reasonable password length ceiling (e.g., 128 characters) and thoroughly validating the exact salt and hash structure/lengths via strict regular expressions before calling `crypto.scryptSync` fully mitigates the CPU exhaustion vulnerability and prevents invalid signature processing.
**Prevention:** Validate input lengths and hash structural specifications explicitly prior to invoking any computationally heavy cryptographic sync functions on the event loop.

## 2026-08-08 - [Cross-Platform Backslash Directory Traversal Bypass]
**Vulnerability:** Path resolution helpers resolving paths on POSIX systems do not treat backslash characters (`\`) as directory separators, which can allow malicious Windows-style path traversal sequences (like `..\..\etc\passwd`) to bypass traversal verification, leading to downstream security vulnerabilities if used in context-sensitive file operations or if the application is ported.
**Learning:** Normalizing backslashes to forward slashes before resolving user-supplied relative paths forces path resolution APIs to treat backslashes as valid directory separators across all platforms, preventing cross-platform directory traversal bypasses.
**Prevention:** Always normalize separators by converting backslashes to forward slashes in relative paths before attempting to resolve them using platform-specific path resolution libraries.

## 2026-08-08 - [Constant-Time Comparison CPU Exhaustion Denial of Service]
**Vulnerability:** Computing HMACs on extremely large user-supplied strings inside constant-time comparison helper functions (using a Double HMAC pattern) can tie up the Node.js event loop and lead to a CPU exhaustion Denial of Service (DoS).
**Learning:** Enforcing a strict length ceiling (e.g., 10,000 characters) on inputs inside comparison helpers protects the crypto subsystem from hashing excessively large payloads.
**Prevention:** Validate input lengths and apply a reasonable maximum string size check to prevent DoS prior to running any cryptographic comparisons on untrusted user inputs.

## 2026-08-07 - [Null-Byte Injection Path Truncation Risk]
**Vulnerability:** Even if `path.resolve` is used to sanitize paths and prevent directory traversal, inputs containing null bytes (`\u0000`) can be resolved successfully but later cause unexpected path truncation or exceptions when passed to lower-level system, C/C++, or database APIs.
**Learning:** Null byte truncation is an older but still highly effective attack vector that must be proactively blocked at the validation boundaries before resolving or sanitizing paths to prevent arbitrary file access or application errors.
**Prevention:** Proactively check and reject inputs containing null bytes (`\u0000`) before running path resolution or routing logic.

## 2026-08-10 - [Weak Secure Token Generation and Validation Bypass]
**Vulnerability:** Secure token generators that accept floating-point or extremely low byte values without strict verification can generate zero-length or extremely short tokens (e.g., `0` or `1` byte), resulting in trivial token prediction or validation bypasses.
**Learning:** Checking for positive values of non-string parameters is insufficient; we must explicitly enforce parameter type and integer correctness using `Number.isInteger()`, and guarantee a secure baseline of entropy by clamping a strict minimum byte size (e.g. 16 bytes).
**Prevention:** Always sanitize input arguments to cryptographic token generation functions to ensure they are valid positive integers, and enforce a minimum token size corresponding to at least 128 bits of entropy.

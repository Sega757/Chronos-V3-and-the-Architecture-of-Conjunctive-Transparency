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

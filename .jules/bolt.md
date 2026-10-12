# Bolt Performance Journal

This journal tracks critical learnings and performance insights for the codebase.

## 2026-08-27 - Repository Empty of Application Code
**Learning:** The repository contains no application source code or build/execution pipeline (only `README.md`, `SECURITY.md`, and `.jules/sentinel.md`). No performance optimizations can be performed because there is no application logic to measure or optimize.
**Action:** When operating in a repository without application code, cleanly initialize the journal and refrain from submitting a PR or inventing artificial changes, adhering strictly to Bolt's guidelines.

## 2026-08-28 - Fast-path IP validation and IPv6 Scope IDs
**Learning:** When fast-pathing `is_private_ip()` validation using regex character checks to bypass `ipaddress.ip_address()` exception overhead on domain names, IPv6 link-local addresses can contain `%scope_id` (e.g., `fe80::1%eth0`). The `%scope_id` must be stripped before non-IP character regex checks AND before calling `ipaddress.ip_address()`, because `ipaddress.ip_address()` raises a `ValueError` if passed a string with a scope ID.
**Action:** Always strip `%scope_id` (`ip_str.split('%', 1)[0]`) before validating IP string character sets or passing to `ipaddress.ip_address()`.

## 2026-08-29 - Validate Domain Whitelists Before Synchronous DNS Resolution
**Learning:** In URL validation functions (`safe_parse_url`), checking the `allowed_hosts` whitelist before executing `block_private_ips` DNS resolution (`socket.getaddrinfo`) avoids making costly synchronous DNS queries for disallowed target domains, turning milliseconds of blocking network latency into microsecond fast rejections (~1000x+ speedup on rejected URLs).
**Action:** When validating URLs against both domain whitelists and private IP ranges, evaluate pure string whitelist matching before executing blocking network DNS lookups.

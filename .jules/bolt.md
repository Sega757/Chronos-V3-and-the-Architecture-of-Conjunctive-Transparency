# Bolt Performance Journal

This journal tracks critical learnings and performance insights for the codebase.

## 2026-08-27 - Repository Empty of Application Code
**Learning:** The repository contains no application source code or build/execution pipeline (only `README.md`, `SECURITY.md`, and `.jules/sentinel.md`). No performance optimizations can be performed because there is no application logic to measure or optimize.
**Action:** When operating in a repository without application code, cleanly initialize the journal and refrain from submitting a PR or inventing artificial changes, adhering strictly to Bolt's guidelines.

## 2026-08-28 - Fast-path IP validation and IPv6 Scope IDs
**Learning:** When fast-pathing `is_private_ip()` validation using regex character checks to bypass `ipaddress.ip_address()` exception overhead on domain names, IPv6 link-local addresses can contain `%scope_id` (e.g., `fe80::1%eth0`). The `%scope_id` must be stripped before non-IP character regex checks AND before calling `ipaddress.ip_address()`, because `ipaddress.ip_address()` raises a `ValueError` if passed a string with a scope ID.
**Action:** Always strip `%scope_id` (`ip_str.split('%', 1)[0]`) before validating IP string character sets or passing to `ipaddress.ip_address()`.

## 2026-10-14 - Order of URL Validation: Whitelist vs DNS Resolution
**Learning:** Performing blocking network DNS resolution (`socket.getaddrinfo`) inside `block_private_ips` before validating target hostnames against `allowed_hosts` introduces high network latency (~10-100ms per request) for disallowed domains.
**Action:** Always position fast in-memory string/whitelist validations before network or syscall checks in URL parsing pipelines to ensure disallowed requests fail fast.

## 2026-10-15 - Fast-pathing urllib.parse Port Access
**Learning:** In Python's `urllib.parse`, accessing `parsed.port` on a `ParseResult` instance triggers string splitting and regex parsing over `parsed.netloc`. By checking `if ':' in parsed.netloc:` before accessing `parsed.port`, we bypass redundant property parsing for standard URLs that do not specify a port (~11-14% performance boost in URL parsing).
**Action:** Always check `':' in parsed.netloc` before accessing `parsed.port` when validating URLs.

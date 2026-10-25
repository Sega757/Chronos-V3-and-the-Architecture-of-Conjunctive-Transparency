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

## 2026-10-16 - Fast-pathing IPv6 Validation via socket.inet_pton
**Learning:** In Python, evaluating IPv6 strings with `ipaddress.ip_address()` constructs pure-Python `IPv6Address` instances and evaluates properties in Python, costing ~13-23µs per call. Using C-level `socket.inet_pton(socket.AF_INET6)` parses IPv6 strings in ~0.5µs, and byte inspection evaluates restricted IPv6 ranges in ~0.9-2.1µs per call (~10x-20x speedup) while remaining 100% compliant with restricted IPv6 ranges and embedded IPv4 parsing.
**Action:** Prefer C-level `socket.inet_pton` and byte inspection for high-frequency IP classification over pure-Python `ipaddress.ip_address()` object allocation.

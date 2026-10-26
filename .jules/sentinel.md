# Sentinel Security Journal 🛡️

## Security Assessment & Learnings

### Repository Status
- Sovereign Agent Swarm architecture with Go (`go-metacore`), Python (`python-worker`), gRPC protobuf specs, PostgreSQL/SQLite schemas, and Docker Compose orchestration.

### SSRF Vulnerability Fix in `python-worker/server.py`
- **Issue (CWE-918):** SSRF bypass via unparseable/alternative IP encodings and DNS resolution. Previously, `is_private_ip` returned `False` when `ipaddress.ip_address()` raised a `ValueError`, allowing malformed IP representations or alternative encodings to bypass the SSRF filter. Furthermore, hostnames were not resolved to underlying IP addresses.
- **Fix:**
  1. Updated `is_private_ip` to decode alternative IPv4 representations (hex `0x7f000001`, octal `0177.0.0.1`, decimal integer `2130706433`, shorthand dotted notation) using `socket.inet_aton` and fail closed on malformed IP-like strings.
  2. Updated `safe_parse_url` when `block_private_ips=True` to resolve hostnames via `socket.getaddrinfo` and fail closed if DNS resolution fails (`socket.gaierror`) or if any resolved IP address belongs to a private/loopback/reserved/multicast range.
  3. Added comprehensive unit tests in `python-worker/test_server.py` covering hex, octal, integer, shorthand IP formats, IPv6 mapped IPv4, DNS rebinding, multi-IP resolution, and DNS failure scenarios.

## 2025-05-18 - SSRF Bypass via IPv4-Compatible and NAT64 IPv6 Addresses
**Vulnerability:** In `python-worker/server.py`, `_is_restricted_ip_obj` checked `ip.ipv4_mapped` for IPv6 addresses, but did not check IPv4-compatible (`::/96`) or NAT64 (`64:ff9b::/96`) IPv6 representations. Python's `ipaddress.IPv6Address.is_global` returns `True` for `::127.0.0.1` and `64:ff9b::127.0.0.1`, allowing SSRF filters to be bypassed.
**Learning:** Standard library `ip.is_global` checks do not automatically decompose IPv4-compatible or NAT64 IPv6 addresses to verify if the embedded IPv4 address targets private or restricted ranges.
**Prevention:** Unpack raw bytes (`ip.packed`) for IPv6 addresses to explicitly extract and validate embedded IPv4 addresses in `::/96` and `64:ff9b::/96` against restricted ranges.

## 2025-05-19 - Reject Embedded Userinfo Credentials in URL Parser
**Vulnerability:** URLs containing embedded user credentials (`user:password@host`) pose credential leakage risks (CWE-255, CWE-598) in logs and referrer headers and enable URL parser differential SSRF bypasses (CWE-918).
**Learning:** Standard URL parsers accept userinfo in `netloc`, which deprecated RFC 3986 format can be abused to bypass host verification or leak sensitive authentication tokens.
**Prevention:** Reject URLs with `@` in `parsed.netloc` during `safe_parse_url` validation while preserving valid `@` usages in path or query parameters.

## 2025-05-20 - SSRF Bypass via SIIT IPv4-Translated IPv6 Addresses
**Vulnerability:** SIIT IPv4-translated IPv6 addresses (`::ffff:0:a.b.c.d` / `::ffff:0:0/96`, RFC 2765 / RFC 6145) were not caught by Python's `ip.ipv4_mapped` (which only checks `::ffff:a.b.c.d` / `::ffff:0:0/80`). Standard `ip.is_global` evaluated `::ffff:0:127.0.0.1` and `::ffff:0:169.254.169.254` as `True`, bypassing SSRF restrictions.
**Learning:** Python's `ipaddress` module does not classify SIIT IPv4-translated addresses as non-global and does not populate `ip.ipv4_mapped` for the `::ffff:0:0/96` prefix.
**Prevention:** Inspect `ip.packed` for prefix `b'\x00'*8 + b'\xff\xff\x00\x00'` (`::ffff:0:0/96`) and extract the last 4 bytes as an `IPv4Address` to validate embedded targets against restricted IP ranges.

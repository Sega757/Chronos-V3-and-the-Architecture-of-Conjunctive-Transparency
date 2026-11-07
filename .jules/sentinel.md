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

## 2025-05-21 - SSRF Bypass via 6to4 Encapsulated IPv6 Addresses
**Vulnerability:** 6to4 IPv6 addresses (`2002::/16`, RFC 3056) embed an IPv4 address in the next 32 bits (`packed[2:6]`). The C-level fast-path byte inspection in `_is_restricted_ipv6_bytes` did not check prefix `b'\x20\x02'`, allowing addresses such as `2002:7f00:1::` (127.0.0.1) and `2002:a00:1::` (10.0.0.1) to bypass `is_private_ip()` and `safe_parse_url()`.
**Learning:** In 6to4 transition mechanisms, the embedded IPv4 target is placed at offset 2 (`packed[2:6]`) rather than at the end of the 16-byte address (`packed[12:16]`), requiring targeted slice extraction.
**Prevention:** Inspect `packed[:2] == b'\x20\x02'` and extract `packed[2:6]` to evaluate the embedded IPv4 integer/address against restricted ranges.

## 2025-05-22 - SSRF Bypass via Teredo Tunneling IPv6 Addresses
**Vulnerability:** Teredo tunneling IPv6 addresses (`2001:0000::/32`, RFC 4380) encapsulate both a Teredo server IPv4 (`packed[4:8]`) and a client IPv4 (`packed[12:16]`, obfuscated via XOR with `0xFFFFFFFF`). Neither `_is_restricted_ipv6_bytes` nor `_is_restricted_ip_obj` checked Teredo addresses, allowing encapsulated loopback, metadata, or private IP targets (e.g., `2001:0:808:808::80ff:fffe` where client IPv4 is `127.0.0.1`) to bypass SSRF validation (CWE-918).
**Learning:** In Teredo tunneling, client IPv4 addresses are bitwise inverted (XOR with `0xFFFFFFFF`), preventing direct substring or byte comparisons without de-obfuscating the last 4 bytes.
**Prevention:** Inspect `packed[:4] == b'\x20\x01\x00\x00'`, extract server IPv4 from `packed[4:8]`, unobfuscate client IPv4 via `struct.unpack('!I', packed[12:16])[0] ^ 0xFFFFFFFF`, and validate both against restricted IPv4 ranges.

## 2025-05-23 - SSRF Bypass via Special-Purpose IPv6 Ranges in Fast-Path Byte Check
**Vulnerability:** In `python-worker/server.py`, the fast-path byte inspection in `_is_restricted_ipv6_bytes` omitted checks for special-purpose IPv6 ranges: discard-only (`100::/64`, RFC 6666), local-use IPv4/IPv6 translation (`64:ff9b:1::/48`, RFC 8215), benchmarking (`2001:2::/48`, RFC 5180), and AS112 direct delegation (`2001:10::/28`, RFC 7535). Because `socket.inet_pton(socket.AF_INET6)` succeeded, the function returned `False` immediately, bypassing subsequent standard library `ipaddress` validation and allowing SSRF attacks against non-routable or local translation addresses (CWE-918).
**Learning:** C-level `inet_pton` fast-paths that short-circuit before `ipaddress.ip_address(ip_base)` must exhaustively inspect all IANA special-purpose prefixes, or non-global addresses will be falsely reported as unrestricted public IPs.
**Prevention:** Inspect binary prefix bytes for `64:ff9b:1::/48`, `100::/64`, `2001:2::/48`, and `2001:10::/28` directly in `_is_restricted_ipv6_bytes`.

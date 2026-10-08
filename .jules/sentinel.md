# Sentinel Security Journal 🛡️

## Security Assessment & Learnings

### Repository Status
- Application code present in `python-worker/` and `go-metacore/`.

## 2026-03-30 - SSRF Filter Bypass via Alternative IPv4 Notations
**Vulnerability:** `is_private_ip` in Python worker relied solely on `ipaddress.ip_address()`, which fails with `ValueError` on alternative IPv4 formats (decimal integers like `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, and shorthand `127.1`) as well as bracketed IPv6 addresses `[::1]`, returning `False` and bypassing SSRF private IP restrictions.
**Learning:** Standard library `ipaddress.ip_address()` strictly parses standard dotted-quad IPv4 strings or integer values, but when passed string representations of decimal/hex/octal IPs, it throws `ValueError` while underlying OS/socket functions resolve them to loopback or private IPs.
**Prevention:** Always strip brackets/scope IDs and use `socket.inet_aton` fallback to normalize string representations of alternative IPv4 formats into packed bytes before checking IP ranges.

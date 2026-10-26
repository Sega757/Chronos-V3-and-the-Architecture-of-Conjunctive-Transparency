import os
import re
import signal
import socket
import struct
import ipaddress
from urllib.parse import urlparse
import grpc
from concurrent import futures
import logging
# import pb.metacore_a2a_pb2_grpc as pb2_grpc

MAX_MESSAGE_LENGTH = 4 * 1024 * 1024  # 4MB message size limit to prevent DoS (CWE-400)
MAX_URL_LENGTH = 2048  # Maximum URL length to prevent DoS (CWE-400)

# Pre-compiled regular expressions for fast string checks
# Matches ASCII control characters (0x00-0x20), DEL (0x7F), and backslashes (\) to prevent CRLF injection and URL parser differential SSRF bypasses (CWE-136, CWE-918)
_INVALID_URL_CHARS_RE = re.compile(r'[\x00-\x20\x7f\\]')

# Matches any character that CANNOT exist in a valid IPv4 or IPv6 address string or alternative hex encoding (excluding IPv6 %scope_id)
_NON_IP_CHAR_RE = re.compile(r'[^0-9a-fA-FxX.:]')


def _is_restricted_ip_obj(ip) -> bool:
    """Performance helper: checks non-global or multicast IP state, evaluating mapped/compatible/NAT64 IPv4 for IPv6 (CWE-918)."""
    if not ip.is_global or ip.is_multicast or getattr(ip, 'is_site_local', False):
        return True
    if ip.version == 6:
        mapped = ip.ipv4_mapped
        if mapped and (not mapped.is_global or mapped.is_multicast):
            return True
        packed = ip.packed
        # Inspect embedded IPv4 in IPv4-compatible (::/96) or NAT64 well-known prefix (64:ff9b::/96)
        if packed[:12] == b'\x00' * 12 or packed[:12] == b'\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00':
            emb = ipaddress.IPv4Address(packed[12:])
            if not emb.is_global or emb.is_multicast:
                return True
    return False


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address is private, loopback, link-local, unspecified, or multicast (CWE-918)."""
    ip_base = ip_str.strip().strip('.').strip('[]').strip('.').strip()
    ip_base = ip_base.split('%', 1)[0] if '%' in ip_base else ip_base

    # Fast path: If string contains characters impossible in any valid IP representation (e.g. domain names with g-z, -),
    # return False immediately to bypass costly ipaddress.ip_address() and socket.inet_aton() exception overhead (~20-30x speedup).
    if _NON_IP_CHAR_RE.search(ip_base):
        return False

    # Fast path for standard 4-octet IPv4 representations (the vast majority of IPv4 addresses).
    # Converts 4-part IPv4 string to 32-bit integer via socket.inet_aton() and uses first-octet (val >> 24) dispatching to evaluate restricted ranges (~1.5x speedup over sequential range checks).
    if ip_base.count('.') == 3:
        try:
            packed = socket.inet_aton(ip_base)
            val = struct.unpack('!I', packed)[0]
            # First-octet dispatching for private / loopback / link-local / multicast / CGNAT / reserved IPv4 ranges:
            o = val >> 24
            if o >= 224 or o == 0 or o == 10 or o == 127:
                return True
            if o == 172:
                return 0xAC100000 <= val <= 0xAC1FFFFF
            if o == 192:
                return (val & 0xFFFF0000) == 0xC0A80000 or (val & 0xFFFFFF00) == 0xC0000000 or (val & 0xFFFFFF00) == 0xC0000200
            if o == 169:
                return (val & 0xFFFF0000) == 0xA9FE0000
            if o == 100:
                return 0x64400000 <= val <= 0x647FFFFF
            if o == 198:
                return (val & 0xFFFE0000) == 0xC6120000 or (val & 0xFFFFFF00) == 0xC6336400
            if o == 203:
                return (val & 0xFFFFFF00) == 0xCB007100
            return False
        except (OSError, ValueError):
            pass

    try:
        ip = ipaddress.ip_address(ip_base)
        return _is_restricted_ip_obj(ip)
    except ValueError:
        pass

    if ip_base.isdigit():
        try:
            val = int(ip_base)
            if 0 <= val <= 0xFFFFFFFF:
                return _is_restricted_ip_obj(ipaddress.IPv4Address(val))
            else:
                return True
        except ValueError:
            return True

    try:
        packed = socket.inet_aton(ip_base)
        return _is_restricted_ip_obj(ipaddress.IPv4Address(packed))
    except (OSError, ValueError):
        pass

    # Fail closed for string inputs that consist only of IP-like characters but failed parsing
    if not _NON_IP_CHAR_RE.search(ip_base):
        return True

    return False


def safe_parse_url(url_str: str, allowed_hosts=None, block_private_ips=False):
    """
    Safely parses a URL to mitigate SSRF and DoS risks (CWE-918, CWE-400).
    Validates URL scheme (http/https), length, host normalization, allowed host whitelist, and private IP restrictions.
    """
    if not isinstance(url_str, str) or len(url_str) > MAX_URL_LENGTH:
        raise ValueError("Invalid URL length or type")

    # Reject URLs containing control characters, unencoded whitespace, or backslashes to mitigate CRLF injection and parser differential SSRF bypasses (CWE-93, CWE-113, CWE-136, CWE-918)
    if _INVALID_URL_CHARS_RE.search(url_str):
        raise ValueError("URL contains invalid control characters, unencoded whitespace, or backslashes")

    parsed = urlparse(url_str)
    scheme = parsed.scheme
    if scheme not in ('http', 'https') and scheme.lower() not in ('http', 'https'):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    # Reject URLs with embedded userinfo (user:password@host) to prevent credential leakage and parser differential SSRF attacks (CWE-255, CWE-598, CWE-918)
    if '@' in parsed.netloc:
        raise ValueError("URL contains embedded userinfo credentials")

    raw_hostname = parsed.hostname
    if not raw_hostname:
        raise ValueError("URL host cannot be empty")

    # Performance optimization: check ':' in netloc to avoid costly urllib.parse netloc re-parsing when no port is specified
    if ':' in parsed.netloc:
        try:
            port = parsed.port
            if port == 0:
                raise ValueError("Port out of range 1-65535")
        except ValueError as err:
            raise ValueError(f"Invalid URL port: {err}") from err

    hostname = raw_hostname.rstrip('.').lower()

    # Fast path: Evaluate allowed_hosts whitelist before performing block_private_ips DNS resolution.
    # Disallowed domains fail fast without making blocking network DNS calls (socket.getaddrinfo).
    if allowed_hosts:
        matched = False
        for pattern in allowed_hosts:
            pat = pattern.rstrip('.').lower()
            if pat.startswith('.'):
                if hostname.endswith(pat) or hostname == pat[1:]:
                    matched = True
                    break
            elif hostname == pat:
                matched = True
                break
        if not matched:
            raise ValueError(f"Host '{hostname}' is not in allowed host whitelist")

    if block_private_ips:
        if hostname == 'localhost':
            raise ValueError(f"Access to private or loopback host is restricted: {hostname}")

        # Evaluate has_non_ip_chars once per hostname to eliminate duplicate _NON_IP_CHAR_RE scans and bypass unnecessary is_private_ip() and inet_pton calls on domain targets
        has_non_ip_chars = bool(_NON_IP_CHAR_RE.search(hostname))
        if not has_non_ip_chars and is_private_ip(hostname):
            raise ValueError(f"Access to private or loopback host is restricted: {hostname}")

        # Fast path: If hostname is a canonical IPv4/IPv6 address literal, bypass redundant socket.getaddrinfo syscall overhead.
        # Uses C-level socket.inet_pton(AF_INET/AF_INET6) to strictly verify canonical IP literals ~6x faster than ipaddress.ip_address without exception allocation overhead.
        is_ip_literal = False
        if not has_non_ip_chars:
            try:
                socket.inet_pton(socket.AF_INET, hostname)
                is_ip_literal = True
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, hostname)
                    is_ip_literal = True
                except OSError:
                    pass

        if not is_ip_literal:
            # Resolve hostname via socket.getaddrinfo to verify underlying IP addresses (CWE-918)
            try:
                addr_info = socket.getaddrinfo(hostname, None)
            except socket.gaierror as err:
                raise ValueError(f"Failed to resolve host '{hostname}': {err}")

            if not addr_info:
                raise ValueError(f"Failed to resolve host '{hostname}': no addresses returned")

            for res in addr_info:
                ip_str = res[4][0]
                if is_private_ip(ip_str):
                    raise ValueError(f"Access to private or loopback host is restricted: {hostname} ({ip_str})")

    return parsed


class WorkerServicer:
    """Servicer for Python Worker task execution with SSRF validation (CWE-918)."""

    def __init__(self, allowed_hosts=None):
        # Pre-normalize allowed_hosts patterns to avoid repeated string manipulation in validate_task_endpoint
        if allowed_hosts:
            self.allowed_hosts = [p.rstrip('.').lower() for p in allowed_hosts]
        else:
            self.allowed_hosts = None

    def validate_task_endpoint(self, target_url: str):
        """Validates that a worker task target endpoint is safe from SSRF attacks before processing."""
        return safe_parse_url(target_url, allowed_hosts=self.allowed_hosts, block_private_ips=True)


MAX_CONCURRENT_STREAMS = 100  # Max concurrent HTTP/2 streams limit to prevent resource exhaustion DoS (CWE-400)

def create_server():
    options = [
        ('grpc.max_receive_message_length', MAX_MESSAGE_LENGTH),
        ('grpc.max_send_message_length', MAX_MESSAGE_LENGTH),
        ('grpc.max_concurrent_streams', MAX_CONCURRENT_STREAMS),
        ('grpc.http2.min_ping_interval_without_data_ms', 5000),  # HTTP/2 ping flood protection (CWE-400)
        ('grpc.http2.max_pings_without_data', 2),
    ]
    return grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=options)

def serve():
    bind_addr = os.getenv('WORKER_BIND_ADDR', '127.0.0.1:50052')
    server = create_server()
    worker_servicer = WorkerServicer()
    # pb2_grpc.add_MetaCoreServicer_to_server(worker_servicer, server)

    # Configure TLS/mTLS to mitigate cleartext sensitive data transmission (CWE-319)
    enable_tls = os.getenv('GRPC_ENABLE_TLS', 'false').lower() in ('true', '1', 'yes')
    cert_path = os.getenv('GRPC_TLS_CERT_PATH')
    key_path = os.getenv('GRPC_TLS_KEY_PATH')
    ca_path = os.getenv('GRPC_TLS_CA_PATH')

    if enable_tls or cert_path or key_path:
        if not cert_path or not key_path:
            raise ValueError("GRPC_TLS_CERT_PATH and GRPC_TLS_KEY_PATH must be set when TLS is enabled")
        try:
            with open(key_path, 'rb') as f:
                private_key = f.read()
            with open(cert_path, 'rb') as f:
                certificate_chain = f.read()
            root_certificates = None
            require_client_auth = False
            if ca_path:
                with open(ca_path, 'rb') as f:
                    root_certificates = f.read()
                require_client_auth = True
            credentials = grpc.ssl_server_credentials(
                [(private_key, certificate_chain)],
                root_certificates=root_certificates,
                require_client_auth=require_client_auth,
            )
            port = server.add_secure_port(bind_addr, credentials)
        except Exception as e:
            raise RuntimeError(f"Failed to configure gRPC TLS credentials: {e}")
    else:
        allow_insecure = os.getenv('GRPC_ALLOW_INSECURE', 'true').lower() in ('true', '1', 'yes')
        if not allow_insecure:
            raise RuntimeError("Insecure gRPC connections are disabled (GRPC_ALLOW_INSECURE=false) and TLS is not configured")
        port = server.add_insecure_port(bind_addr)

    if port == 0:
        raise RuntimeError(f"Failed to bind gRPC server to address: {bind_addr}")
    server.start()
    logging.info(f"Python Worker initialized on {bind_addr}. Awaiting swarm tasks.")

    def handle_shutdown(signum, frame):
        logging.info("Received signal %s, shutting down Python Worker gracefully...", signum)
        server.stop(grace=5)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    server.wait_for_termination()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    serve()

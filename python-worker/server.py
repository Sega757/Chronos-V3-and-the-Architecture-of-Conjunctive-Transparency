import os
import re
import signal
import ipaddress
from urllib.parse import urlparse
import grpc
from concurrent import futures
import logging
# import pb.metacore_a2a_pb2_grpc as pb2_grpc

MAX_MESSAGE_LENGTH = 4 * 1024 * 1024  # 4MB message size limit to prevent DoS (CWE-400)
MAX_URL_LENGTH = 2048  # Maximum URL length to prevent DoS (CWE-400)

# Pre-compiled regular expressions for fast string checks
# Matches ASCII control characters (0x00-0x20) and DEL (0x7F) for CRLF injection prevention (~10x faster than generator expression)
_INVALID_URL_CHARS_RE = re.compile(r'[\x00-\x20\x7f]')

# Matches any character that CANNOT exist in a valid IPv4 or IPv6 address string (excluding IPv6 %scope_id)
_NON_IP_CHAR_RE = re.compile(r'[^0-9a-fA-F.:]')


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address is private, loopback, link-local, unspecified, or multicast (CWE-918)."""
    # Fast path: strip optional IPv6 %scope_id before checking IP character set.
    # If string contains characters outside valid IPv4/IPv6 character sets, skip expensive ipaddress parsing & exception handling (~16x speedup on domain names).
    ip_base = ip_str.split('%', 1)[0] if '%' in ip_str else ip_str
    if _NON_IP_CHAR_RE.search(ip_base):
        return False

    try:
        ip = ipaddress.ip_address(ip_base)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def safe_parse_url(url_str: str, allowed_hosts=None, block_private_ips=False):
    """
    Safely parses a URL to mitigate SSRF and DoS risks (CWE-918, CWE-400).
    Validates URL scheme (http/https), length, host normalization, allowed host whitelist, and private IP restrictions.
    """
    if not isinstance(url_str, str) or len(url_str) > MAX_URL_LENGTH:
        raise ValueError("Invalid URL length or type")

    # Reject URLs containing control characters or unencoded whitespace to mitigate CRLF injection and HTTP response splitting (CWE-93, CWE-113, CWE-158)
    if _INVALID_URL_CHARS_RE.search(url_str):
        raise ValueError("URL contains invalid control characters or unencoded whitespace")

    parsed = urlparse(url_str)
    if parsed.scheme.lower() not in ('http', 'https'):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    if not parsed.hostname:
        raise ValueError("URL host cannot be empty")

    hostname = parsed.hostname.rstrip('.').lower()

    if block_private_ips:
        if hostname == 'localhost' or is_private_ip(hostname):
            raise ValueError(f"Access to private or loopback host is restricted: {hostname}")

    if allowed_hosts:
        matched = False
        for pattern in allowed_hosts:
            pattern = pattern.rstrip('.').lower()
            if pattern.startswith('.'):
                if hostname.endswith(pattern) or hostname == pattern[1:]:
                    matched = True
                    break
            elif hostname == pattern:
                matched = True
                break
        if not matched:
            raise ValueError(f"Host '{hostname}' is not in allowed host whitelist")

    return parsed


class WorkerServicer:
    """Servicer for Python Worker task execution with SSRF validation (CWE-918)."""

    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = allowed_hosts

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

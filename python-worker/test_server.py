import socket
import unittest
from unittest.mock import patch
from server import (
    create_server,
    MAX_MESSAGE_LENGTH,
    MAX_CONCURRENT_STREAMS,
    safe_parse_url,
    is_private_ip,
    parse_canonical_ip,
    WorkerServicer,
)


class TestWorkerServer(unittest.TestCase):
    def test_max_message_length_constant(self):
        self.assertEqual(MAX_MESSAGE_LENGTH, 4 * 1024 * 1024)

    def test_max_concurrent_streams_constant(self):
        self.assertEqual(MAX_CONCURRENT_STREAMS, 100)

    def test_create_server_returns_grpc_server(self):
        server = create_server()
        self.assertIsNotNone(server)

    def test_serve_raises_runtime_error_on_bind_failure(self):
        from unittest.mock import MagicMock
        from server import serve

        mock_server = MagicMock()
        mock_server.add_insecure_port.return_value = 0

        with patch('server.create_server', return_value=mock_server):
            with self.assertRaises(RuntimeError) as ctx:
                serve()
            self.assertIn("Failed to bind gRPC server to address", str(ctx.exception))


class TestSSRFProtection(unittest.TestCase):
    def test_alternative_ipv4_formats(self):
        # Hex format: http://0x7f000001/ -> 127.0.0.1
        self.assertTrue(is_private_ip("0x7f000001"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://0x7f000001/", block_private_ips=True)

        # Decimal / Integer format: http://2130706433/ -> 127.0.0.1
        self.assertTrue(is_private_ip("2130706433"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://2130706433/", block_private_ips=True)

        # Octal notation: http://0177.0.0.1/ -> 127.0.0.1
        self.assertTrue(is_private_ip("0177.0.0.1"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://0177.0.0.1/", block_private_ips=True)

        # Mixed octal / decimal: http://10.0.0.1 vs http://012.0.0.1 -> 10.0.0.1
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("012.0.0.1"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://012.0.0.1/", block_private_ips=True)

    def test_loopback_and_private_ipv6(self):
        # ::1 loopback
        self.assertTrue(is_private_ip("::1"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://[::1]/", block_private_ips=True)

        # Unique local IPv6 fc00::1
        self.assertTrue(is_private_ip("fc00::1"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://[fc00::1]/", block_private_ips=True)

        # IPv4-mapped IPv6 ::ffff:127.0.0.1
        self.assertTrue(is_private_ip("::ffff:127.0.0.1"))
        with self.assertRaises(ValueError):
            safe_parse_url("http://[::ffff:127.0.0.1]/", block_private_ips=True)

    @patch("socket.getaddrinfo")
    def test_dns_rebinding_and_internal_hostnames(self, mock_getaddrinfo):
        # Mock external domain resolving to private IP 192.168.1.1
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80))
        ]
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("http://rebinding.evil.com/data", block_private_ips=True)
        self.assertIn("resolves to restricted IP", str(ctx.exception))

        # Mock external domain resolving to 127.0.0.1
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
        ]
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("http://local.evil.com/data", block_private_ips=True)
        self.assertIn("resolves to restricted IP", str(ctx.exception))

    @patch("socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("http://non-existent-domain-xyz123.com/", block_private_ips=True)
        self.assertIn("Failed to resolve host", str(ctx.exception))

    @patch("socket.getaddrinfo")
    def test_legitimate_public_targets(self, mock_getaddrinfo):
        # Public IP literal
        parsed_ip = safe_parse_url("http://8.8.8.8/", block_private_ips=True)
        self.assertEqual(parsed_ip.hostname, "8.8.8.8")

        # Mocked public domain resolving to 93.184.216.34
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
        ]
        parsed_domain = safe_parse_url("https://example.com/api", block_private_ips=True)
        self.assertEqual(parsed_domain.hostname, "example.com")


class TestSafeParseUrl(unittest.TestCase):
    def test_valid_urls(self):
        parsed = safe_parse_url("https://example.com/api/v1")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "example.com")

    def test_unsupported_schemes(self):
        for invalid_url in ["file:///etc/passwd", "gopher://evil.com", "ftp://example.com"]:
            with self.assertRaises(ValueError) as ctx:
                safe_parse_url(invalid_url)
            self.assertIn("Unsupported URL scheme", str(ctx.exception))

    def test_exceeding_max_url_length(self):
        long_url = "https://example.com/" + "a" * 2050
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url(long_url)
        self.assertIn("Invalid URL length or type", str(ctx.exception))

    def test_reject_control_characters_and_crlf(self):
        invalid_urls = [
            "https://example.com/api\r\nSet-Cookie: admin=1",
            "https://example.com/api\nHeader: value",
            "https://example.com/api\0nullbyte",
            "https://example.com/path with spaces",
            "https://example.com/path\twithtab",
        ]
        for url in invalid_urls:
            with self.assertRaises(ValueError) as ctx:
                safe_parse_url(url)
            self.assertIn("invalid control characters or unencoded whitespace", str(ctx.exception))

    def test_block_private_ips_and_localhost(self):
        private_hosts = ["http://127.0.0.1/admin", "http://localhost/admin", "http://10.0.0.1/internal", "http://169.254.169.254/metadata"]
        for url in private_hosts:
            with self.assertRaises(ValueError) as ctx:
                safe_parse_url(url, block_private_ips=True)
            self.assertIn("Access to private or loopback host is restricted", str(ctx.exception))

    def test_allowed_hosts_whitelist(self):
        self.assertIsNotNone(safe_parse_url("https://api.example.com", allowed_hosts=[".example.com"]))
        self.assertIsNotNone(safe_parse_url("https://example.com", allowed_hosts=["example.com"]))

    def test_disallowed_host_rejection(self):
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("https://evil.com/callback", allowed_hosts=["example.com", ".example.org"])
        self.assertIn("not in allowed host whitelist", str(ctx.exception))

    def test_is_private_ip(self):
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("::1"))
        self.assertTrue(is_private_ip("fe80::1%eth0"))
        self.assertTrue(is_private_ip("fe80::1%wlan0"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("not-an-ip"))
        self.assertFalse(is_private_ip("api.example.com"))

    @patch("socket.getaddrinfo")
    def test_worker_servicer_validate_task_endpoint(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        servicer = WorkerServicer(allowed_hosts=[".example.com"])
        parsed = servicer.validate_task_endpoint("https://api.example.com/task")
        self.assertEqual(parsed.hostname, "api.example.com")

        with self.assertRaises(ValueError):
            servicer.validate_task_endpoint("http://127.0.0.1/internal")


if __name__ == '__main__':
    unittest.main()

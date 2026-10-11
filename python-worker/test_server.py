import unittest
import socket
from unittest.mock import patch, MagicMock
from server import (
    create_server,
    MAX_MESSAGE_LENGTH,
    MAX_CONCURRENT_STREAMS,
    safe_parse_url,
    is_private_ip,
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
        mock_server = MagicMock()
        mock_server.add_insecure_port.return_value = 0

        with patch('server.create_server', return_value=mock_server):
            from server import serve
            with self.assertRaises(RuntimeError) as ctx:
                serve()
            self.assertIn("Failed to bind gRPC server to address", str(ctx.exception))

    @patch('os.getenv')
    def test_serve_missing_tls_cert_and_key_raises_value_error(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            'GRPC_ENABLE_TLS': 'true',
            'GRPC_TLS_CERT_PATH': None,
            'GRPC_TLS_KEY_PATH': None,
        }.get(key, default)

        from server import serve
        with self.assertRaises(ValueError) as ctx:
            serve()
        self.assertIn("GRPC_TLS_CERT_PATH and GRPC_TLS_KEY_PATH must be set", str(ctx.exception))

    @patch('os.getenv')
    def test_serve_disallowed_insecure_mode_raises_runtime_error(self, mock_getenv):
        mock_getenv.side_effect = lambda key, default=None: {
            'GRPC_ENABLE_TLS': 'false',
            'GRPC_ALLOW_INSECURE': 'false',
        }.get(key, default)

        from server import serve
        with self.assertRaises(RuntimeError) as ctx:
            serve()
        self.assertIn("Insecure gRPC connections are disabled", str(ctx.exception))

    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data=b'fake_cert_data')
    @patch('grpc.ssl_server_credentials')
    @patch('os.getenv')
    def test_serve_secure_port_tls_configuration(self, mock_getenv, mock_ssl_creds, mock_file):
        mock_getenv.side_effect = lambda key, default=None: {
            'WORKER_BIND_ADDR': '127.0.0.1:50052',
            'GRPC_ENABLE_TLS': 'true',
            'GRPC_TLS_CERT_PATH': '/path/to/cert.pem',
            'GRPC_TLS_KEY_PATH': '/path/to/key.pem',
            'GRPC_TLS_CA_PATH': '/path/to/ca.pem',
        }.get(key, default)

        mock_server = MagicMock()
        mock_server.add_secure_port.return_value = 50052

        with patch('server.create_server', return_value=mock_server):
            from server import serve
            mock_server.wait_for_termination.side_effect = KeyboardInterrupt
            try:
                serve()
            except KeyboardInterrupt:
                pass
            mock_server.add_secure_port.assert_called_once()
            mock_ssl_creds.assert_called_once()


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

    def test_empty_url_host(self):
        empty_host_urls = [
            "http:///path",
            "http://",
            "https://",
            "http:///foo/bar",
            "http://:8000",
        ]
        for url in empty_host_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError) as ctx:
                    safe_parse_url(url)
                self.assertEqual(str(ctx.exception), "URL host cannot be empty")

    def test_invalid_url_port(self):
        invalid_port_urls = [
            "http://example.com:70000/path",
            "http://example.com:abc/path",
            "http://example.com:-1/path",
        ]
        for url in invalid_port_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError) as ctx:
                    safe_parse_url(url)
                self.assertIn("Invalid URL port", str(ctx.exception))

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
            "https://allowed.com\\@evil.com",
            "https://allowed.com\\evil.com",
            "https://example.com/path\\file",
        ]
        for url in invalid_urls:
            with self.assertRaises(ValueError) as ctx:
                safe_parse_url(url)
            self.assertIn("invalid control characters, unencoded whitespace, or backslashes", str(ctx.exception))

    def test_block_private_ips_and_localhost(self):
        private_hosts = [
            "http://127.0.0.1/admin",
            "http://localhost/admin",
            "http://10.0.0.1/internal",
            "http://169.254.169.254/metadata",
            "http://0x7f000001/admin",
            "http://0177.0.0.1/admin",
            "http://2130706433/admin",
            "http://0/admin",
        ]
        for url in private_hosts:
            with self.assertRaises(ValueError) as ctx:
                safe_parse_url(url, block_private_ips=True)
            self.assertIn("Access to private or loopback host is restricted", str(ctx.exception))

    @patch("socket.getaddrinfo")
    def test_dns_resolution_private_ip_blocking(self, mock_getaddrinfo):
        # Case 1: Domain resolves to public IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))
        ]
        parsed = safe_parse_url("https://example.com/api", block_private_ips=True)
        self.assertEqual(parsed.hostname, "example.com")

        # Case 2: DNS rebinding - Domain resolves to private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))
        ]
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("https://rebind.internal/api", block_private_ips=True)
        self.assertIn("Access to private or loopback host is restricted", str(ctx.exception))

        # Case 3: Domain resolves to multiple IPs, one is private
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("https://multi-ip.example.com/api", block_private_ips=True)
        self.assertIn("Access to private or loopback host is restricted", str(ctx.exception))

    @patch("socket.getaddrinfo")
    def test_dns_resolution_failure_fails_closed(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror(-5, "No address associated with hostname")
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("https://nonexistent.domain.test/api", block_private_ips=True)
        self.assertIn("Failed to resolve host", str(ctx.exception))

    def test_allowed_hosts_whitelist(self):
        self.assertIsNotNone(safe_parse_url("https://api.example.com", allowed_hosts=[".example.com"]))
        self.assertIsNotNone(safe_parse_url("https://example.com", allowed_hosts=["example.com"]))

    def test_disallowed_host_rejection(self):
        with self.assertRaises(ValueError) as ctx:
            safe_parse_url("https://evil.com/callback", allowed_hosts=["example.com", ".example.org"])
        self.assertIn("not in allowed host whitelist", str(ctx.exception))

    def test_is_private_ip(self):
        # Standard IPv4 and IPv6
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("::1"))
        self.assertTrue(is_private_ip("fe80::1%eth0"))
        self.assertTrue(is_private_ip("fe80::1%wlan0"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("not-an-ip"))
        self.assertFalse(is_private_ip("api.example.com"))

        # Alternative IPv4 Encodings
        self.assertTrue(is_private_ip("0x7f000001"))  # Hex
        self.assertTrue(is_private_ip("0177.0.0.1"))  # Octal
        self.assertTrue(is_private_ip("2130706433"))  # Integer/Dword
        self.assertTrue(is_private_ip("127.1"))  # Shorthand
        self.assertTrue(is_private_ip("0x7f.0.0.1"))
        self.assertTrue(is_private_ip("0300.0250.0000.0001"))
        self.assertTrue(is_private_ip("0"))

        # Malformed IP representations (fail-closed)
        self.assertTrue(is_private_ip("999.999.999.999"))

        # IPv6 Mapped IPv4
        self.assertTrue(is_private_ip("::ffff:127.0.0.1"))
        self.assertTrue(is_private_ip("::ffff:10.0.0.1"))

    @patch("socket.getaddrinfo")
    def test_worker_servicer_validate_task_endpoint(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))
        ]
        servicer = WorkerServicer(allowed_hosts=[".example.com"])
        parsed = servicer.validate_task_endpoint("https://api.example.com/task")
        self.assertEqual(parsed.hostname, "api.example.com")

        with self.assertRaises(ValueError):
            servicer.validate_task_endpoint("http://127.0.0.1/internal")


if __name__ == '__main__':
    unittest.main()

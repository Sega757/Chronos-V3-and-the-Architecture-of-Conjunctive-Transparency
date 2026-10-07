import unittest
from server import create_server, MAX_MESSAGE_LENGTH, MAX_CONCURRENT_STREAMS, safe_parse_url, is_private_ip, WorkerServicer

class TestWorkerServer(unittest.TestCase):
    def test_max_message_length_constant(self):
        self.assertEqual(MAX_MESSAGE_LENGTH, 4 * 1024 * 1024)

    def test_max_concurrent_streams_constant(self):
        self.assertEqual(MAX_CONCURRENT_STREAMS, 100)

    def test_create_server_returns_grpc_server(self):
        server = create_server()
        self.assertIsNotNone(server)

    def test_serve_raises_runtime_error_on_bind_failure(self):
        from unittest.mock import patch, MagicMock
        from server import serve

        mock_server = MagicMock()
        mock_server.add_insecure_port.return_value = 0

        with patch('server.create_server', return_value=mock_server):
            with self.assertRaises(RuntimeError) as ctx:
                serve()
            self.assertIn("Failed to bind gRPC server to address", str(ctx.exception))

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
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("not-an-ip"))

    def test_worker_servicer_validate_task_endpoint(self):
        servicer = WorkerServicer(allowed_hosts=[".example.com"])
        parsed = servicer.validate_task_endpoint("https://api.example.com/task")
        self.assertEqual(parsed.hostname, "api.example.com")

        with self.assertRaises(ValueError):
            servicer.validate_task_endpoint("http://127.0.0.1/internal")

if __name__ == '__main__':
    unittest.main()

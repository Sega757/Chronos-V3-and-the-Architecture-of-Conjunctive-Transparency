import os
import tempfile
import unittest
import socket
import datetime
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import grpc
from server import (
    create_server,
    get_server_credentials,
    serve,
    MAX_MESSAGE_LENGTH,
    MAX_CONCURRENT_STREAMS,
    safe_parse_url,
    is_private_ip,
    WorkerServicer,
)


def generate_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class TestWorkerServer(unittest.TestCase):
    def test_max_message_length_constant(self):
        self.assertEqual(MAX_MESSAGE_LENGTH, 4 * 1024 * 1024)

    def test_max_concurrent_streams_constant(self):
        self.assertEqual(MAX_CONCURRENT_STREAMS, 100)

    def test_create_server_returns_grpc_server(self):
        server = create_server()
        self.assertIsNotNone(server)

    def test_get_server_credentials_success(self):
        cert_pem, key_pem = generate_self_signed_cert()
        with tempfile.NamedTemporaryFile(delete=False) as cert_file, tempfile.NamedTemporaryFile(delete=False) as key_file:
            cert_file.write(cert_pem)
            cert_file.flush()
            key_file.write(key_pem)
            key_file.flush()

            try:
                with patch.dict(os.environ, {
                    'GRPC_TLS_CERT_PATH': cert_file.name,
                    'GRPC_TLS_KEY_PATH': key_file.name,
                }):
                    creds = get_server_credentials()
                    self.assertIsInstance(creds, grpc.ServerCredentials)
            finally:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)

    def test_get_server_credentials_mtls(self):
        cert_pem, key_pem = generate_self_signed_cert()
        ca_pem, _ = generate_self_signed_cert()
        with tempfile.NamedTemporaryFile(delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(delete=False) as key_file, \
             tempfile.NamedTemporaryFile(delete=False) as ca_file:
            cert_file.write(cert_pem)
            cert_file.flush()
            key_file.write(key_pem)
            key_file.flush()
            ca_file.write(ca_pem)
            ca_file.flush()

            try:
                with patch.dict(os.environ, {
                    'GRPC_TLS_CERT_PATH': cert_file.name,
                    'GRPC_TLS_KEY_PATH': key_file.name,
                    'GRPC_TLS_CA_PATH': ca_file.name,
                }):
                    creds = get_server_credentials()
                    self.assertIsInstance(creds, grpc.ServerCredentials)
            finally:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)
                os.unlink(ca_file.name)

    def test_get_server_credentials_missing_env_vars(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                get_server_credentials()
            self.assertIn("TLS credentials missing", str(ctx.exception))

    def test_get_server_credentials_nonexistent_file(self):
        with patch.dict(os.environ, {
            'GRPC_TLS_CERT_PATH': '/nonexistent/cert.pem',
            'GRPC_TLS_KEY_PATH': '/nonexistent/key.pem',
        }):
            with self.assertRaises(RuntimeError) as ctx:
                get_server_credentials()
            self.assertIn("Failed to read gRPC TLS certificate file", str(ctx.exception))

    def test_serve_insecure_disabled_by_default(self):
        mock_server = MagicMock()
        with patch.dict(os.environ, {}, clear=True), patch('server.create_server', return_value=mock_server):
            with self.assertRaises(RuntimeError) as ctx:
                serve()
            self.assertIn("TLS credentials missing", str(ctx.exception))

    def test_serve_insecure_explicit_disable_tls_without_allow_insecure_fails(self):
        mock_server = MagicMock()
        with patch.dict(os.environ, {'GRPC_ENABLE_TLS': 'false'}, clear=True), patch('server.create_server', return_value=mock_server):
            with self.assertRaises(RuntimeError) as ctx:
                serve()
            self.assertIn("Insecure gRPC binding is disabled by default", str(ctx.exception))

    def test_serve_insecure_opt_in_success(self):
        mock_server = MagicMock()
        mock_server.add_insecure_port.return_value = 50052

        def stop_immediately(*args, **kwargs):
            mock_server.wait_for_termination.side_effect = None

        mock_server.start.side_effect = stop_immediately

        with patch.dict(os.environ, {'GRPC_ALLOW_INSECURE': 'true'}, clear=True), \
             patch('server.create_server', return_value=mock_server):
            serve()
            mock_server.add_insecure_port.assert_called_once_with('127.0.0.1:50052')
            mock_server.start.assert_called_once()

    def test_serve_secure_mode_with_certs(self):
        cert_pem, key_pem = generate_self_signed_cert()
        with tempfile.NamedTemporaryFile(delete=False) as cert_file, tempfile.NamedTemporaryFile(delete=False) as key_file:
            cert_file.write(cert_pem)
            cert_file.flush()
            key_file.write(key_pem)
            key_file.flush()

            mock_server = MagicMock()
            mock_server.add_secure_port.return_value = 50052

            def stop_immediately(*args, **kwargs):
                mock_server.wait_for_termination.side_effect = None

            mock_server.start.side_effect = stop_immediately

            try:
                with patch.dict(os.environ, {
                    'GRPC_TLS_CERT_PATH': cert_file.name,
                    'GRPC_TLS_KEY_PATH': key_file.name,
                }, clear=True), patch('server.create_server', return_value=mock_server):
                    serve()
                    mock_server.add_secure_port.assert_called_once()
                    mock_server.start.assert_called_once()
            finally:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)

    def test_serve_raises_runtime_error_on_bind_failure(self):
        mock_server = MagicMock()
        mock_server.add_insecure_port.return_value = 0

        with patch.dict(os.environ, {'GRPC_ALLOW_INSECURE': 'true'}), patch('server.create_server', return_value=mock_server):
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

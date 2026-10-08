import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import grpc

from server import create_server, configure_server_port, serve, MAX_MESSAGE_LENGTH, MAX_CONCURRENT_STREAMS, safe_parse_url, is_private_ip, WorkerServicer


def generate_self_signed_cert():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


class TestTlsConfiguration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_pem, self.cert_pem = generate_self_signed_cert()

        self.key_path = os.path.join(self.temp_dir.name, "server.key")
        self.cert_path = os.path.join(self.temp_dir.name, "server.crt")
        self.ca_path = os.path.join(self.temp_dir.name, "ca.crt")

        with open(self.key_path, "wb") as f:
            f.write(self.key_pem)
        with open(self.cert_path, "wb") as f:
            f.write(self.cert_pem)
        with open(self.ca_path, "wb") as f:
            f.write(self.cert_pem)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_configure_server_port_secure_success(self):
        env = {
            "GRPC_ENABLE_TLS": "true",
            "GRPC_TLS_CERT_PATH": self.cert_path,
            "GRPC_TLS_KEY_PATH": self.key_path,
        }
        with patch.dict(os.environ, env, clear=True):
            server = create_server()
            port = configure_server_port(server, "127.0.0.1:0")
            self.assertGreater(port, 0)
            server.stop(0)

    def test_configure_server_port_mtls_success(self):
        env = {
            "GRPC_ENABLE_TLS": "true",
            "GRPC_TLS_CERT_PATH": self.cert_path,
            "GRPC_TLS_KEY_PATH": self.key_path,
            "GRPC_TLS_CA_PATH": self.ca_path,
        }
        with patch.dict(os.environ, env, clear=True):
            server = create_server()
            port = configure_server_port(server, "127.0.0.1:0")
            self.assertGreater(port, 0)
            server.stop(0)

    def test_configure_server_port_missing_certs_fails_fast(self):
        env = {
            "GRPC_ENABLE_TLS": "true",
            "GRPC_TLS_CERT_PATH": "",
            "GRPC_TLS_KEY_PATH": "",
            "GRPC_ALLOW_INSECURE": "false",
        }
        with patch.dict(os.environ, env, clear=True):
            server = MagicMock()
            with self.assertRaises(RuntimeError) as ctx:
                configure_server_port(server, "127.0.0.1:50052")
            self.assertIn("TLS configuration error", str(ctx.exception))

    def test_configure_server_port_nonexistent_cert_file_fails(self):
        env = {
            "GRPC_ENABLE_TLS": "true",
            "GRPC_TLS_CERT_PATH": "/nonexistent/cert.pem",
            "GRPC_TLS_KEY_PATH": self.key_path,
        }
        with patch.dict(os.environ, env, clear=True):
            server = MagicMock()
            with self.assertRaises(RuntimeError) as ctx:
                configure_server_port(server, "127.0.0.1:50052")
            self.assertIn("TLS certificate file not found", str(ctx.exception))

    def test_configure_server_port_insecure_allowed(self):
        env = {
            "GRPC_ENABLE_TLS": "false",
            "GRPC_ALLOW_INSECURE": "true",
        }
        with patch.dict(os.environ, env, clear=True):
            mock_server = MagicMock()
            mock_server.add_insecure_port.return_value = 50052
            port = configure_server_port(mock_server, "127.0.0.1:50052")
            self.assertEqual(port, 50052)
            mock_server.add_insecure_port.assert_called_once_with("127.0.0.1:50052")

    def test_configure_server_port_fallback_when_certs_missing_and_insecure_allowed(self):
        env = {
            "GRPC_ENABLE_TLS": "true",
            "GRPC_ALLOW_INSECURE": "true",
        }
        with patch.dict(os.environ, env, clear=True):
            mock_server = MagicMock()
            mock_server.add_insecure_port.return_value = 50052
            port = configure_server_port(mock_server, "127.0.0.1:50052")
            self.assertEqual(port, 50052)
            mock_server.add_insecure_port.assert_called_once_with("127.0.0.1:50052")

    def test_secure_grpc_channel_communication(self):
        env = {
            "GRPC_ENABLE_TLS": "true",
            "GRPC_TLS_CERT_PATH": self.cert_path,
            "GRPC_TLS_KEY_PATH": self.key_path,
        }
        with patch.dict(os.environ, env, clear=True):
            server = create_server()
            port = configure_server_port(server, "127.0.0.1:0")
            server.start()

            client_credentials = grpc.ssl_channel_credentials(root_certificates=self.cert_pem)
            channel_options = (('grpc.ssl_target_name_override', 'localhost'),)
            channel = grpc.secure_channel(f"127.0.0.1:{port}", client_credentials, options=channel_options)

            # Test channel connectivity
            try:
                grpc.channel_ready_future(channel).result(timeout=3)
                connected = True
            except Exception:
                connected = False

            channel.close()
            server.stop(0)
            self.assertTrue(connected)


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
            with patch.dict(os.environ, {"GRPC_ALLOW_INSECURE": "true"}, clear=True):
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
        self.assertTrue(is_private_ip("fe80::1%eth0"))
        self.assertTrue(is_private_ip("fe80::1%wlan0"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("not-an-ip"))
        self.assertFalse(is_private_ip("api.example.com"))

    def test_worker_servicer_validate_task_endpoint(self):
        servicer = WorkerServicer(allowed_hosts=[".example.com"])
        parsed = servicer.validate_task_endpoint("https://api.example.com/task")
        self.assertEqual(parsed.hostname, "api.example.com")

        with self.assertRaises(ValueError):
            servicer.validate_task_endpoint("http://127.0.0.1/internal")


if __name__ == '__main__':
    unittest.main()

import unittest
from server import create_server, MAX_MESSAGE_LENGTH, MAX_CONCURRENT_STREAMS

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

if __name__ == '__main__':
    unittest.main()

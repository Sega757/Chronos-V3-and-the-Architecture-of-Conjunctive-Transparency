import unittest
from server import create_server, MAX_MESSAGE_LENGTH

class TestWorkerServer(unittest.TestCase):
    def test_max_message_length_constant(self):
        self.assertEqual(MAX_MESSAGE_LENGTH, 4 * 1024 * 1024)

    def test_create_server_returns_grpc_server(self):
        server = create_server()
        self.assertIsNotNone(server)

if __name__ == '__main__':
    unittest.main()

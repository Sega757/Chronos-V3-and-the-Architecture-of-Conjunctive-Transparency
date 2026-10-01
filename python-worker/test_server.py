import unittest
from unittest.mock import patch, MagicMock
import signal
import sys
import os

# Add directory to sys.path if needed
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from server import create_server, serve, MAX_MESSAGE_LENGTH


class TestServerSecurity(unittest.TestCase):

    def test_create_server_has_max_message_length_options(self):
        with patch('grpc.server') as mock_grpc_server:
            create_server()
            mock_grpc_server.assert_called_once()
            _, kwargs = mock_grpc_server.call_args
            options = kwargs.get('options', [])
            expected_options = [
                ('grpc.max_receive_message_length', MAX_MESSAGE_LENGTH),
                ('grpc.max_send_message_length', MAX_MESSAGE_LENGTH),
            ]
            self.assertEqual(options, expected_options)
            self.assertEqual(MAX_MESSAGE_LENGTH, 4 * 1024 * 1024)

    @patch('signal.signal')
    @patch('server.create_server')
    def test_serve_registers_signal_handlers(self, mock_create_server, mock_signal):
        mock_server = MagicMock()
        mock_create_server.return_value = mock_server

        serve()

        mock_server.add_insecure_port.assert_called_once_with('127.0.0.1:50052')
        mock_server.start.assert_called_once()
        mock_server.wait_for_termination.assert_called_once()

        # Check signal registration for SIGINT and SIGTERM
        registered_signals = [call[0][0] for call in mock_signal.call_args_list]
        self.assertIn(signal.SIGINT, registered_signals)
        self.assertIn(signal.SIGTERM, registered_signals)


if __name__ == '__main__':
    unittest.main()

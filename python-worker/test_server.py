import unittest
from unittest.mock import MagicMock, patch
import signal
import sys
import os

# Add python-worker directory to path if needed
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Mock grpc if not installed in environment
try:
    import grpc
except ImportError:
    grpc = MagicMock()
    sys.modules['grpc'] = grpc

import server

class TestWorkerServer(unittest.TestCase):
    @patch('server.grpc.server')
    @patch('server.signal.signal')
    def test_serve_registers_signals_and_starts_server(self, mock_signal, mock_grpc_server):
        mock_server_instance = MagicMock()
        mock_grpc_server.return_value = mock_server_instance

        # Call serve and check mock server interactions
        server.serve()

        mock_grpc_server.assert_called_once()
        mock_server_instance.add_insecure_port.assert_called_once_with('127.0.0.1:50052')
        mock_server_instance.start.assert_called_once()
        mock_server_instance.wait_for_termination.assert_called_once()

        # Check signal registration
        signal_calls = mock_signal.call_args_list
        signals_registered = [call[0][0] for call in signal_calls]
        self.assertIn(signal.SIGINT, signals_registered)
        self.assertIn(signal.SIGTERM, signals_registered)

        # Find the handler passed to signal.signal and test it
        for call in signal_calls:
            args, kwargs = call
            if len(args) >= 2:
                handler = args[1]
                mock_done_event = MagicMock()
                mock_server_instance.stop.return_value = mock_done_event
                handler(signal.SIGTERM, None)
                mock_server_instance.stop.assert_called_with(grace=5)
                mock_done_event.wait.assert_called_with(timeout=5)
                break

if __name__ == '__main__':
    unittest.main()

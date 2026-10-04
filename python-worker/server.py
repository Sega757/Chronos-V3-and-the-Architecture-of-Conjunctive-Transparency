import os
import signal
import grpc
from concurrent import futures
import logging
# import pb.metacore_a2a_pb2_grpc as pb2_grpc

MAX_MESSAGE_LENGTH = 4 * 1024 * 1024  # 4MB message size limit to prevent DoS (CWE-400)
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
    # pb2_grpc.add_MetaCoreServicer_to_server(WorkerServicer(), server)
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

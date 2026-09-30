import os
import signal
import sys
import grpc
from concurrent import futures
import logging
# import pb.metacore_a2a_pb2_grpc as pb2_grpc

def serve():
    bind_addr = os.getenv('WORKER_BIND_ADDR', '127.0.0.1:50052')
    options = [
        ('grpc.max_receive_message_length', 4 * 1024 * 1024),
        ('grpc.max_send_message_length', 4 * 1024 * 1024),
    ]
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=options)
    # pb2_grpc.add_MetaCoreServicer_to_server(WorkerServicer(), server)
    server.add_insecure_port(bind_addr)
    server.start()
    logging.info(f"Python Worker initialized on {bind_addr}. Awaiting swarm tasks.")

    def handle_signal(signum, frame):
        logging.info("Received signal %s, shutting down gRPC server gracefully...", signum)
        done_event = server.stop(grace=5)
        if done_event:
            done_event.wait(timeout=5)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    server.wait_for_termination()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    serve()

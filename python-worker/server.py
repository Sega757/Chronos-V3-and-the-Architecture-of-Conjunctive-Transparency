import os
import grpc
from concurrent import futures
import logging
# import pb.metacore_a2a_pb2_grpc as pb2_grpc

def serve():
    bind_addr = os.getenv('WORKER_BIND_ADDR', '127.0.0.1:50052')
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    # pb2_grpc.add_MetaCoreServicer_to_server(WorkerServicer(), server)
    server.add_insecure_port(bind_addr)
    server.start()
    logging.info(f"Python Worker initialized on {bind_addr}. Awaiting swarm tasks.")
    server.wait_for_termination()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    serve()

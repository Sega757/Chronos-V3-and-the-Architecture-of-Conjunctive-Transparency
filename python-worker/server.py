import grpc
from concurrent import futures
import logging
# import pb.metacore_a2a_pb2_grpc as pb2_grpc

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    # pb2_grpc.add_MetaCoreServicer_to_server(WorkerServicer(), server)
    server.add_insecure_port('[::]:50052')
    server.start()
    logging.info("Python Worker initialized on port 50052. Awaiting swarm tasks.")
    server.wait_for_termination()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    serve()

package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
	// pb "metacore/internal/metacore/pb"
)

func main() {
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to bind network listener: %v", err)
	}

	server := grpc.NewServer()
	// pb.RegisterMetaCoreServer(server, &metaCoreService{})

	log.Printf("META-CORE ADK active and listening on %v", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatalf("gRPC server termination: %v", err)
	}
}

package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	// pb "metacore/internal/metacore/pb"
)

func main() {
	bindAddr := os.Getenv("METACORE_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "127.0.0.1:50051"
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatalf("failed to bind network listener: %v", err)
	}

	// Limit maximum concurrent HTTP/2 streams per connection to prevent DoS via stream flooding
	server := grpc.NewServer(
		grpc.MaxConcurrentStreams(100),
	)
	// pb.RegisterMetaCoreServer(server, &metaCoreService{})

	log.Printf("META-CORE ADK active and listening on %v", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatalf("gRPC server termination: %v", err)
	}
}

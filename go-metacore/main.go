package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	server := grpc.NewServer()
	// pb.RegisterMetaCoreServer(server, &metaCoreService{})

	// Handle graceful shutdown on OS interrupt/termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received termination signal %v, shutting down gRPC server...", sig)
		server.GracefulStop()
		log.Printf("gRPC server shutdown complete.")
	}()

	log.Printf("META-CORE ADK active and listening on %v", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatalf("gRPC server termination: %v", err)
	}
}

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

	server := newServer()
	// pb.RegisterMetaCoreServer(server, &metaCoreService{})

	// Handle operating system signals for graceful server shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received termination signal, shutting down gRPC server gracefully...")
		server.GracefulStop()
	}()

	log.Printf("META-CORE ADK active and listening on %v", listener.Addr())
	if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
		log.Fatalf("gRPC server termination: %v", err)
	}
}

// newServer initializes gRPC server with DoS mitigation options (CWE-400)
func newServer() *grpc.Server {
	return grpc.NewServer(
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(4*1024*1024),
		grpc.MaxSendMsgSize(4*1024*1024),
	)
}

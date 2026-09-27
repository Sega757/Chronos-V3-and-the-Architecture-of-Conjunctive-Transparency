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

	// Limit max concurrent streams and message length to prevent resource exhaustion / DoS attacks (CWE-400)
	server := grpc.NewServer(
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(4*1024*1024),
	)
	// pb.RegisterMetaCoreServer(server, &metaCoreService{})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("Shutting down gRPC server gracefully...")
		server.GracefulStop()
	}()

	log.Printf("META-CORE ADK active and listening on %v", listener.Addr())
	if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
		log.Fatalf("gRPC server termination: %v", err)
	}
}

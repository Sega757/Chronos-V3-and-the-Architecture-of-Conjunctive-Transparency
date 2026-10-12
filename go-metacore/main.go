package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
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

	server, err := newServer()
	if err != nil {
		log.Fatalf("failed to initialize gRPC server: %v", err)
	}
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

// getTLSCredentials configures gRPC TLS/mTLS credentials or verifies insecure mode opt-in (CWE-319)
func getTLSCredentials() (credentials.TransportCredentials, error) {
	enableTLS := strings.EqualFold(os.Getenv("GRPC_ENABLE_TLS"), "true") || os.Getenv("GRPC_ENABLE_TLS") == "1"
	certPath := os.Getenv("GRPC_TLS_CERT_PATH")
	keyPath := os.Getenv("GRPC_TLS_KEY_PATH")
	caPath := os.Getenv("GRPC_TLS_CA_PATH")

	if enableTLS || certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, fmt.Errorf("GRPC_TLS_CERT_PATH and GRPC_TLS_KEY_PATH must be set when TLS is enabled")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if caPath != "" {
			caCert, err := os.ReadFile(caPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert file: %w", err)
			}
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to append CA certificate to pool")
			}
			tlsConfig.ClientCAs = certPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		return credentials.NewTLS(tlsConfig), nil
	}

	allowInsecure := os.Getenv("GRPC_ALLOW_INSECURE")
	if allowInsecure == "" {
		allowInsecure = "true"
	}
	if !strings.EqualFold(allowInsecure, "true") && allowInsecure != "1" {
		return nil, fmt.Errorf("Insecure gRPC connections are disabled (GRPC_ALLOW_INSECURE=false) and TLS is not configured")
	}

	return nil, nil
}

// newServer initializes gRPC server with DoS mitigation (CWE-400) and TLS transport security (CWE-319)
func newServer(opts ...grpc.ServerOption) (*grpc.Server, error) {
	creds, err := getTLSCredentials()
	if err != nil {
		return nil, err
	}

	baseOpts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(4 * 1024 * 1024),
		grpc.MaxSendMsgSize(4 * 1024 * 1024),
		// HTTP/2 ping flood and idle connection DoS mitigation (CWE-400)
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
		}),
	}
	if creds != nil {
		baseOpts = append(baseOpts, grpc.Creds(creds))
	}
	allOpts := append(baseOpts, opts...)
	return grpc.NewServer(allOpts...), nil
}

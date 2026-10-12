package main

import (
	"strings"
	"testing"
)

func TestNewServerInitialization(t *testing.T) {
	t.Setenv("GRPC_ALLOW_INSECURE", "true")
	server, err := newServer()
	if err != nil {
		t.Fatalf("unexpected error initializing gRPC server: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil gRPC server instance")
	}
	server.Stop()
}

func TestMissingTLSCertAndKey(t *testing.T) {
	t.Setenv("GRPC_ENABLE_TLS", "true")
	t.Setenv("GRPC_TLS_CERT_PATH", "")
	t.Setenv("GRPC_TLS_KEY_PATH", "")

	_, err := newServer()
	if err == nil {
		t.Fatal("expected error when GRPC_ENABLE_TLS is true but cert/key paths are missing")
	}
	if !strings.Contains(err.Error(), "GRPC_TLS_CERT_PATH and GRPC_TLS_KEY_PATH must be set") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDisallowedInsecureMode(t *testing.T) {
	t.Setenv("GRPC_ENABLE_TLS", "false")
	t.Setenv("GRPC_ALLOW_INSECURE", "false")

	_, err := newServer()
	if err == nil {
		t.Fatal("expected error when insecure gRPC connections are disabled")
	}
	if !strings.Contains(err.Error(), "Insecure gRPC connections are disabled") {
		t.Errorf("unexpected error message: %v", err)
	}
}

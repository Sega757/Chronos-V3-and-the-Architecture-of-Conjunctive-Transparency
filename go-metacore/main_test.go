package main

import (
	"testing"
)

func TestNewServerInitialization(t *testing.T) {
	server, err := newServer()
	if err != nil {
		t.Fatalf("unexpected error during server creation: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil gRPC server instance")
	}
	server.Stop()
}

func TestNewServerDisallowedInsecureMode(t *testing.T) {
	t.Setenv("GRPC_ENABLE_TLS", "false")
	t.Setenv("GRPC_ALLOW_INSECURE", "false")

	_, err := newServer()
	if err == nil {
		t.Fatal("expected error when insecure mode is disabled and TLS is off")
	}
}

func TestNewServerMissingTLSCertAndKey(t *testing.T) {
	t.Setenv("GRPC_ENABLE_TLS", "true")
	t.Setenv("GRPC_TLS_CERT_PATH", "")
	t.Setenv("GRPC_TLS_KEY_PATH", "")

	_, err := newServer()
	if err == nil {
		t.Fatal("expected error when TLS is enabled without cert/key paths")
	}
}

package main

import (
	"testing"
)

func TestNewServerInitialization(t *testing.T) {
	server := newServer()
	if server == nil {
		t.Fatal("expected non-nil gRPC server instance")
	}
	server.Stop()
}

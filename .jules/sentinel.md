# Sentinel Security Journal 🛡️

## Security Assessment & Learnings

### Repository Status
- As of initialization, the repository contains no application source code (only `README.md`).
- Security audits and fixes will be applied once application code or dependencies are introduced.

### gRPC Server Security Hardening (python-worker)
- Replaced unconditional insecure gRPC port binding (`add_insecure_port`) in `python-worker/server.py` with secure TLS/mTLS configuration using `grpc.ssl_server_credentials`.
- Implemented environment variable configuration (`GRPC_ENABLE_TLS`, `GRPC_TLS_CERT_PATH`, `GRPC_TLS_KEY_PATH`, `GRPC_TLS_CA_PATH`, `GRPC_ALLOW_INSECURE`).
- Implemented fail-fast security: missing or unreadable certificate files raise `RuntimeError` when TLS is expected.
- Restricted insecure port binding to explicit opt-in (`GRPC_ALLOW_INSECURE="true"`), issuing a security warning log when active.
- Added comprehensive unit tests in `python-worker/test_server.py` with ephemeral self-signed TLS certificates.

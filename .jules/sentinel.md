# Sentinel Security Journal 🛡️

## Security Assessment & Learnings

### Repository Status
- As of initialization, the repository contains no application source code (only `README.md`).
- Security audits and fixes will be applied once application code or dependencies are introduced.

### gRPC Server TLS Configuration (python-worker/server.py)
- Fixed insecure gRPC port exposure vulnerability by enforcing TLS credentials (`grpc.ssl_server_credentials`) by default.
- Implemented environment variable configuration (`GRPC_TLS_CERT_PATH`, `GRPC_TLS_KEY_PATH`, `GRPC_TLS_CA_PATH`, `GRPC_ENABLE_TLS`, `GRPC_ALLOW_INSECURE`).
- Added optional mTLS support with client CA validation (`require_client_auth=True`).
- Added fail-fast startup check when TLS is required but certificate/key files are missing or unreadable.
- Created dynamic ephemeral self-signed cert testing strategy in `python-worker/test_server.py` to verify secure gRPC connections and fallback modes.

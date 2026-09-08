.PHONY: proto build up down test

proto:
	@mkdir -p go-metacore/internal/metacore/pb python-worker/pb
	protoc --go_out=go-metacore/ --go-grpc_out=go-metacore/ proto/metacore_a2a.proto
	python3 -m grpc_tools.protoc -Iproto --python_out=python-worker/pb --grpc_python_out=python-worker/pb proto/metacore_a2a.proto

build: proto
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

test:
	cd go-metacore && go test ./...
	cd python-worker && pytest

PYTHON      ?= python3
SERVER_BIN  ?= protobom-server
GO_SERVER   ?= ./server/
PROTO_DIR   ?= proto
PROTO_FILE  ?= $(PROTO_DIR)/protobom_service.proto

GOPROXY     ?= https://proxy.golang.org,direct
export GOPROXY

.PHONY: all deps proto server run-server run-client clean

all: proto server

# Install protoc plugins (Go + Python gRPC tools).
deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	pip install grpcio grpcio-tools

# Generate Go and Python gRPC stubs from the .proto file.
proto:
	@echo "--- Generating Go stubs ---"
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILE)
	@echo "--- Generating Python stubs ---"
	$(PYTHON) -m grpc_tools.protoc \
		-I$(PROTO_DIR) \
		--python_out=. \
		--grpc_python_out=. \
		--pyi_out=. \
		$(PROTO_FILE)

# Build the Go gRPC server binary.
server: proto
	go mod tidy
	go build -o $(SERVER_BIN) $(GO_SERVER)

# Start the server (foreground).
run-server: server
	./$(SERVER_BIN)

# Run the Python client example (server must be running).
run-client:
	$(PYTHON) example_client.py

# Remove build artefacts.
clean:
	rm -f $(SERVER_BIN)
	rm -f protobom_service_pb2.py protobom_service_pb2_grpc.py protobom_service_pb2.pyi
	rm -f $(PROTO_DIR)/*.pb.go

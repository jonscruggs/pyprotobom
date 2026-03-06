# grpc-example — protobom as a gRPC microservice

A Go gRPC server that wraps the [protobom](https://github.com/protobom/protobom)
library, plus a Python client that calls it.  This is the recommended approach
for microservice architectures — the Go server handles all SBOM parsing and
serialisation, and any language can consume it via gRPC.

## Architecture

```
┌─────────────────────────┐         gRPC (protobuf)         ┌──────────────┐
│  Python microservice    │ ──────────────────────────────── │  Go server   │
│  (example_client.py)    │                                  │  (protobom)  │
│                         │  ParseFile / Convert / Render    │              │
│  import pb2 / pb2_grpc  │  CreateDocument / AddNode / ...  │  reader      │
│                         │ ◄──────────────────────────────  │  writer      │
└─────────────────────────┘                                  └──────────────┘
```

The `.proto` service definition lives in `proto/protobom_service.proto` and
generates both Go and Python stubs.

## Prerequisites

| Tool | Install |
|------|---------|
| Go >= 1.22 | [golang.org](https://go.dev/dl/) |
| protoc | `apt install protobuf-compiler` (or [releases](https://github.com/protocolbuffers/protobuf/releases)) |
| protoc-gen-go | `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest` |
| protoc-gen-go-grpc | `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest` |
| Python >= 3.10 | |
| grpcio + grpcio-tools | `pip install grpcio grpcio-tools` |

Or simply run `make deps` to install the Go and Python tooling.

## Quick start

```bash
# 1. Install dependencies (one time)
make deps

# 2. Generate stubs + build server
make

# 3. Start the server (terminal 1)
make run-server
# => protobom gRPC server listening on :50051

# 4. Run the client (terminal 2)
make run-client
```

## What the example demonstrates

1. **List formats** — enumerate supported SBOM output formats.
2. **Parse & inspect** — read a CycloneDX file on the server, then query
   document metadata, nodes, and edges from Python.
3. **In-memory conversion** — send raw CycloneDX bytes over the wire, receive
   SPDX 2.3 JSON bytes back (no file I/O on either side).
4. **Create from scratch** — build a new SBOM by calling `CreateDocument`,
   `AddNode`, and `AddEdge`, then `Render` it to CycloneDX 1.5 JSON.

## gRPC service API

Defined in `proto/protobom_service.proto`:

| RPC | Description |
|-----|-------------|
| `ParseFile(path)` | Parse a server-local SBOM file, return handle |
| `GetDocumentInfo(handle)` | Get document metadata |
| `GetNodes(handle)` | List all nodes + root IDs |
| `GetNodeInfo(handle, node_id)` | Get one node's details |
| `GetEdges(handle)` | List all edges |
| `Convert(sbom_bytes, format)` | Convert SBOM bytes between formats |
| `CreateDocument(id, name, ver)` | Create an empty document |
| `AddNode(handle, ...)` | Add a package node (optionally as root) |
| `AddEdge(handle, from, type, to[])` | Add a relationship edge |
| `Render(handle, format)` | Serialise document to bytes |
| `CloseDocument(handle)` | Free server-side memory |
| `ListFormats()` | List supported output format strings |

## Why gRPC over gopy for microservices?

- No CGo build complexity in Python services
- Any language gets a type-safe client from the `.proto` file
- Server scales independently
- Protobom already uses protobuf internally — natural fit
- See the `gopy-example/` directory for the in-process alternative

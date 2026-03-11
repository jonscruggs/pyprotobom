# Plan: Integrate Real Protobuf into pyprotobom

## Context

The upstream Go `protobom/protobom` repo defines its data model in a single proto file:
- **`api/sbom.proto`** — contains all messages (`Document`, `Metadata`, `NodeList`, `Node`, `Edge`, `Person`, `Tool`, `Property`, `DocumentType`, `ExternalReference`, `SourceData`) and enums (`HashAlgorithm`, `Purpose`, `SoftwareIdentifierType`, plus nested enums like `Edge.Type`, `Node.NodeType`, `ExternalReference.ExternalReferenceType`, `DocumentType.SBOMType`).

The current Python code in `src/protobom/sbom.py` reimplements these as hand-written dataclasses/IntEnums. This plan replaces them with actual protobuf-generated Python classes.

## Steps

### 1. Add the `.proto` file to the repo
- Create `proto/sbom.proto` — copy from upstream `api/sbom.proto`
- Add `option py_generic_services = false;` and a Python-friendly package option

### 2. Generate `_pb2.py` from the proto definition
- Use `grpcio-tools` (which bundles `protoc`) to compile: `python -m grpc_tools.protoc -I proto --python_out=src/protobom/generated proto/sbom.proto`
- Output: `src/protobom/generated/sbom_pb2.py` (and optionally `sbom_pb2.pyi` for type stubs)
- Commit the generated file so users don't need `protoc` installed

### 3. Add `protobuf` runtime dependency
- Add `protobuf>=4.21.0` to `pyproject.toml` `[project.dependencies]`
- Add `grpcio-tools` as an optional dev dependency for regeneration

### 4. Create a compatibility/wrapper layer (`src/protobom/sbom.py`)
- Replace the hand-written dataclasses with thin wrappers or re-exports from the generated protobuf classes
- Key challenge: protobuf message objects have a different API than dataclasses (no `__init__` kwargs in the same way, mutable but not dataclass-like). Two approaches:

  **Option A — Direct use of protobuf messages**: Rewrite `sbom.py` to re-export the generated classes directly. Serializers/unserializers populate protobuf message objects. The `NodeList` graph methods (`node_descendants`, `get_node_by_id`, etc.) become standalone functions or a wrapper class that delegates storage to the protobuf `NodeList` message.

  **Option B — Wrapper dataclasses with proto conversion**: Keep dataclass-like wrappers that internally convert to/from protobuf messages. Adds `to_proto()` / `from_proto()` methods. More Pythonic API but adds a translation layer.

  **Recommended: Option A** — direct protobuf usage with a thin `NodeList` helper class for graph operations. This matches the Go implementation's approach (the Go code uses generated protobuf types directly and adds methods via Go's type extension).

### 5. Update serializers/unserializers
- Modify `src/protobom/native/unserializers/spdx23.py` and `cyclonedx.py` to create protobuf message objects instead of dataclass instances
- Modify `src/protobom/native/serializers/spdx23.py` and `cyclonedx.py` to read from protobuf message objects
- Key API differences:
  - `node.hashes[HashAlgorithm.SHA256] = "abc"` → same (protobuf maps work similarly)
  - `Node(id="foo", name="bar")` → `node = Node(); node.id = "foo"; node.name = "bar"` (or `Node(id="foo", name="bar")` works in protobuf-python too)
  - `node.licenses.append("MIT")` → same (repeated fields support append)
  - Enum access: `sbom_pb2.PURL` instead of `SoftwareIdentifierType.PURL`
  - Timestamp fields: use `google.protobuf.timestamp_pb2.Timestamp` instead of `datetime`

### 6. Update `NodeList` wrapper
- Create a `NodeList` class that wraps `sbom_pb2.NodeList` and provides the graph operations:
  - `get_node_by_id()`, `get_nodes_by_name()`, `node_descendants()`, etc.
  - Set operations: `union()`, `intersect()`
  - Internal indexes rebuilt on mutation
- This mirrors the Go approach where `nodelist.go` adds methods to the generated `NodeList` type

### 7. Update tests
- Update `tests/test_sbom.py` to work with protobuf message objects
- Update `tests/test_reader_writer.py` and `tests/test_formats.py`
- Add a new test verifying protobuf binary serialization/deserialization round-trip

### 8. Update examples
- Update the example scripts to use the new protobuf-based API
- Verify all examples still work

### 9. Add a proto regeneration script/Makefile target
- Add a `Makefile` or script: `make proto` that runs `protoc` to regenerate from `proto/sbom.proto`
- Document in README how to regenerate after proto changes

## File Changes Summary

| File | Action |
|------|--------|
| `proto/sbom.proto` | **NEW** — upstream proto definition |
| `src/protobom/generated/__init__.py` | **NEW** — package init |
| `src/protobom/generated/sbom_pb2.py` | **NEW** — generated protobuf code |
| `src/protobom/generated/sbom_pb2.pyi` | **NEW** — type stubs |
| `pyproject.toml` | **EDIT** — add `protobuf` dependency |
| `src/protobom/sbom.py` | **REWRITE** — thin wrappers + NodeList graph ops around protobuf types |
| `src/protobom/native/unserializers/spdx23.py` | **EDIT** — use protobuf messages |
| `src/protobom/native/unserializers/cyclonedx.py` | **EDIT** — use protobuf messages |
| `src/protobom/native/serializers/spdx23.py` | **EDIT** — use protobuf messages |
| `src/protobom/native/serializers/cyclonedx.py` | **EDIT** — use protobuf messages |
| `src/protobom/reader.py` | **EDIT** — minor adjustments |
| `src/protobom/writer.py` | **EDIT** — minor adjustments |
| `src/protobom/__init__.py` | **EDIT** — update exports |
| `tests/test_sbom.py` | **EDIT** — update for protobuf API |
| `tests/test_reader_writer.py` | **EDIT** — update for protobuf API |
| `tests/test_formats.py` | **EDIT** — likely minimal changes |
| `examples/*.py` | **EDIT** — update API usage |
| `Makefile` | **NEW** — proto regeneration target |

## Risk Considerations

- **API breakage**: The protobuf message API is different from dataclasses. `Document(metadata=m, node_list=nl)` constructor style works but nested message assignment uses `CopyFrom()`. Need careful migration.
- **Timestamp handling**: Protobuf uses `google.protobuf.Timestamp` instead of Python `datetime`. Need helper functions for conversion.
- **Enum naming**: Protobuf nested enums (e.g., `Edge.Type.contains`) have different access patterns than the current `EdgeType.contains`. Will need to re-export or alias for backward compatibility.
- **NodeList methods**: The generated `NodeList` is a plain protobuf message. Graph operations must be added via a wrapper class or standalone functions.

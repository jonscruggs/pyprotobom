# gopy-example — Use protobom (Go) from Python

This directory contains a working example of calling the
[protobom](https://github.com/protobom/protobom) Go library from Python using
[gopy](https://github.com/go-python/gopy).

## How it works

```
protobomgo/          Go wrapper package (gopy-friendly API)
  └─ protobomgo.go   thin layer over protobom reader/writer/sbom

        ↓  gopy build

protobomgo_py/       generated CPython extension (shared lib + .py)

        ↓  import

example.py           Python script that uses the bindings
```

`gopy` inspects the exported Go types and functions in `protobomgo/` and
generates:

* a C shared library (`_protobomgo.cpython-*.so`)
* a pure-Python wrapper module (`protobomgo.py`) that loads it

The result is a regular Python package you can import.

## Prerequisites

| Tool | Version |
|------|---------|
| Go | >= 1.22 |
| Python | >= 3.10 (with development headers, e.g. `python3-dev`) |
| gopy | latest (`go install github.com/go-python/gopy@latest`) |
| goimports | latest (`go install golang.org/x/tools/cmd/goimports@latest`) |

On Debian/Ubuntu:

```bash
sudo apt-get install python3-dev
```

## Quick start

```bash
# 1. Install Go tooling (only needed once)
make deps

# 2. Build the Python extension
make build

# 3. Run the example
make run
#   — or —
python3 example.py
```

## What the example demonstrates

1. **Read an SBOM** — parse a CycloneDX 1.5 JSON file and inspect its nodes
   and edges.
2. **Convert formats** — write the same document out as SPDX 2.3 JSON.
3. **Create from scratch** — build a new SBOM programmatically (add nodes,
   edges, root elements) and serialise it.
4. **One-liner conversion** — `convert_file()` reads + writes in one call.
5. **List formats** — enumerate the output formats supported by protobom.

## Available Python functions

After `import protobomgo_py.protobomgo as protobomgo`:

| Function | Description |
|----------|-------------|
| `read_file(path) → handle` | Parse an SBOM file, return a handle string |
| `get_document_info(handle) → DocumentInfo` | Metadata (name, version, format) |
| `get_node_count(handle) → int` | Number of nodes |
| `get_node_i_ds(handle) → str` | Comma-separated node IDs |
| `get_node_info(handle, node_id) → NodeInfo` | Single node details |
| `get_root_node_i_ds(handle) → str` | Comma-separated root IDs |
| `get_edges(handle) → str` | JSON array of edges |
| `write_file(handle, path, format)` | Write document to file |
| `convert_file(in_path, out_path, format)` | One-step read + write |
| `new_document(id, name, version) → handle` | Create empty document |
| `add_node(handle, id, name, version, purl)` | Add a package node |
| `add_root_node(handle, node_id)` | Mark a node as root |
| `add_edge(handle, from_id, type, to_ids)` | Add a relationship edge |
| `document_to_json(handle, format) → str` | Serialise to string |
| `dump_all_nodes_json(handle) → str` | JSON array of all nodes |
| `close_document(handle)` | Free in-memory document |
| `list_formats() → str` | Comma-separated supported formats |

### Format strings

| Constant | Value |
|----------|-------|
| SPDX 2.3 JSON | `text/spdx+json;version=2.3` |
| CycloneDX 1.4 JSON | `application/vnd.cyclonedx+json;version=1.4` |
| CycloneDX 1.5 JSON | `application/vnd.cyclonedx+json;version=1.5` |
| CycloneDX 1.6 JSON | `application/vnd.cyclonedx+json;version=1.6` |

### Edge types

Edge type strings match the protobuf enum names (camelCase):
`dependsOn`, `contains`, `buildDependency`, `devDependency`, `ancestor`,
`descendant`, `describes`, etc.

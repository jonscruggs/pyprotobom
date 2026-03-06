#!/usr/bin/env python3
"""Example Python gRPC client for the protobom service.

Start the server first:
    ./protobom-server            # listens on :50051

Then run this script:
    python3 example_client.py

Demonstrates:
  1. Reading an SBOM file on the server and inspecting it
  2. In-memory format conversion (CycloneDX -> SPDX) over the wire
  3. Creating a new SBOM from scratch via gRPC calls
  4. Rendering the new document to CycloneDX JSON
"""

import json
import os
import sys

import grpc

# Generated stubs live alongside this script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protobom_service_pb2 as pb
import protobom_service_pb2_grpc as pb_grpc

SERVER = "localhost:50051"

CDX15_JSON = "application/vnd.cyclonedx+json;version=1.5"
SPDX23_JSON = "text/spdx+json;version=2.3"

HR = "-" * 60
SAMPLE_CDX = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "testdata", "sample-cdx.json"
)


def demo_list_formats(stub):
    """List supported output formats."""
    print(HR)
    print("1) Supported output formats")
    print(HR)

    resp = stub.ListFormats(pb.Empty())
    for f in resp.formats:
        print(f"   - {f}")
    print()


def demo_read_and_inspect(stub):
    """Parse an SBOM file on the server and inspect it."""
    print(HR)
    print("2) Reading and inspecting an SBOM file")
    print(HR)

    # Parse file (the path is server-local).
    resp = stub.ParseFile(pb.ParseFileRequest(path=SAMPLE_CDX))
    handle = resp.handle
    print(f"   Handle         : {handle}")

    # Get document metadata.
    info = stub.GetDocumentInfo(pb.DocumentRequest(handle=handle))
    print(f"   Name           : {info.name}")
    print(f"   Version        : {info.version}")
    print(f"   Source format  : {info.source_format}")

    # List nodes.
    nodes_resp = stub.GetNodes(pb.DocumentRequest(handle=handle))
    print(f"   Total nodes    : {len(nodes_resp.nodes)}")
    print(f"   Root elements  : {', '.join(nodes_resp.root_ids)}")
    print()
    print("   Nodes:")
    for n in nodes_resp.nodes:
        purl_str = f"  purl={n.purl}" if n.purl else ""
        print(f"     - [{n.type}] {n.name} @ {n.version}{purl_str}")

    # List edges.
    edges_resp = stub.GetEdges(pb.DocumentRequest(handle=handle))
    print()
    print("   Edges:")
    for e in edges_resp.edges:
        to_str = ", ".join(e.to_nodes)
        print(f"     {e.from_node} --[{e.type}]--> {to_str}")

    print()
    return handle


def demo_convert_in_memory(stub):
    """Send raw CycloneDX bytes and get back SPDX bytes — no file I/O."""
    print(HR)
    print("3) In-memory format conversion (CycloneDX -> SPDX)")
    print(HR)

    with open(SAMPLE_CDX, "rb") as f:
        cdx_bytes = f.read()

    resp = stub.Convert(
        pb.ConvertRequest(sbom_data=cdx_bytes, output_format=SPDX23_JSON)
    )
    print(f"   Detected input format : {resp.detected_format}")
    print(f"   Output size           : {len(resp.sbom_data)} bytes")

    spdx_data = json.loads(resp.sbom_data)
    print(f"   SPDX version          : {spdx_data.get('spdxVersion', 'N/A')}")
    print(f"   Packages              : {len(spdx_data.get('packages', []))}")
    print()


def demo_create_and_render(stub):
    """Build a new SBOM via gRPC and render it to CycloneDX."""
    print(HR)
    print("4) Creating a new SBOM from scratch")
    print(HR)

    # Create an empty document.
    resp = stub.CreateDocument(
        pb.CreateDocumentRequest(id="new-sbom", name="demo-project", version="1")
    )
    handle = resp.handle
    print(f"   Created document: {handle}")

    # Add nodes.
    stub.AddNode(
        pb.AddNodeRequest(
            handle=handle,
            id="app-root",
            name="demo-project",
            version="0.1.0",
            purl="pkg:golang/example.com/demo-project@0.1.0",
            is_root=True,
        )
    )
    stub.AddNode(
        pb.AddNodeRequest(
            handle=handle,
            id="dep-1",
            name="cool-library",
            version="4.2.0",
            purl="pkg:pypi/cool-library@4.2.0",
        )
    )
    stub.AddNode(
        pb.AddNodeRequest(
            handle=handle,
            id="dep-2",
            name="fast-parser",
            version="1.0.3",
            purl="pkg:pypi/fast-parser@1.0.3",
        )
    )

    # Add edges.
    stub.AddEdge(
        pb.AddEdgeRequest(
            handle=handle,
            from_node_id="app-root",
            edge_type="dependsOn",
            to_node_ids=["dep-1", "dep-2"],
        )
    )
    stub.AddEdge(
        pb.AddEdgeRequest(
            handle=handle,
            from_node_id="dep-1",
            edge_type="dependsOn",
            to_node_ids=["dep-2"],
        )
    )

    # Verify via GetNodes.
    nodes_resp = stub.GetNodes(pb.DocumentRequest(handle=handle))
    print(f"   Nodes added    : {len(nodes_resp.nodes)}")
    for n in nodes_resp.nodes:
        print(f"     - {n.name} @ {n.version}")

    # Render to CycloneDX 1.5 JSON.
    render_resp = stub.Render(
        pb.RenderRequest(handle=handle, format=CDX15_JSON)
    )
    cdx_data = json.loads(render_resp.sbom_data)

    print()
    print("   Rendered CycloneDX 1.5 (first 25 lines):")
    snippet = json.dumps(cdx_data, indent=2)
    lines = snippet.splitlines()[:25]
    for line in lines:
        print(f"   {line}")
    if len(snippet.splitlines()) > 25:
        print("   ...")

    # Clean up.
    stub.CloseDocument(pb.DocumentRequest(handle=handle))
    print()


def main():
    print()
    print("=" * 60)
    print("  protobom gRPC service — Python client example")
    print("=" * 60)
    print()

    channel = grpc.insecure_channel(SERVER)
    stub = pb_grpc.ProtobomServiceStub(channel)

    try:
        demo_list_formats(stub)
        handle = demo_read_and_inspect(stub)
        demo_convert_in_memory(stub)
        stub.CloseDocument(pb.DocumentRequest(handle=handle))
        demo_create_and_render(stub)
    finally:
        channel.close()

    print("Done!")


if __name__ == "__main__":
    main()

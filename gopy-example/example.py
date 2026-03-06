#!/usr/bin/env python3
"""Example: using the protobom Go library from Python via gopy bindings.

This script demonstrates:
  1. Reading an existing SBOM (CycloneDX) file
  2. Inspecting document metadata, nodes, and edges
  3. Creating a brand-new SBOM document from scratch
  4. Converting between SBOM formats (CycloneDX -> SPDX)
"""

import json
import os
import sys

# The gopy-generated package lives in the protobomgo_py/ directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protobomgo_py.protobomgo as protobomgo

SAMPLE_CDX = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "testdata", "sample-cdx.json"
)

# Format constants (matching the Go formats package).
CDX15_JSON = "application/vnd.cyclonedx+json;version=1.5"
SPDX23_JSON = "text/spdx+json;version=2.3"

HR = "-" * 60


def demo_read_sbom():
    """Read an existing CycloneDX SBOM and inspect its contents."""
    print(HR)
    print("1) Reading an existing CycloneDX SBOM")
    print(HR)

    handle = protobomgo.read_file(SAMPLE_CDX)
    print(f"   Document handle : {handle}")

    info = protobomgo.get_document_info(handle)
    print(f"   Name            : {info.name}")
    print(f"   Version         : {info.version}")
    print(f"   Source format   : {info.format}")

    count = protobomgo.get_node_count(handle)
    print(f"   Total nodes     : {count}")

    root_ids = protobomgo.get_root_node_i_ds(handle)
    print(f"   Root elements   : {root_ids}")

    # List every node.
    node_ids = protobomgo.get_node_i_ds(handle).split(",")
    print()
    print("   Nodes:")
    for nid in node_ids:
        ni = protobomgo.get_node_info(handle, nid)
        purl_str = f"  purl={ni.purl}" if ni.purl else ""
        print(f"     - [{ni.type}] {ni.name} @ {ni.version}{purl_str}")

    # Show edges.
    edges_json = protobomgo.get_edges(handle)
    edges = json.loads(edges_json)
    print()
    print("   Edges:")
    for e in edges:
        print(f"     {e['FromNode']} --[{e['Type']}]--> {e['ToNodes']}")

    print()
    return handle


def demo_convert_format(handle):
    """Convert the CycloneDX document to SPDX 2.3 JSON."""
    print(HR)
    print("2) Converting CycloneDX -> SPDX 2.3 JSON")
    print(HR)

    output_path = "/tmp/converted-sbom-spdx23.json"
    protobomgo.write_file(handle, output_path, SPDX23_JSON)
    print(f"   Written to: {output_path}")

    with open(output_path) as f:
        spdx_data = json.load(f)
    print(f"   SPDX document name : {spdx_data.get('name', 'N/A')}")
    print(f"   Packages           : {len(spdx_data.get('packages', []))}")
    print()


def demo_create_sbom():
    """Build a new SBOM from scratch and write it as CycloneDX 1.5."""
    print(HR)
    print("3) Creating a new SBOM from scratch")
    print(HR)

    handle = protobomgo.new_document("my-new-sbom", "demo-project", "1")

    # Add a root application node.
    protobomgo.add_node(
        handle,
        "app-root",
        "demo-project",
        "0.1.0",
        "pkg:golang/example.com/demo-project@0.1.0",
    )
    protobomgo.add_root_node(handle, "app-root")

    # Add two dependency nodes.
    protobomgo.add_node(
        handle,
        "dep-1",
        "cool-library",
        "4.2.0",
        "pkg:pypi/cool-library@4.2.0",
    )
    protobomgo.add_node(
        handle,
        "dep-2",
        "fast-parser",
        "1.0.3",
        "pkg:pypi/fast-parser@1.0.3",
    )

    # Create dependency edges (edge types use protobuf camelCase names).
    protobomgo.add_edge(handle, "app-root", "dependsOn", "dep-1,dep-2")
    protobomgo.add_edge(handle, "dep-1", "dependsOn", "dep-2")

    count = protobomgo.get_node_count(handle)
    print(f"   Created document with {count} nodes")

    # Serialise to CycloneDX 1.5 JSON.
    output_path = "/tmp/new-sbom-cdx15.json"
    protobomgo.write_file(handle, output_path, CDX15_JSON)
    print(f"   Written as CycloneDX 1.5 JSON to: {output_path}")

    # Pretty-print a snippet.
    with open(output_path) as f:
        cdx_data = json.load(f)
    snippet = json.dumps(cdx_data, indent=2)
    # Show first 30 lines.
    lines = snippet.splitlines()[:30]
    print()
    print("   First 30 lines of output:")
    for line in lines:
        print(f"   {line}")
    if len(snippet.splitlines()) > 30:
        print("   ...")

    protobomgo.close_document(handle)
    print()


def demo_convenience_convert():
    """One-liner format conversion using convert_file()."""
    print(HR)
    print("4) One-liner format conversion (CycloneDX -> SPDX)")
    print(HR)

    output_path = "/tmp/oneliner-spdx23.json"
    protobomgo.convert_file(SAMPLE_CDX, output_path, SPDX23_JSON)
    print(f"   Converted {SAMPLE_CDX}")
    print(f"         -> {output_path}")

    with open(output_path) as f:
        data = json.load(f)
    print(f"   Result SPDX version: {data.get('spdxVersion', 'N/A')}")
    print()


def demo_list_formats():
    """Show the supported output formats."""
    print(HR)
    print("5) Supported output formats")
    print(HR)

    fmts = protobomgo.list_formats().split(",")
    for f in fmts:
        print(f"   - {f}")
    print()


def main():
    print()
    print("=" * 60)
    print("  protobom Go library via gopy — Python example")
    print("=" * 60)
    print()

    demo_list_formats()
    handle = demo_read_sbom()
    demo_convert_format(handle)
    protobomgo.close_document(handle)
    demo_create_sbom()
    demo_convenience_convert()

    print("Done!")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Example: Merge and compare SBOMs.

Demonstrates combining SBOMs from different sources, computing set
operations (union, intersect), and manipulating the SBOM graph.

Usage:
    python examples/merge_sboms.py
"""

import io
import json
from pathlib import Path

from protobom import Reader, Writer
from protobom.formats import CDX15JSON, Format
from protobom.sbom import Edge, EdgeType, Node, NodeType, Purpose, SoftwareIdentifierType
from protobom.writer import WriteOptions

EXAMPLES_DIR = Path(__file__).parent / "testdata"
OUTPUT_DIR = Path(__file__).parent / "output"


def merge_two_sboms():
    """Merge two SBOMs into a single combined document."""
    print("=" * 60)
    print("Merge two SBOMs")
    print("=" * 60)

    reader = Reader()

    # Load two SBOMs
    web_app = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")
    py_app = reader.parse_file(EXAMPLES_DIR / "cdx14-python-app.json")

    print(f"\nWeb app (CycloneDX 1.5): {len(web_app.node_list.nodes)} components")
    print(f"Python app (CycloneDX 1.4): {len(py_app.node_list.nodes)} components")

    # Union - combines all nodes from both
    merged = web_app.node_list.union(py_app.node_list)
    print(f"\nMerged (union): {len(merged.nodes)} components")
    print(f"  Root elements: {len(merged.root_elements)}")

    print("\n  All components in merged SBOM:")
    for node in merged.nodes:
        purl = node.identifiers.get(int(SoftwareIdentifierType.PURL), "")
        ecosystem = ""
        if "npm/" in purl:
            ecosystem = "[npm]"
        elif "pypi/" in purl:
            ecosystem = "[pypi]"
        print(f"    {node.name}@{node.version} {ecosystem}")

    # Write merged SBOM
    from protobom.sbom import Document, Metadata
    merged_doc = Document(
        metadata=Metadata(name="merged-applications", version="1"),
        node_list=merged,
    )

    OUTPUT_DIR.mkdir(exist_ok=True)
    writer = Writer()
    output_path = OUTPUT_DIR / "merged.cdx.json"
    writer.write_file(
        merged_doc, output_path,
        options=WriteOptions(format=Format(CDX15JSON)),
    )
    print(f"\n  Written merged SBOM to: {output_path}")
    print()


def intersect_sboms():
    """Find common components between two SBOMs."""
    print("=" * 60)
    print("Intersect SBOMs (find common components)")
    print("=" * 60)

    reader = Reader()

    # Both apps — they share no packages (different ecosystems)
    web_app = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")
    py_app = reader.parse_file(EXAMPLES_DIR / "cdx14-python-app.json")

    common = web_app.node_list.intersect(py_app.node_list)
    print(f"\nCommon components between web-app and py-app: {len(common.nodes)}")

    # Intersect the same doc with itself (should return all)
    self_common = web_app.node_list.intersect(web_app.node_list)
    print(f"Self-intersection of web-app: {len(self_common.nodes)} (all)")
    print()


def add_and_remove_nodes():
    """Demonstrate adding and removing nodes from an SBOM."""
    print("=" * 60)
    print("Add and remove nodes")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")
    nl = doc.node_list.copy()  # Work on a copy

    print(f"\nOriginal: {len(nl.nodes)} components")

    # Add a new component
    new_node = Node(
        id="pkg:npm/morgan@1.10.0",
        type=NodeType.PACKAGE,
        name="morgan",
        version="1.10.0",
        description="HTTP request logger middleware for node.js",
        primary_purpose=[Purpose.LIBRARY],
        identifiers={int(SoftwareIdentifierType.PURL): "pkg:npm/morgan@1.10.0"},
    )

    # Add it as a dependency of express
    nl.relate_node_at_id(
        new_node,
        "pkg:npm/express@4.18.2",
        EdgeType.dependsOn,
    )

    print(f"After adding morgan: {len(nl.nodes)} components")

    # Verify it's connected
    express_deps = nl.node_descendants("pkg:npm/express@4.18.2", max_depth=1)
    print(f"Express now depends on:")
    for dep in express_deps:
        print(f"  - {dep.name}@{dep.version}")

    # Remove a component
    nl.remove_nodes(["pkg:npm/debug@4.3.4"])
    print(f"\nAfter removing debug: {len(nl.nodes)} components")

    # Verify the debug node is gone
    debug = nl.get_node_by_id("pkg:npm/debug@4.3.4")
    print(f"Debug node found: {debug is not None}")
    print()


def copy_and_compare():
    """Demonstrate copy and equality operations."""
    print("=" * 60)
    print("Copy and compare NodeLists")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")

    original = doc.node_list
    copied = original.copy()

    print(f"\nOriginal nodes: {len(original.nodes)}")
    print(f"Copied nodes:   {len(copied.nodes)}")
    print(f"Are they equal:  {original.equal(copied)}")

    # Modify the copy
    copied.remove_nodes([copied.nodes[0].id])
    print(f"\nAfter removing a node from copy:")
    print(f"Original nodes: {len(original.nodes)}")
    print(f"Copied nodes:   {len(copied.nodes)}")
    print(f"Are they equal:  {original.equal(copied)}")
    print()


if __name__ == "__main__":
    merge_two_sboms()
    intersect_sboms()
    add_and_remove_nodes()
    copy_and_compare()

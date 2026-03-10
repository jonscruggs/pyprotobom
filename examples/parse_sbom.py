#!/usr/bin/env python3
"""Example: Parse and inspect SBOM documents.

Demonstrates reading SPDX and CycloneDX SBOMs, inspecting metadata,
listing packages, and exploring the dependency graph.

Usage:
    python examples/parse_sbom.py
"""

from pathlib import Path

from protobom import Reader
from protobom.sbom import HashAlgorithm, NodeType, SoftwareIdentifierType

EXAMPLES_DIR = Path(__file__).parent / "testdata"


def parse_spdx_example():
    """Parse an SPDX 2.3 JSON SBOM and print its contents."""
    print("=" * 60)
    print("Parsing SPDX 2.3 SBOM: nginx-1.24.0")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")

    # -- Document metadata --
    meta = doc.metadata
    print(f"\nDocument ID:   {meta.id}")
    print(f"Document Name: {meta.name}")
    print(f"SPDX Version:  {meta.version}")
    print(f"Created:       {meta.date}")

    if meta.tools:
        print("\nTools:")
        for tool in meta.tools:
            print(f"  - {tool.name} v{tool.version}")

    if meta.authors:
        print("\nAuthors:")
        for author in meta.authors:
            org = " (organization)" if author.is_org else ""
            email = f" <{author.email}>" if author.email else ""
            print(f"  - {author.name}{email}{org}")

    # -- Source data (auto-computed by reader) --
    if meta.source_data:
        print(f"\nSource format: {meta.source_data.format}")
        print(f"Source size:   {meta.source_data.size} bytes")

    # -- Packages --
    nl = doc.node_list
    packages = [n for n in nl.nodes if n.type == NodeType.PACKAGE]
    files = [n for n in nl.nodes if n.type == NodeType.FILE]

    print(f"\nPackages ({len(packages)}):")
    for pkg in packages:
        purl = pkg.identifiers.get(int(SoftwareIdentifierType.PURL), "")
        print(f"  [{pkg.id}] {pkg.name} {pkg.version}")
        if purl:
            print(f"    PURL: {purl}")
        if pkg.license_concluded:
            print(f"    License: {pkg.license_concluded}")
        if pkg.hashes:
            for algo_int, digest in pkg.hashes.items():
                algo_name = HashAlgorithm(algo_int).name
                print(f"    {algo_name}: {digest[:20]}...")

    print(f"\nFiles ({len(files)}):")
    for f in files:
        print(f"  [{f.id}] {f.name}")
        if f.file_types:
            print(f"    Types: {', '.join(f.file_types)}")

    # -- Root elements --
    roots = nl.get_root_nodes()
    print(f"\nRoot elements ({len(roots)}):")
    for root in roots:
        print(f"  - {root.name} {root.version}")

    # -- Relationships --
    print(f"\nEdges ({len(nl.edges)}):")
    for edge in nl.edges:
        for target in edge.to:
            target_node = nl.get_node_by_id(target)
            from_node = nl.get_node_by_id(edge.from_)
            from_name = from_node.name if from_node else edge.from_
            to_name = target_node.name if target_node else target
            print(f"  {from_name} --[{edge.type.name}]--> {to_name}")

    print()


def parse_cyclonedx_example():
    """Parse a CycloneDX 1.5 JSON SBOM and print its contents."""
    print("=" * 60)
    print("Parsing CycloneDX 1.5 SBOM: my-web-app")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")

    meta = doc.metadata
    print(f"\nSerial Number: {meta.id}")
    print(f"Document Name: {meta.name}")
    print(f"Created:       {meta.date}")

    if meta.tools:
        print("\nTools:")
        for tool in meta.tools:
            vendor = f" ({tool.vendor})" if tool.vendor else ""
            print(f"  - {tool.name} v{tool.version}{vendor}")

    if meta.document_types:
        print("\nDocument lifecycle phases:")
        for dt in meta.document_types:
            print(f"  - {dt.name} ({dt.type.name})")

    # -- Components --
    nl = doc.node_list
    print(f"\nComponents ({len(nl.nodes)}):")
    for node in nl.nodes:
        purpose = node.primary_purpose[0].name if node.primary_purpose else "unknown"
        purl = node.identifiers.get(int(SoftwareIdentifierType.PURL), "")
        print(f"  {node.name}@{node.version} [{purpose}]")
        if purl:
            print(f"    PURL: {purl}")

    # -- Dependency tree --
    print("\nDependency tree:")
    printed = set()

    def print_tree(node_id, indent=0):
        node = nl.get_node_by_id(node_id)
        if not node or node_id in printed:
            return
        printed.add(node_id)
        prefix = "  " * indent + ("├── " if indent > 0 else "")
        print(f"  {prefix}{node.name}@{node.version}")
        for edge in nl.get_edges_by_from(node_id):
            if edge.type.name == "dependsOn":
                for target in edge.to:
                    print_tree(target, indent + 1)

    for root_id in nl.root_elements:
        print_tree(root_id)

    print()


if __name__ == "__main__":
    parse_spdx_example()
    parse_cyclonedx_example()

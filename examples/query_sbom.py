#!/usr/bin/env python3
"""Example: Search and query SBOM graphs.

Demonstrates using protobom's graph operations to search for packages
by name, PURL, identifier type, and to traverse the dependency tree.

Usage:
    python examples/query_sbom.py
"""

from pathlib import Path

from protobom import Reader
from protobom.sbom import EdgeType, HashAlgorithm, SoftwareIdentifierType

EXAMPLES_DIR = Path(__file__).parent / "testdata"


def find_packages_by_name():
    """Search for packages by name."""
    print("=" * 60)
    print("Find packages by name")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")
    nl = doc.node_list

    # Exact name lookup
    results = nl.get_nodes_by_name("openssl")
    print(f"\nSearch for 'openssl': {len(results)} result(s)")
    for node in results:
        print(f"  {node.name} {node.version} - {node.description}")

    # Search with no match
    results = nl.get_nodes_by_name("curl")
    print(f"\nSearch for 'curl': {len(results)} result(s)")
    print()


def find_by_purl():
    """Search for packages by PURL type."""
    print("=" * 60)
    print("Find packages by PURL type")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")
    nl = doc.node_list

    # Find all npm packages
    npm_pkgs = nl.get_nodes_by_purl_type("npm")
    print(f"\nAll npm packages ({len(npm_pkgs)}):")
    for node in npm_pkgs:
        purl = node.identifiers.get(int(SoftwareIdentifierType.PURL), "")
        print(f"  {purl}")

    # Now try with the Python app
    doc2 = reader.parse_file(EXAMPLES_DIR / "cdx14-python-app.json")
    nl2 = doc2.node_list

    pypi_pkgs = nl2.get_nodes_by_purl_type("pypi")
    print(f"\nAll PyPI packages ({len(pypi_pkgs)}):")
    for node in pypi_pkgs:
        purl = node.identifiers.get(int(SoftwareIdentifierType.PURL), "")
        print(f"  {purl}")
    print()


def find_by_identifier():
    """Search for packages by specific identifiers (PURL, CPE)."""
    print("=" * 60)
    print("Find packages by specific identifier")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")
    nl = doc.node_list

    # Find by PURL
    target_purl = "pkg:generic/openssl@3.1.4"
    results = nl.get_nodes_by_identifier(SoftwareIdentifierType.PURL, target_purl)
    print(f"\nSearch by PURL '{target_purl}':")
    for node in results:
        print(f"  Found: {node.name} {node.version}")
        print(f"    License: {node.license_concluded}")
        print(f"    Download: {node.url_download}")

    # Find by CPE
    target_cpe = "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    results = nl.get_nodes_by_identifier(SoftwareIdentifierType.CPE23, target_cpe)
    print(f"\nSearch by CPE23 '{target_cpe}':")
    for node in results:
        print(f"  Found: {node.name} {node.version}")
    print()


def traverse_dependencies():
    """Traverse the dependency graph."""
    print("=" * 60)
    print("Traverse dependency graph")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")
    nl = doc.node_list

    # Get all descendants of express
    express_ref = "pkg:npm/express@4.18.2"
    descendants = nl.node_descendants(express_ref)
    print(f"\nAll descendants of express ({len(descendants)}):")
    for node in descendants:
        print(f"  - {node.name}@{node.version}")

    # Depth-limited traversal
    descendants_d1 = nl.node_descendants(express_ref, max_depth=1)
    print(f"\nDirect dependencies of express ({len(descendants_d1)}):")
    for node in descendants_d1:
        print(f"  - {node.name}@{node.version}")

    # Find all edges from nginx in the SPDX doc
    doc2 = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")
    nl2 = doc2.node_list

    nginx_edges = nl2.get_edges_by_from("SPDXRef-Package-nginx")
    print(f"\nAll relationships from nginx ({len(nginx_edges)}):")
    for edge in nginx_edges:
        for target in edge.to:
            target_node = nl2.get_node_by_id(target)
            to_name = target_node.name if target_node else target
            print(f"  nginx --[{edge.type.name}]--> {to_name}")

    # Find a specific relationship type
    contains_edge = nl2.get_edge_by_type("SPDXRef-Package-nginx", EdgeType.contains)
    if contains_edge:
        print(f"\nFiles contained in nginx:")
        for target in contains_edge.to:
            node = nl2.get_node_by_id(target)
            if node:
                print(f"  {node.name}")
    print()


def check_hashes():
    """Inspect package hashes/checksums."""
    print("=" * 60)
    print("Inspect package hashes")
    print("=" * 60)

    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")
    nl = doc.node_list

    print(f"\nPackage checksums:")
    for node in nl.nodes:
        if node.hashes:
            print(f"\n  {node.name} {node.version}:")
            for algo_int, digest in node.hashes.items():
                algo_name = HashAlgorithm(algo_int).name
                print(f"    {algo_name}: {digest}")
    print()


if __name__ == "__main__":
    find_packages_by_name()
    find_by_purl()
    find_by_identifier()
    traverse_dependencies()
    check_hashes()

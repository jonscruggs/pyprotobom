#!/usr/bin/env python3
"""Example: Translate between SBOM formats.

Demonstrates reading an SPDX document and writing it out as CycloneDX,
and vice versa. This is the core use case of protobom — lossless
format translation through its neutral intermediate representation.

Usage:
    python examples/translate_sbom.py
"""

import io
import json
from pathlib import Path

from protobom import Reader, Writer
from protobom.formats import CDX15JSON, SPDX23JSON, Format
from protobom.writer import WriteOptions

EXAMPLES_DIR = Path(__file__).parent / "testdata"
OUTPUT_DIR = Path(__file__).parent / "output"


def spdx_to_cyclonedx():
    """Read an SPDX 2.3 SBOM and translate it to CycloneDX 1.5."""
    print("=" * 60)
    print("SPDX 2.3 → CycloneDX 1.5")
    print("=" * 60)

    # Parse the SPDX document
    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")

    print(f"\nParsed SPDX document: {doc.metadata.name}")
    print(f"  Nodes: {len(doc.node_list.nodes)}")
    print(f"  Edges: {len(doc.node_list.edges)}")

    # Write as CycloneDX 1.5
    writer = Writer()
    buf = io.BytesIO()
    writer.write_stream(
        doc, buf,
        options=WriteOptions(format=Format(CDX15JSON)),
    )

    # Show the output
    buf.seek(0)
    cdx_output = json.loads(buf.read().decode("utf-8"))

    print(f"\nCycloneDX output:")
    print(f"  bomFormat:   {cdx_output['bomFormat']}")
    print(f"  specVersion: {cdx_output['specVersion']}")
    print(f"  Components:  {len(cdx_output.get('components', []))}")
    print(f"  Dependencies:{len(cdx_output.get('dependencies', []))}")

    print(f"\n  Components in output:")
    for comp in cdx_output.get("components", []):
        print(f"    - {comp['name']} {comp.get('version', '')} [{comp['type']}]")

    # Also write to file
    OUTPUT_DIR.mkdir(exist_ok=True)
    output_path = OUTPUT_DIR / "nginx-translated.cdx.json"
    writer.write_file(
        doc, output_path,
        options=WriteOptions(format=Format(CDX15JSON)),
    )
    print(f"\n  Written to: {output_path}")
    print()


def cyclonedx_to_spdx():
    """Read a CycloneDX 1.5 SBOM and translate it to SPDX 2.3."""
    print("=" * 60)
    print("CycloneDX 1.5 → SPDX 2.3")
    print("=" * 60)

    # Parse the CycloneDX document
    reader = Reader()
    doc = reader.parse_file(EXAMPLES_DIR / "cdx15-example.json")

    print(f"\nParsed CycloneDX document: {doc.metadata.name}")
    print(f"  Nodes: {len(doc.node_list.nodes)}")
    print(f"  Edges: {len(doc.node_list.edges)}")

    # Write as SPDX 2.3
    writer = Writer()
    buf = io.BytesIO()
    writer.write_stream(
        doc, buf,
        options=WriteOptions(format=Format(SPDX23JSON)),
    )

    # Show the output
    buf.seek(0)
    spdx_output = json.loads(buf.read().decode("utf-8"))

    print(f"\nSPDX output:")
    print(f"  spdxVersion: {spdx_output['spdxVersion']}")
    print(f"  name:        {spdx_output['name']}")
    print(f"  Packages:    {len(spdx_output.get('packages', []))}")
    print(f"  Relationships: {len(spdx_output.get('relationships', []))}")

    print(f"\n  Packages in output:")
    for pkg in spdx_output.get("packages", []):
        print(f"    - {pkg['name']} {pkg.get('versionInfo', '')} ({pkg.get('licenseDeclared', 'N/A')})")

    # Also write to file
    OUTPUT_DIR.mkdir(exist_ok=True)
    output_path = OUTPUT_DIR / "web-app-translated.spdx.json"
    writer.write_file(
        doc, output_path,
        options=WriteOptions(format=Format(SPDX23JSON)),
    )
    print(f"\n  Written to: {output_path}")
    print()


def round_trip():
    """Demonstrate round-trip: SPDX → protobom → CycloneDX → protobom → SPDX."""
    print("=" * 60)
    print("Round trip: SPDX → CDX → SPDX")
    print("=" * 60)

    reader = Reader()
    writer = Writer()

    # Step 1: Read SPDX
    doc_original = reader.parse_file(EXAMPLES_DIR / "spdx23-example.json")
    original_count = len(doc_original.node_list.nodes)
    print(f"\n1. Read SPDX: {original_count} nodes")

    # Step 2: Write as CycloneDX
    cdx_buf = io.BytesIO()
    writer.write_stream(
        doc_original, cdx_buf,
        options=WriteOptions(format=Format(CDX15JSON)),
    )
    cdx_buf.seek(0)
    print(f"2. Wrote as CycloneDX ({cdx_buf.getbuffer().nbytes} bytes)")

    # Step 3: Re-read from CycloneDX
    doc_cdx = reader.parse_stream(cdx_buf)
    cdx_count = len(doc_cdx.node_list.nodes)
    print(f"3. Re-read from CycloneDX: {cdx_count} nodes")

    # Step 4: Write back to SPDX
    spdx_buf = io.BytesIO()
    writer.write_stream(
        doc_cdx, spdx_buf,
        options=WriteOptions(format=Format(SPDX23JSON)),
    )
    spdx_buf.seek(0)
    print(f"4. Wrote back as SPDX ({spdx_buf.getbuffer().nbytes} bytes)")

    # Step 5: Re-read and compare
    doc_final = reader.parse_stream(spdx_buf)
    final_count = len(doc_final.node_list.nodes)
    print(f"5. Re-read final SPDX: {final_count} nodes")

    # Compare node names
    original_names = sorted(n.name for n in doc_original.node_list.nodes)
    final_names = sorted(n.name for n in doc_final.node_list.nodes)

    if original_names == final_names:
        print("\n   All component names preserved through round-trip!")
    else:
        print(f"\n   Original: {original_names}")
        print(f"   Final:    {final_names}")
    print()


if __name__ == "__main__":
    spdx_to_cyclonedx()
    cyclonedx_to_spdx()
    round_trip()

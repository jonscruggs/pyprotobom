"""Tests for Reader and Writer with round-trip verification."""

import io
import json

from protobom.formats import CDX15JSON, SPDX23JSON, Format
from protobom.reader import Reader, ReadOptions
from protobom.writer import Writer, WriteOptions
from protobom.sbom import (
    Document,
    Edge,
    EdgeType,
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    Metadata,
    Node,
    NodeList,
    NodeType,
    Person,
    Property,
    Purpose,
    SoftwareIdentifierType,
    Tool,
)


# ---------------------------------------------------------------------------
# Sample CycloneDX document
# ---------------------------------------------------------------------------
SAMPLE_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {
        "timestamp": "2024-01-15T10:30:00Z",
        "tools": [
            {"name": "test-tool", "version": "1.0.0", "vendor": "TestCo"}
        ],
        "authors": [
            {"name": "Test Author", "email": "test@example.com"}
        ],
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg-1",
            "name": "my-lib",
            "version": "2.0.0",
            "purl": "pkg:npm/my-lib@2.0.0",
            "licenses": [{"license": {"id": "MIT"}}],
            "hashes": [
                {"alg": "SHA-256", "content": "abc123def456"},
            ],
            "externalReferences": [
                {"type": "website", "url": "https://example.com"}
            ],
            "properties": [
                {"name": "custom:key", "value": "custom-value"}
            ],
        },
        {
            "type": "application",
            "bom-ref": "pkg-2",
            "name": "my-app",
            "version": "1.0.0",
            "description": "A test application",
            "supplier": {"name": "SupplierCo"},
        },
    ],
    "dependencies": [
        {"ref": "pkg-2", "dependsOn": ["pkg-1"]},
        {"ref": "pkg-1", "dependsOn": []},
    ],
}


# ---------------------------------------------------------------------------
# Sample SPDX document
# ---------------------------------------------------------------------------
SAMPLE_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test-document",
    "documentNamespace": "https://example.com/test",
    "creationInfo": {
        "created": "2024-01-15T10:30:00Z",
        "creators": [
            "Tool: test-tool-1.0.0",
            "Person: Test Author (test@example.com)",
        ],
    },
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-1",
            "name": "my-package",
            "versionInfo": "3.0.0",
            "downloadLocation": "https://example.com/download",
            "homepage": "https://example.com",
            "copyrightText": "Copyright 2024 Test",
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "primaryPackagePurpose": "LIBRARY",
            "supplier": "Organization: TestOrg (org@example.com)",
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": "abc123"},
            ],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/my-package@3.0.0",
                },
            ],
        },
    ],
    "files": [
        {
            "SPDXID": "SPDXRef-File-1",
            "fileName": "README.md",
            "copyrightText": "NOASSERTION",
            "licenseConcluded": "MIT",
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            ],
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-1",
        },
        {
            "spdxElementId": "SPDXRef-Package-1",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-File-1",
        },
    ],
}


class TestCDXReaderWriter:
    """Test CycloneDX read/write."""

    def test_read_cyclonedx(self):
        stream = io.BytesIO(json.dumps(SAMPLE_CDX).encode())
        reader = Reader()
        doc = reader.parse_stream(stream)

        assert doc.metadata.id == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        assert doc.metadata.version == "1"
        assert len(doc.metadata.tools) == 1
        assert doc.metadata.tools[0].name == "test-tool"
        assert len(doc.metadata.authors) == 1
        assert doc.metadata.authors[0].email == "test@example.com"

        # Check nodes
        assert len(doc.node_list.nodes) == 2
        pkg1 = doc.node_list.get_node_by_id("pkg-1")
        assert pkg1 is not None
        assert pkg1.name == "my-lib"
        assert pkg1.version == "2.0.0"
        assert pkg1.licenses == ["MIT"]
        assert pkg1.hashes[int(HashAlgorithm.SHA256)] == "abc123def456"
        assert pkg1.identifiers[int(SoftwareIdentifierType.PURL)] == "pkg:npm/my-lib@2.0.0"
        assert len(pkg1.external_references) == 1
        assert len(pkg1.properties) == 1
        assert pkg1.properties[0].name == "custom:key"

        pkg2 = doc.node_list.get_node_by_id("pkg-2")
        assert pkg2 is not None
        assert pkg2.name == "my-app"
        assert pkg2.primary_purpose == [Purpose.APPLICATION]
        assert pkg2.description == "A test application"

        # Check dependencies
        dep_edge = doc.node_list.get_edge_by_type("pkg-2", EdgeType.dependsOn)
        assert dep_edge is not None
        assert "pkg-1" in dep_edge.to

        # Source data
        assert doc.metadata.source_data is not None
        assert doc.metadata.source_data.size > 0

    def test_write_cyclonedx(self):
        doc = _make_test_document()
        writer = Writer()
        buf = io.BytesIO()
        writer.write_stream(
            doc, buf, WriteOptions(format=Format(CDX15JSON))
        )
        buf.seek(0)
        result = json.loads(buf.read())

        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.5"
        assert len(result["components"]) == 1
        comp = result["components"][0]
        assert comp["name"] == "test-pkg"
        assert comp["version"] == "1.0.0"
        assert comp["type"] == "library"

    def test_roundtrip_cyclonedx(self):
        """Read a CDX document, write it back, and verify key data is preserved."""
        stream = io.BytesIO(json.dumps(SAMPLE_CDX).encode())
        reader = Reader()
        doc = reader.parse_stream(stream)

        writer = Writer()
        buf = io.BytesIO()
        writer.write_stream(
            doc, buf, WriteOptions(format=Format(CDX15JSON))
        )
        buf.seek(0)
        result = json.loads(buf.read())

        assert result["bomFormat"] == "CycloneDX"
        assert len(result["components"]) == 2

        # Verify component data preserved
        names = {c["name"] for c in result["components"]}
        assert "my-lib" in names
        assert "my-app" in names


class TestSPDXReaderWriter:
    """Test SPDX 2.3 read/write."""

    def test_read_spdx(self):
        stream = io.BytesIO(json.dumps(SAMPLE_SPDX).encode())
        reader = Reader()
        doc = reader.parse_stream(stream)

        assert "example.com/test" in doc.metadata.id
        assert doc.metadata.name == "test-document"
        assert doc.metadata.version == "SPDX-2.3"
        assert len(doc.metadata.tools) == 1
        assert doc.metadata.tools[0].name == "test-tool"
        assert len(doc.metadata.authors) == 1

        # Check package
        pkg = doc.node_list.get_node_by_id("SPDXRef-Package-1")
        assert pkg is not None
        assert pkg.name == "my-package"
        assert pkg.version == "3.0.0"
        assert pkg.license_concluded == "Apache-2.0"
        assert pkg.primary_purpose == [Purpose.LIBRARY]
        assert pkg.hashes[int(HashAlgorithm.SHA256)] == "abc123"
        assert pkg.identifiers[int(SoftwareIdentifierType.PURL)] == "pkg:npm/my-package@3.0.0"
        assert pkg.copyright == "Copyright 2024 Test"
        assert len(pkg.suppliers) == 1
        assert pkg.suppliers[0].is_org

        # Check file
        file_node = doc.node_list.get_node_by_id("SPDXRef-File-1")
        assert file_node is not None
        assert file_node.type == NodeType.FILE
        assert file_node.name == "README.md"
        assert file_node.license_concluded == "MIT"

        # Check root elements
        assert "SPDXRef-Package-1" in doc.node_list.root_elements

        # Check relationships
        edge = doc.node_list.get_edge_by_type("SPDXRef-Package-1", EdgeType.contains)
        assert edge is not None
        assert "SPDXRef-File-1" in edge.to

    def test_write_spdx(self):
        doc = _make_test_document()
        writer = Writer()
        buf = io.BytesIO()
        writer.write_stream(
            doc, buf, WriteOptions(format=Format(SPDX23JSON))
        )
        buf.seek(0)
        result = json.loads(buf.read())

        assert result["spdxVersion"] == "SPDX-2.3"
        assert result["dataLicense"] == "CC0-1.0"
        assert len(result["packages"]) == 1
        pkg = result["packages"][0]
        assert pkg["name"] == "test-pkg"
        assert pkg["versionInfo"] == "1.0.0"

    def test_roundtrip_spdx(self):
        """Read an SPDX document, write it back, and verify key data is preserved."""
        stream = io.BytesIO(json.dumps(SAMPLE_SPDX).encode())
        reader = Reader()
        doc = reader.parse_stream(stream)

        writer = Writer()
        buf = io.BytesIO()
        writer.write_stream(
            doc, buf, WriteOptions(format=Format(SPDX23JSON))
        )
        buf.seek(0)
        result = json.loads(buf.read())

        assert result["spdxVersion"] == "SPDX-2.3"
        assert len(result["packages"]) == 1
        assert result["packages"][0]["name"] == "my-package"
        assert len(result["files"]) == 1
        assert result["files"][0]["fileName"] == "README.md"

    def test_cross_format_cdx_to_spdx(self):
        """Read CycloneDX, write as SPDX."""
        stream = io.BytesIO(json.dumps(SAMPLE_CDX).encode())
        reader = Reader()
        doc = reader.parse_stream(stream)

        writer = Writer()
        buf = io.BytesIO()
        writer.write_stream(
            doc, buf, WriteOptions(format=Format(SPDX23JSON))
        )
        buf.seek(0)
        result = json.loads(buf.read())

        assert result["spdxVersion"] == "SPDX-2.3"
        assert len(result["packages"]) == 2
        names = {p["name"] for p in result["packages"]}
        assert "my-lib" in names
        assert "my-app" in names

    def test_cross_format_spdx_to_cdx(self):
        """Read SPDX, write as CycloneDX."""
        stream = io.BytesIO(json.dumps(SAMPLE_SPDX).encode())
        reader = Reader()
        doc = reader.parse_stream(stream)

        writer = Writer()
        buf = io.BytesIO()
        writer.write_stream(
            doc, buf, WriteOptions(format=Format(CDX15JSON))
        )
        buf.seek(0)
        result = json.loads(buf.read())

        assert result["bomFormat"] == "CycloneDX"
        # Packages become components, files may or may not appear
        assert len(result["components"]) >= 1


class TestReaderErrors:
    def test_unknown_format(self):
        stream = io.BytesIO(b"not a valid sbom document")
        reader = Reader()
        try:
            reader.parse_stream(stream)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Unable to detect" in str(e)

    def test_writer_no_format(self):
        doc = Document()
        writer = Writer()
        buf = io.BytesIO()
        try:
            writer.write_stream(doc, buf)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "format must be specified" in str(e)


def _make_test_document() -> Document:
    """Create a simple test document."""
    node = Node(
        id="SPDXRef-test-pkg",
        type=NodeType.PACKAGE,
        name="test-pkg",
        version="1.0.0",
        licenses=["MIT"],
        primary_purpose=[Purpose.LIBRARY],
        hashes={int(HashAlgorithm.SHA256): "abc123"},
        identifiers={int(SoftwareIdentifierType.PURL): "pkg:npm/test-pkg@1.0.0"},
    )
    nl = NodeList()
    nl.add_root_node(node)

    return Document(
        metadata=Metadata(
            id="test-doc-id",
            name="test-document",
            tools=[Tool(name="protobom-python", version="0.1.0")],
        ),
        node_list=nl,
    )

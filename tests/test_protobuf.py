"""Tests for protobuf serialization/deserialization round-trips."""

import io
from datetime import datetime, timezone
from pathlib import Path

from protobom.sbom import (
    Document,
    DocumentType,
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
    SBOMType,
    SoftwareIdentifierType,
    SourceData,
    Tool,
)
from protobom.generated import sbom_pb2 as pb

TESTDATA_DIR = Path(__file__).parent.parent / "examples" / "testdata"


class TestProtoConversion:
    """Test to_proto() / from_proto() round-trips for each type."""

    def test_property_roundtrip(self):
        original = Property(name="key", data="value")
        restored = Property.from_proto(original.to_proto())
        assert restored.name == "key"
        assert restored.data == "value"

    def test_person_roundtrip(self):
        original = Person(
            name="Alice",
            is_org=True,
            email="alice@example.com",
            url="https://example.com",
            phone="555-1234",
            contacts=[Person(name="Bob", email="bob@example.com")],
        )
        restored = Person.from_proto(original.to_proto())
        assert restored.name == "Alice"
        assert restored.is_org is True
        assert restored.email == "alice@example.com"
        assert len(restored.contacts) == 1
        assert restored.contacts[0].name == "Bob"

    def test_tool_roundtrip(self):
        original = Tool(name="scanner", version="2.0", vendor="Acme")
        restored = Tool.from_proto(original.to_proto())
        assert restored.name == "scanner"
        assert restored.version == "2.0"
        assert restored.vendor == "Acme"

    def test_external_reference_roundtrip(self):
        original = ExternalReference(
            url="https://example.com/advisory",
            type=ExternalReferenceType.SECURITY_ADVISORY,
            comment="Critical fix",
            authority="CERT",
            hashes={int(HashAlgorithm.SHA256): "abc123"},
        )
        restored = ExternalReference.from_proto(original.to_proto())
        assert restored.url == "https://example.com/advisory"
        assert restored.type == ExternalReferenceType.SECURITY_ADVISORY
        assert restored.comment == "Critical fix"
        assert restored.hashes[int(HashAlgorithm.SHA256)] == "abc123"

    def test_document_type_roundtrip(self):
        original = DocumentType(
            type=SBOMType.BUILD, name="build", description="Build phase SBOM"
        )
        restored = DocumentType.from_proto(original.to_proto())
        assert restored.type == SBOMType.BUILD
        assert restored.name == "build"

    def test_source_data_roundtrip(self):
        original = SourceData(
            format="text/spdx+json;version=2.3",
            hashes={int(HashAlgorithm.SHA256): "deadbeef"},
            size=4096,
            uri="https://example.com/sbom.json",
        )
        restored = SourceData.from_proto(original.to_proto())
        assert restored.format == "text/spdx+json;version=2.3"
        assert restored.size == 4096
        assert restored.uri == "https://example.com/sbom.json"

    def test_node_roundtrip(self):
        original = Node(
            id="pkg-1",
            type=NodeType.PACKAGE,
            name="my-package",
            version="1.0.0",
            licenses=["MIT", "Apache-2.0"],
            hashes={int(HashAlgorithm.SHA256): "abc123"},
            primary_purpose=[Purpose.LIBRARY],
            identifiers={int(SoftwareIdentifierType.PURL): "pkg:npm/my-package@1.0.0"},
            suppliers=[Person(name="Acme Corp", is_org=True)],
            properties=[Property(name="ecosystem", data="npm")],
            external_references=[
                ExternalReference(url="https://example.com", type=ExternalReferenceType.WEBSITE)
            ],
            copyright="Copyright 2024",
            description="A test package",
            release_date=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        restored = Node.from_proto(original.to_proto())
        assert restored.id == "pkg-1"
        assert restored.name == "my-package"
        assert restored.version == "1.0.0"
        assert restored.licenses == ["MIT", "Apache-2.0"]
        assert restored.hashes[int(HashAlgorithm.SHA256)] == "abc123"
        assert restored.primary_purpose == [Purpose.LIBRARY]
        assert restored.identifiers[int(SoftwareIdentifierType.PURL)] == "pkg:npm/my-package@1.0.0"
        assert len(restored.suppliers) == 1
        assert restored.suppliers[0].name == "Acme Corp"
        assert len(restored.properties) == 1
        assert len(restored.external_references) == 1
        assert restored.release_date == datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_edge_roundtrip(self):
        original = Edge(
            type=EdgeType.dependsOn,
            from_="pkg-a",
            to=["pkg-b", "pkg-c"],
        )
        restored = Edge.from_proto(original.to_proto())
        assert restored.type == EdgeType.dependsOn
        assert restored.from_ == "pkg-a"
        assert restored.to == ["pkg-b", "pkg-c"]

    def test_node_list_roundtrip(self):
        nl = NodeList()
        nl.add_node(Node(id="a", name="A"))
        nl.add_node(Node(id="b", name="B"))
        nl.add_edge(Edge(type=EdgeType.dependsOn, from_="a", to=["b"]))
        nl.root_elements.append("a")

        restored = NodeList.from_proto(nl.to_proto())
        assert len(restored.nodes) == 2
        assert len(restored.edges) == 1
        assert restored.root_elements == ["a"]
        assert restored.get_node_by_id("a").name == "A"

    def test_metadata_roundtrip(self):
        original = Metadata(
            id="test-doc",
            version="1",
            name="Test",
            date=datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
            tools=[Tool(name="scanner", version="1.0")],
            authors=[Person(name="Alice")],
            comment="A test document",
            document_types=[DocumentType(type=SBOMType.BUILD)],
            source_data=SourceData(format="test", size=100),
        )
        restored = Metadata.from_proto(original.to_proto())
        assert restored.id == "test-doc"
        assert restored.name == "Test"
        assert restored.date == datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert len(restored.tools) == 1
        assert len(restored.authors) == 1
        assert restored.source_data is not None
        assert restored.source_data.size == 100


class TestProtobufBinarySerialization:
    """Test full document protobuf binary serialization."""

    def _make_document(self) -> Document:
        nl = NodeList()
        nl.add_node(Node(
            id="pkg:npm/express@4.18.2",
            name="express",
            version="4.18.2",
            licenses=["MIT"],
            primary_purpose=[Purpose.LIBRARY],
            identifiers={int(SoftwareIdentifierType.PURL): "pkg:npm/express@4.18.2"},
            hashes={int(HashAlgorithm.SHA256): "deadbeef"},
        ))
        nl.add_node(Node(
            id="pkg:npm/debug@4.3.4",
            name="debug",
            version="4.3.4",
        ))
        nl.add_edge(Edge(
            type=EdgeType.dependsOn,
            from_="pkg:npm/express@4.18.2",
            to=["pkg:npm/debug@4.3.4"],
        ))
        nl.root_elements.append("pkg:npm/express@4.18.2")

        return Document(
            metadata=Metadata(
                id="test-sbom",
                name="test-app",
                version="1",
                date=datetime(2024, 1, 1, tzinfo=timezone.utc),
                tools=[Tool(name="test-tool", version="1.0")],
            ),
            node_list=nl,
        )

    def test_serialize_deserialize_roundtrip(self):
        doc = self._make_document()
        data = doc.serialize_to_proto()
        assert isinstance(data, bytes)
        assert len(data) > 0

        restored = Document.deserialize_from_proto(data)
        assert restored.metadata.id == "test-sbom"
        assert restored.metadata.name == "test-app"
        assert len(restored.node_list.nodes) == 2
        assert len(restored.node_list.edges) == 1
        assert restored.node_list.root_elements == ["pkg:npm/express@4.18.2"]

        # Verify node data preserved
        express = restored.node_list.get_node_by_id("pkg:npm/express@4.18.2")
        assert express is not None
        assert express.name == "express"
        assert express.version == "4.18.2"
        assert express.licenses == ["MIT"]
        assert express.hashes[int(HashAlgorithm.SHA256)] == "deadbeef"

    def test_proto_message_interop(self):
        """Test that we can work with raw protobuf messages."""
        doc = self._make_document()
        pb_doc = doc.to_proto()

        # Access via protobuf API
        assert pb_doc.metadata.id == "test-sbom"
        assert len(pb_doc.node_list.nodes) == 2
        assert pb_doc.node_list.root_elements == ["pkg:npm/express@4.18.2"]

        # Serialize via protobuf and restore via our API
        data = pb_doc.SerializeToString()
        restored = Document.deserialize_from_proto(data)
        assert restored.metadata.name == "test-app"

    def test_writer_protobuf_format(self):
        """Test writing to protobuf binary format via Writer."""
        from protobom.writer import Writer, WriteOptions
        from protobom.formats import Format, PROTOBUF

        doc = self._make_document()
        buf = io.BytesIO()
        writer = Writer()
        writer.write_stream(doc, buf, WriteOptions(format=Format(PROTOBUF)))

        buf.seek(0)
        restored = Document.deserialize_from_proto(buf.read())
        assert restored.metadata.name == "test-app"
        assert len(restored.node_list.nodes) == 2

    def test_reader_protobuf_format(self):
        """Test reading from protobuf binary format via Reader."""
        from protobom.reader import Reader

        doc = self._make_document()
        data = doc.serialize_to_proto()

        reader = Reader()
        restored = reader.parse_stream(io.BytesIO(data))
        assert restored.metadata.name == "test-app"
        assert len(restored.node_list.nodes) == 2

    def test_cross_format_roundtrip(self):
        """Test: parse JSON SBOM -> protobuf binary -> restore."""
        if not (TESTDATA_DIR / "cdx15-example.json").exists():
            return  # skip if no test data

        from protobom.reader import Reader

        reader = Reader()
        doc = reader.parse_file(TESTDATA_DIR / "cdx15-example.json")

        # Serialize to protobuf binary
        data = doc.serialize_to_proto()
        assert len(data) > 0

        # Restore from protobuf binary
        restored = Document.deserialize_from_proto(data)
        assert len(restored.node_list.nodes) == len(doc.node_list.nodes)

        # Node names should be preserved
        original_names = sorted(n.name for n in doc.node_list.nodes)
        restored_names = sorted(n.name for n in restored.node_list.nodes)
        assert original_names == restored_names

    def test_empty_document_roundtrip(self):
        doc = Document()
        data = doc.serialize_to_proto()
        restored = Document.deserialize_from_proto(data)
        assert restored.metadata.id == ""
        assert len(restored.node_list.nodes) == 0

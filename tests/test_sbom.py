"""Tests for core SBOM data models."""

import copy

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


class TestNode:
    def test_create_default_node(self):
        node = Node()
        assert node.id == ""
        assert node.type == NodeType.PACKAGE
        assert node.name == ""
        assert node.version == ""
        assert node.licenses == []
        assert node.hashes == {}
        assert node.primary_purpose == []

    def test_create_node_with_values(self):
        node = Node(
            id="pkg-1",
            type=NodeType.PACKAGE,
            name="my-package",
            version="1.0.0",
            licenses=["MIT"],
            hashes={int(HashAlgorithm.SHA256): "abc123"},
            primary_purpose=[Purpose.LIBRARY],
        )
        assert node.id == "pkg-1"
        assert node.name == "my-package"
        assert node.version == "1.0.0"
        assert node.licenses == ["MIT"]
        assert node.hashes[int(HashAlgorithm.SHA256)] == "abc123"
        assert node.primary_purpose == [Purpose.LIBRARY]

    def test_node_identifiers(self):
        node = Node(
            identifiers={
                int(SoftwareIdentifierType.PURL): "pkg:npm/express@4.18.2",
                int(SoftwareIdentifierType.CPE23): "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*",
            }
        )
        assert node.identifiers[int(SoftwareIdentifierType.PURL)] == "pkg:npm/express@4.18.2"

    def test_node_external_references(self):
        node = Node(
            external_references=[
                ExternalReference(
                    url="https://example.com",
                    type=ExternalReferenceType.WEBSITE,
                )
            ]
        )
        assert len(node.external_references) == 1
        assert node.external_references[0].url == "https://example.com"

    def test_node_properties(self):
        node = Node(
            properties=[
                Property(name="key1", data="value1"),
                Property(name="key2", data="value2"),
            ]
        )
        assert len(node.properties) == 2
        assert node.properties[0].name == "key1"


class TestEdge:
    def test_create_edge(self):
        edge = Edge(
            type=EdgeType.dependsOn,
            from_="pkg-a",
            to=["pkg-b", "pkg-c"],
        )
        assert edge.type == EdgeType.dependsOn
        assert edge.from_ == "pkg-a"
        assert edge.to == ["pkg-b", "pkg-c"]


class TestNodeList:
    def _make_node_list(self):
        nl = NodeList()
        nl.add_node(Node(id="a", name="A", version="1.0"))
        nl.add_node(Node(id="b", name="B", version="2.0"))
        nl.add_node(Node(id="c", name="C", version="3.0"))
        nl.add_edge(Edge(type=EdgeType.dependsOn, from_="a", to=["b"]))
        nl.add_edge(Edge(type=EdgeType.contains, from_="a", to=["c"]))
        nl.root_elements.append("a")
        nl._root_index.add("a")
        return nl

    def test_add_node(self):
        nl = NodeList()
        node = Node(id="test", name="Test")
        nl.add_node(node)
        assert len(nl.nodes) == 1
        assert nl.get_node_by_id("test") is node

    def test_add_root_node(self):
        nl = NodeList()
        node = Node(id="root", name="Root")
        nl.add_root_node(node)
        assert "root" in nl.root_elements
        assert nl.get_root_nodes() == [node]

    def test_get_node_by_id(self):
        nl = self._make_node_list()
        assert nl.get_node_by_id("a").name == "A"
        assert nl.get_node_by_id("missing") is None

    def test_get_nodes_by_name(self):
        nl = self._make_node_list()
        results = nl.get_nodes_by_name("B")
        assert len(results) == 1
        assert results[0].id == "b"

    def test_get_root_nodes(self):
        nl = self._make_node_list()
        roots = nl.get_root_nodes()
        assert len(roots) == 1
        assert roots[0].id == "a"

    def test_get_edge_by_type(self):
        nl = self._make_node_list()
        edge = nl.get_edge_by_type("a", EdgeType.dependsOn)
        assert edge is not None
        assert edge.to == ["b"]
        assert nl.get_edge_by_type("a", EdgeType.ancestor) is None

    def test_remove_nodes(self):
        nl = self._make_node_list()
        nl.remove_nodes(["b"])
        assert nl.get_node_by_id("b") is None
        assert len(nl.nodes) == 2
        # Edge from a->b should be removed since b is gone
        dep_edge = nl.get_edge_by_type("a", EdgeType.dependsOn)
        assert dep_edge is None

    def test_node_descendants(self):
        nl = self._make_node_list()
        descendants = nl.node_descendants("a")
        desc_ids = {n.id for n in descendants}
        assert "b" in desc_ids
        assert "c" in desc_ids

    def test_node_descendants_max_depth(self):
        nl = NodeList()
        nl.add_node(Node(id="1"))
        nl.add_node(Node(id="2"))
        nl.add_node(Node(id="3"))
        nl.add_edge(Edge(type=EdgeType.contains, from_="1", to=["2"]))
        nl.add_edge(Edge(type=EdgeType.contains, from_="2", to=["3"]))
        # Depth 1 should only get immediate children
        desc = nl.node_descendants("1", max_depth=1)
        desc_ids = {n.id for n in desc}
        assert "2" in desc_ids
        assert "3" not in desc_ids

    def test_union(self):
        nl1 = NodeList()
        nl1.add_node(Node(id="a", name="A"))
        nl2 = NodeList()
        nl2.add_node(Node(id="b", name="B"))

        result = nl1.union(nl2)
        assert len(result.nodes) == 2
        assert result.get_node_by_id("a") is not None
        assert result.get_node_by_id("b") is not None

    def test_intersect(self):
        nl1 = NodeList()
        nl1.add_node(Node(id="a", name="A"))
        nl1.add_node(Node(id="b", name="B"))
        nl2 = NodeList()
        nl2.add_node(Node(id="b", name="B"))
        nl2.add_node(Node(id="c", name="C"))

        result = nl1.intersect(nl2)
        assert len(result.nodes) == 1
        assert result.get_node_by_id("b") is not None

    def test_copy(self):
        nl = self._make_node_list()
        nl_copy = nl.copy()
        assert len(nl_copy.nodes) == len(nl.nodes)
        # Modifying copy shouldn't affect original
        nl_copy.nodes[0].name = "Modified"
        assert nl.nodes[0].name == "A"

    def test_equal(self):
        nl1 = NodeList()
        nl1.add_node(Node(id="a"))
        nl1.add_node(Node(id="b"))
        nl2 = NodeList()
        nl2.add_node(Node(id="b"))
        nl2.add_node(Node(id="a"))
        assert nl1.equal(nl2)

    def test_relate_node_at_id(self):
        nl = NodeList()
        nl.add_node(Node(id="parent"))
        child = Node(id="child")
        nl.relate_node_at_id(child, "parent", EdgeType.contains)
        assert nl.get_node_by_id("child") is not None
        edge = nl.get_edge_by_type("parent", EdgeType.contains)
        assert edge is not None
        assert "child" in edge.to

    def test_get_nodes_by_identifier(self):
        nl = NodeList()
        nl.add_node(Node(
            id="a",
            identifiers={int(SoftwareIdentifierType.PURL): "pkg:npm/foo@1.0"},
        ))
        nl.add_node(Node(id="b"))
        results = nl.get_nodes_by_identifier(
            SoftwareIdentifierType.PURL, "pkg:npm/foo@1.0"
        )
        assert len(results) == 1
        assert results[0].id == "a"

    def test_get_nodes_by_purl_type(self):
        nl = NodeList()
        nl.add_node(Node(
            id="a",
            identifiers={int(SoftwareIdentifierType.PURL): "pkg:npm/foo@1.0"},
        ))
        nl.add_node(Node(
            id="b",
            identifiers={int(SoftwareIdentifierType.PURL): "pkg:pypi/bar@2.0"},
        ))
        results = nl.get_nodes_by_purl_type("npm")
        assert len(results) == 1
        assert results[0].id == "a"


class TestDocument:
    def test_create_document(self):
        doc = Document()
        assert doc.metadata is not None
        assert doc.node_list is not None

    def test_document_with_metadata(self):
        doc = Document(
            metadata=Metadata(
                id="test-doc",
                name="Test Document",
                tools=[Tool(name="test-tool", version="1.0")],
                authors=[Person(name="Test Author")],
            )
        )
        assert doc.metadata.id == "test-doc"
        assert doc.metadata.name == "Test Document"
        assert len(doc.metadata.tools) == 1
        assert len(doc.metadata.authors) == 1


class TestEnums:
    def test_node_type_values(self):
        assert NodeType.PACKAGE == 0
        assert NodeType.FILE == 1

    def test_hash_algorithm_values(self):
        assert HashAlgorithm.SHA256 == 3
        assert HashAlgorithm.SHA512 == 5

    def test_edge_type_values(self):
        assert EdgeType.contains == 5
        assert EdgeType.dependsOn == 10
        assert EdgeType.describes == 13

    def test_purpose_values(self):
        assert Purpose.APPLICATION == 1
        assert Purpose.LIBRARY == 16

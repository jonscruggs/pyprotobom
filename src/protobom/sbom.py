"""Core SBOM data models mirroring the protobom protobuf schema.

Each dataclass provides to_proto() and from_proto() methods for converting
to/from the generated protobuf message types in protobom.generated.sbom_pb2.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional

from google.protobuf.timestamp_pb2 import Timestamp as PbTimestamp

from protobom.generated import sbom_pb2 as pb


# ---------------------------------------------------------------------------
# Enumerations  (values match the proto definitions exactly)
# ---------------------------------------------------------------------------

class NodeType(IntEnum):
    """Type of a node in the SBOM graph."""
    PACKAGE = 0
    FILE = 1


class SBOMType(IntEnum):
    """Type/phase of the SBOM document."""
    OTHER = 0
    DESIGN = 1
    SOURCE = 2
    BUILD = 3
    ANALYZED = 4
    DEPLOYED = 5
    RUNTIME = 6
    DISCOVERY = 7
    DECOMISSION = 8


class HashAlgorithm(IntEnum):
    """Hash algorithm identifiers."""
    UNKNOWN = 0
    MD5 = 1
    SHA1 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5
    SHA3_256 = 6
    SHA3_384 = 7
    SHA3_512 = 8
    BLAKE2B_256 = 9
    BLAKE2B_384 = 10
    BLAKE2B_512 = 11
    BLAKE3 = 12
    MD2 = 13
    ADLER32 = 14
    MD4 = 15
    MD6 = 16
    SHA224 = 17


class EdgeType(IntEnum):
    """Relationship type between nodes."""
    UNKNOWN = 0
    amends = 1
    ancestor = 2
    buildDependency = 3
    buildTool = 4
    contains = 5
    contained_by = 6
    copy = 7
    dataFile = 8
    dependencyManifest = 9
    dependsOn = 10
    dependencyOf = 11
    descendant = 12
    describes = 13
    describedBy = 14
    devDependency = 15
    devTool = 16
    distributionArtifact = 17
    documentation = 18
    dynamicLink = 19
    example = 20
    expandedFromArchive = 21
    fileAdded = 22
    fileDeleted = 23
    fileModified = 24
    generates = 25
    generatedFrom = 26
    metafile = 27
    optionalComponent = 28
    optionalDependency = 29
    other = 30
    packages = 31
    patch = 32
    prerequisite = 33
    prerequisiteFor = 34
    providedDependency = 35
    requirementFor = 36
    runtimeDependency = 37
    specificationFor = 38
    staticLink = 39
    test = 40
    testCase = 41
    testDependency = 42
    testTool = 43
    variant = 44


class Purpose(IntEnum):
    """Purpose/category of a software component."""
    UNKNOWN_PURPOSE = 0
    APPLICATION = 1
    ARCHIVE = 2
    BOM = 3
    CONFIGURATION = 4
    CONTAINER = 5
    DATA = 6
    DEVICE = 7
    DEVICE_DRIVER = 8
    DOCUMENTATION = 9
    EVIDENCE = 10
    EXECUTABLE = 11
    FILE = 12
    FIRMWARE = 13
    FRAMEWORK = 14
    INSTALL = 15
    LIBRARY = 16
    MACHINE_LEARNING_MODEL = 17
    MANIFEST = 18
    MODEL = 19
    MODULE = 20
    OPERATING_SYSTEM = 21
    OTHER = 22
    PATCH = 23
    PLATFORM = 24
    REQUIREMENT = 25
    SOURCE = 26
    SPECIFICATION = 27


class SoftwareIdentifierType(IntEnum):
    """Type of software identifier."""
    UNKNOWN_IDENTIFIER_TYPE = 0
    PURL = 1
    CPE22 = 2
    CPE23 = 3
    GITOID = 4


class ExternalReferenceType(IntEnum):
    """Type of external reference."""
    UNKNOWN = 0
    ATTESTATION = 1
    BINARY = 2
    BOM = 3
    BOWER = 4
    BUILD_META = 5
    BUILD_SYSTEM = 6
    CERTIFICATION_REPORT = 7
    CHAT = 8
    CODIFIED_INFRASTRUCTURE = 9
    COMPONENT_ANALYSIS_REPORT = 10
    CONFIGURATION = 11
    DISTRIBUTION_INTAKE = 12
    DOCUMENTATION = 13
    DOWNLOAD = 14
    DYNAMIC_ANALYSIS_REPORT = 15
    EOL_NOTICE = 16
    EVIDENCE = 17
    EXPORT_CONTROL_ASSESSMENT = 18
    FORMULATION = 19
    FUNDING = 20
    ISSUE_TRACKER = 21
    LICENSE = 22
    LOG = 23
    MAILING_LIST = 24
    MATURITY_REPORT = 25
    MAVEN_CENTRAL = 26
    METRICS = 27
    MODEL_CARD = 28
    NPM = 29
    NUGET = 30
    OTHER = 31
    PENTEST_REPORT = 32
    PRIVACY_ASSESSMENT = 33
    PRODUCT_METADATA = 34
    PURCHASE_ORDER = 35
    QUALITY_ASSESSMENT_REPORT = 36
    QUALITY_METRICS = 37
    RELEASE_HISTORY = 38
    RELEASE_NOTES = 39
    RISK_ASSESSMENT = 40
    RUNTIME_ANALYSIS_REPORT = 41
    SECURE_SOFTWARE_ATTESTATION = 42
    SECURITY_ADVERSARY_MODEL = 43
    SECURITY_ADVISORY = 44
    SECURITY_CONTACT = 45
    SECURITY_FIX = 46
    SECURITY_OTHER = 47
    SECURITY_PENTEST_REPORT = 48
    SECURITY_POLICY = 49
    SECURITY_SWID = 50
    SECURITY_THREAT_MODEL = 51
    SOCIAL = 52
    SOURCE_ARTIFACT = 53
    STATIC_ANALYSIS_REPORT = 54
    SUPPORT = 55
    SCM = 56
    THREAT_MODEL = 57
    VULNERABILITY_ASSERTION = 58
    VULNERABILITY_DISCLOSURE_REPORT = 59
    VULNERABILITY_EXPLOITABILITY_ASSESSMENT = 60
    WEBSITE = 61


# ---------------------------------------------------------------------------
# Protobuf timestamp helpers
# ---------------------------------------------------------------------------

def _datetime_to_pb_timestamp(dt: Optional[datetime]) -> Optional[PbTimestamp]:
    """Convert a Python datetime to a protobuf Timestamp."""
    if dt is None:
        return None
    ts = PbTimestamp()
    ts.FromDatetime(dt)
    return ts


def _pb_timestamp_to_datetime(ts: PbTimestamp) -> Optional[datetime]:
    """Convert a protobuf Timestamp to a Python datetime, or None if unset."""
    if ts.seconds == 0 and ts.nanos == 0:
        return None
    return ts.ToDatetime(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Property:
    """Key-value pair for extensible metadata."""
    name: str = ""
    data: str = ""

    def to_proto(self) -> pb.Property:
        return pb.Property(name=self.name, data=self.data)

    @staticmethod
    def from_proto(msg: pb.Property) -> Property:
        return Property(name=msg.name, data=msg.data)


@dataclass
class ExternalReference:
    """An external reference to a resource."""
    url: str = ""
    type: ExternalReferenceType = ExternalReferenceType.UNKNOWN
    comment: str = ""
    authority: str = ""
    hashes: dict[int, str] = field(default_factory=dict)  # HashAlgorithm -> hash

    def to_proto(self) -> pb.ExternalReference:
        return pb.ExternalReference(
            url=self.url,
            type=int(self.type),
            comment=self.comment,
            authority=self.authority,
            hashes=self.hashes,
        )

    @staticmethod
    def from_proto(msg: pb.ExternalReference) -> ExternalReference:
        return ExternalReference(
            url=msg.url,
            type=ExternalReferenceType(msg.type),
            comment=msg.comment,
            authority=msg.authority,
            hashes=dict(msg.hashes),
        )


@dataclass
class Person:
    """Represents an individual or organization."""
    name: str = ""
    is_org: bool = False
    email: str = ""
    url: str = ""
    phone: str = ""
    contacts: list[Person] = field(default_factory=list)

    def to_proto(self) -> pb.Person:
        return pb.Person(
            name=self.name,
            is_org=self.is_org,
            email=self.email,
            url=self.url,
            phone=self.phone,
            contacts=[c.to_proto() for c in self.contacts],
        )

    @staticmethod
    def from_proto(msg: pb.Person) -> Person:
        return Person(
            name=msg.name,
            is_org=msg.is_org,
            email=msg.email,
            url=msg.url,
            phone=msg.phone,
            contacts=[Person.from_proto(c) for c in msg.contacts],
        )


@dataclass
class Tool:
    """Represents a software tool."""
    name: str = ""
    version: str = ""
    vendor: str = ""

    def to_proto(self) -> pb.Tool:
        return pb.Tool(name=self.name, version=self.version, vendor=self.vendor)

    @staticmethod
    def from_proto(msg: pb.Tool) -> Tool:
        return Tool(name=msg.name, version=msg.version, vendor=msg.vendor)


@dataclass
class DocumentType:
    """Document type/phase categorization."""
    type: SBOMType = SBOMType.OTHER
    name: str = ""
    description: str = ""

    def to_proto(self) -> pb.DocumentType:
        return pb.DocumentType(
            type=int(self.type),
            name=self.name,
            description=self.description,
        )

    @staticmethod
    def from_proto(msg: pb.DocumentType) -> DocumentType:
        return DocumentType(
            type=SBOMType(msg.type),
            name=msg.name,
            description=msg.description,
        )


@dataclass
class SourceData:
    """Information about the original document source."""
    format: str = ""
    hashes: dict[int, str] = field(default_factory=dict)
    size: int = 0
    uri: str = ""

    def to_proto(self) -> pb.SourceData:
        return pb.SourceData(
            format=self.format,
            hashes=self.hashes,
            size=self.size,
            uri=self.uri if self.uri else None,
        )

    @staticmethod
    def from_proto(msg: pb.SourceData) -> SourceData:
        return SourceData(
            format=msg.format,
            hashes=dict(msg.hashes),
            size=msg.size,
            uri=msg.uri if msg.HasField("uri") else "",
        )


@dataclass
class Metadata:
    """Document metadata."""
    id: str = ""
    version: str = ""
    name: str = ""
    date: Optional[datetime] = None
    tools: list[Tool] = field(default_factory=list)
    authors: list[Person] = field(default_factory=list)
    comment: str = ""
    document_types: list[DocumentType] = field(default_factory=list)
    source_data: Optional[SourceData] = None

    def to_proto(self) -> pb.Metadata:
        msg = pb.Metadata(
            id=self.id,
            version=self.version,
            name=self.name,
            comment=self.comment,
            tools=[t.to_proto() for t in self.tools],
            authors=[a.to_proto() for a in self.authors],
            documentTypes=[dt.to_proto() for dt in self.document_types],
        )
        ts = _datetime_to_pb_timestamp(self.date)
        if ts is not None:
            msg.date.CopyFrom(ts)
        if self.source_data is not None:
            msg.source_data.CopyFrom(self.source_data.to_proto())
        return msg

    @staticmethod
    def from_proto(msg: pb.Metadata) -> Metadata:
        date = _pb_timestamp_to_datetime(msg.date) if msg.HasField("date") else None
        source_data = (
            SourceData.from_proto(msg.source_data)
            if msg.HasField("source_data")
            else None
        )
        return Metadata(
            id=msg.id,
            version=msg.version,
            name=msg.name,
            date=date,
            tools=[Tool.from_proto(t) for t in msg.tools],
            authors=[Person.from_proto(a) for a in msg.authors],
            comment=msg.comment,
            document_types=[DocumentType.from_proto(dt) for dt in msg.documentTypes],
            source_data=source_data,
        )


@dataclass
class Node:
    """A node in the SBOM graph representing a software component or file."""
    id: str = ""
    type: NodeType = NodeType.PACKAGE
    name: str = ""
    version: str = ""
    file_name: str = ""
    url_home: str = ""
    url_download: str = ""
    licenses: list[str] = field(default_factory=list)
    license_concluded: str = ""
    license_comments: str = ""
    copyright: str = ""
    hashes: dict[int, str] = field(default_factory=dict)  # HashAlgorithm -> hash
    source_info: str = ""
    primary_purpose: list[Purpose] = field(default_factory=list)
    comment: str = ""
    summary: str = ""
    description: str = ""
    attribution: list[str] = field(default_factory=list)
    suppliers: list[Person] = field(default_factory=list)
    originators: list[Person] = field(default_factory=list)
    external_references: list[ExternalReference] = field(default_factory=list)
    identifiers: dict[int, str] = field(default_factory=dict)  # SoftwareIdentifierType -> value
    properties: list[Property] = field(default_factory=list)
    release_date: Optional[datetime] = None
    build_date: Optional[datetime] = None
    valid_until_date: Optional[datetime] = None
    file_types: list[str] = field(default_factory=list)

    def to_proto(self) -> pb.Node:
        msg = pb.Node(
            id=self.id,
            type=int(self.type),
            name=self.name,
            version=self.version,
            file_name=self.file_name,
            url_home=self.url_home,
            url_download=self.url_download,
            licenses=self.licenses,
            license_concluded=self.license_concluded,
            license_comments=self.license_comments,
            copyright=self.copyright,
            source_info=self.source_info,
            comment=self.comment,
            summary=self.summary,
            description=self.description,
            attribution=self.attribution,
            suppliers=[s.to_proto() for s in self.suppliers],
            originators=[o.to_proto() for o in self.originators],
            external_references=[e.to_proto() for e in self.external_references],
            hashes=self.hashes,
            identifiers=self.identifiers,
            primary_purpose=[int(p) for p in self.primary_purpose],
            properties=[p.to_proto() for p in self.properties],
            file_types=self.file_types,
        )
        for attr, field_name in [
            ("release_date", "release_date"),
            ("build_date", "build_date"),
            ("valid_until_date", "valid_until_date"),
        ]:
            ts = _datetime_to_pb_timestamp(getattr(self, attr))
            if ts is not None:
                getattr(msg, field_name).CopyFrom(ts)
        return msg

    @staticmethod
    def from_proto(msg: pb.Node) -> Node:
        return Node(
            id=msg.id,
            type=NodeType(msg.type),
            name=msg.name,
            version=msg.version,
            file_name=msg.file_name,
            url_home=msg.url_home,
            url_download=msg.url_download,
            licenses=list(msg.licenses),
            license_concluded=msg.license_concluded,
            license_comments=msg.license_comments,
            copyright=msg.copyright,
            hashes=dict(msg.hashes),
            source_info=msg.source_info,
            primary_purpose=[Purpose(p) for p in msg.primary_purpose],
            comment=msg.comment,
            summary=msg.summary,
            description=msg.description,
            attribution=list(msg.attribution),
            suppliers=[Person.from_proto(s) for s in msg.suppliers],
            originators=[Person.from_proto(o) for o in msg.originators],
            external_references=[
                ExternalReference.from_proto(e) for e in msg.external_references
            ],
            identifiers=dict(msg.identifiers),
            properties=[Property.from_proto(p) for p in msg.properties],
            release_date=(
                _pb_timestamp_to_datetime(msg.release_date)
                if msg.HasField("release_date")
                else None
            ),
            build_date=(
                _pb_timestamp_to_datetime(msg.build_date)
                if msg.HasField("build_date")
                else None
            ),
            valid_until_date=(
                _pb_timestamp_to_datetime(msg.valid_until_date)
                if msg.HasField("valid_until_date")
                else None
            ),
            file_types=list(msg.file_types),
        )


@dataclass
class Edge:
    """A relationship between nodes in the SBOM graph."""
    type: EdgeType = EdgeType.UNKNOWN
    from_: str = ""  # source node ID
    to: list[str] = field(default_factory=list)  # target node IDs

    def to_proto(self) -> pb.Edge:
        # The proto field is named 'from' (Python reserved word)
        msg = pb.Edge(type=int(self.type), to=self.to)
        setattr(msg, "from", self.from_)
        return msg

    @staticmethod
    def from_proto(msg: pb.Edge) -> Edge:
        return Edge(
            type=EdgeType(msg.type),
            from_=getattr(msg, "from"),
            to=list(msg.to),
        )


class NodeList:
    """Collection of nodes and edges forming the SBOM graph.

    Provides graph operations, set operations, and node/edge management.
    """

    def __init__(
        self,
        nodes: list[Node] | None = None,
        edges: list[Edge] | None = None,
        root_elements: list[str] | None = None,
    ):
        self.nodes: list[Node] = nodes or []
        self.edges: list[Edge] = edges or []
        self.root_elements: list[str] = root_elements or []
        # Internal indexes
        self._node_index: dict[str, Node] = {}
        self._edge_index: dict[str, list[Edge]] = {}
        self._root_index: set[str] = set()
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        """Rebuild all internal indexes."""
        self._node_index = {n.id: n for n in self.nodes}
        self._edge_index = {}
        for e in self.edges:
            self._edge_index.setdefault(e.from_, []).append(e)
        self._root_index = set(self.root_elements)

    def add_node(self, node: Node) -> None:
        """Add a node to the node list."""
        self.nodes.append(node)
        self._node_index[node.id] = node

    def add_root_node(self, node: Node) -> None:
        """Add a node and register it as a root element."""
        self.add_node(node)
        if node.id not in self._root_index:
            self.root_elements.append(node.id)
            self._root_index.add(node.id)

    def add_edge(self, edge: Edge) -> None:
        """Add an edge to the node list."""
        self.edges.append(edge)
        self._edge_index.setdefault(edge.from_, []).append(edge)

    def get_node_by_id(self, node_id: str) -> Optional[Node]:
        """Retrieve a node by its ID."""
        return self._node_index.get(node_id)

    def get_nodes_by_name(self, name: str) -> list[Node]:
        """Return all nodes matching the given name."""
        return [n for n in self.nodes if n.name == name]

    def get_root_nodes(self) -> list[Node]:
        """Return the root nodes of the graph."""
        return [n for n in self.nodes if n.id in self._root_index]

    def get_edge_by_type(self, from_element: str, edge_type: EdgeType) -> Optional[Edge]:
        """Get the first edge of the given type from the specified node."""
        for e in self._edge_index.get(from_element, []):
            if e.type == edge_type:
                return e
        return None

    def get_edges_by_from(self, from_element: str) -> list[Edge]:
        """Get all edges originating from the specified node."""
        return self._edge_index.get(from_element, [])

    def remove_nodes(self, node_ids: list[str]) -> None:
        """Remove nodes by ID and clean up associated edges."""
        ids_to_remove = set(node_ids)
        self.nodes = [n for n in self.nodes if n.id not in ids_to_remove]
        self.root_elements = [r for r in self.root_elements if r not in ids_to_remove]
        self.edges = [
            Edge(
                type=e.type,
                from_=e.from_,
                to=[t for t in e.to if t not in ids_to_remove],
            )
            for e in self.edges
            if e.from_ not in ids_to_remove
        ]
        # Remove edges with empty targets
        self.edges = [e for e in self.edges if e.to]
        self._rebuild_indexes()

    def get_nodes_by_identifier(
        self, id_type: SoftwareIdentifierType, value: str
    ) -> list[Node]:
        """Find nodes matching a software identifier type and value."""
        return [
            n for n in self.nodes
            if n.identifiers.get(int(id_type)) == value
        ]

    def get_nodes_by_purl_type(self, purl_type: str) -> list[Node]:
        """Retrieve nodes matching a PURL type (e.g., 'npm', 'pypi')."""
        prefix = f"pkg:{purl_type}/"
        return [
            n for n in self.nodes
            if any(
                v.startswith(prefix)
                for k, v in n.identifiers.items()
                if k == int(SoftwareIdentifierType.PURL)
            )
        ]

    def node_descendants(self, node_id: str, max_depth: int = -1) -> list[Node]:
        """Traverse and return all descendants of a node up to max_depth."""
        visited: set[str] = set()
        result: list[Node] = []
        self._traverse_descendants(node_id, 0, max_depth, visited, result)
        return result

    def _traverse_descendants(
        self,
        node_id: str,
        depth: int,
        max_depth: int,
        visited: set[str],
        result: list[Node],
    ) -> None:
        if node_id in visited:
            return
        visited.add(node_id)
        for edge in self._edge_index.get(node_id, []):
            for target_id in edge.to:
                if target_id in visited:
                    continue
                if max_depth >= 0 and depth >= max_depth:
                    continue
                node = self._node_index.get(target_id)
                if node:
                    result.append(node)
                    self._traverse_descendants(
                        target_id, depth + 1, max_depth, visited, result
                    )

    def union(self, other: NodeList) -> NodeList:
        """Return a new NodeList combining this and other."""
        new_nl = self.copy()
        existing_ids = {n.id for n in new_nl.nodes}
        for node in other.nodes:
            if node.id not in existing_ids:
                new_nl.add_node(copy.deepcopy(node))
                existing_ids.add(node.id)
        for edge in other.edges:
            new_nl.add_edge(copy.deepcopy(edge))
        for root in other.root_elements:
            if root not in new_nl._root_index:
                new_nl.root_elements.append(root)
                new_nl._root_index.add(root)
        return new_nl

    def intersect(self, other: NodeList) -> NodeList:
        """Return a new NodeList with nodes common to both."""
        other_ids = {n.id for n in other.nodes}
        common_nodes = [copy.deepcopy(n) for n in self.nodes if n.id in other_ids]
        common_ids = {n.id for n in common_nodes}
        common_edges = [
            copy.deepcopy(e)
            for e in self.edges
            if e.from_ in common_ids and all(t in common_ids for t in e.to)
        ]
        common_roots = [r for r in self.root_elements if r in common_ids]
        return NodeList(nodes=common_nodes, edges=common_edges, root_elements=common_roots)

    def copy(self) -> NodeList:
        """Create a deep copy of this NodeList."""
        return NodeList(
            nodes=[copy.deepcopy(n) for n in self.nodes],
            edges=[copy.deepcopy(e) for e in self.edges],
            root_elements=list(self.root_elements),
        )

    def equal(self, other: NodeList) -> bool:
        """Check if two NodeLists have the same node IDs."""
        return {n.id for n in self.nodes} == {n.id for n in other.nodes}

    def relate_node_at_id(
        self, node: Node, target_id: str, edge_type: EdgeType
    ) -> None:
        """Add a node and create a relationship to an existing node."""
        self.add_node(node)
        # Find or create edge
        existing = self.get_edge_by_type(target_id, edge_type)
        if existing:
            if node.id not in existing.to:
                existing.to.append(node.id)
        else:
            self.add_edge(Edge(type=edge_type, from_=target_id, to=[node.id]))

    def to_proto(self) -> pb.NodeList:
        """Convert to a protobuf NodeList message."""
        return pb.NodeList(
            nodes=[n.to_proto() for n in self.nodes],
            edges=[e.to_proto() for e in self.edges],
            root_elements=self.root_elements,
        )

    @staticmethod
    def from_proto(msg: pb.NodeList) -> NodeList:
        """Create a NodeList from a protobuf NodeList message."""
        return NodeList(
            nodes=[Node.from_proto(n) for n in msg.nodes],
            edges=[Edge.from_proto(e) for e in msg.edges],
            root_elements=list(msg.root_elements),
        )


@dataclass
class Document:
    """Root SBOM document containing metadata and a node graph."""
    metadata: Metadata = field(default_factory=Metadata)
    node_list: NodeList = field(default_factory=NodeList)

    def to_proto(self) -> pb.Document:
        """Convert to a protobuf Document message."""
        msg = pb.Document()
        msg.metadata.CopyFrom(self.metadata.to_proto())
        msg.node_list.CopyFrom(self.node_list.to_proto())
        return msg

    @staticmethod
    def from_proto(msg: pb.Document) -> Document:
        """Create a Document from a protobuf Document message."""
        return Document(
            metadata=Metadata.from_proto(msg.metadata),
            node_list=NodeList.from_proto(msg.node_list),
        )

    def serialize_to_proto(self) -> bytes:
        """Serialize to protobuf binary format."""
        return self.to_proto().SerializeToString()

    @staticmethod
    def deserialize_from_proto(data: bytes) -> Document:
        """Deserialize from protobuf binary format."""
        msg = pb.Document()
        msg.ParseFromString(data)
        return Document.from_proto(msg)

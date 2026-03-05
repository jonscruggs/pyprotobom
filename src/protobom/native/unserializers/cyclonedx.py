"""CycloneDX format unserializer - converts CycloneDX JSON/XML to protobom."""

from __future__ import annotations

import json
from typing import IO, Any, Optional

from protobom.native import UnserializeOptions, Unserializer
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
    Tool,
)


# ---------------------------------------------------------------------------
# Type mapping tables
# ---------------------------------------------------------------------------

_CDX_HASH_ALGO_MAP: dict[str, HashAlgorithm] = {
    "MD5": HashAlgorithm.MD5,
    "SHA-1": HashAlgorithm.SHA1,
    "SHA-256": HashAlgorithm.SHA256,
    "SHA-384": HashAlgorithm.SHA384,
    "SHA-512": HashAlgorithm.SHA512,
    "SHA3-256": HashAlgorithm.SHA3_256,
    "SHA3-384": HashAlgorithm.SHA3_384,
    "SHA3-512": HashAlgorithm.SHA3_512,
    "BLAKE2b-256": HashAlgorithm.BLAKE2B_256,
    "BLAKE2b-384": HashAlgorithm.BLAKE2B_384,
    "BLAKE2b-512": HashAlgorithm.BLAKE2B_512,
    "BLAKE3": HashAlgorithm.BLAKE3,
}

_CDX_COMPONENT_TYPE_MAP: dict[str, Purpose] = {
    "application": Purpose.APPLICATION,
    "container": Purpose.CONTAINER,
    "data": Purpose.DATA,
    "device": Purpose.DEVICE,
    "device-driver": Purpose.DEVICE_DRIVER,
    "file": Purpose.FILE,
    "firmware": Purpose.FIRMWARE,
    "framework": Purpose.FRAMEWORK,
    "library": Purpose.LIBRARY,
    "machine-learning-model": Purpose.MACHINE_LEARNING_MODEL,
    "operating-system": Purpose.OPERATING_SYSTEM,
    "platform": Purpose.PLATFORM,
}

_CDX_EXTREF_TYPE_MAP: dict[str, ExternalReferenceType] = {
    "advisories": ExternalReferenceType.SECURITY_ADVISORY,
    "attestation": ExternalReferenceType.ATTESTATION,
    "bom": ExternalReferenceType.BOM,
    "build-meta": ExternalReferenceType.BUILD_META,
    "build-system": ExternalReferenceType.BUILD_SYSTEM,
    "certification-report": ExternalReferenceType.CERTIFICATION_REPORT,
    "chat": ExternalReferenceType.CHAT,
    "codified-infrastructure": ExternalReferenceType.CODIFIED_INFRASTRUCTURE,
    "component-analysis-report": ExternalReferenceType.COMPONENT_ANALYSIS_REPORT,
    "configuration": ExternalReferenceType.CONFIGURATION,
    "distribution": ExternalReferenceType.DOWNLOAD,
    "distribution-intake": ExternalReferenceType.DISTRIBUTION_INTAKE,
    "documentation": ExternalReferenceType.DOCUMENTATION,
    "dynamic-analysis-report": ExternalReferenceType.DYNAMIC_ANALYSIS_REPORT,
    "evidence": ExternalReferenceType.EVIDENCE,
    "formulation": ExternalReferenceType.FORMULATION,
    "issue-tracker": ExternalReferenceType.ISSUE_TRACKER,
    "license": ExternalReferenceType.LICENSE,
    "log": ExternalReferenceType.LOG,
    "mailing-list": ExternalReferenceType.MAILING_LIST,
    "maturity-report": ExternalReferenceType.MATURITY_REPORT,
    "model-card": ExternalReferenceType.MODEL_CARD,
    "other": ExternalReferenceType.OTHER,
    "pentest-report": ExternalReferenceType.PENTEST_REPORT,
    "quality-metrics": ExternalReferenceType.QUALITY_METRICS,
    "release-notes": ExternalReferenceType.RELEASE_NOTES,
    "risk-assessment": ExternalReferenceType.RISK_ASSESSMENT,
    "runtime-analysis-report": ExternalReferenceType.RUNTIME_ANALYSIS_REPORT,
    "social": ExternalReferenceType.SOCIAL,
    "source-distribution": ExternalReferenceType.SOURCE_ARTIFACT,
    "static-analysis-report": ExternalReferenceType.STATIC_ANALYSIS_REPORT,
    "support": ExternalReferenceType.SUPPORT,
    "threat-model": ExternalReferenceType.THREAT_MODEL,
    "vulnerability-assertion": ExternalReferenceType.VULNERABILITY_ASSERTION,
    "vcs": ExternalReferenceType.SCM,
    "website": ExternalReferenceType.WEBSITE,
}

_CDX_PHASE_MAP: dict[str, SBOMType] = {
    "design": SBOMType.DESIGN,
    "pre-build": SBOMType.SOURCE,
    "build": SBOMType.BUILD,
    "post-build": SBOMType.ANALYZED,
    "operations": SBOMType.DEPLOYED,
    "discovery": SBOMType.DISCOVERY,
    "decommission": SBOMType.DECOMISSION,
}


class CDXUnserializer(Unserializer):
    """Unserializes CycloneDX JSON documents into protobom Documents."""

    def __init__(self, version: str = "", encoding: str = "json"):
        self.version = version
        self.encoding = encoding
        self._component_counter = 0

    def unserialize(
        self,
        reader: IO[bytes],
        options: Optional[UnserializeOptions] = None,
    ) -> Document:
        """Parse a CycloneDX JSON document into a protobom Document."""
        content = reader.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        bom = json.loads(content)
        self._component_counter = 0

        metadata = self._parse_metadata(bom)
        node_list = NodeList()

        # Parse components
        components = bom.get("components", [])
        for comp in components:
            nodes, edges = self._component_to_node_list(comp)
            for n in nodes:
                node_list.add_node(n)
            for e in edges:
                node_list.add_edge(e)

        # Set root elements - the top-level components
        for comp in components:
            comp_id = comp.get("bom-ref", "")
            if comp_id:
                node_list.root_elements.append(comp_id)
                node_list._root_index.add(comp_id)

        # Parse dependency graph
        deps = self._parse_dependency_graph(bom)
        for edge in deps:
            node_list.add_edge(edge)

        return Document(metadata=metadata, node_list=node_list)

    def _parse_metadata(self, bom: dict) -> Metadata:
        """Parse CycloneDX metadata into protobom Metadata."""
        md = Metadata()
        cdx_metadata = bom.get("metadata", {})

        md.id = bom.get("serialNumber", "")
        md.version = str(bom.get("version", 1))

        # Parse timestamp
        timestamp = cdx_metadata.get("timestamp")
        if timestamp:
            md.date = _parse_datetime(timestamp)

        # Parse tools
        tools_data = cdx_metadata.get("tools")
        if tools_data:
            if isinstance(tools_data, list):
                for t in tools_data:
                    md.tools.append(Tool(
                        name=t.get("name", ""),
                        version=t.get("version", ""),
                        vendor=t.get("vendor", ""),
                    ))
            elif isinstance(tools_data, dict):
                # CDX 1.5+ tools format
                for t in tools_data.get("components", []):
                    md.tools.append(Tool(
                        name=t.get("name", ""),
                        version=t.get("version", ""),
                    ))

        # Parse authors
        authors = cdx_metadata.get("authors")
        if authors:
            for a in authors:
                md.authors.append(Person(
                    name=a.get("name", ""),
                    email=a.get("email", ""),
                    phone=a.get("phone", ""),
                ))

        # Parse component (main component)
        component = cdx_metadata.get("component")
        if component:
            md.name = component.get("name", "")

        # Parse lifecycles
        lifecycles = cdx_metadata.get("lifecycles", [])
        for lc in lifecycles:
            phase = lc.get("phase", "")
            sbom_type = _CDX_PHASE_MAP.get(phase, SBOMType.OTHER)
            md.document_types.append(DocumentType(type=sbom_type, name=phase))

        return md

    def _component_to_node_list(
        self, component: dict
    ) -> tuple[list[Node], list[Edge]]:
        """Convert a CycloneDX component and its children to nodes and edges."""
        nodes: list[Node] = []
        edges: list[Edge] = []

        node = self._component_to_node(component)
        nodes.append(node)

        # Process sub-components
        sub_components = component.get("components", [])
        if sub_components:
            child_ids = []
            for sub in sub_components:
                sub_nodes, sub_edges = self._component_to_node_list(sub)
                nodes.extend(sub_nodes)
                edges.extend(sub_edges)
                if sub_nodes:
                    child_ids.append(sub_nodes[0].id)

            if child_ids:
                edges.append(Edge(
                    type=EdgeType.contains,
                    from_=node.id,
                    to=child_ids,
                ))

        return nodes, edges

    def _component_to_node(self, component: dict) -> Node:
        """Convert a single CycloneDX component to a protobom Node."""
        self._component_counter += 1

        node = Node()
        node.id = component.get("bom-ref", f"protobom-auto-{self._component_counter}")
        node.type = NodeType.PACKAGE
        node.name = component.get("name", "")
        node.version = component.get("version", "")
        node.copyright = component.get("copyright", "")
        node.description = component.get("description", "")
        node.comment = component.get("comment", "")

        # Map component type to purpose
        comp_type = component.get("type", "")
        purpose = _CDX_COMPONENT_TYPE_MAP.get(comp_type, Purpose.UNKNOWN_PURPOSE)
        if purpose != Purpose.UNKNOWN_PURPOSE:
            node.primary_purpose.append(purpose)

        # Parse PURL
        purl = component.get("purl", "")
        if purl:
            node.identifiers[int(SoftwareIdentifierType.PURL)] = purl

        # Parse CPE
        cpe = component.get("cpe", "")
        if cpe:
            if cpe.startswith("cpe:2.3:"):
                node.identifiers[int(SoftwareIdentifierType.CPE23)] = cpe
            else:
                node.identifiers[int(SoftwareIdentifierType.CPE22)] = cpe

        # Parse supplier
        supplier = component.get("supplier")
        if supplier:
            node.suppliers.append(Person(
                name=supplier.get("name", ""),
                url=", ".join(supplier.get("url", [])) if isinstance(supplier.get("url"), list) else supplier.get("url", ""),
            ))

        # Parse author / manufacturer
        author = component.get("author", "")
        if author:
            node.originators.append(Person(name=author))
        manufacturer = component.get("manufacturer")
        if manufacturer:
            node.originators.append(Person(
                name=manufacturer.get("name", ""),
                is_org=True,
            ))

        # Parse hashes
        for h in component.get("hashes", []):
            algo = _CDX_HASH_ALGO_MAP.get(h.get("alg", ""), HashAlgorithm.UNKNOWN)
            if algo != HashAlgorithm.UNKNOWN:
                node.hashes[int(algo)] = h.get("content", "")

        # Parse licenses
        node.licenses = self._parse_licenses(component.get("licenses", []))

        # Parse external references
        for ref in component.get("externalReferences", []):
            ext_ref = ExternalReference(
                url=ref.get("url", ""),
                type=_CDX_EXTREF_TYPE_MAP.get(ref.get("type", ""), ExternalReferenceType.OTHER),
                comment=ref.get("comment", ""),
            )
            for h in ref.get("hashes", []):
                algo = _CDX_HASH_ALGO_MAP.get(h.get("alg", ""), HashAlgorithm.UNKNOWN)
                if algo != HashAlgorithm.UNKNOWN:
                    ext_ref.hashes[int(algo)] = h.get("content", "")
            node.external_references.append(ext_ref)

        # Parse properties
        for prop in component.get("properties", []):
            node.properties.append(Property(
                name=prop.get("name", ""),
                data=prop.get("value", ""),
            ))

        return node

    def _parse_licenses(self, licenses: list[dict]) -> list[str]:
        """Parse CycloneDX license choices into a list of license strings."""
        result = []
        for lc in licenses:
            if "license" in lc:
                lic = lc["license"]
                if "id" in lic:
                    result.append(lic["id"])
                elif "name" in lic:
                    result.append(lic["name"])
            if "expression" in lc:
                result.append(lc["expression"])
        return result

    def _parse_dependency_graph(self, bom: dict) -> list[Edge]:
        """Parse the CycloneDX dependency graph into edges."""
        edges: list[Edge] = []
        dependencies = bom.get("dependencies", [])
        for dep in dependencies:
            ref = dep.get("ref", "")
            depends_on = dep.get("dependsOn", [])
            if ref and depends_on:
                edges.append(Edge(
                    type=EdgeType.dependsOn,
                    from_=ref,
                    to=depends_on,
                ))
        return edges


def _parse_datetime(date_str: str) -> Any:
    """Parse an ISO 8601 / RFC 3339 datetime string."""
    from datetime import datetime, timezone

    # Handle various datetime formats
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ]:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    # Fallback: try fromisoformat (Python 3.11+)
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None

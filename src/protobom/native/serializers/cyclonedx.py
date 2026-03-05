"""CycloneDX format serializer - converts protobom to CycloneDX JSON."""

from __future__ import annotations

import json
import uuid
from typing import IO, Any, Optional

from protobom.native import SerializeOptions, Serializer
from protobom.sbom import (
    Document,
    EdgeType,
    ExternalReferenceType,
    HashAlgorithm,
    Node,
    NodeList,
    Purpose,
    SBOMType,
)


# ---------------------------------------------------------------------------
# Reverse mapping tables (protobom -> CycloneDX)
# ---------------------------------------------------------------------------

_PROTOBOM_HASH_TO_CDX: dict[int, str] = {
    int(HashAlgorithm.MD5): "MD5",
    int(HashAlgorithm.SHA1): "SHA-1",
    int(HashAlgorithm.SHA256): "SHA-256",
    int(HashAlgorithm.SHA384): "SHA-384",
    int(HashAlgorithm.SHA512): "SHA-512",
    int(HashAlgorithm.SHA3_256): "SHA3-256",
    int(HashAlgorithm.SHA3_384): "SHA3-384",
    int(HashAlgorithm.SHA3_512): "SHA3-512",
    int(HashAlgorithm.BLAKE2B_256): "BLAKE2b-256",
    int(HashAlgorithm.BLAKE2B_384): "BLAKE2b-384",
    int(HashAlgorithm.BLAKE2B_512): "BLAKE2b-512",
    int(HashAlgorithm.BLAKE3): "BLAKE3",
}

_PROTOBOM_PURPOSE_TO_CDX: dict[int, str] = {
    int(Purpose.APPLICATION): "application",
    int(Purpose.CONTAINER): "container",
    int(Purpose.DATA): "data",
    int(Purpose.DEVICE): "device",
    int(Purpose.DEVICE_DRIVER): "device-driver",
    int(Purpose.FILE): "file",
    int(Purpose.FIRMWARE): "firmware",
    int(Purpose.FRAMEWORK): "framework",
    int(Purpose.LIBRARY): "library",
    int(Purpose.MACHINE_LEARNING_MODEL): "machine-learning-model",
    int(Purpose.OPERATING_SYSTEM): "operating-system",
    int(Purpose.PLATFORM): "platform",
}

_PROTOBOM_EXTREF_TO_CDX: dict[int, str] = {
    int(ExternalReferenceType.SECURITY_ADVISORY): "advisories",
    int(ExternalReferenceType.ATTESTATION): "attestation",
    int(ExternalReferenceType.BOM): "bom",
    int(ExternalReferenceType.BUILD_META): "build-meta",
    int(ExternalReferenceType.BUILD_SYSTEM): "build-system",
    int(ExternalReferenceType.CERTIFICATION_REPORT): "certification-report",
    int(ExternalReferenceType.CHAT): "chat",
    int(ExternalReferenceType.CODIFIED_INFRASTRUCTURE): "codified-infrastructure",
    int(ExternalReferenceType.COMPONENT_ANALYSIS_REPORT): "component-analysis-report",
    int(ExternalReferenceType.CONFIGURATION): "configuration",
    int(ExternalReferenceType.DOWNLOAD): "distribution",
    int(ExternalReferenceType.DISTRIBUTION_INTAKE): "distribution-intake",
    int(ExternalReferenceType.DOCUMENTATION): "documentation",
    int(ExternalReferenceType.DYNAMIC_ANALYSIS_REPORT): "dynamic-analysis-report",
    int(ExternalReferenceType.EVIDENCE): "evidence",
    int(ExternalReferenceType.FORMULATION): "formulation",
    int(ExternalReferenceType.ISSUE_TRACKER): "issue-tracker",
    int(ExternalReferenceType.LICENSE): "license",
    int(ExternalReferenceType.LOG): "log",
    int(ExternalReferenceType.MAILING_LIST): "mailing-list",
    int(ExternalReferenceType.MATURITY_REPORT): "maturity-report",
    int(ExternalReferenceType.MODEL_CARD): "model-card",
    int(ExternalReferenceType.OTHER): "other",
    int(ExternalReferenceType.PENTEST_REPORT): "pentest-report",
    int(ExternalReferenceType.QUALITY_METRICS): "quality-metrics",
    int(ExternalReferenceType.RELEASE_NOTES): "release-notes",
    int(ExternalReferenceType.RISK_ASSESSMENT): "risk-assessment",
    int(ExternalReferenceType.RUNTIME_ANALYSIS_REPORT): "runtime-analysis-report",
    int(ExternalReferenceType.SOCIAL): "social",
    int(ExternalReferenceType.SOURCE_ARTIFACT): "source-distribution",
    int(ExternalReferenceType.STATIC_ANALYSIS_REPORT): "static-analysis-report",
    int(ExternalReferenceType.SUPPORT): "support",
    int(ExternalReferenceType.THREAT_MODEL): "threat-model",
    int(ExternalReferenceType.VULNERABILITY_ASSERTION): "vulnerability-assertion",
    int(ExternalReferenceType.SCM): "vcs",
    int(ExternalReferenceType.WEBSITE): "website",
}

_SBOM_TYPE_TO_PHASE: dict[int, str] = {
    int(SBOMType.DESIGN): "design",
    int(SBOMType.SOURCE): "pre-build",
    int(SBOMType.BUILD): "build",
    int(SBOMType.ANALYZED): "post-build",
    int(SBOMType.DEPLOYED): "operations",
    int(SBOMType.DISCOVERY): "discovery",
    int(SBOMType.DECOMISSION): "decommission",
}


class CDXSerializeOptions(SerializeOptions):
    """Options for CycloneDX serialization."""

    def __init__(self, generate_serial_number: bool = True):
        self.generate_serial_number = generate_serial_number


class CDXSerializer(Serializer):
    """Serializes protobom Documents to CycloneDX JSON format."""

    def __init__(self, version: str = "1.5", encoding: str = "json"):
        self.version = version
        self.encoding = encoding

    def serialize(
        self,
        document: Document,
        options: Optional[SerializeOptions] = None,
    ) -> dict:
        """Convert a protobom Document to a CycloneDX JSON dict."""
        if options is None:
            options = CDXSerializeOptions()

        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": self.version,
        }

        # Serial number
        serial = document.metadata.id
        if isinstance(options, CDXSerializeOptions) and options.generate_serial_number:
            if not serial or not _is_valid_serial_number(serial):
                serial = f"urn:uuid:{uuid.uuid4()}"
        if serial:
            bom["serialNumber"] = serial

        # Version
        try:
            bom["version"] = int(document.metadata.version)
        except (ValueError, TypeError):
            bom["version"] = 1

        # Metadata
        bom["metadata"] = self._build_metadata(document)

        # Components
        components = self._build_components(document.node_list)
        if components:
            bom["components"] = components

        # Dependencies
        dependencies = self._build_dependencies(document.node_list, components)
        if dependencies:
            bom["dependencies"] = dependencies

        return bom

    def render(
        self,
        native_doc: Any,
        writer: IO[bytes],
        options: Optional[SerializeOptions] = None,
    ) -> None:
        """Render CycloneDX JSON to a byte stream."""
        output = json.dumps(native_doc, indent=2, default=str)
        if isinstance(output, str):
            output = output.encode("utf-8")
        writer.write(output)

    def _build_metadata(self, document: Document) -> dict:
        """Build CycloneDX metadata section."""
        md: dict[str, Any] = {}
        meta = document.metadata

        if meta.date:
            md["timestamp"] = meta.date.isoformat()

        # Tools
        if meta.tools:
            tools = []
            for t in meta.tools:
                tool: dict[str, str] = {}
                if t.name:
                    tool["name"] = t.name
                if t.version:
                    tool["version"] = t.version
                if t.vendor:
                    tool["vendor"] = t.vendor
                tools.append(tool)
            md["tools"] = tools

        # Authors
        if meta.authors:
            authors = []
            for a in meta.authors:
                author: dict[str, str] = {}
                if a.name:
                    author["name"] = a.name
                if a.email:
                    author["email"] = a.email
                if a.phone:
                    author["phone"] = a.phone
                authors.append(author)
            md["authors"] = authors

        # Lifecycles from document types
        if meta.document_types:
            lifecycles = []
            for dt in meta.document_types:
                phase = _SBOM_TYPE_TO_PHASE.get(int(dt.type))
                if phase:
                    lifecycles.append({"phase": phase})
            if lifecycles:
                md["lifecycles"] = lifecycles

        return md

    def _build_components(self, node_list: NodeList) -> list[dict]:
        """Build CycloneDX components from the node list."""
        components = []
        for node in node_list.nodes:
            components.append(self._node_to_component(node))
        return components

    def _node_to_component(self, node: Node) -> dict:
        """Convert a protobom Node to a CycloneDX component dict."""
        comp: dict[str, Any] = {}

        # Type from purpose
        comp_type = "library"  # default
        if node.primary_purpose:
            mapped = _PROTOBOM_PURPOSE_TO_CDX.get(int(node.primary_purpose[0]))
            if mapped:
                comp_type = mapped
        comp["type"] = comp_type

        if node.id:
            comp["bom-ref"] = node.id
        if node.name:
            comp["name"] = node.name
        if node.version:
            comp["version"] = node.version
        if node.description:
            comp["description"] = node.description
        if node.copyright:
            comp["copyright"] = node.copyright
        if node.comment:
            comp["comment"] = node.comment

        # PURL
        from protobom.sbom import SoftwareIdentifierType
        purl = node.identifiers.get(int(SoftwareIdentifierType.PURL), "")
        if purl:
            comp["purl"] = purl

        # CPE
        cpe23 = node.identifiers.get(int(SoftwareIdentifierType.CPE23), "")
        cpe22 = node.identifiers.get(int(SoftwareIdentifierType.CPE22), "")
        if cpe23:
            comp["cpe"] = cpe23
        elif cpe22:
            comp["cpe"] = cpe22

        # Supplier
        if node.suppliers:
            s = node.suppliers[0]
            supplier: dict[str, Any] = {"name": s.name}
            if s.url:
                supplier["url"] = [s.url]
            comp["supplier"] = supplier

        # Hashes
        hashes = []
        for algo_int, value in node.hashes.items():
            cdx_algo = _PROTOBOM_HASH_TO_CDX.get(algo_int)
            if cdx_algo:
                hashes.append({"alg": cdx_algo, "content": value})
        if hashes:
            comp["hashes"] = hashes

        # Licenses
        if node.licenses:
            licenses = []
            for lic in node.licenses:
                # Check if it looks like an SPDX expression with operators
                if " AND " in lic or " OR " in lic:
                    licenses.append({"expression": lic})
                else:
                    licenses.append({"license": {"id": lic}})
            comp["licenses"] = licenses

        # External references
        if node.external_references:
            ext_refs = []
            for ref in node.external_references:
                ext: dict[str, Any] = {"url": ref.url}
                cdx_type = _PROTOBOM_EXTREF_TO_CDX.get(int(ref.type), "other")
                ext["type"] = cdx_type
                if ref.comment:
                    ext["comment"] = ref.comment
                if ref.hashes:
                    ref_hashes = []
                    for h_algo, h_val in ref.hashes.items():
                        h_cdx = _PROTOBOM_HASH_TO_CDX.get(h_algo)
                        if h_cdx:
                            ref_hashes.append({"alg": h_cdx, "content": h_val})
                    if ref_hashes:
                        ext["hashes"] = ref_hashes
                ext_refs.append(ext)
            comp["externalReferences"] = ext_refs

        # Properties
        if node.properties:
            props = []
            for p in node.properties:
                props.append({"name": p.name, "value": p.data})
            comp["properties"] = props

        return comp

    def _build_dependencies(
        self, node_list: NodeList, components: list[dict]
    ) -> list[dict]:
        """Build CycloneDX dependency graph from edges."""
        deps: list[dict] = []
        seen_refs: set[str] = set()

        for edge in node_list.edges:
            if edge.type == EdgeType.dependsOn and edge.from_:
                deps.append({
                    "ref": edge.from_,
                    "dependsOn": list(edge.to),
                })
                seen_refs.add(edge.from_)

        # Add entries for components without explicit dependencies
        for comp in components:
            ref = comp.get("bom-ref", "")
            if ref and ref not in seen_refs:
                deps.append({"ref": ref, "dependsOn": []})

        return deps


def _is_valid_serial_number(serial: str) -> bool:
    """Check if a string is a valid CycloneDX serial number (URN UUID)."""
    if not serial.startswith("urn:uuid:"):
        return False
    try:
        uuid.UUID(serial[9:])
        return True
    except ValueError:
        return False

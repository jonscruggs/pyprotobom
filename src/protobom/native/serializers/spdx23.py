"""SPDX 2.3 format serializer - converts protobom to SPDX 2.3 JSON."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import IO, Any, Optional

from protobom.native import SerializeOptions, Serializer
from protobom.sbom import (
    Document,
    EdgeType,
    ExternalReferenceType,
    HashAlgorithm,
    Node,
    NodeType,
    Person,
    Purpose,
    SoftwareIdentifierType,
)


# ---------------------------------------------------------------------------
# Reverse mapping tables (protobom -> SPDX 2.3)
# ---------------------------------------------------------------------------

_PROTOBOM_HASH_TO_SPDX: dict[int, str] = {
    int(HashAlgorithm.MD5): "MD5",
    int(HashAlgorithm.SHA1): "SHA1",
    int(HashAlgorithm.SHA224): "SHA224",
    int(HashAlgorithm.SHA256): "SHA256",
    int(HashAlgorithm.SHA384): "SHA384",
    int(HashAlgorithm.SHA512): "SHA512",
    int(HashAlgorithm.SHA3_256): "SHA3-256",
    int(HashAlgorithm.SHA3_384): "SHA3-384",
    int(HashAlgorithm.SHA3_512): "SHA3-512",
    int(HashAlgorithm.BLAKE2B_256): "BLAKE2b-256",
    int(HashAlgorithm.BLAKE2B_384): "BLAKE2b-384",
    int(HashAlgorithm.BLAKE2B_512): "BLAKE2b-512",
    int(HashAlgorithm.BLAKE3): "BLAKE3",
    int(HashAlgorithm.ADLER32): "ADLER32",
    int(HashAlgorithm.MD2): "MD2",
    int(HashAlgorithm.MD4): "MD4",
    int(HashAlgorithm.MD6): "MD6",
}

_PROTOBOM_PURPOSE_TO_SPDX: dict[int, str] = {
    int(Purpose.APPLICATION): "APPLICATION",
    int(Purpose.ARCHIVE): "ARCHIVE",
    int(Purpose.BOM): "BOM",
    int(Purpose.CONTAINER): "CONTAINER",
    int(Purpose.DATA): "DATA",
    int(Purpose.DEVICE): "DEVICE",
    int(Purpose.DEVICE_DRIVER): "DEVICE_DRIVER",
    int(Purpose.DOCUMENTATION): "DOCUMENTATION",
    int(Purpose.EVIDENCE): "EVIDENCE",
    int(Purpose.EXECUTABLE): "EXECUTABLE",
    int(Purpose.FILE): "FILE",
    int(Purpose.FIRMWARE): "FIRMWARE",
    int(Purpose.FRAMEWORK): "FRAMEWORK",
    int(Purpose.INSTALL): "INSTALL",
    int(Purpose.LIBRARY): "LIBRARY",
    int(Purpose.MANIFEST): "MANIFEST",
    int(Purpose.MODEL): "MODEL",
    int(Purpose.MODULE): "MODULE",
    int(Purpose.OPERATING_SYSTEM): "OPERATING_SYSTEM",
    int(Purpose.OTHER): "OTHER",
    int(Purpose.PATCH): "PATCH",
    int(Purpose.REQUIREMENT): "REQUIREMENT",
    int(Purpose.SOURCE): "SOURCE",
    int(Purpose.SPECIFICATION): "SPECIFICATION",
}

_PROTOBOM_EDGE_TO_SPDX: dict[int, str] = {
    int(EdgeType.amends): "AMENDS",
    int(EdgeType.ancestor): "ANCESTOR_OF",
    int(EdgeType.buildDependency): "BUILD_DEPENDENCY_OF",
    int(EdgeType.buildTool): "BUILD_TOOL_OF",
    int(EdgeType.contained_by): "CONTAINED_BY",
    int(EdgeType.contains): "CONTAINS",
    int(EdgeType.copy): "COPY_OF",
    int(EdgeType.dataFile): "DATA_FILE_OF",
    int(EdgeType.dependencyManifest): "DEPENDENCY_MANIFEST_OF",
    int(EdgeType.dependencyOf): "DEPENDENCY_OF",
    int(EdgeType.dependsOn): "DEPENDS_ON",
    int(EdgeType.descendant): "DESCENDANT_OF",
    int(EdgeType.describedBy): "DESCRIBED_BY",
    int(EdgeType.describes): "DESCRIBES",
    int(EdgeType.devDependency): "DEV_DEPENDENCY_OF",
    int(EdgeType.devTool): "DEV_TOOL_OF",
    int(EdgeType.distributionArtifact): "DISTRIBUTION_ARTIFACT",
    int(EdgeType.documentation): "DOCUMENTATION_OF",
    int(EdgeType.dynamicLink): "DYNAMIC_LINK",
    int(EdgeType.example): "EXAMPLE_OF",
    int(EdgeType.expandedFromArchive): "EXPANDED_FROM_ARCHIVE",
    int(EdgeType.fileAdded): "FILE_ADDED",
    int(EdgeType.fileDeleted): "FILE_DELETED",
    int(EdgeType.fileModified): "FILE_MODIFIED",
    int(EdgeType.generatedFrom): "GENERATED_FROM",
    int(EdgeType.generates): "GENERATES",
    int(EdgeType.prerequisite): "HAS_PREREQUISITE",
    int(EdgeType.metafile): "METAFILE_OF",
    int(EdgeType.optionalComponent): "OPTIONAL_COMPONENT_OF",
    int(EdgeType.optionalDependency): "OPTIONAL_DEPENDENCY_OF",
    int(EdgeType.other): "OTHER",
    int(EdgeType.packages): "PACKAGE_OF",
    int(EdgeType.patch): "PATCH_FOR",
    int(EdgeType.prerequisiteFor): "PREREQUISITE_FOR",
    int(EdgeType.providedDependency): "PROVIDED_DEPENDENCY_OF",
    int(EdgeType.requirementFor): "REQUIREMENT_DESCRIPTION_FOR",
    int(EdgeType.runtimeDependency): "RUNTIME_DEPENDENCY_OF",
    int(EdgeType.specificationFor): "SPECIFICATION_FOR",
    int(EdgeType.staticLink): "STATIC_LINK",
    int(EdgeType.test): "TEST_OF",
    int(EdgeType.testCase): "TEST_CASE_OF",
    int(EdgeType.testDependency): "TEST_DEPENDENCY_OF",
    int(EdgeType.testTool): "TEST_TOOL_OF",
    int(EdgeType.variant): "VARIANT_OF",
}

_PROTOBOM_EXTREF_TO_SPDX_CATEGORY: dict[int, tuple[str, str]] = {
    int(ExternalReferenceType.BOWER): ("PACKAGE-MANAGER", "bower"),
    int(ExternalReferenceType.MAVEN_CENTRAL): ("PACKAGE-MANAGER", "maven-central"),
    int(ExternalReferenceType.NPM): ("PACKAGE-MANAGER", "npm"),
    int(ExternalReferenceType.NUGET): ("PACKAGE-MANAGER", "nuget"),
    int(ExternalReferenceType.DOWNLOAD): ("PACKAGE-MANAGER", "purl"),
    int(ExternalReferenceType.SECURITY_ADVISORY): ("SECURITY", "advisory"),
    int(ExternalReferenceType.SECURITY_FIX): ("SECURITY", "fix"),
    int(ExternalReferenceType.SECURITY_OTHER): ("SECURITY", "url"),
    int(ExternalReferenceType.SECURITY_SWID): ("SECURITY", "swid"),
}


class SPDX23SerializeOptions(SerializeOptions):
    """Options for SPDX 2.3 serialization."""

    def __init__(
        self,
        generate_document_id: bool = True,
        license_expression_operator: str = "AND",
    ):
        self.generate_document_id = generate_document_id
        self.license_expression_operator = license_expression_operator

    def validate(self) -> None:
        if self.license_expression_operator not in ("AND", "OR"):
            raise ValueError(
                f"LicenseExpressionOperator must be 'AND' or 'OR', "
                f"got '{self.license_expression_operator}'"
            )


class SPDX23Serializer(Serializer):
    """Serializes protobom Documents to SPDX 2.3 JSON format."""

    def serialize(
        self,
        document: Document,
        options: Optional[SerializeOptions] = None,
    ) -> dict:
        """Convert a protobom Document to an SPDX 2.3 JSON dict."""
        if options is None:
            options = SPDX23SerializeOptions()

        spdx: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
        }

        # Document name and namespace
        meta = document.metadata
        spdx["name"] = meta.name or "protobom-document"

        # Build namespace from ID
        namespace = self._build_namespace(meta.id, options)
        spdx["documentNamespace"] = namespace

        # Creation info
        creation_info: dict[str, Any] = {}
        if meta.date:
            creation_info["created"] = meta.date.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            creation_info["created"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        creators = []
        for tool in meta.tools:
            tool_str = f"Tool: {tool.name}"
            if tool.version:
                tool_str += f"-{tool.version}"
            creators.append(tool_str)
        for author in meta.authors:
            prefix = "Organization" if author.is_org else "Person"
            author_str = f"{prefix}: {author.name}"
            if author.email:
                author_str += f" ({author.email})"
            creators.append(author_str)
        if not creators:
            creators.append("Tool: protobom-python")
        creation_info["creators"] = creators

        if meta.comment:
            creation_info["comment"] = meta.comment
        spdx["creationInfo"] = creation_info

        # Packages and files
        packages = []
        files = []
        for node in document.node_list.nodes:
            if node.type == NodeType.FILE:
                files.append(self._node_to_file(node))
            else:
                packages.append(self._node_to_package(node, options))

        if packages:
            spdx["packages"] = packages
        if files:
            spdx["files"] = files

        # Relationships
        relationships = self._build_relationships(document)
        if relationships:
            spdx["relationships"] = relationships

        return spdx

    def render(
        self,
        native_doc: Any,
        writer: IO[bytes],
        options: Optional[SerializeOptions] = None,
    ) -> None:
        """Render SPDX 2.3 JSON to a byte stream."""
        output = json.dumps(native_doc, indent=2, default=str)
        if isinstance(output, str):
            output = output.encode("utf-8")
        writer.write(output)

    def _build_namespace(self, doc_id: str, options: SerializeOptions) -> str:
        """Build an SPDX namespace from the document ID."""
        if doc_id and "#" in doc_id:
            # Already has namespace#id format
            return doc_id.split("#")[0]
        if doc_id:
            return doc_id
        if isinstance(options, SPDX23SerializeOptions) and options.generate_document_id:
            return f"https://spdx.org/spdxdocs/protobom-{uuid.uuid4()}"
        return ""

    def _node_to_package(self, node: Node, options: SerializeOptions) -> dict:
        """Convert a protobom Node to an SPDX package dict."""
        pkg: dict[str, Any] = {
            "SPDXID": node.id or f"SPDXRef-Package-{uuid.uuid4().hex[:8]}",
            "name": node.name or "NOASSERTION",
            "downloadLocation": node.url_download or "NOASSERTION",
        }

        if node.version:
            pkg["versionInfo"] = node.version
        if node.file_name:
            pkg["packageFileName"] = node.file_name
        if node.url_home:
            pkg["homepage"] = node.url_home
        if node.copyright:
            pkg["copyrightText"] = node.copyright
        else:
            pkg["copyrightText"] = "NOASSERTION"
        if node.summary:
            pkg["summary"] = node.summary
        if node.description:
            pkg["description"] = node.description
        if node.comment:
            pkg["comment"] = node.comment
        if node.source_info:
            pkg["sourceInfo"] = node.source_info

        # License
        if node.license_concluded:
            pkg["licenseConcluded"] = node.license_concluded
        else:
            pkg["licenseConcluded"] = "NOASSERTION"

        if node.licenses:
            pkg["licenseDeclared"] = self._licenses_to_expression(
                node.licenses, options
            )
        else:
            pkg["licenseDeclared"] = "NOASSERTION"

        if node.license_comments:
            pkg["licenseComments"] = node.license_comments

        # Purpose
        if node.primary_purpose:
            spdx_purpose = _PROTOBOM_PURPOSE_TO_SPDX.get(
                int(node.primary_purpose[0])
            )
            if spdx_purpose:
                pkg["primaryPackagePurpose"] = spdx_purpose

        # Checksums
        checksums = self._build_checksums(node)
        if checksums:
            pkg["checksums"] = checksums

        # Supplier
        if node.suppliers:
            pkg["supplier"] = _person_to_spdx_actor(node.suppliers[0])
        # Originator
        if node.originators:
            pkg["originator"] = _person_to_spdx_actor(node.originators[0])

        # External references
        ext_refs = self._build_external_refs(node)
        if ext_refs:
            pkg["externalRefs"] = ext_refs

        # Dates
        if node.release_date:
            pkg["releaseDate"] = node.release_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        if node.build_date:
            pkg["builtDate"] = node.build_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        if node.valid_until_date:
            pkg["validUntilDate"] = node.valid_until_date.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        # Attributions
        if node.attribution:
            pkg["attributionTexts"] = list(node.attribution)

        return pkg

    def _node_to_file(self, node: Node) -> dict:
        """Convert a protobom Node to an SPDX file dict."""
        f: dict[str, Any] = {
            "SPDXID": node.id or f"SPDXRef-File-{uuid.uuid4().hex[:8]}",
            "fileName": node.name,
        }

        if node.copyright:
            f["copyrightText"] = node.copyright
        else:
            f["copyrightText"] = "NOASSERTION"

        if node.comment:
            f["comment"] = node.comment

        if node.license_concluded:
            f["licenseConcluded"] = node.license_concluded
        else:
            f["licenseConcluded"] = "NOASSERTION"

        if node.licenses:
            f["licenseInfoInFiles"] = list(node.licenses)

        if node.file_types:
            f["fileTypes"] = list(node.file_types)

        checksums = self._build_checksums(node)
        if checksums:
            f["checksums"] = checksums

        if node.attribution:
            f["attributionTexts"] = list(node.attribution)

        return f

    def _build_checksums(self, node: Node) -> list[dict]:
        """Build SPDX checksum list from node hashes."""
        checksums = []
        for algo_int, value in node.hashes.items():
            spdx_algo = _PROTOBOM_HASH_TO_SPDX.get(algo_int)
            if spdx_algo:
                checksums.append({
                    "algorithm": spdx_algo,
                    "checksumValue": value,
                })
        return checksums

    def _build_external_refs(self, node: Node) -> list[dict]:
        """Build SPDX external reference list."""
        refs = []

        # Add software identifiers as external refs
        for id_type, value in node.identifiers.items():
            if id_type == int(SoftwareIdentifierType.PURL):
                refs.append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": value,
                })
            elif id_type == int(SoftwareIdentifierType.CPE23):
                refs.append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": value,
                })
            elif id_type == int(SoftwareIdentifierType.CPE22):
                refs.append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe22Type",
                    "referenceLocator": value,
                })

        # Add external references
        for ext_ref in node.external_references:
            cat_type = _PROTOBOM_EXTREF_TO_SPDX_CATEGORY.get(int(ext_ref.type))
            if cat_type:
                category, ref_type = cat_type
            else:
                category = "OTHER"
                ref_type = "OTHER"
            ref: dict[str, str] = {
                "referenceCategory": category,
                "referenceType": ref_type,
                "referenceLocator": ext_ref.url,
            }
            if ext_ref.comment:
                ref["comment"] = ext_ref.comment
            refs.append(ref)

        return refs

    def _build_relationships(self, document: Document) -> list[dict]:
        """Build SPDX relationships from edges."""
        relationships = []

        # Add DESCRIBES relationships for root elements
        for root_id in document.node_list.root_elements:
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root_id,
            })

        # Add edge relationships
        for edge in document.node_list.edges:
            spdx_rel = _PROTOBOM_EDGE_TO_SPDX.get(int(edge.type), "OTHER")
            for target in edge.to:
                relationships.append({
                    "spdxElementId": edge.from_,
                    "relationshipType": spdx_rel,
                    "relatedSpdxElement": target,
                })

        return relationships

    def _licenses_to_expression(
        self, licenses: list[str], options: SerializeOptions
    ) -> str:
        """Combine multiple licenses into an SPDX expression."""
        if not licenses:
            return "NOASSERTION"
        if len(licenses) == 1:
            return licenses[0]

        operator = " AND "
        if isinstance(options, SPDX23SerializeOptions):
            operator = f" {options.license_expression_operator} "

        return operator.join(licenses)


def _person_to_spdx_actor(person: Person) -> str:
    """Convert a protobom Person to an SPDX actor string."""
    prefix = "Organization" if person.is_org else "Person"
    result = f"{prefix}: {person.name}"
    if person.email:
        result += f" ({person.email})"
    return result

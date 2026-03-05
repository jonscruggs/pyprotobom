"""SPDX 2.3 format unserializer - converts SPDX JSON to protobom."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import IO, Optional

from protobom.native import UnserializeOptions, Unserializer
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
    Purpose,
    SoftwareIdentifierType,
    Tool,
)


# ---------------------------------------------------------------------------
# Type mapping tables
# ---------------------------------------------------------------------------

_SPDX_HASH_ALGO_MAP: dict[str, HashAlgorithm] = {
    "MD5": HashAlgorithm.MD5,
    "SHA1": HashAlgorithm.SHA1,
    "SHA224": HashAlgorithm.SHA224,
    "SHA256": HashAlgorithm.SHA256,
    "SHA384": HashAlgorithm.SHA384,
    "SHA512": HashAlgorithm.SHA512,
    "SHA3-256": HashAlgorithm.SHA3_256,
    "SHA3-384": HashAlgorithm.SHA3_384,
    "SHA3-512": HashAlgorithm.SHA3_512,
    "BLAKE2b-256": HashAlgorithm.BLAKE2B_256,
    "BLAKE2b-384": HashAlgorithm.BLAKE2B_384,
    "BLAKE2b-512": HashAlgorithm.BLAKE2B_512,
    "BLAKE3": HashAlgorithm.BLAKE3,
    "ADLER32": HashAlgorithm.ADLER32,
    "MD2": HashAlgorithm.MD2,
    "MD4": HashAlgorithm.MD4,
    "MD6": HashAlgorithm.MD6,
}

_SPDX_PURPOSE_MAP: dict[str, Purpose] = {
    "APPLICATION": Purpose.APPLICATION,
    "ARCHIVE": Purpose.ARCHIVE,
    "BOM": Purpose.BOM,
    "CONTAINER": Purpose.CONTAINER,
    "DATA": Purpose.DATA,
    "DEVICE": Purpose.DEVICE,
    "DEVICE_DRIVER": Purpose.DEVICE_DRIVER,
    "DOCUMENTATION": Purpose.DOCUMENTATION,
    "EVIDENCE": Purpose.EVIDENCE,
    "EXECUTABLE": Purpose.EXECUTABLE,
    "FILE": Purpose.FILE,
    "FIRMWARE": Purpose.FIRMWARE,
    "FRAMEWORK": Purpose.FRAMEWORK,
    "INSTALL": Purpose.INSTALL,
    "LIBRARY": Purpose.LIBRARY,
    "MANIFEST": Purpose.MANIFEST,
    "MODEL": Purpose.MODEL,
    "MODULE": Purpose.MODULE,
    "OPERATING_SYSTEM": Purpose.OPERATING_SYSTEM,
    "OTHER": Purpose.OTHER,
    "PATCH": Purpose.PATCH,
    "REQUIREMENT": Purpose.REQUIREMENT,
    "SOURCE": Purpose.SOURCE,
    "SPECIFICATION": Purpose.SPECIFICATION,
}

_SPDX_REL_MAP: dict[str, EdgeType] = {
    "AMENDS": EdgeType.amends,
    "ANCESTOR_OF": EdgeType.ancestor,
    "BUILD_DEPENDENCY_OF": EdgeType.buildDependency,
    "BUILD_TOOL_OF": EdgeType.buildTool,
    "CONTAINED_BY": EdgeType.contained_by,
    "CONTAINS": EdgeType.contains,
    "COPY_OF": EdgeType.copy,
    "DATA_FILE_OF": EdgeType.dataFile,
    "DEPENDENCY_MANIFEST_OF": EdgeType.dependencyManifest,
    "DEPENDENCY_OF": EdgeType.dependencyOf,
    "DEPENDS_ON": EdgeType.dependsOn,
    "DESCENDANT_OF": EdgeType.descendant,
    "DESCRIBED_BY": EdgeType.describedBy,
    "DESCRIBES": EdgeType.describes,
    "DEV_DEPENDENCY_OF": EdgeType.devDependency,
    "DEV_TOOL_OF": EdgeType.devTool,
    "DISTRIBUTION_ARTIFACT": EdgeType.distributionArtifact,
    "DOCUMENTATION_OF": EdgeType.documentation,
    "DYNAMIC_LINK": EdgeType.dynamicLink,
    "EXAMPLE_OF": EdgeType.example,
    "EXPANDED_FROM_ARCHIVE": EdgeType.expandedFromArchive,
    "FILE_ADDED": EdgeType.fileAdded,
    "FILE_DELETED": EdgeType.fileDeleted,
    "FILE_MODIFIED": EdgeType.fileModified,
    "GENERATED_FROM": EdgeType.generatedFrom,
    "GENERATES": EdgeType.generates,
    "HAS_PREREQUISITE": EdgeType.prerequisite,
    "METAFILE_OF": EdgeType.metafile,
    "OPTIONAL_COMPONENT_OF": EdgeType.optionalComponent,
    "OPTIONAL_DEPENDENCY_OF": EdgeType.optionalDependency,
    "OTHER": EdgeType.other,
    "PACKAGE_OF": EdgeType.packages,
    "PATCH_APPLIED": EdgeType.patch,
    "PATCH_FOR": EdgeType.patch,
    "PREREQUISITE_FOR": EdgeType.prerequisiteFor,
    "PROVIDED_DEPENDENCY_OF": EdgeType.providedDependency,
    "REQUIREMENT_DESCRIPTION_FOR": EdgeType.requirementFor,
    "RUNTIME_DEPENDENCY_OF": EdgeType.runtimeDependency,
    "SPECIFICATION_FOR": EdgeType.specificationFor,
    "STATIC_LINK": EdgeType.staticLink,
    "TEST_OF": EdgeType.test,
    "TEST_CASE_OF": EdgeType.testCase,
    "TEST_DEPENDENCY_OF": EdgeType.testDependency,
    "TEST_TOOL_OF": EdgeType.testTool,
    "VARIANT_OF": EdgeType.variant,
}

_SPDX_EXTREF_CATEGORY_TYPE_MAP: dict[tuple[str, str], ExternalReferenceType] = {
    ("PACKAGE-MANAGER", "bower"): ExternalReferenceType.BOWER,
    ("PACKAGE-MANAGER", "maven-central"): ExternalReferenceType.MAVEN_CENTRAL,
    ("PACKAGE-MANAGER", "npm"): ExternalReferenceType.NPM,
    ("PACKAGE-MANAGER", "nuget"): ExternalReferenceType.NUGET,
    ("PACKAGE-MANAGER", "purl"): ExternalReferenceType.DOWNLOAD,
    ("SECURITY", "cpe22Type"): ExternalReferenceType.SECURITY_OTHER,
    ("SECURITY", "cpe23Type"): ExternalReferenceType.SECURITY_OTHER,
    ("SECURITY", "advisory"): ExternalReferenceType.SECURITY_ADVISORY,
    ("SECURITY", "fix"): ExternalReferenceType.SECURITY_FIX,
    ("SECURITY", "url"): ExternalReferenceType.SECURITY_OTHER,
    ("SECURITY", "swid"): ExternalReferenceType.SECURITY_SWID,
    ("PERSISTENT-ID", "swh"): ExternalReferenceType.OTHER,
    ("PERSISTENT-ID", "gitoid"): ExternalReferenceType.OTHER,
}

_SPDX_EXTREF_ID_MAP: dict[str, SoftwareIdentifierType] = {
    "purl": SoftwareIdentifierType.PURL,
    "cpe22Type": SoftwareIdentifierType.CPE22,
    "cpe23Type": SoftwareIdentifierType.CPE23,
    "gitoid": SoftwareIdentifierType.GITOID,
}


class SPDX23Unserializer(Unserializer):
    """Unserializes SPDX 2.3 JSON documents into protobom Documents."""

    def unserialize(
        self,
        reader: IO[bytes],
        options: Optional[UnserializeOptions] = None,
    ) -> Document:
        """Parse an SPDX 2.3 JSON document into a protobom Document."""
        if options is None:
            options = UnserializeOptions()

        content = reader.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        spdx_doc = json.loads(content)

        metadata = self._parse_metadata(spdx_doc)
        node_list = NodeList()

        # Parse packages
        for pkg in spdx_doc.get("packages", []):
            node = self._package_to_node(options, pkg)
            node_list.add_node(node)

        # Parse files
        for f in spdx_doc.get("files", []):
            node = self._file_to_node(f)
            node_list.add_node(node)

        # Parse relationships and set root elements
        doc_spdx_id = spdx_doc.get("SPDXID", "SPDXRef-DOCUMENT")
        for rel in spdx_doc.get("relationships", []):
            edge = self._relationship_to_edge(rel)
            if edge:
                # Check if this is a DESCRIBES relationship from the document
                if (
                    rel.get("spdxElementId") == doc_spdx_id
                    and rel.get("relationshipType") == "DESCRIBES"
                ):
                    target = rel.get("relatedSpdxElement", "")
                    if target and target not in node_list._root_index:
                        node_list.root_elements.append(target)
                        node_list._root_index.add(target)
                else:
                    node_list.add_edge(edge)

        return Document(metadata=metadata, node_list=node_list)

    def _parse_metadata(self, spdx_doc: dict) -> Metadata:
        """Parse SPDX document metadata."""
        md = Metadata()

        # Build document identifier
        namespace = spdx_doc.get("documentNamespace", "")
        spdx_id = spdx_doc.get("SPDXID", "")
        if namespace:
            md.id = f"{namespace}#{spdx_id}" if spdx_id else namespace
        else:
            md.id = f"urn:protobom:{uuid.uuid4()}"

        md.name = spdx_doc.get("name", "")
        md.version = spdx_doc.get("spdxVersion", "")
        md.comment = spdx_doc.get("comment", "")

        # Parse creation info
        creation_info = spdx_doc.get("creationInfo", {})
        created = creation_info.get("created")
        if created:
            md.date = _parse_spdx_datetime(created)

        md.comment = creation_info.get("comment", md.comment)

        # Parse creators
        for creator_str in creation_info.get("creators", []):
            parts = creator_str.split(":", 1)
            if len(parts) == 2:
                creator_type, creator_value = parts[0].strip(), parts[1].strip()
                if creator_type == "Tool":
                    # Parse tool name and version (last dash-separated segment is version)
                    last_dash = creator_value.rfind("-")
                    if last_dash > 0:
                        tool = Tool(
                            name=creator_value[:last_dash].strip(),
                            version=creator_value[last_dash + 1:].strip(),
                        )
                    else:
                        tool = Tool(name=creator_value.strip())
                    md.tools.append(tool)
                elif creator_type in ("Person", "Organization"):
                    person = Person(
                        name=creator_value,
                        is_org=(creator_type == "Organization"),
                    )
                    # Extract email if present
                    if "(" in creator_value and ")" in creator_value:
                        name_part = creator_value[:creator_value.index("(")].strip()
                        email_part = creator_value[
                            creator_value.index("(") + 1:creator_value.index(")")
                        ].strip()
                        person.name = name_part
                        person.email = email_part
                    md.authors.append(person)

        return md

    def _package_to_node(
        self, options: UnserializeOptions, pkg: dict
    ) -> Node:
        """Convert an SPDX package to a protobom Node."""
        node = Node()
        node.id = pkg.get("SPDXID", "")
        node.type = NodeType.PACKAGE
        node.name = pkg.get("name", "")
        node.version = pkg.get("versionInfo", "")
        node.file_name = pkg.get("packageFileName", "")
        node.url_download = pkg.get("downloadLocation", "")
        node.url_home = pkg.get("homepage", "")
        node.copyright = pkg.get("copyrightText", "")
        node.summary = pkg.get("summary", "")
        node.description = pkg.get("description", "")
        node.comment = pkg.get("comment", "")
        node.source_info = pkg.get("sourceInfo", "")

        # License
        license_concluded = pkg.get("licenseConcluded", "")
        if license_concluded and license_concluded != "NOASSERTION":
            node.license_concluded = license_concluded

        license_declared = pkg.get("licenseDeclared", "")
        if license_declared and license_declared != "NOASSERTION":
            if license_declared not in node.licenses:
                node.licenses.append(license_declared)

        license_info = pkg.get("licenseInfoFromFiles", [])
        for lic in license_info:
            if lic and lic != "NOASSERTION" and lic not in node.licenses:
                node.licenses.append(lic)

        node.license_comments = pkg.get("licenseComments", "")

        # Primary purpose
        purpose_str = pkg.get("primaryPackagePurpose", "")
        if purpose_str:
            purpose = _SPDX_PURPOSE_MAP.get(purpose_str, Purpose.UNKNOWN_PURPOSE)
            if purpose != Purpose.UNKNOWN_PURPOSE:
                node.primary_purpose.append(purpose)

        # Checksums
        for cs in pkg.get("checksums", []):
            algo = _SPDX_HASH_ALGO_MAP.get(
                cs.get("algorithm", ""), HashAlgorithm.UNKNOWN
            )
            if algo != HashAlgorithm.UNKNOWN:
                node.hashes[int(algo)] = cs.get("checksumValue", "")

        # Supplier
        supplier_str = pkg.get("supplier", "")
        if supplier_str and supplier_str != "NOASSERTION":
            node.suppliers.append(_parse_spdx_actor(supplier_str))

        # Originator
        originator_str = pkg.get("originator", "")
        if originator_str and originator_str != "NOASSERTION":
            node.originators.append(_parse_spdx_actor(originator_str))

        # External references
        for ext_ref in pkg.get("externalRefs", []):
            ref_type, is_identifier = self._ext_ref_to_protobom(ext_ref)
            if is_identifier:
                id_type = _SPDX_EXTREF_ID_MAP.get(
                    ext_ref.get("referenceType", "")
                )
                if id_type is not None:
                    node.identifiers[int(id_type)] = ext_ref.get(
                        "referenceLocator", ""
                    )
            else:
                node.external_references.append(ExternalReference(
                    url=ext_ref.get("referenceLocator", ""),
                    type=ref_type,
                    comment=ext_ref.get("comment", ""),
                ))

        # Dates
        release_date = pkg.get("releaseDate")
        if release_date:
            node.release_date = _parse_spdx_datetime(release_date)
        build_date = pkg.get("builtDate")
        if build_date:
            node.build_date = _parse_spdx_datetime(build_date)
        valid_until = pkg.get("validUntilDate")
        if valid_until:
            node.valid_until_date = _parse_spdx_datetime(valid_until)

        # Attributions
        for attr in pkg.get("attributionTexts", []):
            node.attribution.append(attr)

        return node

    def _file_to_node(self, file_data: dict) -> Node:
        """Convert an SPDX file to a protobom Node."""
        node = Node()
        node.id = file_data.get("SPDXID", "")
        node.type = NodeType.FILE
        node.name = file_data.get("fileName", "")
        node.copyright = file_data.get("copyrightText", "")
        node.comment = file_data.get("comment", "")

        # License
        license_concluded = file_data.get("licenseConcluded", "")
        if license_concluded and license_concluded != "NOASSERTION":
            node.license_concluded = license_concluded

        license_info = file_data.get("licenseInfoInFiles", [])
        for lic in license_info:
            if lic and lic != "NOASSERTION" and lic not in node.licenses:
                node.licenses.append(lic)

        # File types
        node.file_types = file_data.get("fileTypes", [])

        # Checksums
        for cs in file_data.get("checksums", []):
            algo = _SPDX_HASH_ALGO_MAP.get(
                cs.get("algorithm", ""), HashAlgorithm.UNKNOWN
            )
            if algo != HashAlgorithm.UNKNOWN:
                node.hashes[int(algo)] = cs.get("checksumValue", "")

        # Attributions
        for attr in file_data.get("attributionTexts", []):
            node.attribution.append(attr)

        return node

    def _relationship_to_edge(self, rel: dict) -> Optional[Edge]:
        """Convert an SPDX relationship to a protobom Edge."""
        rel_type_str = rel.get("relationshipType", "")
        edge_type = _SPDX_REL_MAP.get(rel_type_str, EdgeType.UNKNOWN)

        from_element = rel.get("spdxElementId", "")
        to_element = rel.get("relatedSpdxElement", "")

        if not from_element or not to_element:
            return None

        return Edge(type=edge_type, from_=from_element, to=[to_element])

    def _ext_ref_to_protobom(
        self, ext_ref: dict
    ) -> tuple[ExternalReferenceType, bool]:
        """Convert an SPDX external reference to protobom type.

        Returns (type, is_software_identifier).
        """
        category = ext_ref.get("referenceCategory", "")
        ref_type = ext_ref.get("referenceType", "")

        # Check if this is a software identifier (PURL, CPE, etc.)
        is_identifier = ref_type in _SPDX_EXTREF_ID_MAP

        key = (category, ref_type)
        protobom_type = _SPDX_EXTREF_CATEGORY_TYPE_MAP.get(
            key, ExternalReferenceType.OTHER
        )

        return protobom_type, is_identifier


def _parse_spdx_actor(actor_str: str) -> Person:
    """Parse an SPDX actor string like 'Organization: Acme (acme@example.com)'."""
    person = Person()
    parts = actor_str.split(":", 1)
    if len(parts) == 2:
        actor_type, value = parts[0].strip(), parts[1].strip()
        person.is_org = actor_type == "Organization"

        if "(" in value and ")" in value:
            person.name = value[:value.index("(")].strip()
            person.email = value[value.index("(") + 1:value.index(")")].strip()
        else:
            person.name = value
    else:
        person.name = actor_str

    return person


def _parse_spdx_datetime(date_str: str) -> Optional[datetime]:
    """Parse an SPDX datetime string (RFC 3339)."""
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
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None

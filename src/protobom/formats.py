"""SBOM format detection and format constants."""

from __future__ import annotations

import json
from typing import IO, Optional


# Encoding constants
JSON = "json"
XML = "xml"
TEXT = "text"

# Format type families
SPDX = "spdx"
CYCLONEDX = "cyclonedx"

# SPDX format strings (MIME-like)
SPDX23JSON = "text/spdx+json;version=2.3"
SPDX23TV = "text/spdx+text;version=2.3"
SPDX22JSON = "text/spdx+json;version=2.2"
SPDX22TV = "text/spdx+text;version=2.2"

# CycloneDX format strings
CDX10JSON = "application/vnd.cyclonedx+json;version=1.0"
CDX11JSON = "application/vnd.cyclonedx+json;version=1.1"
CDX12JSON = "application/vnd.cyclonedx+json;version=1.2"
CDX13JSON = "application/vnd.cyclonedx+json;version=1.3"
CDX14JSON = "application/vnd.cyclonedx+json;version=1.4"
CDX15JSON = "application/vnd.cyclonedx+json;version=1.5"
CDX16JSON = "application/vnd.cyclonedx+json;version=1.6"

# Protobuf binary format
PROTOBUF = "application/vnd.protobom+protobuf"

# List of supported formats
SUPPORTED_FORMATS = [
    SPDX23JSON,
    SPDX23TV,
    SPDX22JSON,
    SPDX22TV,
    CDX14JSON,
    CDX15JSON,
    CDX16JSON,
]


class Format:
    """Represents an SBOM format with version and encoding information."""

    def __init__(self, format_string: str):
        self._format = format_string

    def __str__(self) -> str:
        return self._format

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Format):
            return self._format == other._format
        if isinstance(other, str):
            return self._format == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._format)

    def version(self) -> str:
        """Extract the version from the format string."""
        parts = self._format.split(";version=")
        if len(parts) >= 2:
            return parts[1]
        return ""

    def major(self) -> str:
        """Get the major version number."""
        v = self.version()
        parts = v.split(".")
        return parts[0] if parts else ""

    def minor(self) -> str:
        """Get the minor version number."""
        v = self.version()
        parts = v.split(".")
        return parts[1] if len(parts) >= 2 else ""

    def encoding(self) -> str:
        """Determine the encoding (json, xml, or text)."""
        if JSON in self._format:
            return JSON
        if TEXT in self._format or "text/" in self._format:
            return TEXT
        if XML in self._format:
            return XML
        return ""

    def type(self) -> str:
        """Determine the format family (spdx or cyclonedx)."""
        lower = self._format.lower()
        if SPDX in lower:
            return SPDX
        if CYCLONEDX in lower:
            return CYCLONEDX
        return ""

    def uri(self) -> str:
        """Get the MIME type prefix."""
        return self._format.split("+")[0] if "+" in self._format else self._format


def sniff(stream: IO[bytes]) -> Optional[Format]:
    """Detect the SBOM format by examining the stream content.

    Reads the stream to detect the format, then seeks back to the beginning.
    Returns None if the format cannot be determined.
    """
    pos = stream.tell()
    try:
        content = stream.read()
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = content
    finally:
        stream.seek(pos)

    return sniff_string(text)


def sniff_string(text: str) -> Optional[Format]:
    """Detect the SBOM format from a string."""
    text = text.strip()

    # Try JSON first
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return _detect_json_format(data)

    # Check for SPDX tag-value format
    if text.startswith("SPDXVersion:"):
        return _detect_spdx_tv_format(text)

    return None


def _detect_json_format(data: dict) -> Optional[Format]:
    """Detect format from parsed JSON data."""
    # CycloneDX detection
    if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
        spec_version = data.get("specVersion", "")
        version_map = {
            "1.0": CDX10JSON,
            "1.1": CDX11JSON,
            "1.2": CDX12JSON,
            "1.3": CDX13JSON,
            "1.4": CDX14JSON,
            "1.5": CDX15JSON,
            "1.6": CDX16JSON,
        }
        fmt = version_map.get(spec_version)
        return Format(fmt) if fmt else None

    # SPDX detection
    if "spdxVersion" in data:
        spdx_version = data.get("spdxVersion", "")
        if "2.3" in spdx_version:
            return Format(SPDX23JSON)
        if "2.2" in spdx_version:
            return Format(SPDX22JSON)

    return None


def _detect_spdx_tv_format(text: str) -> Optional[Format]:
    """Detect SPDX tag-value format version."""
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("SPDXVersion:"):
            version_str = line.split(":", 1)[1].strip()
            if "2.3" in version_str:
                return Format(SPDX23TV)
            if "2.2" in version_str:
                return Format(SPDX22TV)
            break
    return None

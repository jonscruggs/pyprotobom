"""Reader for parsing SBOM documents from files and streams."""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

from protobom import formats
from protobom.formats import Format
from protobom.native import Unserializer, UnserializeOptions
from protobom.native.unserializers.cyclonedx import CDXUnserializer
from protobom.native.unserializers.spdx23 import SPDX23Unserializer
from protobom.sbom import Document, HashAlgorithm, SourceData
from protobom.storage import Backend, RetrieveOptions


@dataclass
class ReadOptions:
    """Options for reading SBOM documents."""
    format: Optional[Format] = None
    unserialize_options: Optional[UnserializeOptions] = None


# Default unserializer registry
_unserializers: dict[str, Unserializer] = {}
_initialized = False


def _ensure_initialized() -> None:
    """Initialize default unserializers on first use."""
    global _initialized
    if _initialized:
        return
    _initialized = True

    # Register CycloneDX unserializers for all versions
    for version in ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"]:
        fmt_str = f"application/vnd.cyclonedx+json;version={version}"
        _unserializers[fmt_str] = CDXUnserializer(version=version, encoding="json")

    # Register SPDX unserializers
    _unserializers[formats.SPDX23JSON] = SPDX23Unserializer()
    _unserializers[formats.SPDX22JSON] = SPDX23Unserializer()  # 2.2 is close enough


def register_unserializer(format_string: str, unserializer: Unserializer) -> None:
    """Register a custom unserializer for a format."""
    _ensure_initialized()
    _unserializers[format_string] = unserializer


def unregister_unserializer(format_string: str) -> None:
    """Unregister an unserializer for a format."""
    _ensure_initialized()
    _unserializers.pop(format_string, None)


def get_unserializer(format_string: str) -> Optional[Unserializer]:
    """Get the registered unserializer for a format."""
    _ensure_initialized()
    return _unserializers.get(format_string)


class Reader:
    """Reads and parses SBOM documents from files and streams.

    Supports automatic format detection ("sniffing") and multiple
    SBOM formats including SPDX 2.3 and CycloneDX 1.0-1.6.

    Example::

        reader = Reader()
        document = reader.parse_file("sbom.json")
        print(document.metadata.name)
    """

    def __init__(
        self,
        backend: Optional[Backend] = None,
        options: Optional[ReadOptions] = None,
    ):
        self._backend = backend
        self._options = options or ReadOptions()

    def parse_file(
        self,
        path: str | Path,
        options: Optional[ReadOptions] = None,
    ) -> Document:
        """Parse an SBOM document from a file path."""
        path = Path(path)
        with open(path, "rb") as f:
            return self.parse_stream(f, options)

    def parse_stream(
        self,
        stream: IO[bytes],
        options: Optional[ReadOptions] = None,
    ) -> Document:
        """Parse an SBOM document from a byte stream."""
        opts = options or self._options

        # Read the full content for hashing and format detection
        content = stream.read()
        buf = io.BytesIO(content)

        # Detect format
        detected_format = opts.format
        if detected_format is None:
            detected_format = formats.sniff(buf)
            buf.seek(0)

        if detected_format is None:
            # Try protobuf binary format
            try:
                return Document.deserialize_from_proto(content)
            except Exception:
                pass
            raise ValueError("Unable to detect SBOM format from stream content")

        # Get unserializer
        _ensure_initialized()
        format_str = str(detected_format)
        unserializer = _unserializers.get(format_str)
        if unserializer is None:
            raise ValueError(f"No unserializer registered for format: {format_str}")

        # Parse
        unserialize_opts = opts.unserialize_options
        document = unserializer.unserialize(buf, unserialize_opts)

        # Compute source data hashes
        source_data = SourceData(
            format=format_str,
            size=len(content),
            hashes={
                int(HashAlgorithm.SHA256): hashlib.sha256(content).hexdigest(),
                int(HashAlgorithm.SHA512): hashlib.sha512(content).hexdigest(),
            },
        )
        document.metadata.source_data = source_data

        return document

    def retrieve(
        self,
        document_id: str,
        options: Optional[RetrieveOptions] = None,
    ) -> Document:
        """Retrieve a document from the storage backend."""
        if self._backend is None:
            raise RuntimeError("No storage backend configured")
        return self._backend.retrieve(document_id, options)

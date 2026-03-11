"""Writer for serializing SBOM documents to files and streams."""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Optional

from protobom import formats
from protobom.formats import Format
from protobom.native import Serializer, SerializeOptions
from protobom.native.serializers.cyclonedx import CDXSerializer
from protobom.native.serializers.spdx23 import SPDX23Serializer
from protobom.sbom import Document
from protobom.storage import Backend, StoreOptions


@dataclass
class WriteOptions:
    """Options for writing SBOM documents."""
    format: Optional[Format] = None
    serialize_options: Optional[SerializeOptions] = None


# Default serializer registry
_serializers: dict[str, Serializer] = {}
_initialized = False


def _ensure_initialized() -> None:
    """Initialize default serializers on first use."""
    global _initialized
    if _initialized:
        return
    _initialized = True

    # Register CycloneDX serializers
    for version in ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"]:
        fmt_str = f"application/vnd.cyclonedx+json;version={version}"
        _serializers[fmt_str] = CDXSerializer(version=version, encoding="json")

    # Register SPDX serializers
    _serializers[formats.SPDX23JSON] = SPDX23Serializer()


def register_serializer(format_string: str, serializer: Serializer) -> None:
    """Register a custom serializer for a format."""
    _ensure_initialized()
    _serializers[format_string] = serializer


def unregister_serializer(format_string: str) -> None:
    """Unregister a serializer for a format."""
    _ensure_initialized()
    _serializers.pop(format_string, None)


def get_serializer(format_string: str) -> Optional[Serializer]:
    """Get the registered serializer for a format."""
    _ensure_initialized()
    return _serializers.get(format_string)


class Writer:
    """Writes SBOM documents to files and streams.

    Supports serialization to SPDX 2.3 and CycloneDX 1.0-1.6 JSON formats.

    Example::

        writer = Writer()
        writer.write_file(document, "output.cdx.json",
                         WriteOptions(format=Format(formats.CDX15JSON)))
    """

    def __init__(
        self,
        backend: Optional[Backend] = None,
        options: Optional[WriteOptions] = None,
    ):
        self._backend = backend
        self._options = options or WriteOptions()

    def write_file(
        self,
        document: Document,
        path: str | Path,
        options: Optional[WriteOptions] = None,
    ) -> None:
        """Write an SBOM document to a file."""
        path = Path(path)
        with open(path, "wb") as f:
            self.write_stream(document, f, options)

    def write_stream(
        self,
        document: Document,
        stream: IO[bytes],
        options: Optional[WriteOptions] = None,
    ) -> None:
        """Write an SBOM document to a byte stream."""
        opts = options or self._options

        if opts.format is None:
            raise ValueError(
                "Output format must be specified in WriteOptions"
            )

        _ensure_initialized()
        format_str = str(opts.format)

        # Handle protobuf binary format
        if format_str == formats.PROTOBUF:
            stream.write(document.serialize_to_proto())
            return

        serializer = _serializers.get(format_str)
        if serializer is None:
            raise ValueError(f"No serializer registered for format: {format_str}")

        native_doc = serializer.serialize(document, opts.serialize_options)
        serializer.render(native_doc, stream, opts.serialize_options)

    def store(
        self,
        document: Document,
        options: Optional[StoreOptions] = None,
    ) -> None:
        """Store a document using the storage backend."""
        if self._backend is None:
            raise RuntimeError("No storage backend configured")
        self._backend.store(document, options)

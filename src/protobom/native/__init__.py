"""Native format serializers and unserializers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import IO, Any, Optional

from protobom.sbom import Document


@dataclass
class SerializeOptions:
    """Options for serializing a document."""


@dataclass
class UnserializeOptions:
    """Options for unserializing a document."""
    # When true, SPDX annotations are converted to node properties
    annotations_to_properties: bool = False


class Serializer(ABC):
    """Interface for serializing protobom documents to native formats."""

    @abstractmethod
    def serialize(
        self,
        document: Document,
        options: Optional[SerializeOptions] = None,
    ) -> Any:
        """Convert a protobom Document to a native format representation."""

    @abstractmethod
    def render(
        self,
        native_doc: Any,
        writer: IO[bytes],
        options: Optional[SerializeOptions] = None,
    ) -> None:
        """Render a native format document to a byte stream."""


class Unserializer(ABC):
    """Interface for unserializing native format documents to protobom."""

    @abstractmethod
    def unserialize(
        self,
        reader: IO[bytes],
        options: Optional[UnserializeOptions] = None,
    ) -> Document:
        """Parse a native format document into a protobom Document."""

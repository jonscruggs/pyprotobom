"""Storage backend interfaces for persisting and retrieving SBOM documents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from protobom.sbom import Document


@dataclass
class StoreOptions:
    """Options for storing a document."""
    backend_options: dict = field(default_factory=dict)


@dataclass
class RetrieveOptions:
    """Options for retrieving a document."""
    backend_options: dict = field(default_factory=dict)


class Storer(ABC):
    """Interface for storing SBOM documents."""

    @abstractmethod
    def store(self, document: Document, options: Optional[StoreOptions] = None) -> None:
        """Store an SBOM document."""


class Retriever(ABC):
    """Interface for retrieving SBOM documents."""

    @abstractmethod
    def retrieve(
        self, document_id: str, options: Optional[RetrieveOptions] = None
    ) -> Document:
        """Retrieve an SBOM document by ID."""


class Backend(Storer, Retriever):
    """Combined storage backend that can both store and retrieve documents."""

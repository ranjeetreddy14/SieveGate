"""
Abstract classifier interface.

SieveGate depends on this ABC, never on a concrete vendor SDK.
Any classifier can sit behind it: the commercial edition ships an adapter
for TypeSafe's Jev model, and MockClassifier implements it for tests and
development.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import ClassificationResult


class Classifier(ABC):
    """
    Contract every classifier must satisfy.

    Takes an arbitrary payload (text today; images/files later)
    and returns a single ClassificationResult covering both
    compliance and routing.
    """

    @abstractmethod
    async def classify(self, payload: Any) -> ClassificationResult:
        """
        Classify a payload and return a structured result.

        Args:
            payload: The content to classify.  v1 expects str;
                     non-str payloads should be handled gracefully
                     by implementations (flag or block, never crash).

        Returns:
            ClassificationResult with verdict + routing.
        """
        ...

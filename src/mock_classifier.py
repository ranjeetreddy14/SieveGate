"""
Mock classifier for tests and development.

Returns configurable results without calling any external service.
Use a real Classifier in production.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Optional

from .classifier import Classifier
from .models import (
    ClassificationResult,
    ComplianceVerdict,
    ContentCategory,
    ModelTier,
    PayloadType,
    RoutingRecommendation,
)


# Default "safe" result — no PII, leak risk 0, route to small model.
# Every signal is filled in, so the default policy has nothing to block.
_DEFAULT_RESULT = ClassificationResult(
    verdict=ComplianceVerdict(
        contains_pii=False,
        data_leak_risk=0.0,
        payload_type=PayloadType.TEXT,
        content_category=ContentCategory.GENERAL_TEXT,
        pii_probability=0.0,
        secret_probability=0.0,
        financial_probability=0.0,
        leak_risk_confidence=1.0,
        category_confidence=1.0,
        contains_secret=False,
        contains_financial=False,
    ),
    routing=RoutingRecommendation(
        tier=ModelTier.SMALL,
        reason="mock: default safe result",
    ),
)


class MockClassifier(Classifier):
    """
    A fake classifier whose output you control at construction time.

    Pass a ClassificationResult to override the default, or leave it
    to get a safe, everything-allowed result.  Useful for unit tests
    and for running the skeleton before the real SDK is wired up.

    Any ComplianceVerdict field can also be set by keyword, on top of
    the result, e.g. MockClassifier(pii_probability=0.3) or
    MockClassifier(secret_probability=None) for a missing signal.
    """

    def __init__(
        self,
        result: Optional[ClassificationResult] = None,
        *,
        raise_on_classify: Optional[Exception] = None,
        **verdict_fields: Any,
    ) -> None:
        # The result every classify() call will return.
        result = result or _DEFAULT_RESULT
        if verdict_fields:
            # Unknown field names raise TypeError here.
            result = replace(result, verdict=replace(result.verdict, **verdict_fields))
        self._result = result
        # If set, classify() raises this instead of returning — lets
        # us test the fail-secure path without a real network error.
        self._raise_on_classify = raise_on_classify

    async def classify(self, payload: Any) -> ClassificationResult:
        """Return the pre-configured result (or raise if told to)."""
        if self._raise_on_classify is not None:
            raise self._raise_on_classify
        return self._result

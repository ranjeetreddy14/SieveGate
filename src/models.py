"""
Structured results returned by every classifier.

These dataclasses define the output shape:
one call → one compliance verdict + one routing recommendation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping, Optional

if TYPE_CHECKING:
    from .prefilter import Finding


# --- Compliance verdict ---

class PayloadType(Enum):
    """Broad content category detected in the payload."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    UNKNOWN = "unknown"


class ContentCategory(Enum):
    """
    What sensitive content a text payload contains (not its topic).
    Only known for text payloads.
    """
    GENERAL_TEXT = "general_text"
    SOURCE_CODE = "source_code"
    CREDENTIALS = "credentials"
    CUSTOMER_PII = "customer_pii"
    EMPLOYEE_HR = "employee_hr"
    FINANCIAL_RECORDS = "financial_records"
    HEALTH_RECORDS = "health_records"
    LEGAL_CONTRACT = "legal_contract"
    STRATEGY_CONFIDENTIAL = "strategy_confidential"
    INFRASTRUCTURE_SECURITY = "infrastructure_security"


@dataclass(frozen=True)
class ComplianceVerdict:
    """
    The compliance half of a classification result.

    contains_pii:      True if personal data was detected (display flag:
                       see contains_secret / contains_financial below).
    data_leak_risk:    0.0 (safe) → 1.0 (certain leak).
    payload_type:      The modality of the content (text, image, ...).
    content_category:  What kind of text it is, when the classifier says.

    Vendor-neutral signals the enforcement policy reads.  None means
    "this classifier did not provide this signal":
    pii_probability:        0.0–1.0, how likely personal data is present.
    secret_probability:     0.0–1.0 that it contains a secret.
    financial_probability:  0.0–1.0 that it contains financial records.
    leak_risk_confidence:   0.0–1.0, how sure the classifier is of
                            data_leak_risk (low = unsure).
    category_confidence:    0.0–1.0, how sure it is of content_category.
    contains_secret / contains_financial:  yes/no flags for display, set
                            the same way as contains_pii.  All three flags
                            are informational: the classifier sets them at
                            its own cut-off (0.5 for TypeSafe), while the
                            policy blocks on the probabilities at its own
                            thresholds.  So a payload can be blocked for
                            pii>=0.30 with contains_pii=False.
    """
    contains_pii: bool
    data_leak_risk: float          # 0.0–1.0
    payload_type: PayloadType
    content_category: Optional[ContentCategory] = None
    pii_probability: Optional[float] = None
    secret_probability: Optional[float] = None
    financial_probability: Optional[float] = None
    leak_risk_confidence: Optional[float] = None
    category_confidence: Optional[float] = None
    contains_secret: Optional[bool] = None
    contains_financial: Optional[bool] = None


# --- Routing recommendation ---

class ModelTier(Enum):
    """
    Which model tier should handle this query.
    Tiers are intentionally coarse — the buyer maps them
    to their own model catalogue.
    """
    BLOCKED = "blocked"   # Don't send at all
    SMALL = "small"       # Cheap / fast model
    MEDIUM = "medium"     # Mid-range
    LARGE = "large"       # Full-capability model


@dataclass(frozen=True)
class RoutingRecommendation:
    """
    The routing/cost half of a classification result.

    tier:   Which model tier should handle the query.
    reason: Short human-readable explanation (for logs / dashboards).
    """
    tier: ModelTier
    reason: str = ""


# --- Raw classifier answers ---

@dataclass(frozen=True)
class Judgment:
    """
    One raw answer from the classifier, kept so callers can apply their
    own thresholds instead of trusting a single yes/no.

    value:          yes-probability (yes/no question), score level
                    (rubric question) or chosen label (choice question).
    confidence:     0.0–1.0 when the classifier reports one; None for
                    yes/no questions, whose probability already says it all.
    probabilities:  full distribution for choice and score questions.
    """
    value: float | str
    confidence: Optional[float] = None
    probabilities: Optional[Mapping[str | int, float]] = None


# --- Combined result ---

@dataclass(frozen=True)
class ClassificationResult:
    """
    Everything a single classifier call returns.
    The SieveGate layer reads this and decides whether to
    allow, block, or reroute the outbound call.
    """
    verdict: ComplianceVerdict
    routing: RoutingRecommendation
    # If the classifier itself failed, this carries the error message.
    error: Optional[str] = None
    # Raw answers by question name (empty for mocks and blocked results).
    judgments: Mapping[str, Judgment] = field(
        default_factory=lambda: MappingProxyType({})
    )
    # Set by SieveGate's enforcement policy (see policy.py):
    # policy_reasons: short reason codes for every rule that fired, e.g.
    #     ("pii>=0.30", "category:credentials").  Codes only, never text
    #     from the payload.  Empty when nothing fired or the policy did not
    #     run (fail-secure blocks: see `error`).
    # would_block:    True when the gate's decision is to block: a policy
    #     hit in either mode, or a fail-secure block.  In "observe" mode it
    #     is the only sign of a policy hit, because the payload still passes.
    # policy_mode:    "enforce" or "observe"; empty if no gate set it.
    # Reconfirmation:
    # needs_confirmation: True when the payload is not blocked but the
    #     policy asks a person to reconfirm before it is sent (e.g. it looks
    #     like financial records that may be hypothetical).  SieveGate does
    #     not ask; the caller does.  Always False on a blocked result.
    # confirm_reasons: reason codes for that request, e.g.
    #     ("confirm:category:financial_records",).  Kept on blocked results
    #     too, for the audit trail.
    # Local pre-filter:
    # prefilter_findings: what the pre-filter found (kind, detector, span;
    #     never the matched text).  Set on a pre-filter block, and in
    #     prefilter_mode="observe" on whatever result the gate returns.
    #     Empty when nothing was found or the pre-filter is off.
    policy_reasons: tuple[str, ...] = ()
    would_block: bool = False
    policy_mode: str = ""
    needs_confirmation: bool = False
    confirm_reasons: tuple[str, ...] = ()
    prefilter_findings: tuple[Finding, ...] = ()

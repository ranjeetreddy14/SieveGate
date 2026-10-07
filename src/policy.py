"""
Enforcement policy: turns a classifier's verdict into "allow" or "block".

The policy reads only the vendor-neutral ComplianceVerdict fields, never a
classifier's own question names, so any Classifier works with any policy.

Defaults are zero-trust: when in doubt, block.  They were tuned on blind
test sets and then measured on a holdout set they were never tuned on
(see docs/DEMO.md for the results).
Buyers loosen or tighten them by constructing their own EnforcementPolicy.
"""

from __future__ import annotations

import inspect
import math
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from .models import ClassificationResult, ContentCategory

ENFORCE = "enforce"
OBSERVE = "observe"
_MODES = (ENFORCE, OBSERVE)

# A buyer-supplied rule: (result, context) -> a short reason code to block,
# or None to allow.  It sees the classifier's result and the caller's context.
ExtraRule = Callable[[ClassificationResult, Optional[Mapping[str, Any]]], Optional[str]]

_THRESHOLDS = (
    "pii_threshold",
    "secret_threshold",
    "financial_threshold",
    "max_leak_risk",
    "min_leak_confidence",
)


@dataclass(frozen=True)
class EnforcementPolicy:
    """
    Which verdicts block a payload.  Every rule is checked and every hit is
    reported; one hit is enough to block.  Set a threshold to None to turn
    that rule off.  Invalid settings raise at construction.

    mode:                 "enforce" blocks; "observe" lets the payload pass
                          but reports would_block and the reasons.
    pii_threshold:        block if pii_probability >= this.
    secret_threshold:     block if secret_probability >= this.
    financial_threshold:  block if financial_probability >= this.
    max_leak_risk:        block if data_leak_risk >= this (0.5 = level 2 of 0–4).
    min_leak_confidence:  block if leak_risk_confidence < this (unsure = block).
    block_categories:     block if content_category is one of these.  Labels
                          (strings) or ContentCategory values.
    confirm_categories:   don't block, but set needs_confirmation on the
                          result if content_category is one of these (and
                          nothing blocks).  The caller asks a person to
                          reconfirm before sending.
    block_on_missing_signal:  block if a signal an active rule needs is None
                          (the classifier did not provide it).
    extra_rules:          buyer-supplied rules; see ExtraRule.
    """
    mode: str = ENFORCE
    pii_threshold: Optional[float] = 0.30
    secret_threshold: Optional[float] = 0.50
    financial_threshold: Optional[float] = 0.50
    max_leak_risk: Optional[float] = 0.50
    min_leak_confidence: Optional[float] = 0.30
    # These labels block on their own: in testing, the classifier's label
    # caught sensitive documents that the probability rules let through.
    # financial_records and strategy_confidential stay opt-in.
    block_categories: frozenset[ContentCategory] = frozenset({
        ContentCategory.CREDENTIALS,
        ContentCategory.CUSTOMER_PII,
        ContentCategory.EMPLOYEE_HR,
        ContentCategory.HEALTH_RECORDS,
        ContentCategory.LEGAL_CONTRACT,
        ContentCategory.INFRASTRUCTURE_SECURITY,
    })
    # A financial_records label alone does not block, because finance text
    # is often hypothetical.  It passes with a request to reconfirm.
    # Clearly sensitive financial data is still blocked by
    # financial_threshold.
    confirm_categories: frozenset[ContentCategory] = frozenset({ContentCategory.FINANCIAL_RECORDS})
    block_on_missing_signal: bool = True
    extra_rules: tuple[ExtraRule, ...] = ()

    def __post_init__(self) -> None:
        # Config mistakes must be loud: raise now, never fail open later.
        if self.mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}, got {self.mode!r}")
        for name in _THRESHOLDS:
            _check_threshold(name, getattr(self, name))
        if not isinstance(self.block_on_missing_signal, bool):
            raise TypeError("block_on_missing_signal must be True or False")
        object.__setattr__(self, "block_categories", _categories(self.block_categories))
        object.__setattr__(self, "confirm_categories", _categories(self.confirm_categories))
        if isinstance(self.extra_rules, (str, bytes)) or not isinstance(self.extra_rules, Iterable):
            raise TypeError("extra_rules must be a sequence of callables")
        rules = tuple(self.extra_rules)
        for rule in rules:
            if not callable(rule):
                raise TypeError("every extra rule must be callable")
        object.__setattr__(self, "extra_rules", rules)

    def evaluate(
        self,
        result: ClassificationResult,
        context: Optional[Mapping[str, Any]] = None,
    ) -> tuple[str, ...]:
        """
        Check every rule against a classifier result and return the reason
        codes of all that fired (empty tuple = allow).  Does not apply the
        mode; SieveGate does that.
        """
        v = result.verdict
        reasons: list[str] = []

        def missing(field_name: str) -> None:
            if self.block_on_missing_signal:
                reasons.append(f"missing:{field_name}")

        def at_least(code: str, field_name: str, threshold: Optional[float]) -> None:
            if threshold is None:
                return
            value = getattr(v, field_name)
            if value is None:
                missing(field_name)
            elif value >= threshold:
                reasons.append(f"{code}>={_fmt(threshold)}")

        at_least("pii", "pii_probability", self.pii_threshold)
        at_least("secret", "secret_probability", self.secret_threshold)
        at_least("financial", "financial_probability", self.financial_threshold)
        at_least("leak", "data_leak_risk", self.max_leak_risk)

        if self.min_leak_confidence is not None:
            if v.leak_risk_confidence is None:
                missing("leak_risk_confidence")
            elif v.leak_risk_confidence < self.min_leak_confidence:
                reasons.append(f"leak_conf<{_fmt(self.min_leak_confidence)}")

        if self.block_categories:
            if v.content_category is None:
                missing("content_category")
            elif v.content_category in self.block_categories:
                reasons.append(f"category:{v.content_category.value}")

        for rule in self.extra_rules:
            reasons.extend(_run_rule(rule, result, context))

        return tuple(reasons)

    def confirmations(self, result: ClassificationResult) -> tuple[str, ...]:
        """
        Reason codes for verdicts that don't block but should be reconfirmed
        by a person before sending (empty tuple = nothing to confirm).  A
        label in both block_categories and confirm_categories blocks.
        """
        category = result.verdict.content_category
        if category in self.confirm_categories and category not in self.block_categories:
            return (f"confirm:category:{category.value}",)
        return ()


def _run_rule(
    rule: ExtraRule,
    result: ClassificationResult,
    context: Optional[Mapping[str, Any]],
) -> tuple[str, ...]:
    """Run one extra rule.  Anything but None or a non-empty str blocks."""
    name = _rule_name(rule)
    try:
        code = rule(result, context)
    except Exception:  # noqa: BLE001 — a broken rule must block, not crash
        # Never report the message: it could echo the context or payload.
        return (f"rule_error:{name}",)
    if code is None:
        return ()
    if isinstance(code, str) and code:
        return (f"rule:{name}:{code}",)
    if inspect.iscoroutine(code):
        code.close()  # async rules are not supported; don't leave it pending
    return (f"rule_error:{name}",)


def _rule_name(rule: ExtraRule) -> str:
    return getattr(rule, "__name__", None) or type(rule).__name__


def _fmt(threshold: float) -> str:
    """0.3 -> '0.30'; keep extra digits if the buyer set them (0.333 -> '0.333')."""
    text = f"{threshold:.2f}"
    return text if float(text) == threshold else repr(float(threshold))


def _check_threshold(name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number between 0 and 1, or None")
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1, got {value!r}")


def _categories(value: Any) -> frozenset[ContentCategory]:
    # A bare string would otherwise be read as a set of single letters.
    if isinstance(value, (str, ContentCategory)) or not isinstance(value, Iterable):
        raise TypeError("block_categories must be a set of labels, e.g. {'credentials'}")
    categories = set()
    for item in value:
        if isinstance(item, ContentCategory):
            categories.add(item)
        elif isinstance(item, str):
            try:
                categories.add(ContentCategory(item))
            except ValueError:
                raise ValueError(f"unknown content category label {item!r}") from None
        else:
            raise TypeError("block_categories items must be labels or ContentCategory values")
    return frozenset(categories)

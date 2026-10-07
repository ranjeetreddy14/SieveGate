"""
SieveGate — the core gate that sits in front of every outbound LLM call.

A local pre-filter (prefilter.py) runs first; anything it finds is blocked
before the payload leaves the machine.  Otherwise the gate calls the
classifier once and returns both the compliance verdict and the routing
recommendation.  If anything goes wrong (error or timeout), the payload is
blocked by default (fail-secure).  Otherwise the enforcement policy
(policy.py) decides whether the verdict blocks it.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, replace
from typing import Any, Mapping, Optional

from .classifier import Classifier
from .models import (
    ClassificationResult,
    ComplianceVerdict,
    ContentCategory,
    ModelTier,
    PayloadType,
    RoutingRecommendation,
)
from .policy import ENFORCE, EnforcementPolicy
from .prefilter import PreFilter

PREFILTER_MODES = ("enforce", "observe", "off")


@dataclass
class SieveGateSettings:
    """
    Runtime-tunable settings for SieveGate.

    classify_timeout_seconds: How long to wait for the classifier
        before treating the call as failed.  Jev's published
        response time is a *range* (70-500 ms), so this must be
        configurable — not hardcoded.
    prefilter_mode: "enforce" (default) blocks on any pre-filter finding
        before the classifier is called.  "observe" records findings on
        the result but still sends the payload to the classifier.  "off"
        skips the pre-filter entirely.
    """
    classify_timeout_seconds: float = 2.0  # generous default
    prefilter_mode: str = "enforce"

    def __post_init__(self) -> None:
        _check_prefilter_mode(self.prefilter_mode)


def _check_prefilter_mode(mode: Any) -> None:
    if mode not in PREFILTER_MODES:
        raise ValueError(f"prefilter_mode must be one of {PREFILTER_MODES}, got {mode!r}")


# The result returned whenever the gate blocks a payload.
def _blocked_result(reason: str, policy_mode: str = "") -> ClassificationResult:
    return ClassificationResult(
        verdict=ComplianceVerdict(
            contains_pii=False,       # unknown, but block anyway
            data_leak_risk=1.0,       # assume worst case
            payload_type=PayloadType.UNKNOWN,
        ),
        routing=RoutingRecommendation(
            tier=ModelTier.BLOCKED,
            reason=reason,
        ),
        error=reason,
        would_block=True,
        policy_mode=policy_mode,
    )


# The result returned when the local pre-filter blocks a payload.  Same
# shape as the other blocked results, but it is a decision, not an error, so
# `error` stays None.  No classifier ran, so every verdict signal is None.
def _prefilter_blocked_result(findings, codes, policy_mode: str) -> ClassificationResult:
    return ClassificationResult(
        verdict=ComplianceVerdict(
            contains_pii=False,       # unknown, but block anyway
            data_leak_risk=1.0,       # assume worst case
            payload_type=PayloadType.TEXT,
        ),
        routing=RoutingRecommendation(
            tier=ModelTier.BLOCKED,
            reason="blocked by prefilter: " + ";".join(codes),
        ),
        would_block=True,
        policy_mode=policy_mode,
        prefilter_findings=findings,
    )


# Verdict signals that must be None or a number in 0..1.
_UNIT_SIGNALS = (
    "pii_probability",
    "secret_probability",
    "financial_probability",
    "leak_risk_confidence",
    "category_confidence",
)


def _invalid_signal(verdict: Any) -> Optional[str]:
    """
    Name of the first verdict field the policy cannot trust, or None.
    A NaN compares False with every threshold, so without this check a
    broken classifier could slip a payload past the policy.
    """
    if not isinstance(verdict, ComplianceVerdict):
        return "verdict"
    if not _is_unit(verdict.data_leak_risk):
        return "data_leak_risk"
    for name in _UNIT_SIGNALS:
        value = getattr(verdict, name)
        if value is not None and not _is_unit(value):
            return name
    if verdict.content_category is not None and not isinstance(
        verdict.content_category, ContentCategory
    ):
        return "content_category"
    return None


def _is_unit(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


class SieveGate:
    """
    The main entry point.

    Usage:
        gate = SieveGate(classifier=my_classifier)
        result = await gate.evaluate_payload("some user prompt")

    The payload parameter is typed as Any so the signature is
    multimodal-ready, but v1 only processes str.  Non-text payloads
    are flagged and blocked safely — they never crash the gate.

    policy: the EnforcementPolicy to apply; defaults to the zero-trust
        EnforcementPolicy().
    prefilter: the local PreFilter to run first; defaults to PreFilter()
        with every built-in detector on.  settings.prefilter_mode says
        whether its findings block.
    """

    def __init__(
        self,
        classifier: Classifier,
        settings: SieveGateSettings | None = None,
        policy: EnforcementPolicy | None = None,
        prefilter: PreFilter | None = None,
    ) -> None:
        self._classifier = classifier
        self._settings = settings or SieveGateSettings()
        # Settings are mutable, so check the mode again here.
        _check_prefilter_mode(self._settings.prefilter_mode)
        if policy is None:
            policy = EnforcementPolicy()
        if not isinstance(policy, EnforcementPolicy):
            raise TypeError("policy must be an EnforcementPolicy")
        self._policy = policy
        if prefilter is None:
            prefilter = PreFilter()
        if not isinstance(prefilter, PreFilter):
            raise TypeError("prefilter must be a PreFilter")
        self._prefilter = prefilter

    async def evaluate_payload(
        self,
        payload: Any,
        context: Optional[Mapping[str, Any]] = None,
    ) -> ClassificationResult:
        """
        Evaluate a single payload.

        Returns a ClassificationResult with both the compliance verdict
        and the routing recommendation.

        context: optional caller data passed to the policy's extra rules
            (e.g. the model the caller wants to use).  Never logged and
            never copied into the result.

        Order: non-text / empty checks, then the local pre-filter, then the
        classifier (with a timeout), then the policy.

        Pre-filter (settings.prefilter_mode):
          - "enforce": any finding → block; the classifier is not called,
            so the payload never leaves the machine
          - "observe": findings are recorded on the result
            (prefilter_findings) and the payload still goes to the
            classifier
          - "off": not run
          - Pre-filter raises → block, in "enforce" and "observe" alike

        Fail-secure contract (checked first, before any policy rule):
          - Classifier raises  → block
          - Classifier times out → block
          - Classifier returns something invalid → block
          - Non-text payload    → block (v1 doesn't process these yet)
        Then the policy: in "enforce" mode any rule hit → block; in
        "observe" mode the payload passes with would_block=True.  A
        payload that passes may carry needs_confirmation=True (see the
        policy's confirm_categories): the caller should ask a person to
        reconfirm before sending it.
        """
        mode = self._policy.mode

        # v1: only text is supported.  Anything else is blocked safely.
        if not isinstance(payload, str):
            return _blocked_result(
                f"non-text payload ({type(payload).__name__}) is not supported in v1",
                mode,
            )

        # Empty / whitespace-only strings aren't worth classifying.
        if not payload.strip():
            return _blocked_result("empty or whitespace-only payload", mode)

        # Local pre-filter: runs before anything leaves the machine.
        findings: tuple = ()
        prefilter_mode = self._settings.prefilter_mode
        if prefilter_mode != "off":
            try:
                scan = self._prefilter.scan(payload)
                findings = scan.findings
                codes = scan.codes
            except Exception as exc:  # noqa: BLE001 — a pre-filter bug must block
                # Type name only, as for classifier errors.
                return _blocked_result(f"prefilter error: {type(exc).__name__}", mode)
            if findings and prefilter_mode == "enforce":
                return _prefilter_blocked_result(findings, codes, mode)

        def blocked(reason: str) -> ClassificationResult:
            # In observe mode, fail-secure blocks keep the findings too.
            return replace(_blocked_result(reason, mode), prefilter_findings=findings)

        # Call the classifier with a timeout.
        try:
            result = await asyncio.wait_for(
                self._classifier.classify(payload),
                timeout=self._settings.classify_timeout_seconds,
            )
        except asyncio.TimeoutError:
            return blocked(
                f"classifier timed out after {self._settings.classify_timeout_seconds}s"
            )
        except Exception as exc:  # noqa: BLE001 — intentionally broad
            # Any other error: fail-secure.  Report only the exception
            # type, never its message: SDK errors can echo the request
            # body, which would leak the payload into results and logs.
            return blocked(f"classifier error: {type(exc).__name__}")

        # Fail-secure: never hand back anything but a real result
        # (a misbehaving classifier could return None or a dict).
        if not isinstance(result, ClassificationResult):
            return blocked(
                f"classifier returned an invalid result ({type(result).__name__})"
            )
        bad_field = _invalid_signal(result.verdict)
        if bad_field is not None:
            return blocked(f"classifier returned an invalid signal ({bad_field})")

        try:
            reasons = self._policy.evaluate(result, context)
            confirms = self._policy.confirmations(result)
        except Exception as exc:  # noqa: BLE001 — a policy bug must block
            return blocked(f"policy error: {type(exc).__name__}")

        routing = result.routing
        if reasons and mode == ENFORCE:
            routing = RoutingRecommendation(
                tier=ModelTier.BLOCKED,
                reason="blocked by policy: " + ";".join(reasons),
            )
        return replace(
            result,
            routing=routing,
            policy_reasons=reasons,
            would_block=bool(reasons),
            policy_mode=mode,
            # A block overrides a request to reconfirm.
            needs_confirmation=bool(confirms) and routing.tier is not ModelTier.BLOCKED,
            confirm_reasons=confirms,
            prefilter_findings=findings,
        )

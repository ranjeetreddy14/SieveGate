"""
Offline tests for the local pre-filter inside SieveGate.
MockClassifier only: no network, no TypeSafe.  Secret-format values are built
at runtime from parts.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from sievegate.mock_classifier import MockClassifier
from sievegate.models import ClassificationResult, ContentCategory, ModelTier
from sievegate.policy import EnforcementPolicy
from sievegate.prefilter import Detector, PreFilter, RegexDetector, redact
from sievegate.sieve import SieveGate, SieveGateSettings

SSN = "-".join(["078", "05", "1120"])
STRIPE_KEY = "sk" + "_live_" + "Q7" * 12
SSN_PAYLOAD = f"Customer record: Jane Roe, SSN {SSN}, please summarise"
CLEAN = "What is the difference between TCP and UDP?"


class CountingClassifier(MockClassifier):
    """MockClassifier that counts classify() calls."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.calls = 0

    async def classify(self, payload: Any) -> ClassificationResult:
        self.calls += 1
        return await super().classify(payload)


class Exploding(Detector):
    """A detector that raises, with payload-like text in the message."""
    id = "exploding"
    kind = "boom"

    def __init__(self, message: str = "boom") -> None:
        self.message = message

    def find(self, text):
        raise RuntimeError(self.message + text)


def gate(mode: str = "enforce", classifier=None, prefilter=None, policy=None, **verdict):
    clf = classifier if classifier is not None else CountingClassifier(**verdict)
    g = SieveGate(clf, SieveGateSettings(prefilter_mode=mode), policy=policy, prefilter=prefilter)
    return g, clf


def run(g: SieveGate, payload: Any) -> ClassificationResult:
    return asyncio.run(g.evaluate_payload(payload))


# --- Defaults ------------------------------------------------------------------

def test_prefilter_is_on_by_default():
    assert SieveGateSettings().prefilter_mode == "enforce"
    clf = CountingClassifier()
    result = run(SieveGate(clf), SSN_PAYLOAD)
    assert result.routing.tier is ModelTier.BLOCKED
    assert clf.calls == 0


def test_clean_payload_reaches_classifier_with_no_findings():
    g, clf = gate()
    result = run(g, CLEAN)
    assert clf.calls == 1
    assert result.routing.tier is ModelTier.SMALL
    assert result.prefilter_findings == ()
    assert result.would_block is False


# --- I1 and the block result's shape ---------------------------------------

def test_i1_prefilter_block_never_calls_classifier():
    g, clf = gate()
    run(g, SSN_PAYLOAD)
    run(g, "deploy key " + STRIPE_KEY)
    assert clf.calls == 0


def test_prefilter_block_result_shape():
    g, _ = gate()
    result = run(g, SSN_PAYLOAD)
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.routing.reason == "blocked by prefilter: prefilter:national_id"
    assert result.error is None             # a decision, not an error
    assert result.would_block is True
    assert result.policy_reasons == ()       # the policy did not run
    assert result.policy_mode == "enforce"
    assert result.needs_confirmation is False
    assert result.confirm_reasons == ()
    assert result.judgments == {}
    v = result.verdict
    assert (v.pii_probability, v.secret_probability, v.financial_probability,
            v.leak_risk_confidence, v.category_confidence, v.content_category) == (None,) * 6
    (f,) = result.prefilter_findings
    assert (f.kind, f.detector) == ("national_id", "us_ssn")
    assert SSN_PAYLOAD[f.start:f.end] == SSN


def test_several_kinds_are_all_reported():
    payload = f"{SSN} and {STRIPE_KEY}"
    g, _ = gate()
    result = run(g, payload)
    assert result.routing.reason == (
        "blocked by prefilter: prefilter:national_id;prefilter:payment_credential"
    )
    assert [f.detector for f in result.prefilter_findings] == ["us_ssn", "stripe_live_key"]


def test_prefilter_block_records_policy_mode():
    g, _ = gate(policy=EnforcementPolicy(mode="observe"))
    result = run(g, SSN_PAYLOAD)
    assert result.routing.tier is ModelTier.BLOCKED   # pre-filter enforce still blocks
    assert result.policy_mode == "observe"


def test_block_never_sets_needs_confirmation():
    # Even a classifier that would ask for reconfirmation is never reached.
    g, clf = gate(content_category=ContentCategory.FINANCIAL_RECORDS)
    result = run(g, SSN_PAYLOAD)
    assert result.needs_confirmation is False
    assert clf.calls == 0
    # Control: without the SSN the same classifier does ask.
    assert run(g, CLEAN).needs_confirmation is True


def test_spans_let_the_caller_redact_and_resend():
    payload = f"Refund {SSN} please, key {STRIPE_KEY}"
    g, clf = gate()
    result = run(g, payload)
    redacted = redact(payload, result.prefilter_findings)
    assert redacted == "Refund [REDACTED:national_id] please, key [REDACTED:payment_credential]"
    resent = run(g, redacted)
    assert resent.routing.tier is ModelTier.SMALL
    assert clf.calls == 1


# --- I3 at gate level ---------------------------------------------------------

def test_prefilter_block_result_has_no_payload_text(caplog):
    canary = "CANARYz9" + "x" * 16
    payload = "conn postgres://app:" + canary + "@db/x"
    g, _ = gate()
    with caplog.at_level(logging.DEBUG):
        result = run(g, payload)
    assert result.routing.tier is ModelTier.BLOCKED
    assert canary not in repr(result)
    assert canary not in caplog.text


# --- I4: errors inside the pre-filter block -----------------------------------

@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_i4_prefilter_exception_blocks_without_calling_classifier(mode):
    canary = "CANARYerr" + "0" * 8
    g, clf = gate(mode, prefilter=PreFilter(extra_detectors=(Exploding(canary),)))
    result = run(g, CLEAN)
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.routing.reason == "prefilter error: RuntimeError"
    assert result.error == "prefilter error: RuntimeError"
    assert result.would_block is True
    assert clf.calls == 0
    assert canary not in repr(result)
    assert "TCP" not in repr(result)


def test_i4_detector_returning_bad_span_blocks():
    class BadSpan(Detector):
        id = "bad_span"
        kind = "x"

        def find(self, text):
            return [(0, len(text) + 5)]

    g, clf = gate(prefilter=PreFilter(extra_detectors=(BadSpan(),)))
    result = run(g, CLEAN)
    assert result.routing.reason == "prefilter error: ValueError"
    assert clf.calls == 0


# --- I5: observe mode ----------------------------------------------------------

def test_i5_observe_mode_records_findings_and_calls_classifier():
    g, clf = gate("observe")
    result = run(g, SSN_PAYLOAD)
    assert clf.calls == 1
    assert result.routing.tier is ModelTier.SMALL          # clean verdict → pass
    assert result.would_block is False
    assert [f.detector for f in result.prefilter_findings] == ["us_ssn"]


def test_observe_mode_policy_block_keeps_findings():
    g, clf = gate("observe", pii_probability=0.99)
    result = run(g, SSN_PAYLOAD)
    assert clf.calls == 1
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.policy_reasons == ("pii>=0.30",)
    assert [f.kind for f in result.prefilter_findings] == ["national_id"]


def test_observe_mode_fail_secure_block_keeps_findings():
    g, _ = gate("observe", classifier=CountingClassifier(raise_on_classify=RuntimeError("x")))
    result = run(g, SSN_PAYLOAD)
    assert result.routing.reason == "classifier error: RuntimeError"
    assert [f.kind for f in result.prefilter_findings] == ["national_id"]


def test_observe_mode_clean_payload_has_no_findings():
    g, clf = gate("observe")
    assert run(g, CLEAN).prefilter_findings == ()
    assert clf.calls == 1


# --- I6: off ---------------------------------------------------------------------

def test_i6_off_mode_never_runs_the_prefilter():
    # The detector would raise if it ran.
    g, clf = gate("off", prefilter=PreFilter(extra_detectors=(Exploding(),)))
    result = run(g, SSN_PAYLOAD)
    assert clf.calls == 1
    assert result.routing.tier is ModelTier.SMALL
    assert result.prefilter_findings == ()


def test_i6_off_mode_matches_classifier_and_policy_only():
    # Same result as the gate gives for a payload the pre-filter has nothing
    # to say about: the classifier-and-policy path, untouched.
    for verdict in ({}, {"pii_probability": 0.9}, {"content_category": ContentCategory.FINANCIAL_RECORDS}):
        off, _ = gate("off", **verdict)
        on, _ = gate("enforce", **verdict)
        assert run(off, SSN_PAYLOAD) == run(on, CLEAN)


# --- Order: modality checks come first ---------------------------------------------

@pytest.mark.parametrize("payload,reason", [
    (b"\x89PNG", "non-text payload (bytes) is not supported in v1"),
    ("   ", "empty or whitespace-only payload"),
])
def test_modality_and_empty_checks_run_before_prefilter(payload, reason):
    # The exploding detector proves the pre-filter never ran.
    g, clf = gate(prefilter=PreFilter(extra_detectors=(Exploding(),)))
    result = run(g, payload)
    assert result.routing.reason == reason
    assert result.prefilter_findings == ()
    assert clf.calls == 0


# --- Custom pre-filters in the gate ---------------------------------------------

def test_gate_uses_a_custom_prefilter():
    codename = RegexDetector("project_codename", "internal_codename", r"\bPROJECT-ORION\b")
    pf = PreFilter(disabled_detectors={"us_ssn"}, extra_detectors=(codename,))
    g, clf = gate(prefilter=pf)
    assert run(g, SSN_PAYLOAD).routing.tier is ModelTier.SMALL    # SSN detector off
    blocked = run(g, "PROJECT-ORION ships in May")
    assert blocked.routing.reason == "blocked by prefilter: prefilter:internal_codename"
    assert clf.calls == 1


# --- Settings validation ------------------------------------------------------------

@pytest.mark.parametrize("bad", ["ENFORCE", "block", "", None, True])
def test_bad_prefilter_mode_raises(bad):
    with pytest.raises(ValueError):
        SieveGateSettings(prefilter_mode=bad)


def test_gate_rechecks_a_mutated_prefilter_mode():
    settings = SieveGateSettings()
    settings.prefilter_mode = "disabled"
    with pytest.raises(ValueError):
        SieveGate(MockClassifier(), settings)


def test_prefilter_argument_must_be_a_prefilter():
    with pytest.raises(TypeError):
        SieveGate(MockClassifier(), prefilter=object())


# --- Paths the pre-filter now shadows, re-covered with it off -------------------------
# Some policy tests send a payload with a valid-format SSN.  The pre-filter
# now blocks it first, so they no longer reach the paths below.  These keep
# those paths covered.

def test_off_mode_classifier_error_does_not_echo_payload():
    echo = RuntimeError(f"bad request, body was: {SSN_PAYLOAD}")
    g, _ = gate("off", classifier=CountingClassifier(raise_on_classify=echo))
    result = run(g, SSN_PAYLOAD)
    assert result.routing.reason == "classifier error: RuntimeError"
    assert SSN not in repr(result)


def test_off_mode_policy_block_has_no_payload_text():
    g, _ = gate("off", pii_probability=0.99, content_category=ContentCategory.CREDENTIALS)
    result = run(g, SSN_PAYLOAD)
    assert result.policy_reasons == ("pii>=0.30", "category:credentials")
    assert SSN not in repr(result)


def test_off_mode_observe_policy_has_no_payload_text():
    g, _ = gate("off", policy=EnforcementPolicy(mode="observe"), pii_probability=0.99)
    result = run(g, SSN_PAYLOAD)
    assert result.would_block is True
    assert result.routing.tier is ModelTier.SMALL
    assert SSN not in repr(result)


def test_off_mode_raising_extra_rule_blocks_without_message():
    def broken(result, context):
        raise RuntimeError(f"boom {SSN_PAYLOAD}")

    g, _ = gate("off", policy=EnforcementPolicy(extra_rules=(broken,)))
    result = run(g, SSN_PAYLOAD)
    assert result.policy_reasons == ("rule_error:broken",)
    assert SSN not in repr(result)

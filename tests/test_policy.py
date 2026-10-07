"""
Offline tests for the enforcement policy and its place in the gate.
MockClassifier only: no network, no TypeSafe.
"""

from __future__ import annotations

import asyncio
import math

import pytest

from sievegate.mock_classifier import MockClassifier
from sievegate.models import ClassificationResult, ContentCategory, ModelTier
from sievegate.policy import EnforcementPolicy
from sievegate.sieve import SieveGate, SieveGateSettings

FAKE_SSN = "078-05-1120"
# No vendor prefix on purpose: a realistic-looking key (e.g. sk_live_...)
# trips GitHub push protection.  The tests only need a distinctive string.
FAKE_KEY = "fake-key-NOT-REAL-7f3a9c1e5b2d"
LEAKY_PAYLOAD = f"Customer SSN {FAKE_SSN}, prod key {FAKE_KEY}"
# FAKE_SSN is valid under SSA rules,
# so the local pre-filter would block LEAKY_PAYLOAD before the policy or the
# classifier runs.  Tests that send it turn the pre-filter off so they keep
# testing the path they were written for.
PREFILTER_OFF = "off"
# The default blocking categories.
DEFAULT_BLOCK_CATEGORIES = frozenset({
    ContentCategory.CREDENTIALS,
    ContentCategory.CUSTOMER_PII,
    ContentCategory.EMPLOYEE_HR,
    ContentCategory.HEALTH_RECORDS,
    ContentCategory.LEGAL_CONTRACT,
    ContentCategory.INFRASTRUCTURE_SECURITY,
})


def run(gate: SieveGate, payload="some text", context=None) -> ClassificationResult:
    if context is None:
        return asyncio.run(gate.evaluate_payload(payload))
    return asyncio.run(gate.evaluate_payload(payload, context))


def gate_with(policy: EnforcementPolicy | None = None, **verdict_fields) -> SieveGate:
    return SieveGate(MockClassifier(**verdict_fields), policy=policy)


def assert_passed(result: ClassificationResult) -> None:
    assert result.routing.tier is not ModelTier.BLOCKED
    assert result.policy_reasons == ()
    assert result.would_block is False


def assert_blocked(result: ClassificationResult, *reasons: str) -> None:
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.would_block is True
    assert result.policy_reasons == reasons
    assert result.error is None  # a policy block is not an error


# --- Defaults --------------------------------------------------------------

def test_defaults_are_zero_trust_values():
    p = EnforcementPolicy()
    assert p.mode == "enforce"
    assert p.pii_threshold == 0.30
    assert p.secret_threshold == 0.50
    assert p.financial_threshold == 0.50
    assert p.max_leak_risk == 0.50
    assert p.min_leak_confidence == 0.30
    assert p.block_categories == DEFAULT_BLOCK_CATEGORIES
    assert p.block_on_missing_signal is True
    assert p.extra_rules == ()


def test_gate_uses_default_policy_and_safe_payload_passes():
    result = run(SieveGate(MockClassifier()))
    assert_passed(result)
    assert result.routing.tier is ModelTier.SMALL
    assert result.policy_mode == "enforce"


# --- Each "at least" rule: blocks at the threshold, passes just below -----

AT_LEAST_RULES = [
    ("pii_probability", 0.30, "pii>=0.30"),
    ("secret_probability", 0.50, "secret>=0.50"),
    ("financial_probability", 0.50, "financial>=0.50"),
    ("data_leak_risk", 0.50, "leak>=0.50"),
]


@pytest.mark.parametrize("field, threshold, code", AT_LEAST_RULES)
def test_rule_blocks_at_threshold(field, threshold, code):
    assert_blocked(run(gate_with(**{field: threshold})), code)


@pytest.mark.parametrize("field, threshold, code", AT_LEAST_RULES)
def test_rule_passes_just_below_threshold(field, threshold, code):
    assert_passed(run(gate_with(**{field: math.nextafter(threshold, 0.0)})))


def test_leak_confidence_blocks_just_below_minimum():
    assert_blocked(
        run(gate_with(leak_risk_confidence=math.nextafter(0.30, 0.0))), "leak_conf<0.30"
    )


def test_leak_confidence_passes_at_minimum():
    assert_passed(run(gate_with(leak_risk_confidence=0.30)))


@pytest.mark.parametrize("category", sorted(DEFAULT_BLOCK_CATEGORIES, key=lambda c: c.value))
def test_default_categories_block(category):
    assert_blocked(run(gate_with(content_category=category)), f"category:{category.value}")


@pytest.mark.parametrize(
    "category", [c for c in ContentCategory if c not in DEFAULT_BLOCK_CATEGORIES]
)
def test_other_categories_pass_by_default(category):
    assert_passed(run(gate_with(content_category=category)))


def test_buyer_can_opt_in_more_categories():
    policy = EnforcementPolicy(block_categories={"credentials", "financial_records"})
    assert_blocked(
        run(gate_with(policy, content_category=ContentCategory.FINANCIAL_RECORDS)),
        "category:financial_records",
    )


def test_buyer_can_narrow_categories():
    policy = EnforcementPolicy(block_categories={"credentials"})
    assert_passed(run(gate_with(policy, content_category=ContentCategory.HEALTH_RECORDS)))


def test_custom_threshold_reason_keeps_extra_digits():
    policy = EnforcementPolicy(pii_threshold=0.333)
    assert_blocked(run(gate_with(policy, pii_probability=0.4)), "pii>=0.333")


# --- Turning rules off ---------------------------------------------------

@pytest.mark.parametrize(
    "setting, field, value",
    [
        ("pii_threshold", "pii_probability", 1.0),
        ("secret_threshold", "secret_probability", 1.0),
        ("financial_threshold", "financial_probability", 1.0),
        ("max_leak_risk", "data_leak_risk", 1.0),
        ("min_leak_confidence", "leak_risk_confidence", 0.0),
    ],
)
def test_none_threshold_disables_rule(setting, field, value):
    policy = EnforcementPolicy(**{setting: None})
    assert_passed(run(gate_with(policy, **{field: value})))


def test_empty_block_categories_disables_category_rule():
    policy = EnforcementPolicy(block_categories=frozenset())
    assert_passed(run(gate_with(policy, content_category=ContentCategory.CREDENTIALS)))


# --- Several rules -------------------------------------------------------

def test_all_firing_rules_are_reported_in_order():
    result = run(gate_with(
        pii_probability=0.9,
        secret_probability=0.9,
        financial_probability=0.9,
        data_leak_risk=0.9,
        leak_risk_confidence=0.1,
        content_category=ContentCategory.CREDENTIALS,
    ))
    assert_blocked(
        result,
        "pii>=0.30", "secret>=0.50", "financial>=0.50",
        "leak>=0.50", "leak_conf<0.30", "category:credentials",
    )
    assert result.routing.reason == "blocked by policy: " + ";".join(result.policy_reasons)


# --- Observe mode --------------------------------------------------------

def test_observe_mode_passes_but_reports():
    policy = EnforcementPolicy(mode="observe")
    result = run(gate_with(policy, pii_probability=0.9, data_leak_risk=0.9))
    assert result.routing.tier is ModelTier.SMALL
    assert result.would_block is True
    assert result.policy_reasons == ("pii>=0.30", "leak>=0.50")
    assert result.policy_mode == "observe"


def test_observe_mode_clean_payload():
    result = run(gate_with(EnforcementPolicy(mode="observe")))
    assert_passed(result)
    assert result.policy_mode == "observe"


# --- Missing signals -----------------------------------------------------

MISSABLE = [
    "pii_probability",
    "secret_probability",
    "financial_probability",
    "leak_risk_confidence",
    "content_category",
]


@pytest.mark.parametrize("field", MISSABLE)
def test_missing_signal_blocks_by_default(field):
    assert_blocked(run(gate_with(**{field: None})), f"missing:{field}")


@pytest.mark.parametrize("field", MISSABLE)
def test_missing_signal_passes_when_allowed(field):
    policy = EnforcementPolicy(block_on_missing_signal=False)
    assert_passed(run(gate_with(policy, **{field: None})))


def test_missing_signal_for_disabled_rule_is_ignored():
    policy = EnforcementPolicy(secret_threshold=None)
    assert_passed(run(gate_with(policy, secret_probability=None)))


# --- Extra rules and context ---------------------------------------------

def test_extra_rule_blocks_with_its_code():
    def tier_cap(result, context):
        return "tier_over_cap"

    result = run(gate_with(EnforcementPolicy(extra_rules=(tier_cap,))))
    assert_blocked(result, "rule:tier_cap:tier_over_cap")


def test_extra_rule_returning_none_allows():
    def allow_all(result, context):
        return None

    assert_passed(run(gate_with(EnforcementPolicy(extra_rules=[allow_all]))))


def test_extra_rule_that_raises_blocks_without_message():
    def broken(result, context):
        raise RuntimeError(f"boom {LEAKY_PAYLOAD}")

    gate = SieveGate(
        MockClassifier(),
        SieveGateSettings(prefilter_mode=PREFILTER_OFF),
        policy=EnforcementPolicy(extra_rules=(broken,)),
    )
    result = run(gate, LEAKY_PAYLOAD)
    assert_blocked(result, "rule_error:broken")
    assert FAKE_SSN not in repr(result)


@pytest.mark.parametrize("bad", ["", 0, True, ("x",)])
def test_extra_rule_returning_junk_blocks(bad):
    def odd(result, context):
        return bad

    assert_blocked(run(gate_with(EnforcementPolicy(extra_rules=(odd,)))), "rule_error:odd")


def test_async_extra_rule_is_not_supported_and_blocks():
    async def async_rule(result, context):
        return None

    assert_blocked(
        run(gate_with(EnforcementPolicy(extra_rules=(async_rule,)))), "rule_error:async_rule"
    )


def test_context_reaches_rule_and_defaults_to_none():
    seen = []

    def spy(result, context):
        seen.append(context)
        return None

    gate = gate_with(EnforcementPolicy(extra_rules=(spy,)))
    run(gate)
    ctx = {"requested_model": "big-model"}
    run(gate, context=ctx)
    assert seen == [None, ctx]


def test_rule_sees_classifier_result():
    seen = []

    def spy(result, context):
        seen.append(result.routing.tier)
        return None

    run(gate_with(EnforcementPolicy(extra_rules=(spy,))))
    assert seen == [ModelTier.SMALL]


def test_context_is_not_copied_into_result():
    def uses_context(result, context):
        return "over_cap" if context["requested_model"] == "big-model" else None

    ctx = {"requested_model": "big-model", "note": FAKE_SSN}
    result = run(gate_with(EnforcementPolicy(extra_rules=(uses_context,))), context=ctx)
    assert_blocked(result, "rule:uses_context:over_cap")
    assert FAKE_SSN not in repr(result)
    assert "big-model" not in repr(result)


# --- Reconfirmation (pass, but ask a person first) ------------------------

def test_default_confirm_categories():
    assert EnforcementPolicy().confirm_categories == frozenset({ContentCategory.FINANCIAL_RECORDS})


def test_financial_label_alone_passes_with_confirmation():
    result = run(gate_with(content_category=ContentCategory.FINANCIAL_RECORDS))
    assert_passed(result)
    assert result.routing.tier is ModelTier.SMALL
    assert result.needs_confirmation is True
    assert result.confirm_reasons == ("confirm:category:financial_records",)


def test_sensitive_financial_data_still_blocks():
    # E.g. a cheque or account numbers: the financial probability rule blocks.
    result = run(gate_with(
        content_category=ContentCategory.FINANCIAL_RECORDS, financial_probability=0.9
    ))
    assert_blocked(result, "financial>=0.50")
    assert result.needs_confirmation is False
    assert result.confirm_reasons == ("confirm:category:financial_records",)  # audit trail


def test_clean_payload_needs_no_confirmation():
    result = run(gate_with())
    assert result.needs_confirmation is False
    assert result.confirm_reasons == ()


def test_block_category_wins_over_confirm_category():
    policy = EnforcementPolicy(block_categories={"financial_records"})
    result = run(gate_with(policy, content_category=ContentCategory.FINANCIAL_RECORDS))
    assert_blocked(result, "category:financial_records")
    assert result.needs_confirmation is False
    assert result.confirm_reasons == ()


def test_empty_confirm_categories_turns_confirmation_off():
    policy = EnforcementPolicy(confirm_categories=frozenset())
    result = run(gate_with(policy, content_category=ContentCategory.FINANCIAL_RECORDS))
    assert_passed(result)
    assert result.needs_confirmation is False


def test_buyer_can_choose_confirm_categories():
    policy = EnforcementPolicy(confirm_categories={"strategy_confidential"})
    result = run(gate_with(policy, content_category=ContentCategory.STRATEGY_CONFIDENTIAL))
    assert result.needs_confirmation is True
    assert result.confirm_reasons == ("confirm:category:strategy_confidential",)


def test_observe_mode_still_asks_for_confirmation():
    policy = EnforcementPolicy(mode="observe")
    result = run(gate_with(
        policy, content_category=ContentCategory.FINANCIAL_RECORDS, pii_probability=0.9
    ))
    assert result.routing.tier is ModelTier.SMALL  # observe: nothing blocks
    assert result.would_block is True
    assert result.needs_confirmation is True


def test_missing_category_does_not_block_for_confirm_rule_alone():
    policy = EnforcementPolicy(block_categories=frozenset())
    result = run(gate_with(policy, content_category=None))
    assert_passed(result)
    assert result.needs_confirmation is False


def test_fail_secure_block_needs_no_confirmation():
    result = run(SieveGate(MockClassifier()), b"bytes")
    assert result.needs_confirmation is False
    assert result.confirm_reasons == ()


def test_confirmation_bug_blocks_fail_secure():
    class Broken(EnforcementPolicy):
        def confirmations(self, result):
            raise ZeroDivisionError

    result = run(SieveGate(MockClassifier(), policy=Broken()))
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.error == "policy error: ZeroDivisionError"


# --- Invalid configuration -----------------------------------------------

@pytest.mark.parametrize(
    "kwargs, error",
    [
        ({"mode": "audit"}, ValueError),
        ({"mode": "ENFORCE"}, ValueError),
        ({"pii_threshold": 1.5}, ValueError),
        ({"secret_threshold": -0.1}, ValueError),
        ({"financial_threshold": float("nan")}, ValueError),
        ({"max_leak_risk": float("inf")}, ValueError),
        ({"min_leak_confidence": "0.3"}, TypeError),
        ({"pii_threshold": True}, TypeError),
        ({"block_categories": {"customer_data"}}, ValueError),  # old label
        ({"block_categories": {"not_a_label"}}, ValueError),
        ({"block_categories": "credentials"}, TypeError),  # bare string
        ({"block_categories": {42}}, TypeError),
        ({"confirm_categories": {"not_a_label"}}, ValueError),
        ({"confirm_categories": "financial_records"}, TypeError),  # bare string
        ({"block_on_missing_signal": "yes"}, TypeError),
        ({"extra_rules": ("not callable",)}, TypeError),
        ({"extra_rules": len}, TypeError),
    ],
)
def test_invalid_config_raises_at_construction(kwargs, error):
    with pytest.raises(error):
        EnforcementPolicy(**kwargs)


def test_gate_rejects_non_policy():
    with pytest.raises(TypeError):
        SieveGate(MockClassifier(), policy={"pii_threshold": 0.3})


def test_threshold_edges_are_valid():
    EnforcementPolicy(pii_threshold=0, max_leak_risk=1)


def test_policy_is_frozen():
    with pytest.raises(AttributeError):
        EnforcementPolicy().pii_threshold = 0.9


# --- Fail-secure runs before the policy ----------------------------------

class _Slow(MockClassifier):
    async def classify(self, payload):
        await asyncio.sleep(1)
        return await super().classify(payload)


class _Returns(MockClassifier):
    def __init__(self, value):
        super().__init__()
        self._value = value

    async def classify(self, payload):
        return self._value


def _spy_policy(calls: list, mode="enforce") -> EnforcementPolicy:
    def spy(result, context):
        calls.append(1)
        return None

    return EnforcementPolicy(mode=mode, extra_rules=(spy,))


@pytest.mark.parametrize("mode", ["enforce", "observe"])
@pytest.mark.parametrize(
    "classifier, payload, reason_start",
    [
        (MockClassifier(raise_on_classify=RuntimeError("x")), "text", "classifier error: RuntimeError"),
        (_Slow(), "text", "classifier timed out"),
        (_Returns(None), "text", "classifier returned an invalid result"),
        (_Returns({"tier": "small"}), "text", "classifier returned an invalid result"),
        (MockClassifier(pii_probability=float("nan")), "text", "classifier returned an invalid signal (pii_probability)"),
        (MockClassifier(data_leak_risk=2.0), "text", "classifier returned an invalid signal (data_leak_risk)"),
        (MockClassifier(leak_risk_confidence=-0.1), "text", "classifier returned an invalid signal (leak_risk_confidence)"),
        (MockClassifier(content_category="credentials"), "text", "classifier returned an invalid signal (content_category)"),
        (MockClassifier(), b"bytes", "non-text payload (bytes)"),
        (MockClassifier(), "   ", "empty or whitespace-only payload"),
    ],
    ids=["raises", "timeout", "none", "dict", "nan", "leak-out-of-range",
         "conf-negative", "category-str", "bytes", "empty"],
)
def test_fail_secure_blocks_before_policy(classifier, payload, reason_start, mode):
    calls: list = []
    gate = SieveGate(
        classifier,
        SieveGateSettings(classify_timeout_seconds=0.05),
        policy=_spy_policy(calls, mode),
    )
    result = run(gate, payload)
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.error is not None and result.error.startswith(reason_start)
    assert result.would_block is True
    assert result.policy_reasons == ()
    assert result.policy_mode == mode
    assert calls == []  # the policy never ran


def test_policy_bug_blocks_fail_secure():
    class Broken(EnforcementPolicy):
        def evaluate(self, result, context=None):
            raise ZeroDivisionError

    result = run(SieveGate(MockClassifier(), policy=Broken()))
    assert result.routing.tier is ModelTier.BLOCKED
    assert result.error == "policy error: ZeroDivisionError"


# --- No payload text in results ------------------------------------------

def test_policy_blocked_result_has_no_payload_text():
    gate = SieveGate(
        MockClassifier(
            pii_probability=0.99,
            secret_probability=0.99,
            data_leak_risk=1.0,
            content_category=ContentCategory.CREDENTIALS,
        ),
        SieveGateSettings(prefilter_mode=PREFILTER_OFF),
    )
    result = run(gate, LEAKY_PAYLOAD)
    assert result.routing.tier is ModelTier.BLOCKED
    text = repr(result)
    assert FAKE_SSN not in text
    assert FAKE_KEY not in text


def test_error_blocked_result_has_no_payload_text():
    # Real SDK errors can echo the request body; the gate must not.
    echo = RuntimeError(f"bad request, body was: {LEAKY_PAYLOAD}")
    gate = SieveGate(
        MockClassifier(raise_on_classify=echo), SieveGateSettings(prefilter_mode=PREFILTER_OFF)
    )
    result = run(gate, LEAKY_PAYLOAD)
    assert result.routing.tier is ModelTier.BLOCKED
    text = repr(result)
    assert FAKE_SSN not in text
    assert FAKE_KEY not in text


def test_observe_result_has_no_payload_text():
    gate = SieveGate(
        MockClassifier(pii_probability=0.99),
        SieveGateSettings(prefilter_mode=PREFILTER_OFF),
        policy=EnforcementPolicy(mode="observe"),
    )
    text = repr(run(gate, LEAKY_PAYLOAD))
    assert FAKE_SSN not in text
    assert FAKE_KEY not in text


# --- Existing behaviour kept ---------------------------------------------

def test_existing_fields_unchanged_on_pass():
    result = run(gate_with(pii_probability=0.1))
    assert result.verdict.contains_pii is False
    assert result.routing.reason == "mock: default safe result"


def test_mock_overrides_reject_unknown_fields():
    with pytest.raises(TypeError):
        MockClassifier(not_a_field=1)

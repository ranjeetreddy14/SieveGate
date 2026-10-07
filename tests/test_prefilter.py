"""
Offline tests for the local pre-filter (sievegate.prefilter).

No literal in this file matches a real provider's secret format.  Every
format-matching value is built at runtime from parts, so the committed
source never contains one.
"""

from __future__ import annotations

import ast
import base64
import json
import logging
import random
import subprocess
import sys
import time
from dataclasses import fields

import pytest

import sievegate.prefilter as prefilter_module
from sievegate.prefilter import (
    DEFAULT_DETECTORS,
    DETECTOR_IDS,
    Detector,
    Finding,
    PreFilter,
    PreFilterResult,
    RegexDetector,
    redact,
)

PF = PreFilter()


def found(text: str, pf: PreFilter = PF) -> list[str]:
    """Detector IDs that fired, in order."""
    return [f.detector for f in pf.scan(text).findings]


# --- Runtime builders ---------------------------------------------------

def luhn_complete(body: str) -> str:
    """Append the Luhn check digit to `body`."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def luhn_break(number: str) -> str:
    """Same number with a wrong check digit."""
    return number[:-1] + str((int(number[-1]) + 1) % 10)


def group(number: str, sizes: tuple[int, ...], sep: str) -> str:
    out, i = [], 0
    for size in sizes:
        out.append(number[i:i + size])
        i += size
    return sep.join(out)


def iban_complete(country: str, bban: str) -> str:
    """Build an IBAN with valid check digits (ISO 7064 mod 97-10)."""
    number = int("".join(str(int(ch, 36)) for ch in bban + country + "00"))
    return f"{country}{98 - number % 97:02d}{bban}"


def b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def pem(label: str) -> str:
    return "-----" + "BEGIN " + label + "-----"


VISA = luhn_complete("4" + "539" + "1488" + "0343" + "646")          # 16 digits
MASTERCARD = luhn_complete("5" + "425" + "2334" + "3010" + "990")    # 16
MASTERCARD_2 = luhn_complete("2" + "223" + "0000" + "4841" + "001")  # 16, 2-series
AMEX = luhn_complete("37" + "8282" + "2463" + "1000")                # 15
DISCOVER = luhn_complete("6011" + "1111" + "1111" + "111")           # 16
STRIPE_TEST_CARD = luhn_complete("42" * 7 + "4")                     # 16; test cards are blocked


# --- Each detector: true positives -------------------------------------------

POSITIVES = {
    "pem_private_key": [
        "ssh fails with this key:\n" + pem("OPENSSH " + "PRIVATE KEY") + "\nb3BlbnNzaC1rZXk=",
        pem("RSA " + "PRIVATE KEY") + "\nMIIEow",
        pem("PRIVATE " + "KEY") + "\nMIIEvg",
        pem("ENCRYPTED " + "PRIVATE KEY"),
        pem("EC " + "PRIVATE KEY"),
        pem("PGP " + "PRIVATE KEY BLOCK"),
    ],
    "aws_access_key_id": [
        "aws_access_key_id = " + "AK" + "IA" + "Z7Q2" * 4,
        "export KEY=" + "AS" + "IA" + "R4ND0M" + "0" * 10 + "\n",
    ],
    "github_token": [
        "token: " + "gh" + "p_" + "aB3dE5" * 6,
        "Authorization: token " + "gh" + "s_" + "Zz9" * 12,
        "GH_TOKEN=" + "github" + "_pat_" + "11ABCDEFG" + "0" * 13 + "_" + "x" * 59,
    ],
    "slack_token": [
        "SLACK_BOT_TOKEN=" + "xo" + "xb-" + "1234567890-0987654321-" + "AbCd" * 6,
        "user token " + "xo" + "xp-" + "11-22-33-" + "ffee" * 8,
        "app token " + "xa" + "pp-" + "1-A0123-456-" + "abcd" * 8,
    ],
    "stripe_live_key": [
        "STRIPE_SECRET=" + "sk" + "_live_" + "Z" * 24,
        "restricted: " + "rk" + "_live_" + "51Hq" * 8,
    ],
    "google_api_key": [
        "key=" + "AI" + "za" + "SyD" + "x" * 32 + "&q=1",
        "GOOGLE_API_KEY=" + "AI" + "za" + "Q-_9" * 8 + "abc",
    ],
    "llm_api_key": [
        "ANTHROPIC_API_KEY=" + "sk-" + "ant-" + "api03-" + "Ab_-" * 23 + "AA",
        "admin " + "sk-" + "ant-" + "admin01-" + "q" * 40,
        "OPENAI_API_KEY=" + "sk-" + "proj-" + "A1b2" * 10 + "T3Blbk" + "FJ" + "C3d4" * 10,
        "legacy " + "sk-" + "Q" * 20 + "T3Blbk" + "FJ" + "R" * 20,
    ],
    "jwt": [
        "Bearer " + b64url({"alg": "HS256", "typ": "JWT"}) + "." + b64url({"sub": "42", "admin": True})
        + "." + "s1gnatureXYZ",
        "cookie=" + b64url({"alg": "RS256"}) + "." + b64url({"iss": "acme", "exp": 1}) + "." + "abc_DEF-123",
    ],
    "credentialed_url": [
        "conn failed: postgres://app:" + "Tr0ub4dor" + "@db.internal:5432/orders",
        "REDIS_URL=redis://:" + "s3cretT0ken" + "@cache:6379/0",
        "https://deploy:" + "hunter2x" + "@git.example.com/repo.git",
    ],
    "payment_card": [
        "card " + group(VISA, (4, 4, 4, 4), " ") + " exp 12/27",
        "pan=" + MASTERCARD,
        group(MASTERCARD_2, (4, 4, 4, 4), "-"),
        "Amex " + group(AMEX, (4, 6, 5), " "),
        DISCOVER + " 12/26 737",
        "Stripe test card " + group(STRIPE_TEST_CARD, (4, 4, 4, 4), " "),
    ],
    "us_ssn": [
        "SSN: " + "-".join(["078", "05", "1120"]),
        "customer,ssn\nJane," + " ".join(["219", "09", "9999"]),
        "Age 45 " + "-".join(["123", "45", "6789"]),
    ],
    "iban": [
        "IBAN " + iban_complete("DE", "370400440532013000"),
        "pay to " + group(iban_complete("GB", "WEST12345698765432"), (4, 4, 4, 4, 4, 2), " ") + " today",
        iban_complete("FR", "20041010050500013M02606"),
    ],
}

# --- Each detector: lookalike negatives ---------------------------------------

GIT_SHA = "3f786850e387550fdab836ed7e6dc881de23001b"
UUID = "123e4567-e89b-12d3-a456-426614174000"

NEGATIVES = {
    "pem_private_key": [
        pem("PUBLIC KEY") + "\nMIIBIj",
        pem("CERTIFICATE") + "\nMIIDdz",
        pem("PGP PUBLIC KEY BLOCK"),
        pem("SSH2 PUBLIC KEY"),
        "How do I generate a private key with openssl genpkey?",
    ],
    "aws_access_key_id": [
        "AK" + "IA" + "Z7Q2" * 3 + "ABC",           # 19 chars, too short
        "X" + "AK" + "IA" + "Z7Q2" * 4,             # embedded in a longer token
        "ak" + "ia" + "z7q2" * 4,                    # lowercase
        "AK" + "ID" + "Z7Q2" * 4,                    # unknown prefix
    ],
    "github_token": [
        "gh" + "p_" + "a" * 35,                      # one short
        "gh" + "x_" + "a" * 36,                      # unknown type letter
        "my_" + "gh" + "p_" + "a" * 36,              # inside an identifier
        "github" + "_pat_" + "short",
    ],
    "slack_token": [
        "xo" + "xb-" + "12345",                      # too short
        "xo" + "xz-" + "1234567890-abcdef",          # unknown type
        "Install the Slack app and copy the xoxb token from the OAuth page",
    ],
    "stripe_live_key": [
        "sk" + "_test_" + "Z" * 24,                  # test mode: left to Jev
        "pk" + "_live_" + "Z" * 24,                  # publishable, safe to expose
        "sk" + "_live_" + "Z" * 10,                  # too short
    ],
    "google_api_key": [
        "AI" + "za" + "x" * 34,                      # too short
        "AI" + "za" + "x" * 36,                      # too long
        "ai" + "za" + "x" * 35,                      # wrong case
    ],
    "llm_api_key": [
        "sk-" + "ant-" + "api03-" + "short",
        "task-" + "ant-" + "api03-" + "x" * 40,      # inside a word
        "sk-" + "Q" * 48,                            # no OpenAI marker
        "Set ANTHROPIC_API_KEY to your sk-ant-... key",
    ],
    "jwt": [
        "eyJ" + "hbGciOiJIUzI1NiJ9",                 # one segment only
        "eyJ" + "notjson1" + "." + "eyJ" + "notjson2" + "." + "sig12345",  # segments aren't JSON
        b64url({"a": 1}) + "." + b64url({"b": 2}),   # two segments
    ],
    "credentialed_url": [
        "postgres://user:password@localhost",
        "mysql://root:changeme@127.0.0.1/db",
        "DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/x",
        "amqp://guest:<password>@rabbit",
        "https://u:****@host.example",
        "https://u:xxxx@host.example",
        "redis://:{{ redis_pass }}@cache",
        "url = 'postgresql://%(user)s:%(pw)s@%(host)s'",
        "https://user@example.com/path",
        "https://example.com:8080/a@b",
    ],
    "payment_card": [
        luhn_break(VISA),                            # Luhn-invalid 16 digits
        group(luhn_break(MASTERCARD), (4, 4, 4, 4), " "),
        luhn_complete("9" + "1" * 14),               # Luhn-valid, no known issuer
        GIT_SHA,
        UUID,
        "version 1.2.3.4",
        "call +1 (555) 123-4567",
        "order ORD-2024-000123",
        " ".join(VISA),                              # spaced-out single digits
        VISA[:8] + " " + VISA[8:12] + "-" + VISA[12:],  # mixed separators
        "timestamp 1696600000000",
    ],
    "us_ssn": [
        "000-00-0000",
        "-".join(["123", "00", "6789"]),             # group 00
        "-".join(["123", "45", "0000"]),             # serial 0000
        "-".join(["666", "45", "6789"]),             # area 666
        "-".join(["912", "45", "6789"]),             # area 900-999
        "call 555-123-4567",
        "1-234-56-7890-1",
        "123456789",                                 # bare 9 digits: too noisy
        "-".join(["123", "45", "6789"]).replace("-", "- "),
    ],
    "iban": [
        luhn_break(iban_complete("DE", "370400440532013000")),  # bad check digits
        "DE89 3704",                                 # too short
        "ORD-2024-000123",
        iban_complete("DE", "370400440532013000").lower(),
    ],
}


def test_every_detector_has_tests():
    assert set(POSITIVES) == DETECTOR_IDS
    assert set(NEGATIVES) == DETECTOR_IDS
    for det in DETECTOR_IDS:
        assert len(POSITIVES[det]) >= 2
        assert len(NEGATIVES[det]) >= 3


@pytest.mark.parametrize(
    "detector,text", [(d, t) for d, ts in POSITIVES.items() for t in ts]
)
def test_true_positive(detector, text):
    assert detector in found(text)


@pytest.mark.parametrize(
    "detector,text", [(d, t) for d, ts in NEGATIVES.items() for t in ts]
)
def test_lookalike_negative(detector, text):
    assert found(text) == []


def _base64_image() -> str:
    rnd = random.Random(1234)
    data = b"\x89PNG\r\n\x1a\n" + bytes(rnd.getrandbits(8) for _ in range(200_000))
    return "data:image/png;base64," + base64.b64encode(data).decode()


REQUIRED_LOOKALIKES = [
    luhn_break(VISA),
    "000-00-0000",
    "-".join(["123", "00", "6789"]),
    GIT_SHA,
    UUID,
    "1.2.3.4",
    "+1 (555) 123-4567",
    "ORD-2024-000123",
    "postgres://user:password@localhost",
]


@pytest.mark.parametrize("text", REQUIRED_LOOKALIKES)
def test_required_lookalikes_pass(text):
    assert found(text) == []


def test_base64_image_data_passes():
    assert found(_base64_image()) == []


# --- Spans and result shape --------------------------------------------------

def test_span_covers_the_secret():
    key = "sk" + "_live_" + "Z" * 24
    text = "prefix " + key + " suffix"
    (f,) = PF.scan(text).findings
    assert text[f.start:f.end] == key
    assert (f.kind, f.detector) == ("payment_credential", "stripe_live_key")


def test_private_key_span_covers_the_key_body():
    # So redact() removes the key material, not just the header.
    body = "MIIEow" + "IBAAKCAQEA" + "x9Zq" * 15
    block = (pem("RSA " + "PRIVATE KEY") + "\nProc-Type: 4,ENCRYPTED\n\n" + body + "\n"
             + body[:20] + "==\n" + "-----" + "END RSA " + "PRIVATE KEY" + "-----")
    text = "why won't this work?\n" + block + "\nthanks"
    (f,) = PF.scan(text).findings
    assert text[f.start:f.end] == block
    assert redact(text, (f,)) == "why won't this work?\n[REDACTED:private_key]\nthanks"


def test_private_key_without_end_line_stops_at_prose():
    text = pem("PRIVATE " + "KEY") + "\nMIIEvg\nAbCd\n\nWhat is wrong here?"
    (f,) = PF.scan(text).findings
    assert text[f.end:] == "\n\nWhat is wrong here?"


def test_findings_are_sorted_and_codes_deduplicated():
    ssn = "-".join(["078", "05", "1120"])
    text = f"{VISA} then {ssn} then {MASTERCARD}"
    result = PF.scan(text)
    assert [f.detector for f in result.findings] == ["payment_card", "us_ssn", "payment_card"]
    assert result.codes == ("prefilter:card_number", "prefilter:national_id")
    assert result.blocked is True


def test_redact_replaces_spans():
    ssn = "-".join(["078", "05", "1120"])
    text = f"a {ssn} b {VISA} c"
    assert redact(text, PF.scan(text).findings) == "a [REDACTED:national_id] b [REDACTED:card_number] c"
    assert redact("nothing here", ()) == "nothing here"


def test_redact_merges_overlapping_findings():
    token = "gh" + "p_" + "aB3dE5" * 6
    text = "clone https://bot:" + token + "@git.example.com/x.git now"
    findings = PF.scan(text).findings
    assert {f.detector for f in findings} == {"credentialed_url", "github_token"}
    out = redact(text, findings)
    assert token not in out
    assert out == "clone [REDACTED:credentialed_url]git.example.com/x.git now"
    nested = (Finding("outer", "d1", 0, 10), Finding("inner", "d2", 2, 5))
    assert redact("0123456789xyz", nested) == "[REDACTED:outer]xyz"


def test_clean_text_has_no_findings():
    result = PF.scan("What is the difference between TCP and UDP?")
    assert result.findings == ()
    assert result.blocked is False
    assert result.codes == ()


# --- Invariants ------------------------------------------------------------

def test_i2_prefilter_never_returns_a_pass_verdict():
    # The only outputs are findings (block) or no findings (continue to the
    # classifier).  There is no "safe" or "skip the classifier" field.
    assert [f.name for f in fields(PreFilterResult)] == ["findings"]
    public = {n for n in dir(PreFilterResult) if not n.startswith("_")}
    assert public == {"findings", "blocked", "codes"}
    assert PreFilterResult().blocked is False


def test_i3_findings_never_contain_the_matched_value(caplog):
    canary = "CANARY7q3x" + "k9"
    secrets = [
        "sk" + "_live_" + canary + "Z" * 12,
        "postgres://app:" + canary + "@db/x",
        "gh" + "p_" + canary + "a" * 24,
    ]
    text = "\n".join(secrets)
    with caplog.at_level(logging.DEBUG):
        result = PF.scan(text)
    assert len(result.findings) == 3
    assert [f.name for f in fields(Finding)] == ["kind", "detector", "start", "end"]
    for blob in (repr(result), repr(result.findings), repr(result.codes), caplog.text):
        assert canary not in blob


def test_i7_whole_payload_is_scanned():
    key = "AK" + "IA" + "Z7Q2" * 4
    text = ("lorem ipsum dolor sit amet " * 40_000) + key
    assert len(text) > 1_000_000
    (f,) = PF.scan(text).findings
    assert f.end == len(text)
    assert f.detector == "aws_access_key_id"


# --- Config ------------------------------------------------------------------

def test_default_detector_ids_are_stable():
    assert DETECTOR_IDS == {
        "pem_private_key", "aws_access_key_id", "github_token", "slack_token",
        "stripe_live_key", "google_api_key", "llm_api_key", "jwt",
        "credentialed_url", "payment_card", "us_ssn", "iban",
    }
    assert len(DEFAULT_DETECTORS) == len(DETECTOR_IDS)


def test_disable_a_detector():
    pf = PreFilter(disabled_detectors=frozenset({"payment_card"}))
    assert found(VISA, pf) == []
    assert "payment_card" not in [d.id for d in pf.detectors]
    assert found("-".join(["078", "05", "1120"]), pf) == ["us_ssn"]


def test_disabled_detectors_accepts_any_iterable():
    pf = PreFilter(disabled_detectors=["iban", "jwt"])
    assert pf.disabled_detectors == frozenset({"iban", "jwt"})


@pytest.mark.parametrize("bad,exc", [
    ({"no_such_detector"}, ValueError),
    ("payment_card", TypeError),          # a bare string, not a set
    ({1}, TypeError),
    (None, TypeError),
])
def test_bad_disabled_detectors_raise(bad, exc):
    with pytest.raises(exc):
        PreFilter(disabled_detectors=bad)


def _codename() -> RegexDetector:
    return RegexDetector("project_codename", "internal_codename", r"\bPROJECT-ORION\b")


def test_custom_detector_runs():
    pf = PreFilter(extra_detectors=(_codename(),))
    result = pf.scan("status of PROJECT-ORION launch")
    assert [(f.kind, f.detector) for f in result.findings] == [("internal_codename", "project_codename")]
    assert result.codes == ("prefilter:internal_codename",)


def test_custom_detector_subclass():
    class Word(Detector):
        id = "word_bluebird"
        kind = "codename"

        def find(self, text):
            i = text.find("bluebird")
            return [] if i < 0 else [(i, i + 8)]

    assert found("ship bluebird now", PreFilter(extra_detectors=[Word()])) == ["word_bluebird"]


class _Kind(Detector):
    def __init__(self, id="x_det", kind="x_kind"):
        self.id, self.kind = id, kind

    def find(self, text):
        return []


@pytest.mark.parametrize("bad,exc", [
    ((lambda text: [],), TypeError),                    # not a Detector
    (("not a detector",), TypeError),
    ("abc", TypeError),                                 # a bare string
    ((_Kind(id="payment_card"),), ValueError),          # clashes with a built-in
    ((_Kind(), _Kind()), ValueError),                   # duplicate ID
    ((_Kind(id=""),), ValueError),
    ((_Kind(kind="has space"),), ValueError),           # could carry text into codes
    ((_Kind(kind=7),), ValueError),
])
def test_bad_extra_detectors_raise(bad, exc):
    with pytest.raises(exc):
        PreFilter(extra_detectors=bad)


@pytest.mark.parametrize("span", [(5, 2), (-1, 3), (0, 999), ("0", 3), (0,), (True, 3), (3, 3)])
def test_detector_returning_bad_span_raises(span):
    class Bad(Detector):
        id = "bad_span"
        kind = "x"

        def find(self, text):
            return [span]

    with pytest.raises(ValueError):
        PreFilter(extra_detectors=(Bad(),)).scan("some text here")


def test_scan_rejects_non_text():
    with pytest.raises(TypeError):
        PF.scan(b"bytes")


def test_prefilter_is_frozen():
    with pytest.raises(Exception):
        PF.disabled_detectors = frozenset()  # type: ignore[misc]


# --- Stdlib only ---------------------------------------------------------------

def test_prefilter_imports_only_the_standard_library():
    tree = ast.parse(open(prefilter_module.__file__, encoding="utf-8").read())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "the pre-filter must not import other sievegate modules"
            modules.add(node.module.split(".")[0])
    allowed = set(sys.stdlib_module_names) | {"__future__"}
    assert modules and modules <= allowed, modules - allowed


# --- Performance ---------------------------------------------------------------

def _mixed_megabyte() -> str:
    rnd = random.Random(99)
    words = ["the", "invoice", "server", "2024-10-06", "v1.2.3", "1234", "x=1;", "https://example.com/a",
             "ORD-2024-000123", "+1 555 123 4567", GIT_SHA, UUID, "eyJ", "sk-", "def f(x):", "AKIA", "-----"]
    text = _base64_image()[:300_000] + " ".join(rnd.choice(words) for _ in range(200_000))
    return text[:1_000_000]


def test_one_megabyte_scans_under_250ms():
    text = _mixed_megabyte()
    PF.scan(text[:10_000])  # warm up
    best = min(_timed(lambda: PF.scan(text)) for _ in range(3))
    assert best < 0.25, f"{best * 1000:.0f} ms"


def _timed(fn) -> float:
    t0 = time.perf_counter()
    fn()
    return time.perf_counter() - t0


ADVERSARIAL = {
    "a_1m": "'a' * 1_000_000",
    "begin_100k": "'-----BEGIN' * 100_000",
    "digits_spaced_200k": "' '.join(str(i % 10) for i in range(200_000))",
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_adversarial_input_finishes_under_2s(name):
    # A separate process with a hard timeout, so a runaway regex can't hang
    # the suite.  The scan itself is timed inside the process.
    code = (
        "import time; from sievegate.prefilter import PreFilter; "
        f"t = {ADVERSARIAL[name]}; pf = PreFilter(); t0 = time.perf_counter(); "
        "pf.scan(t); print(time.perf_counter() - t0)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30, check=True
    )
    assert float(out.stdout.strip()) < 2.0

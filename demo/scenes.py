"""
The demo's scenes.

Every payload is fake and was written for this demo.  Values that match a real
provider's secret format (keys, tokens, card numbers) are built at runtime
from parts, so no such literal is ever committed.

`intended` is what the scene was written to show.  It is used only for the
docs' "what we expected" line and is never displayed as the result: the
demo always shows the real decision.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass, field
from typing import Callable, Union

Payload = Union[str, bytes]


@dataclass(frozen=True)
class Scene:
    id: str
    title: str
    story: str
    build: Callable[[], Payload]
    intended: str
    group: str
    # Scene 15 only: wrap the classifier so it never answers.
    simulated_outage: bool = False
    # Runtime-built secret values in the payload, for the canary checks.
    secrets: Callable[[], tuple[str, ...]] = field(default=lambda: ())


# --- Runtime-built fake values ---------------------------------------------

def _luhn_complete(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def fake_card() -> str:
    """A Luhn-valid Visa-format number, grouped 4-4-4-4.  Not a real card."""
    digits = _luhn_complete("4" + "716" + "0291" + "8837" + "502")
    return " ".join(digits[i:i + 4] for i in range(0, 16, 4))


def fake_ssn() -> str:
    """Valid under SSA format rules; made up for this demo."""
    return "-".join(["536", "22", "8147"])


def fake_aws_key_id() -> str:
    return "AK" + "IA" + "DEMO" + "7Q2X" + "K9WM" + "R4TZ"


def fake_aws_secret() -> str:
    return "wJal" + "rDemo" + "0nly" + "/K7MDENG" + "/bPxNotReal" + "EXAMPLEKEY"


def fake_db_password() -> str:
    return "Tr0ub4dor" + "-demo-" + "88"


def fake_private_key_header() -> str:
    return "-----" + "BEGIN " + "OPENSSH " + "PRIVATE KEY" + "-----"


def fake_private_key_body() -> str:
    rnd = random.Random(20261006)
    blob = bytes(rnd.getrandbits(8) for _ in range(180))
    text = base64.b64encode(b"openssh-key-v1\x00DEMO-NOT-A-REAL-KEY" + blob).decode()
    return "\n".join(text[i:i + 70] for i in range(0, len(text), 70))


def fake_encoded_credential() -> str:
    raw = "svc_billing:" + "Hx9" + "!demo" + "Pass" + "-2026" + "@billing-db"
    return base64.b64encode(raw.encode()).decode()


def fake_png() -> bytes:
    rnd = random.Random(7)
    return b"\x89PNG\r\n\x1a\n" + bytes(rnd.getrandbits(8) for _ in range(504))


# --- Payload builders -------------------------------------------------------------

def _plain_question() -> str:
    return ("What's the difference between TCP and UDP, and why would a video-calling "
            "app usually pick UDP?")


def _hard_reasoning() -> str:
    return (
        "Our warehouse ships from three sites. Site A can pack 120 orders an hour, B 90 and "
        "C 60, but C is 40% cheaper per order. Orders arrive at 200 an hour from 8am to 2pm "
        "and must all ship by 6pm. Work out the cheapest staffing plan across the three sites, "
        "show the reasoning step by step, and say how the plan changes if site B goes down "
        "for two hours at noon."
    )


def _code_review() -> str:
    return (
        "Can you review this function for bugs and style?\n\n"
        "def moving_average(values, window):\n"
        "    if window <= 0:\n"
        "        raise ValueError('window must be positive')\n"
        "    out = []\n"
        "    for i in range(len(values) - window + 1):\n"
        "        out.append(sum(values[i:i + window]) / window)\n"
        "    return out\n"
    )


def _private_key_paste() -> str:
    return (
        "ssh keeps saying 'Permission denied (publickey)'. Here's the key I'm using, "
        "what's wrong with it?\n\n"
        + fake_private_key_header() + "\n" + fake_private_key_body() + "\n"
        + "-----" + "END " + "OPENSSH " + "PRIVATE KEY" + "-----\n"
    )


def _aws_key_in_config() -> str:
    return (
        "Why does boto3 say the region is missing? My config file:\n\n"
        "[default]\n"
        f"aws_access_key_id = {fake_aws_key_id()}\n"
        f"aws_secret_access_key = {fake_aws_secret()}\n"
        "output = json\n"
    )


def _db_url_with_password() -> str:
    return (
        "Getting this on startup, any idea?\n\n"
        "Traceback (most recent call last):\n"
        '  File "app/db.py", line 42, in connect\n'
        "    engine = create_engine(settings.DATABASE_URL)\n"
        "sqlalchemy.exc.OperationalError: could not connect to server: Connection refused\n"
        f"    Is the server running at postgres://svc_orders:{fake_db_password()}"
        "@orders-db.internal:5432/orders ?\n"
    )


def _support_ticket_card() -> str:
    return (
        "Summarise this support ticket for the billing team:\n\n"
        "Ticket #48213 from Dana Whitfield: 'I was charged twice for my annual plan. "
        f"The card I used is {fake_card()}, expiry 09/28. Please refund the duplicate.'"
    )


def _customer_row_ssn() -> str:
    return (
        "Clean up this CSV row so the date is ISO format:\n\n"
        "customer_id,name,dob,ssn,plan\n"
        f"C-10442,Marcus Ellery,03/14/1987,{fake_ssn()},premium\n"
    )


def _patient_note() -> str:
    return (
        "Rewrite this note in plain language for the patient's family: "
        "Eleanor Vance, 67, seen today at the Riverside clinic. Diagnosed with stage 2 "
        "chronic kidney disease; started on lisinopril 10 mg daily. Follow-up bloods in "
        "six weeks; refer to nephrology if eGFR drops further."
    )


def _performance_review() -> str:
    return (
        "Help me tighten this performance review before I send it to HR: "
        "Priya Raman (Senior Analyst) missed three quarterly deadlines this year and "
        "two clients complained about her reports. I'm recommending she goes on a "
        "60-day performance improvement plan and doesn't receive a bonus."
    )


def _base64_secret() -> str:
    return (
        "Our deploy script has this hard-coded, can you tell me what format it is?\n\n"
        f"BILLING_DB_AUTH = \"{fake_encoded_credential()}\"\n"
    )


def _budget_question() -> str:
    return (
        "Hypothetically, if our marketing department had a $480,000 annual budget and "
        "we moved 15% from events to paid search, how should we phase the shift over "
        "four quarters to limit risk?"
    )


def _placeholder_ssn_fixture() -> str:
    return (
        "CI went red after the logging upgrade. This pytest case keeps failing:\n\n"
        "PLACEHOLDER = {'customer': 'Sample Person', 'tax_id': '000-00-0000'}\n\n"
        "def test_logger_scrubs_tax_id(caplog):\n"
        "    record_signup(PLACEHOLDER)\n"
        "    assert '000-00-0000' not in caplog.text\n"
    )


def _jev_outage() -> str:
    return "Draft a friendly reminder email about next week's team offsite."


# --- The scenes, in demo order --------------------------------------------------------

SCENES: tuple[Scene, ...] = (
    Scene("plain_question", "Plain question",
          "An employee asks a general networking question.",
          _plain_question, "PASS, tier small", "Normal traffic"),
    Scene("hard_reasoning", "Hard reasoning",
          "An analyst asks a multi-step reasoning problem.",
          _hard_reasoning, "PASS, tier medium", "Normal traffic"),
    Scene("code_review", "Code review",
          "A developer asks for a review of a harmless function.",
          _code_review, "PASS", "Normal traffic"),
    Scene("private_key_paste", "Private key paste",
          "A developer pastes a private key into 'why won't SSH work?'.",
          _private_key_paste, "BLOCKED by pre-filter", "Stopped locally",
          secrets=lambda: (fake_private_key_header(), fake_private_key_body())),
    Scene("aws_key_in_config", "Cloud key in a config file",
          "A developer shares a config file that contains a cloud access key.",
          _aws_key_in_config, "BLOCKED by pre-filter", "Stopped locally",
          secrets=lambda: (fake_aws_key_id(),)),
    Scene("db_url_with_password", "Database password in a stack trace",
          "A stack trace with a credentialed database URL buried in the noise.",
          _db_url_with_password, "BLOCKED by pre-filter", "Stopped locally",
          secrets=lambda: (fake_db_password(),)),
    Scene("support_ticket_card", "Card number in a support ticket",
          "A support agent pastes a ticket where the customer typed their card number.",
          _support_ticket_card, "BLOCKED by pre-filter", "Stopped locally",
          secrets=lambda: (fake_card(), fake_card().replace(" ", ""))),
    Scene("customer_row_ssn", "SSN in a customer CSV row",
          "An analyst asks for help cleaning a CSV row that holds a customer's SSN.",
          _customer_row_ssn, "BLOCKED by pre-filter", "Stopped locally",
          secrets=lambda: (fake_ssn(),)),
    Scene("patient_note", "Patient note",
          "A clinician asks for a plain-language rewrite of a named patient's diagnosis.",
          _patient_note, "BLOCKED by policy", "Caught by understanding, not patterns"),
    Scene("performance_review", "Performance review",
          "A manager drafts a named employee's performance review.",
          _performance_review, "BLOCKED by policy", "Caught by understanding, not patterns"),
    Scene("base64_secret", "Base64-encoded credential",
          "A deploy script with a base64-encoded database credential.",
          _base64_secret, "BLOCKED by policy", "Caught by understanding, not patterns"),
    Scene("budget_question", "Hypothetical budget",
          "A finance lead asks about a hypothetical department budget.",
          _budget_question, "PASS + RECONFIRM", "Reconfirm"),
    Scene("placeholder_ssn_fixture", "Placeholder SSN in a unit test",
          "A developer asks why a unit test using 000-00-0000 as a placeholder fails.",
          _placeholder_ssn_fixture,
          "Pre-filter ignores it; final outcome is whatever Jev decides", "Edge cases and safety nets"),
    Scene("image_bytes", "Raw image bytes",
          "An app sends raw image bytes to the gate.",
          fake_png, "BLOCKED by modality", "Edge cases and safety nets"),
    Scene("jev_outage", "Simulated classifier outage",
          "SIMULATED OUTAGE: the classifier never answers (the demo's timeout is shortened).",
          _jev_outage, "BLOCKED, fail-secure", "Edge cases and safety nets",
          simulated_outage=True),
)

SCENES_BY_ID = {s.id: s for s in SCENES}

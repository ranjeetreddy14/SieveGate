"""
Local pre-filter: a fast, offline pattern check that runs before the classifier.

It catches the obvious things (private keys, known token formats, credentialed
URLs, card numbers, SSNs, IBANs) so those payloads are blocked without ever
leaving the machine.  It can only make the gate stricter: a scan returns
findings (block) or no findings (carry on to the classifier), never "safe".

Findings carry a detector ID, a kind and a span, never the matched text.  The
caller already holds the payload, so spans reveal nothing new, and they let the
caller redact locally and resend.

Standard library only (re, dataclasses, plus base64 and json to confirm JWTs):
no network, no extra installs.
No Unicode normalisation: full-width or otherwise obfuscated variants are left
to the classifier.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Pattern

# Detector IDs and kinds end up in reason codes, so keep them to a fixed,
# boring alphabet: never anything that could carry payload text.
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


# --- Public types -----------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """
    One thing the pre-filter found.  Deliberately has no value field.

    kind:      what was found, e.g. "private_key", "card_number".
    detector:  the ID of the detector that found it.
    start/end: where it is in the payload (payload[start:end]).
    """
    kind: str
    detector: str
    start: int
    end: int


@dataclass(frozen=True)
class PreFilterResult:
    """Findings from one scan.  Any finding means block."""
    findings: tuple[Finding, ...] = ()

    @property
    def blocked(self) -> bool:
        return bool(self.findings)

    @property
    def codes(self) -> tuple[str, ...]:
        """Reason codes, one per kind in order of first appearance."""
        return tuple(dict.fromkeys(f"prefilter:{f.kind}" for f in self.findings))


class Detector(ABC):
    """
    One pattern check.  Subclass it (or use RegexDetector) to add your own,
    e.g. internal project codenames.

    id:    stable identifier, used in PreFilter(disabled_detectors=...).
    kind:  what a match means, used in reason codes ("prefilter:<kind>").
    find:  yields (start, end) spans of every match in the text.
    """
    id: str
    kind: str

    @abstractmethod
    def find(self, text: str) -> Iterable[tuple[int, int]]:
        ...


class RegexDetector(Detector):
    """
    A detector built from a regex, with an optional confirm(match) check.

    The regex only finds candidates; confirm() (if given) decides whether a
    candidate counts.  `span_group` picks which group's span is reported.
    `hints`, if given, are substrings at least one of which must appear in the
    text for the regex to run at all (a cheap fast path).
    """

    def __init__(
        self,
        id: str,
        kind: str,
        pattern: str | Pattern[str],
        confirm: Optional[Callable[[re.Match[str]], bool]] = None,
        span_group: int | str = 0,
        hints: tuple[str, ...] = (),
    ) -> None:
        self.id = id
        self.kind = kind
        self._regex = re.compile(pattern) if isinstance(pattern, str) else pattern
        self._confirm = confirm
        self._span_group = span_group
        self._hints = tuple(hints)

    def find(self, text: str) -> Iterable[tuple[int, int]]:
        if self._hints and not any(h in text for h in self._hints):
            return
        for match in self._regex.finditer(text):
            if self._confirm is None or self._confirm(match):
                yield match.span(self._span_group)

    def __repr__(self) -> str:
        return f"RegexDetector(id={self.id!r}, kind={self.kind!r})"


# --- Confirmation rules -----------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    """ISO/IEC 7812-1 Luhn check digit."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_brand_ok(digits: str) -> bool:
    """
    Known issuer prefix and length (brands' published IIN ranges):
    Visa 4 (13, 16, 19 digits); Mastercard 51-55 and 2221-2720 (16);
    American Express 34, 37 (15); Discover 6011, 644-649, 65 (16-19).
    """
    n = len(digits)
    if digits[0] == "4":
        return n in (13, 16, 19)
    two, four = int(digits[:2]), int(digits[:4])
    if 51 <= two <= 55 or 2221 <= four <= 2720:
        return n == 16
    if two in (34, 37):
        return n == 15
    if four == 6011 or two == 65 or 644 <= int(digits[:3]) <= 649:
        return 16 <= n <= 19
    return False


class _CardDetector(Detector):
    """
    Payment card numbers.  Candidates are runs of digit groups separated by a
    single space or dash; every window of whole groups holding 13-19 digits is
    checked with Luhn plus the issuer prefix.  Windows must use one separator
    throughout, and every group but the last needs 3+ digits (real layouts
    are 4-4-4-4, 4-6-5, 4-6-4, 4-4-4-4-3), so spaced-out single digits are
    never read as a card.  Published test card numbers count as cards.
    """
    id = "payment_card"
    kind = "card_number"
    # A run of digit groups holding at least 13 digits (checked by the lookahead,
    # so short numbers never reach Python code).
    _RUN = re.compile(r"\d(?<!\d\d)(?=(?:[ -]?\d){12})\d*(?:[ -]\d+)*")
    _GROUP = re.compile(r"\d+")

    def find(self, text: str) -> Iterable[tuple[int, int]]:
        for run in self._RUN.finditer(text):
            groups = [(g.start(), g.end()) for g in self._GROUP.finditer(run.group())]
            base = run.start()
            i = 0
            while i < len(groups):
                span = self._card_starting_at(text, base, groups, i)
                if span is None:
                    i += 1
                    continue
                yield span
                # Resume after the card's last group.
                end = span[1]
                while i < len(groups) and base + groups[i][0] < end:
                    i += 1

    @staticmethod
    def _card_starting_at(text, base, groups, i) -> Optional[tuple[int, int]]:
        digits = ""
        sep = None
        for j in range(i, len(groups)):
            start, end = groups[j]
            if j > i:
                this_sep = text[base + groups[j - 1][1]]
                if sep is None:
                    sep = this_sep
                elif this_sep != sep:
                    return None
                if groups[j - 1][1] - groups[j - 1][0] < 3:
                    return None  # only the last group may be short
            digits += text[base + start:base + end]
            if len(digits) > 19:
                return None
            if len(digits) >= 13 and _card_brand_ok(digits) and _luhn_ok(digits):
                return base + groups[i][0], base + end
        return None


class _PemDetector(Detector):
    """
    PEM armour headers for private keys only: PKCS#8 "PRIVATE KEY" and
    "ENCRYPTED PRIVATE KEY" (RFC 7468), OpenSSL's traditional RSA / EC / DSA
    headers, OpenSSH's own format (OpenSSH PROTOCOL.key) and OpenPGP's
    "PGP PRIVATE KEY BLOCK" (RFC 4880).  PUBLIC KEY and CERTIFICATE headers
    don't match.  The header alone is enough to block.

    The span runs from the header over the armoured body (base64 lines and
    "Name: value" header lines) to the END line if there is one, so that
    redact() removes the key material, not just the header.
    """
    id = "pem_private_key"
    kind = "private_key"
    _HEADER = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    )
    # One armour line after a line break: base64, an RFC 1421 / 4880 header
    # line, a blank line, or the END line (which finishes the block).
    _LINE = re.compile(
        r"\r?\n[ \t]*(?:(?P<end>-----END [A-Z ]{0,40}-----)|[A-Za-z0-9+/=]{1,512}"
        r"|[A-Za-z][A-Za-z0-9-]{0,63}: [^\r\n]{0,512}|)[ \t]*(?=\r?\n|\Z)"
    )

    def find(self, text: str) -> Iterable[tuple[int, int]]:
        if "-----BEGIN" not in text:
            return
        pos = 0
        while True:
            header = self._HEADER.search(text, pos)
            if header is None:
                return
            end = cursor = header.end()
            while True:
                line = self._LINE.match(text, cursor)
                if line is None:
                    break
                cursor = line.end()
                if line.group().strip():
                    end = cursor  # the span never ends on a blank line
                if line.group("end"):
                    break
            yield header.start(), end
            pos = end


def _ssn_ok(m: re.Match[str]) -> bool:
    """SSA rules: area not 000, 666 or 900-999; group not 00; serial not 0000."""
    if m.group("a1") is not None:
        area, group, serial = m.group("a1", "g1", "s1")
    else:
        area, group, serial = m.group("a2", "g2", "s2")
    a = int(area)
    return a != 0 and a != 666 and a < 900 and group != "00" and serial != "0000"


def _iban_ok(m: re.Match[str]) -> bool:
    """ISO 13616 / ISO 7064 mod 97-10: the rearranged number mod 97 must be 1."""
    compact = m.group().replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


def _b64url_json_object(segment: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return isinstance(json.loads(raw), dict)
    except (binascii.Error, ValueError, UnicodeDecodeError, RecursionError):
        return False


def _jwt_ok(m: re.Match[str]) -> bool:
    """RFC 7519: header and payload are base64url-encoded JSON objects."""
    return _b64url_json_object(m.group("header")) and _b64url_json_object(m.group("payload"))


# Obvious placeholder passwords, compared case-insensitively against the
# whole password.  Templating forms: <...>, ${...}, {{...}}, %(...)s.
_PLACEHOLDER_PASSWORD = re.compile(
    r"(?:password|pass|secret|changeme|x{3,}|\*{3,}|<[^>]*>|\$\{[^}]*\}|\{\{.*\}\}|%\([^)]*\)s)",
    re.IGNORECASE | re.DOTALL,
)


def _real_password(m: re.Match[str]) -> bool:
    return _PLACEHOLDER_PASSWORD.fullmatch(m.group("password")) is None


# --- Built-in detectors -----------------------------------------------------
#
# Every regex has a lookbehind at its start so a long run of token characters
# has only one place a match can start: no quadratic rescans on hostile input.
# Where possible the first character is matched *before* the lookbehind
# (e.g. "g(?<![A-Za-z0-9_]g)h..."), which lets the regex engine jump straight
# to candidate characters instead of testing the lookbehind at every position.
# Quantifiers are bounded where a pattern has to search past them.

# Characters that can sit next to a token in base64 data.  Used as the
# boundary for fixed-length tokens so base64 blobs don't produce matches.
_B64 = r"A-Za-z0-9+/"

DEFAULT_DETECTORS: tuple[Detector, ...] = (
    _PemDetector(),
    # AWS access key IDs: "AKIA" (long-term) and "ASIA" (temporary STS)
    # prefixes, per the AWS STS GetAccessKeyInfo reference; 20 characters,
    # as in AWS's documented examples.
    RegexDetector(
        "aws_access_key_id", "cloud_credential",
        rf"(?<![{_B64}])(?:AKIA|ASIA)[A-Z0-9]{{16}}(?![{_B64}=])",
        hints=("AKIA", "ASIA"),
    ),
    # GitHub tokens (GitHub engineering blog, "Behind GitHub's new
    # authentication token formats"): ghp_ / gho_ / ghu_ / ghs_ / ghr_ then
    # base62 (30 random + 6 checksum characters).  Fine-grained personal
    # access tokens start with github_pat_.
    RegexDetector(
        "github_token", "code_host_token",
        r"g(?<![A-Za-z0-9_]g)(?:h[pousr]_[A-Za-z0-9]{36,255}|ithub_pat_[A-Za-z0-9_]{22,255})",
        hints=("gh", "github_pat_"),
    ),
    # Slack tokens (Slack docs, "Token types"): bot xoxb-, user xoxp-,
    # app-level xapp-.  Also the older xoxa- / xoxr- / xoxs- forms; no
    # ordinary text starts like that.
    RegexDetector(
        "slack_token", "chat_token",
        r"x(?<![A-Za-z0-9_-]x)(?:ox[abprs]|app)-[A-Za-z0-9-]{10,255}",
        hints=("xox", "xapp-"),
    ),
    # Stripe live-mode secret and restricted keys (Stripe docs, "API keys":
    # live keys start with sk_live_ / rk_live_).  Test-mode sk_test_ keys
    # are not secrets and are left to the classifier.
    RegexDetector(
        "stripe_live_key", "payment_credential",
        r"[sr](?<![A-Za-z0-9_][sr])k_live_[A-Za-z0-9]{16,255}",
        hints=("_live_",),
    ),
    # Google API keys: "AIza" + 35 of [A-Za-z0-9_-] (39 characters), per
    # Microsoft Purview's "Google API key" entity definition.
    RegexDetector(
        "google_api_key", "cloud_credential",
        rf"(?<![{_B64}_-])AIza[0-9A-Za-z_-]{{35}}(?![{_B64}_=-])",
        hints=("AIza",),
    ),
    # LLM provider keys.  Anthropic: sk-ant-api03- (API) and sk-ant-admin01-
    # (admin).  OpenAI: sk-, sk-proj-, sk-svcacct- or sk-admin- keys carrying
    # the "T3BlbkFJ" marker (base64 of "OpenAI") that every OpenAI key
    # contains, per GitGuardian's OpenAI detector docs.  The marker avoids
    # matching any other "sk-..." string.
    RegexDetector(
        "llm_api_key", "ai_credential",
        r"s(?<![A-Za-z0-9_-]s)k-(?:ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{32,255}"
        r"|(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,200}T3BlbkFJ[A-Za-z0-9_-]{16,200})",
        hints=("sk-",),
    ),
    # JSON Web Tokens, compact serialisation (RFC 7519 / RFC 7515): three
    # base64url segments.  "eyJ" is base64 for '{"'.  Confirmed by decoding
    # header and payload to JSON objects.
    RegexDetector(
        "jwt", "bearer_token",
        r"(?P<header>e(?<![A-Za-z0-9_-]e)yJ[A-Za-z0-9_-]{5,8192})\.(?P<payload>eyJ[A-Za-z0-9_-]{5,65536})"
        r"\.[A-Za-z0-9_-]{5,8192}",
        confirm=_jwt_ok,
        hints=("eyJ",),
    ),
    # URLs with a password in the userinfo part (RFC 3986 section 3.2.1:
    # scheme://user:password@host).  The user may be empty (redis://:<password>@host).
    # Skipped when the password is an obvious placeholder.
    RegexDetector(
        "credentialed_url", "credentialed_url",
        r"[A-Za-z](?<![A-Za-z0-9+.-][A-Za-z])[A-Za-z0-9+.-]{0,31}://[^\s:/?#@]{0,256}"
        r":(?P<password>[^\s/?#@]{1,256})@(?=[A-Za-z0-9\[])",
        confirm=_real_password,
        hints=("://",),
    ),
    _CardDetector(),
    # US Social Security numbers, separated forms only (a bare 9-digit number
    # is too noisy).  One separator throughout.  Validity per the SSA:
    # area not 000, 666 or 900-999; group not 00; serial not 0000.
    # The lookarounds stop a match inside a longer run like 1-234-56-7890-1.
    RegexDetector(
        "us_ssn", "national_id",
        r"(?P<a1>\d(?<!\d\d)(?<!\d-\d)\d{2})-(?P<g1>\d{2})-(?P<s1>\d{4})(?!\d|-\d)"
        r"|(?P<a2>\d(?<!\d\d)(?<!\d \d)\d{2}) (?P<g2>\d{2}) (?P<s2>\d{4})(?!\d| \d)",
        confirm=_ssn_ok,
    ),
    # IBANs (ISO 13616): country code, 2 check digits, 11-30 alphanumerics;
    # compact or printed in groups of 4.  Confirmed with mod 97 == 1.
    RegexDetector(
        "iban", "bank_account",
        r"[A-Z](?<![A-Za-z0-9][A-Z])[A-Z]\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)"
        r"(?![A-Za-z0-9])",
        confirm=_iban_ok,
    ),
)

DETECTOR_IDS: frozenset[str] = frozenset(d.id for d in DEFAULT_DETECTORS)


# --- The pre-filter ---------------------------------------------------------

@dataclass(frozen=True)
class PreFilter:
    """
    Runs every active detector over the whole payload (no truncation).
    Invalid settings raise at construction, like EnforcementPolicy.

    disabled_detectors:  built-in detector IDs to switch off.
    extra_detectors:     your own Detector instances, run after the built-ins.
    """
    disabled_detectors: frozenset[str] = frozenset()
    extra_detectors: tuple[Detector, ...] = ()

    def __post_init__(self) -> None:
        disabled = self.disabled_detectors
        if isinstance(disabled, (str, bytes)) or not isinstance(disabled, Iterable):
            raise TypeError("disabled_detectors must be a set of detector IDs")
        disabled = frozenset(disabled)
        for item in disabled:
            if not isinstance(item, str):
                raise TypeError("disabled_detectors must contain detector ID strings")
            if item not in DETECTOR_IDS:
                raise ValueError(f"unknown detector ID {item!r}")
        object.__setattr__(self, "disabled_detectors", disabled)

        extras = self.extra_detectors
        if isinstance(extras, (str, bytes)) or not isinstance(extras, Iterable):
            raise TypeError("extra_detectors must be a sequence of Detector instances")
        extras = tuple(extras)
        seen = set(DETECTOR_IDS)
        for det in extras:
            if not isinstance(det, Detector):
                raise TypeError("every extra detector must be a Detector instance")
            for attr in ("id", "kind"):
                value = getattr(det, attr, None)
                if not isinstance(value, str) or not _NAME.fullmatch(value):
                    raise ValueError(
                        f"detector {attr} must be 1-64 characters of letters, digits, _ . -"
                    )
            if not callable(getattr(det, "find", None)):
                raise TypeError("every extra detector needs a callable find()")
            if det.id in seen:
                raise ValueError(f"duplicate detector ID {det.id!r}")
            seen.add(det.id)
        object.__setattr__(self, "extra_detectors", extras)

    @property
    def detectors(self) -> tuple[Detector, ...]:
        """The detectors this pre-filter runs, in order."""
        builtins = tuple(d for d in DEFAULT_DETECTORS if d.id not in self.disabled_detectors)
        return builtins + self.extra_detectors

    def scan(self, text: str) -> PreFilterResult:
        """
        Scan the whole text.  Returns findings (block) or none (continue to
        the classifier).  Raises on a non-str input or a detector that
        returns a bad span; the gate turns any exception into a block.
        """
        if not isinstance(text, str):
            raise TypeError("the pre-filter scans text only")
        findings = []
        for det in self.detectors:
            for span in det.find(text):
                start, end = _check_span(span, len(text))
                findings.append(Finding(kind=det.kind, detector=det.id, start=start, end=end))
        findings.sort(key=lambda f: (f.start, f.end, f.detector))
        return PreFilterResult(findings=tuple(findings))


def redact(text: str, findings: Iterable[Finding]) -> str:
    """
    Replace every finding's span in `text` with "[REDACTED:<kind>]".
    Overlapping findings are merged into one marker (the first one's kind).
    Use it on the caller's side to redact locally and resend.
    """
    out = []
    pos = 0
    for f in sorted(findings, key=lambda f: (f.start, -f.end)):
        if f.start >= pos:
            out.append(text[pos:f.start])
            out.append(f"[REDACTED:{f.kind}]")
            pos = f.end
        else:
            pos = max(pos, f.end)  # overlaps the previous marker: extend it
    out.append(text[pos:])
    return "".join(out)


def _check_span(span: object, length: int) -> tuple[int, int]:
    """A detector's span must be two ints with 0 <= start < end <= length."""
    if not isinstance(span, tuple) or len(span) != 2:
        raise ValueError("detector returned a malformed span")
    start, end = span
    if (
        isinstance(start, bool) or isinstance(end, bool)
        or not isinstance(start, int) or not isinstance(end, int)
        or not 0 <= start < end <= length
    ):
        raise ValueError("detector returned an out-of-range span")
    return start, end

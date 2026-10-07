"""
Classifiers used by the demo, and the recording file format.

ReplayClassifier is a real `Classifier` subclass: it returns the verdicts a
live run recorded, so the real SieveGate, pre-filter and EnforcementPolicy
all run on top of it with no key and no network.  That is the swappable
interface at work: the gate doesn't know it isn't talking to Jev.

A recording stores, per scene: the classifier's result (verdict signals,
routing, raw answers with confidences and probabilities), the latency, and
a SHA-256 fingerprint of the payload, so a scene whose text has changed is
not replayed with stale answers.  It stores no payload text.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any, Optional

from sievegate.classifier import Classifier
from sievegate.models import (
    ClassificationResult,
    ComplianceVerdict,
    ContentCategory,
    Judgment,
    ModelTier,
    PayloadType,
    RoutingRecommendation,
)

RECORDINGS_DIR = Path(__file__).resolve().parent / "recordings"
FORMAT_VERSION = 1


def fingerprint(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def default_recording() -> Path:
    """The newest live recording if there is one, else the synthetic one."""
    live = sorted(RECORDINGS_DIR.glob("live_*.json"))
    return live[-1] if live else RECORDINGS_DIR / "synthetic.json"


# --- Serialisation --------------------------------------------------------------

_VERDICT_FIELDS = (
    "contains_pii", "data_leak_risk", "pii_probability", "secret_probability",
    "financial_probability", "leak_risk_confidence", "category_confidence",
    "contains_secret", "contains_financial",
)


def result_to_json(result: ClassificationResult) -> dict:
    """A classifier's result as JSON (the classifier's own output, before the policy)."""
    v = result.verdict
    data = {name: getattr(v, name) for name in _VERDICT_FIELDS}
    data["payload_type"] = v.payload_type.value
    data["content_category"] = v.content_category.value if v.content_category else None
    return {
        "verdict": data,
        "routing": {"tier": result.routing.tier.value, "reason": result.routing.reason},
        "judgments": {
            name: {
                "value": j.value,
                "confidence": j.confidence,
                "probabilities": None if j.probabilities is None else
                {str(k): p for k, p in j.probabilities.items()},
            }
            for name, j in result.judgments.items()
        },
    }


def result_from_json(data: dict) -> ClassificationResult:
    v = dict(data["verdict"])
    v["payload_type"] = PayloadType(v["payload_type"])
    v["content_category"] = (
        ContentCategory(v["content_category"]) if v["content_category"] is not None else None
    )
    judgments = {
        name: Judgment(
            value=j["value"],
            confidence=j["confidence"],
            probabilities=None if j["probabilities"] is None else MappingProxyType(dict(j["probabilities"])),
        )
        for name, j in data.get("judgments", {}).items()
    }
    return ClassificationResult(
        verdict=ComplianceVerdict(**v),
        routing=RoutingRecommendation(
            tier=ModelTier(data["routing"]["tier"]), reason=data["routing"]["reason"]
        ),
        judgments=MappingProxyType(judgments),
    )


def load_recording(path: Path) -> dict:
    with Path(path).open(encoding="utf-8") as fh:
        rec = json.load(fh)
    if rec.get("format") != FORMAT_VERSION:
        raise ValueError(f"unsupported recording format in {path}")
    return rec


def save_recording(path: Path, meta: dict, scenes: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rec = {"format": FORMAT_VERSION, **meta, "scenes": scenes}
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(rec, fh, indent=2, sort_keys=False)
        fh.write("\n")


# --- Classifiers ------------------------------------------------------------------

class RecordingMissing(LookupError):
    """No recorded answer for this scene, or the scene's text has changed."""


class ReplayClassifier(Classifier):
    """
    Returns the recorded classifier result for one scene.  If the scene has no
    recording, or the payload no longer matches the recorded fingerprint, it
    raises, and the gate blocks fail-secure.
    """

    def __init__(self, recording: dict, scene_id: str) -> None:
        self._entry = recording.get("scenes", {}).get(scene_id)
        self.sent = False          # True once a recorded answer was returned
        self.latency_ms: Optional[float] = None

    async def classify(self, payload: Any) -> ClassificationResult:
        if self._entry is None:
            raise RecordingMissing("no recording for this scene")
        if not isinstance(payload, str) or fingerprint(payload) != self._entry["payload_sha256"]:
            raise RecordingMissing("recording does not match this payload")
        self.sent = True
        self.latency_ms = self._entry["latency_ms"]
        return result_from_json(self._entry["result"])


class LiveClassifier(Classifier):
    """
    Wraps the real TypeSafe classifier for one scene: marks that the payload
    was handed to it (it left the machine) and keeps the result and the
    classifier latency so the run can be saved as a recording.
    """

    def __init__(self, inner: Classifier) -> None:
        self._inner = inner
        self.sent = False
        self.latency_ms: Optional[float] = None
        self.result: Optional[ClassificationResult] = None

    async def classify(self, payload: Any) -> ClassificationResult:
        self.sent = True
        started = time.perf_counter()
        result = await self._inner.classify(payload)
        self.latency_ms = (time.perf_counter() - started) * 1000
        self.result = result
        return result


class OutageClassifier(Classifier):
    """Scene 15: a classifier that never answers.  Nothing is forwarded."""

    def __init__(self) -> None:
        self.sent = False
        self.latency_ms: Optional[float] = None

    async def classify(self, payload: Any) -> ClassificationResult:
        await asyncio.sleep(3600)  # the gate's timeout fires long before this
        raise AssertionError("unreachable")


class WouldSendToJev(Exception):
    """Raised by SkipClassifier: the payload got past the local checks."""


class SkipClassifier(Classifier):
    """
    prefilter-only mode: stands where Jev would be and sends nothing.  If the
    gate reaches it, the payload passed the modality checks and the pre-filter
    and would have been sent to Jev.
    """

    def __init__(self) -> None:
        self.sent = False
        self.reached = False
        self.latency_ms: Optional[float] = None

    async def classify(self, payload: Any) -> ClassificationResult:
        self.reached = True
        raise WouldSendToJev()

"""
SieveGate gate demo: tells the story of the gate scene by scene.

    python demo/run_demo.py                      # replay (default): no key, no network
    python demo/run_demo.py --mode prefilter-only
    python demo/run_demo.py --mode live          # commercial edition only
    python demo/run_demo.py --scene patient_note
    python demo/run_demo.py --record docs/demo/  # one SVG per scene + summary + pipeline
    python demo/run_demo.py --text "your own text"          # local checks only, never sent
    python demo/run_demo.py --policy pii_threshold=0.5      # change a policy setting

Needs the demo extra:  pip install -e .[demo]

Modes:
  replay          The real SieveGate, pre-filter and policy, with the classifier
                  replaced by ReplayClassifier, which returns answers recorded in
                  a live run (demo/recordings/).  No key, no network.
  live            Real Jev calls.  Needs the commercial edition's adapter; in
                  this edition it says so and exits.
  prefilter-only  Only the modality checks and the local pre-filter.  Scenes that
                  would reach Jev say so and stop there.

--text checks your own text with the gate's local stages (modality check and
pre-filter) and shows what was caught, or that it would go on to Jev.  It never
calls the API, in any mode.  --policy name=value rebuilds the enforcement
policy with one setting changed (repeatable), so you can watch the decisions
on the recorded answers change.

Scene 15 is always a simulated outage: the classifier is replaced by one that
never answers, under a shortened timeout.  It never calls the real API.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from dataclasses import fields
from datetime import date
from importlib import metadata
from pathlib import Path

try:
    from rich.console import Console
except ImportError:  # the library never needs rich; only this demo does
    sys.exit("The demo needs the 'rich' package: pip install -e .[demo]")

import render
from branding import NAME
from replay_classifier import (
    LiveClassifier,
    OutageClassifier,
    ReplayClassifier,
    SkipClassifier,
    default_recording,
    fingerprint,
    load_recording,
    result_to_json,
    save_recording,
)
from scenes import SCENES, SCENES_BY_ID, Scene

from sievegate.models import ModelTier
from sievegate.policy import EnforcementPolicy
from sievegate.prefilter import PreFilter, redact
from sievegate.sieve import SieveGate, SieveGateSettings

MODES = ("replay", "live", "prefilter-only")
GATE_TIMEOUT_SECONDS = 5.0      # generous, as in the recorded live run
OUTAGE_TIMEOUT_SECONDS = 0.5    # scene 15 only


def masked_preview(payload) -> str:
    if isinstance(payload, bytes):
        kind = "PNG image" if payload.startswith(b"\x89PNG") else "binary data"
        return f"<{len(payload)} bytes of {kind}>"
    return render.preview(redact(payload, PreFilter().scan(payload).findings))


def outcome_for(scene: Scene, result, classifier, mode: str, elapsed_ms: float) -> render.Outcome:
    reason = result.routing.reason
    blocked = result.routing.tier is ModelTier.BLOCKED
    sent = getattr(classifier, "sent", False)
    prefilter_codes = tuple(dict.fromkeys(f"prefilter:{f.kind}" for f in result.prefilter_findings))
    notes = []

    if isinstance(classifier, SkipClassifier) and classifier.reached:
        decision, decided_by, codes = "SKIPPED", "—", ("→ would be sent to Jev (skipped in this mode)",)
    elif not blocked and result.would_block:
        # Policy in observe mode: it would have blocked, but only reports.
        decision = "PASS + RECONFIRM" if result.needs_confirmation else "PASS"
        decided_by = "none (observe mode: the policy would block)"
        codes = result.policy_reasons + result.confirm_reasons
    elif not blocked:
        decision = "PASS + RECONFIRM" if result.needs_confirmation else "PASS"
        decided_by, codes = "none (passed)", result.confirm_reasons
    elif reason.startswith("blocked by prefilter:"):
        decision, decided_by, codes = "BLOCKED", "pre-filter", prefilter_codes
    elif reason.startswith(("non-text payload", "empty or whitespace")):
        decision, decided_by, codes = "BLOCKED", "modality", (reason,)
    elif result.policy_reasons:
        decision, decided_by, codes = "BLOCKED", "policy", result.policy_reasons
    else:
        decision, decided_by, codes = "BLOCKED", "fail-secure", (result.error or reason,)

    if scene.simulated_outage:
        notes.append("Simulated outage: the classifier was replaced by one that never answers.")
    if decided_by == "fail-secure" and mode == "replay" and not sent and not scene.simulated_outage:
        notes.append("No usable recording for this scene, so the gate blocked it fail-secure.")

    v = result.verdict
    signals = None
    if v.pii_probability is not None and decided_by not in ("pre-filter", "modality", "fail-secure"):
        signals = {
            "pii": v.pii_probability, "secret": v.secret_probability,
            "financial": v.financial_probability, "leak": v.data_leak_risk,
            "leak_conf": v.leak_risk_confidence,
            "category": v.content_category.value if v.content_category else None,
            "category_conf": v.category_confidence,
        }

    tier = "—" if decision == "SKIPPED" else result.routing.tier.value
    if mode == "replay" and sent and classifier.latency_ms is not None:
        latency = f"{classifier.latency_ms:.0f} ms (recorded)"
    elif decision == "SKIPPED" or not sent:
        latency = f"{elapsed_ms:.2f} ms (local)" if elapsed_ms < 100 else f"{elapsed_ms:.0f} ms (local)"
    else:
        latency = f"{elapsed_ms:.0f} ms"

    if decision == "SKIPPED":
        left = "No (skipped in this mode)"
    elif sent and mode == "replay":
        left = "Yes (sent to Jev in the recorded live run)"
    elif sent:
        left = "Yes (sent to Jev)"
    else:
        left = "No"
    return render.Outcome(scene.id, scene.title, decision, decided_by, tuple(codes), tier,
                          latency, left, signals, notes)


async def run_scene(scene: Scene, mode: str, recording: dict | None, live_inner,
                    policy: EnforcementPolicy | None = None):
    payload = scene.build()
    if scene.simulated_outage:
        classifier = OutageClassifier()
        timeout = OUTAGE_TIMEOUT_SECONDS
    elif mode == "replay":
        classifier = ReplayClassifier(recording or {}, scene.id)
        timeout = GATE_TIMEOUT_SECONDS
    elif mode == "live":
        classifier = LiveClassifier(live_inner)
        timeout = GATE_TIMEOUT_SECONDS
    else:
        classifier = SkipClassifier()
        timeout = GATE_TIMEOUT_SECONDS
    gate = SieveGate(classifier, SieveGateSettings(classify_timeout_seconds=timeout), policy=policy)
    started = time.perf_counter()
    result = await gate.evaluate_payload(payload)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return payload, classifier, result, elapsed_ms


async def check_text(text: str, console: Console) -> int:
    """
    --text: run the user's own text through the real gate's local stages
    (modality check and pre-filter).  The classifier slot is filled by one
    that never sends anything, so this can't call the API.
    """
    classifier = SkipClassifier()
    gate = SieveGate(classifier)
    started = time.perf_counter()
    result = await gate.evaluate_payload(text)
    elapsed_ms = (time.perf_counter() - started) * 1000
    masked = redact(text, result.prefilter_findings) if result.prefilter_findings else text
    if classifier.reached:
        verdict = ("NOT CAUGHT LOCALLY", "→ would be sent to Jev for classification "
                   "(not sent: --text never calls the API)")
    elif result.prefilter_findings:
        verdict = ("BLOCKED", "pre-filter: stopped on this machine, never sent")
    else:
        verdict = ("BLOCKED", f"modality: {result.routing.reason}")
    render.text_check(console, render.flatten(masked), verdict, result.prefilter_findings, elapsed_ms)
    return 0


_POLICY_SETS = ("block_categories", "confirm_categories")


def parse_policy(items: list[str]) -> EnforcementPolicy | None:
    """--policy name=value (repeatable) → EnforcementPolicy.  Raises ValueError."""
    if not items:
        return None
    allowed = {f.name for f in fields(EnforcementPolicy)} - {"extra_rules"}
    kwargs = {}
    for item in items:
        name, sep, value = item.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or name not in allowed:
            raise ValueError(f"--policy expects name=value with name one of {sorted(allowed)}")
        if name in _POLICY_SETS:
            kwargs[name] = frozenset(v.strip() for v in value.split(",") if v.strip())
        elif name == "mode":
            kwargs[name] = value
        elif name == "block_on_missing_signal":
            if value.lower() not in ("true", "false"):
                raise ValueError("block_on_missing_signal must be true or false")
            kwargs[name] = value.lower() == "true"
        elif value.lower() == "none":
            kwargs[name] = None
        else:
            try:
                kwargs[name] = float(value)
            except ValueError:
                raise ValueError(f"{name} must be a number between 0 and 1, or none") from None
    try:
        return EnforcementPolicy(**kwargs)  # validates every setting
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from None


async def run(args) -> int:
    console = Console(record=bool(args.record), width=110, no_color=args.no_color,
                      highlight=False, file=args.out)
    record_dir = Path(args.record) if args.record else None

    if args.text is not None:
        return await check_text(args.text, console)

    recording, synthetic, note = None, False, ""
    live_inner = None
    if args.mode == "live":
        # Live classification needs the commercial edition's Jev adapter.
        console.print("Live mode is available in the commercial edition. "
                      "Use --mode replay (the default) to see a recorded live run.")
        return 2
    if args.mode == "replay":
        path = Path(args.recording) if args.recording else default_recording()
        recording = load_recording(path) if path.exists() else {"scenes": {}}
        synthetic = recording.get("source") == "synthetic"
        note = f"recording: {path.name}" + ("" if path.exists() else " (not found)")
        if recording.get("recorded_on"):
            note += f", recorded {recording['recorded_on']}"
    if args.policy_obj is not None:
        note += ("   " if note else "") + "custom policy: " + "; ".join(args.policy)

    scenes = [SCENES_BY_ID[args.scene]] if args.scene else list(SCENES)

    render.banner(console, args.mode, synthetic, note)
    render.pipeline(console)
    if record_dir:
        record_dir.mkdir(parents=True, exist_ok=True)
        console.save_svg(str(record_dir / "pipeline.svg"), title=f"{NAME} · how the gate decides")

    outcomes, recorded = [], {}
    try:
        for scene in scenes:
            payload, classifier, result, elapsed_ms = await run_scene(
                scene, args.mode, recording, live_inner, args.policy_obj)
            outcome = outcome_for(scene, result, classifier, args.mode, elapsed_ms)
            outcomes.append(outcome)
            number = [s.id for s in SCENES].index(scene.id) + 1
            render.scene(console, number, len(SCENES), scene.title, scene.story,
                         masked_preview(payload), outcome, synthetic)
            if record_dir:
                console.save_svg(str(record_dir / f"{number:02d}_{scene.id}.svg"),
                                 title=f"{NAME} · scene {number}: {scene.title}")
            if isinstance(classifier, LiveClassifier) and classifier.result is not None:
                recorded[scene.id] = {
                    "payload_sha256": fingerprint(payload),
                    "latency_ms": round(classifier.latency_ms, 1),
                    "result": result_to_json(classifier.result),
                }
    finally:
        if live_inner is not None:
            await live_inner.aclose()

    render.summary(console, outcomes, args.mode, synthetic)
    if record_dir:
        console.save_svg(str(record_dir / "summary.svg"), title=f"{NAME} · demo summary")

    if args.save_recording:
        meta = {
            "source": "live",
            "recorded_on": date.today().isoformat(),
            "sdk": f"typesafe-sdk {metadata.version('typesafe-sdk')}",
            "model": "jev-latest (SDK default)",
            "policy": "EnforcementPolicy() defaults",
            "gate_timeout_seconds": GATE_TIMEOUT_SECONDS,
            "note": "Classifier answers only. No payload text: each scene is matched by a "
                    "SHA-256 fingerprint of its payload.",
        }
        save_recording(Path(args.save_recording), meta, recorded)
        console.print(f"Saved {len(recorded)} recorded answers to {args.save_recording}")
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=f"{NAME} gate demo")
    parser.add_argument("--mode", choices=MODES, default="replay")
    parser.add_argument("--scene", choices=sorted(SCENES_BY_ID), help="run one scene only")
    parser.add_argument("--record", metavar="DIR", help="save one SVG per scene, plus summary and pipeline")
    parser.add_argument("--no-color", action="store_true", help="plain output for simple terminals")
    parser.add_argument("--recording", metavar="FILE", help="replay mode: recording to use")
    parser.add_argument("--save-recording", metavar="FILE", help="live mode: save the answers for replay")
    parser.add_argument("--text", metavar="TEXT",
                        help="check your own text with the local stages only (never calls the API)")
    parser.add_argument("--policy", metavar="NAME=VALUE", action="append", default=[],
                        help="change one enforcement-policy setting (repeatable), e.g. "
                             "pii_threshold=0.5, max_leak_risk=none, mode=observe, "
                             "block_categories=credentials,health_records")
    args = parser.parse_args(argv)
    if args.save_recording and args.mode != "live":
        parser.error("--save-recording only works with --mode live")
    if args.save_recording and args.policy:
        parser.error("--save-recording records with the default policy; drop --policy")
    if args.recording and args.mode != "replay":
        parser.error("--recording only works with --mode replay")
    if args.text is not None and (args.mode == "live" or args.scene or args.record
                                  or args.recording or args.policy):
        parser.error("--text runs on its own: it can't be combined with --mode live, "
                     "--scene, --record, --recording or --policy")
    try:
        args.policy_obj = parse_policy(args.policy)
    except ValueError as exc:
        parser.error(str(exc))
    args.out = None
    return args


def main(argv=None, out=None) -> int:
    # Windows consoles and pipes often default to a legacy code page that
    # can't print the arrows and dashes used here.
    if out is None and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    args = parse_args(argv)
    args.out = out
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())

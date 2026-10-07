"""
Offline tests for the gate demo (demo/run_demo.py).  No key, no network.

The demo is not part of the installed package; these tests import it from
the demo/ folder.  They need the demo extra (rich) and are skipped without it.
"""

from __future__ import annotations

import asyncio
import html
import io
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("rich")

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"
sys.path.insert(0, str(DEMO_DIR))

import replay_classifier  # noqa: E402
import run_demo  # noqa: E402
from scenes import SCENES, SCENES_BY_ID  # noqa: E402

PREFILTER_SCENES = {"private_key_paste", "aws_key_in_config", "db_url_with_password",
                    "support_ticket_card", "customer_row_ssn"}
LOCAL_SCENES = PREFILTER_SCENES | {"image_bytes", "jev_outage"}
JEV_SCENES = {s.id for s in SCENES} - LOCAL_SCENES


class _NoNetwork(Exception):
    pass


@pytest.fixture
def offline(monkeypatch):
    """
    An event loop created first (on Windows it needs a local socket pair),
    then every way of opening a socket or resolving a name raises.
    """
    loop = asyncio.new_event_loop()

    def refuse(*args, **kwargs):
        raise _NoNetwork("network disabled in this test")

    class NoSocket(socket.socket):
        def __init__(self, *args, **kwargs):
            refuse()

    monkeypatch.setattr(socket, "socket", NoSocket)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "socketpair", refuse)
    with pytest.raises(_NoNetwork):
        socket.create_connection(("example.com", 443))
    yield loop
    loop.close()


def _args(*argv: str):
    args = run_demo.parse_args(list(argv))
    args.out = io.StringIO()
    return args


def run_main(loop, *argv: str) -> tuple[int, str]:
    args = _args(*argv)
    code = loop.run_until_complete(run_demo.run(args))
    return code, args.out.getvalue()


def outcomes(loop, mode: str, recording: dict | None) -> dict:
    out = {}
    for scene in SCENES:
        payload, clf, result, ms = loop.run_until_complete(
            run_demo.run_scene(scene, mode, recording, None))
        out[scene.id] = run_demo.outcome_for(scene, result, clf, mode, ms)
    return out


def default_recording() -> dict:
    return replay_classifier.load_recording(replay_classifier.default_recording())


# --- Replay ----------------------------------------------------------------------------

def test_replay_runs_every_scene_with_network_disabled(offline):
    code, text = run_main(offline)
    assert code == 0
    assert "Scene 15/15" in text
    assert "demo summary" in text


def test_replay_decisions(offline):
    got = outcomes(offline, "replay", default_recording())
    for sid in PREFILTER_SCENES:
        assert (got[sid].decision, got[sid].decided_by, got[sid].left_machine) == ("BLOCKED", "pre-filter", "No")
    assert (got["image_bytes"].decided_by, got["image_bytes"].left_machine) == ("modality", "No")
    assert (got["jev_outage"].decided_by, got["jev_outage"].left_machine) == ("fail-secure", "No")
    # Every scene that reaches the classifier has a usable recording.
    for sid in JEV_SCENES:
        assert got[sid].left_machine.startswith("Yes"), sid
        assert got[sid].latency.endswith("(recorded)"), sid
        assert got[sid].signals is not None, sid


def test_missing_recording_blocks_fail_secure(offline):
    got = outcomes(offline, "replay", {"scenes": {}})
    for sid in JEV_SCENES:
        o = got[sid]
        assert (o.decision, o.decided_by, o.left_machine) == ("BLOCKED", "fail-secure", "No"), sid
        assert o.codes == ("classifier error: RecordingMissing",)
        assert any("No usable recording" in n for n in o.notes)


def test_stale_recording_blocks_fail_secure(offline):
    rec = json.loads(json.dumps(default_recording()))
    entry = rec["scenes"]["plain_question"]
    entry["payload_sha256"] = "0" * 64
    o = outcomes(offline, "replay", rec)["plain_question"]
    assert o.decided_by == "fail-secure"


def test_missing_recording_file_shows_fail_secure(offline, tmp_path):
    code, text = run_main(offline, "--recording", str(tmp_path / "nope.json"))
    assert code == 0
    assert "(not found)" in text
    assert "fail-secure" in text


def test_synthetic_banner_only_on_synthetic_data(offline, tmp_path):
    rec = default_recording()
    for source, shown in (("synthetic", True), ("live", False)):
        path = tmp_path / f"{source}.json"
        replay_classifier.save_recording(path, {"source": source}, rec["scenes"])
        _, text = run_main(offline, "--recording", str(path), "--scene", "plain_question")
        assert ("SYNTHETIC DATA" in text) is shown


def test_one_scene(offline):
    code, text = run_main(offline, "--scene", "patient_note")
    assert code == 0
    assert "Patient note" in text
    assert "Scene 1/15" not in text


# --- prefilter-only ------------------------------------------------------------------------

def test_prefilter_only_mode_makes_no_network_calls(offline):
    code, text = run_main(offline, "--mode", "prefilter-only")
    assert code == 0
    got = outcomes(offline, "prefilter-only", None)
    for sid in JEV_SCENES:
        assert got[sid].decision == "SKIPPED", sid
        assert got[sid].left_machine == "No (skipped in this mode)"
    for sid in PREFILTER_SCENES:
        assert got[sid].decided_by == "pre-filter"
    assert got["jev_outage"].decided_by == "fail-secure"
    assert "would be sent to Jev (skipped in this mode)" in text


# --- live mode guard -------------------------------------------------------------------------

def test_live_mode_points_to_commercial_edition(offline):
    code, text = run_main(offline, "--mode", "live")
    assert code == 2
    assert "Live mode is available in the commercial edition" in text


def test_save_recording_needs_live_mode():
    with pytest.raises(SystemExit):
        run_demo.parse_args(["--save-recording", "x.json"])


# --- --text: your own text, local checks only ----------------------------------------------

def test_text_with_a_card_number_is_caught_locally(offline):
    from scenes import fake_card
    card = fake_card()
    code, text = run_main(offline, "--text", f"Please refund the card {card}, thanks")
    assert code == 0
    assert "[REDACTED:card_number]" in text
    assert "payment_card" in text
    assert "BLOCKED" in text
    for form in (card, card.replace(" ", "")):
        assert form not in text


def test_text_that_nothing_catches_would_be_sent_to_jev(offline):
    code, text = run_main(offline, "--text", "What is the capital of France?")
    assert code == 0
    assert "would be sent to Jev" in text
    assert "never calls the API" in text
    assert "What is the capital of France?" in text


def test_empty_text_is_blocked_by_modality(offline):
    _, text = run_main(offline, "--text", "   ")
    assert "empty or whitespace-only payload" in text


def test_text_never_reaches_a_real_classifier(offline):
    # --text never hands the payload to a classifier (the network is off here).
    code, text = run_main(offline, "--text", "hello")
    assert code == 0
    assert "Left this machine?  No" in text


@pytest.mark.parametrize("extra", [["--mode", "live"], ["--scene", "plain_question"],
                                   ["--record", "x"], ["--policy", "mode=observe"]])
def test_text_runs_on_its_own(extra):
    with pytest.raises(SystemExit):
        run_demo.parse_args(["--text", "hi", *extra])


# --- --policy: change a setting, see the decisions change -----------------------------------

def test_lowering_a_threshold_turns_a_pass_into_a_block(offline):
    scene = SCENES_BY_ID["plain_question"]
    rec = default_recording()

    def outcome(policy=None):
        _, clf, result, ms = offline.run_until_complete(
            run_demo.run_scene(scene, "replay", rec, None, policy))
        return run_demo.outcome_for(scene, result, clf, "replay", ms)

    default = outcome()
    strict = outcome(run_demo.parse_policy(["pii_threshold=0.05"]))
    assert default.decision == "PASS"
    assert (strict.decision, strict.decided_by, strict.codes) == ("BLOCKED", "policy", ("pii>=0.05",))


def test_observe_mode_shows_what_would_have_blocked(offline):
    code, text = run_main(offline, "--scene", "patient_note", "--policy", "mode=observe")
    assert code == 0
    assert "observe mode: the policy would block" in text
    assert "custom policy: mode=observe" in text


def test_parse_policy_values():
    p = run_demo.parse_policy(["max_leak_risk=none", "block_categories=credentials,health_records",
                               "confirm_categories=", "block_on_missing_signal=false"])
    assert p.max_leak_risk is None
    assert {c.value for c in p.block_categories} == {"credentials", "health_records"}
    assert p.confirm_categories == frozenset()
    assert p.block_on_missing_signal is False
    assert run_demo.parse_policy([]) is None


@pytest.mark.parametrize("bad", ["pii_threshold=2", "pii_threshold=abc", "colour=red",
                                 "block_categories=no_such_label", "mode=loud", "extra_rules=x"])
def test_bad_policy_settings_are_rejected(bad):
    with pytest.raises(SystemExit):
        run_demo.parse_args(["--policy", bad])


# --- Screenshots -----------------------------------------------------------------------------

def _svg_text(path: Path) -> str:
    return html.unescape(path.read_text(encoding="utf-8")).replace("\xa0", " ")


@pytest.fixture
def recorded(offline, tmp_path):
    out = tmp_path / "svg"
    code, _ = run_main(offline, "--record", str(out))
    assert code == 0
    return out


def test_record_writes_one_svg_per_scene_plus_cards(recorded):
    names = {p.name for p in recorded.glob("*.svg")}
    expected = {f"{i:02d}_{s.id}.svg" for i, s in enumerate(SCENES, 1)} | {"pipeline.svg", "summary.svg"}
    assert names == expected


def test_prefilter_scene_svgs_show_redaction(recorded):
    for i, s in enumerate(SCENES, 1):
        if s.id in PREFILTER_SCENES:
            assert "[REDACTED:" in _svg_text(recorded / f"{i:02d}_{s.id}.svg"), s.id


def test_no_svg_contains_a_runtime_built_secret(recorded):
    svgs = {p.name: _svg_text(p) for p in recorded.glob("*.svg")}
    for scene in SCENES:
        for secret in scene.secrets():
            for line in secret.splitlines():
                if len(line) >= 8:
                    for name, text in svgs.items():
                        assert line not in text, (scene.id, name)


def test_masking_removes_every_runtime_secret_from_the_whole_payload(monkeypatch):
    # Without the preview window, so a secret can't hide just past the cut.
    import render
    monkeypatch.setattr(render, "PREVIEW_CHARS", 10**6)
    for scene in SCENES:
        payload = scene.build()
        if not isinstance(payload, str):
            continue
        masked = run_demo.masked_preview(payload)
        for secret in scene.secrets():
            for line in secret.splitlines():
                if len(line) >= 8:
                    assert line not in masked, scene.id
        if scene.id in PREFILTER_SCENES:
            assert "[REDACTED:" in masked


# --- Recording format ---------------------------------------------------------------------------

def test_recording_holds_no_payload_text():
    raw = replay_classifier.default_recording().read_text(encoding="utf-8")
    for scene in SCENES:
        payload = scene.build()
        if isinstance(payload, str):
            for line in payload.splitlines():
                if len(line.strip()) >= 12:
                    assert line.strip() not in raw, scene.id


def test_recording_round_trip(offline):
    rec = default_recording()
    for sid, entry in rec["scenes"].items():
        result = replay_classifier.result_from_json(entry["result"])
        assert replay_classifier.result_to_json(result) == entry["result"], sid
        assert sid in SCENES_BY_ID


# --- The library doesn't need rich ------------------------------------------------------------------

def test_library_imports_without_rich():
    code = (
        "import sys; sys.modules['rich'] = None; "
        "import sievegate.sieve, sievegate.prefilter, sievegate.policy, sievegate.mock_classifier; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "ok"

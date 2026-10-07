"""
Terminal rendering for the demo (rich).  Everything dynamic is passed as
rich Text, never as markup, so payload text can't be read as markup tags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from branding import NAME, TAGLINE

SYNTHETIC_BANNER = "SYNTHETIC DATA — not real Jev output."
PREVIEW_CHARS = 100

BADGE_STYLE = {
    "BLOCKED": "bold white on red",
    "PASS": "bold white on green",
    "PASS + RECONFIRM": "bold black on yellow",
    "SKIPPED": "bold white on blue",
}


@dataclass
class Outcome:
    """What happened to one scene, in display terms."""
    scene_id: str
    title: str
    decision: str                 # BLOCKED / PASS / PASS + RECONFIRM / SKIPPED
    decided_by: str               # modality / pre-filter / policy / fail-secure / none (passed) / -
    codes: tuple[str, ...]
    tier: str
    latency: str
    left_machine: str
    signals: Optional[dict] = None
    notes: list[str] = field(default_factory=list)


def flatten(text: str) -> str:
    """Text on one line, with ⏎ for line breaks."""
    return " ⏎ ".join(line.strip() for line in text.strip().splitlines() if line.strip())


def text_check(console: Console, masked: str, verdict: tuple[str, str], findings, elapsed_ms: float) -> None:
    """--text: the user's own text after the local checks."""
    decision, detail = verdict
    style = BADGE_STYLE["BLOCKED"] if decision == "BLOCKED" else BADGE_STYLE["SKIPPED"]
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column()
    shown = masked if len(masked) <= 600 else masked[:600] + " …"
    grid.add_row(Text("Your text"), Text(shown or "(empty)", style="italic"))
    grid.add_row(Text("Result"), Text(f" {decision} ", style=style))
    grid.add_row(Text("Why"), Text(detail))
    if findings:
        lines = "\n".join(f"{f.detector} → {f.kind} (characters {f.start}–{f.end})" for f in findings)
        grid.add_row(Text("Detectors fired"), Text(lines))
    grid.add_row(Text("Time"), Text(f"{elapsed_ms:.2f} ms (local)"))
    grid.add_row(Text("Left this machine?"), Text("No"))
    console.print(Panel(Group(Text(f"{NAME} · check your own text (local only)", style="bold cyan"),
                              Text(""), grid), box=box.ROUNDED))


def preview(masked: str) -> str:
    """
    About 100 characters of the masked payload, on one line.  Normally the
    start of the payload; if the first [REDACTED:...] marker would fall
    outside that, the window starts a little before it instead, so the
    viewer sees what the pre-filter caught.  A marker is never cut in half.
    """
    flat = flatten(masked)
    start = 0
    first = flat.find("[REDACTED:")
    if first >= 0 and flat.index("]", first) + 1 > PREVIEW_CHARS:
        start = max(0, first - 40)
        start = flat.rfind(" ", 0, start) + 1 if " " in flat[:start] else start  # whole words
    end = min(len(flat), start + PREVIEW_CHARS)
    straddle = flat.rfind("[REDACTED:", start, end)
    if straddle >= 0:
        end = max(end, flat.index("]", straddle) + 1)
    text = flat[start:end].strip()
    return ("… " if start > 0 else "") + text + (" …" if end < len(flat) else "")


def banner(console: Console, mode: str, synthetic: bool, recording_note: str) -> None:
    title = Text(NAME, style="bold cyan")
    body = Text(TAGLINE + "\n\n")
    body.append("Mode: ", style="bold")
    body.append(mode)
    if recording_note:
        body.append("   " + recording_note, style="dim")
    console.print(Panel(Group(title, body), box=box.ROUNDED))
    if synthetic:
        synthetic_warning(console)


def synthetic_warning(console: Console) -> None:
    console.print(Text(f" {SYNTHETIC_BANNER} ", style="bold black on yellow"), justify="center")


def pipeline(console: Console) -> None:
    """Title card: the order of the gate's stages."""
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Stage")
    table.add_column("Where it runs")
    table.add_column("If it says no")
    rows = [
        ("1", "Modality check: is it text, and not empty?", "this machine", "BLOCKED — never sent"),
        ("2", "Local pre-filter: known secret formats, cards, SSNs, IBANs",
         "this machine, no network", "BLOCKED — never sent"),
        ("3", "Jev classifier (TypeSafe): one call, six questions", "TypeSafe API",
         "no answer in time → BLOCKED (fail-secure)"),
        ("4", "Enforcement policy: thresholds and categories", "this machine", "BLOCKED"),
    ]
    for row in rows:
        table.add_row(*(Text(c) for c in row))
    outcomes = Text("Otherwise: ", style="bold")
    outcomes.append("PASS", style=BADGE_STYLE["PASS"])
    outcomes.append(" with a recommended model tier, or ")
    outcomes.append("PASS + RECONFIRM", style=BADGE_STYLE["PASS + RECONFIRM"])
    outcomes.append(" when a person should confirm first.")
    console.print(Panel(Group(Text(f"How {NAME} decides", style="bold cyan"), table, outcomes),
                        box=box.ROUNDED))


def scene(console: Console, number: int, total: int, title: str, story: str,
          masked_preview: str, outcome: Outcome, synthetic: bool) -> None:
    if synthetic:
        synthetic_warning(console)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column()
    grid.add_row(Text("Story"), Text(story))
    grid.add_row(Text("Payload"), Text(masked_preview, style="italic"))
    badge = Text(f" {outcome.decision} ", style=BADGE_STYLE.get(outcome.decision, "bold"))
    grid.add_row(Text("Decision"), badge)
    grid.add_row(Text("Decided by"), Text(outcome.decided_by))
    grid.add_row(Text("Reason codes"), Text("; ".join(outcome.codes) if outcome.codes else "—"))
    if outcome.signals:
        grid.add_row(Text("Jev signals"), Text(_signals(outcome.signals)))
    grid.add_row(Text("Routing tier"), Text(outcome.tier))
    grid.add_row(Text("Latency"), Text(outcome.latency))
    grid.add_row(Text("Left this machine?"), Text(outcome.left_machine))
    for note in outcome.notes:
        grid.add_row(Text("Note"), Text(note, style="dim"))
    header = Text(f"Scene {number}/{total} · {title}", style="bold cyan")
    console.print(Panel(Group(header, Text(""), grid), box=box.ROUNDED))


def _signals(s: dict) -> str:
    parts = []
    for name, key in (("PII", "pii"), ("secret", "secret"), ("financial", "financial")):
        if s.get(key) is not None:
            parts.append(f"{name} {s[key]:.2f}")
    if s.get("leak") is not None:
        conf = f" (conf {s['leak_conf']:.2f})" if s.get("leak_conf") is not None else ""
        parts.append(f"leak {s['leak']:.2f}{conf}")
    if s.get("category"):
        conf = f" ({s['category_conf']:.2f})" if s.get("category_conf") is not None else ""
        parts.append(f"category {s['category']}{conf}")
    return " · ".join(parts)


def summary(console: Console, outcomes: list[Outcome], mode: str, synthetic: bool) -> None:
    if synthetic:
        synthetic_warning(console)
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    for col, kw in (("#", {"justify": "right"}), ("Scene", {}), ("Decision", {}),
                    ("Decided by", {}), ("Tier", {}), ("Latency", {"justify": "right"}),
                    ("Left machine", {})):
        table.add_column(col, **kw)
    for i, o in enumerate(outcomes, 1):
        table.add_row(Text(str(i)), Text(o.title),
                      Text(o.decision, style=BADGE_STYLE.get(o.decision, "")),
                      Text(o.decided_by), Text(o.tier), Text(o.latency), Text(o.left_machine.split(" ")[0]))
    stopped = sum(o.decision == "BLOCKED" and o.left_machine.startswith("No") for o in outcomes)
    policy = sum(o.decided_by == "policy" for o in outcomes)
    passed = sum(o.decision == "PASS" for o in outcomes)
    reconfirm = sum(o.decision == "PASS + RECONFIRM" for o in outcomes)
    skipped = sum(o.decision == "SKIPPED" for o in outcomes)
    counts = Text()
    counts.append(f"{stopped} stopped locally (never sent)", style="bold")
    counts.append(f"  ·  {policy} blocked by policy  ·  {passed} passed  ·  "
                  f"{reconfirm} passed with a request to reconfirm")
    if skipped:
        counts.append(f"  ·  {skipped} would be sent to Jev (skipped in this mode)")
    console.print(Panel(Group(Text(f"{NAME} demo summary · mode: {mode}", style="bold cyan"),
                              table, counts), box=box.ROUNDED))

"""Baselines (accept what is there today, fail only on new findings) and allowlists.

Baseline file (JSON, written by ``skill-scan-gate baseline``)::

    {"tool": "skill-scan-gate", "baselineVersion": 1,
     "findings": [{"rule": "SSG101", "file": "skills/x/SKILL.md", "line": 4,
                   "fingerprint": "..."}]}

A finding is suppressed when its fingerprint is in the baseline. Fingerprints hash the
rule, the file and the line's text, not its number, so edits elsewhere in a file do not
turn known findings into new ones.

Allowlist file (text, one entry per line, ``#`` starts a comment)::

    SSG204  skills/notify/SKILL.md          # posts build status to our own chat webhook
    SSG302  hooks/install.sh:12             # writes the completion file, reviewed 2026-10
    *       vendor/**                       # third-party copy, scanned upstream

The first field is a rule id or ``*``; the second is a path glob relative to the scanned
directory, optionally with ``:LINE``. Entries that match nothing are reported as warnings.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .rules import RULES
from .scanner import Finding

BASELINE_VERSION = 1


class SuppressionError(ValueError):
    """A baseline or allowlist file that cannot be used."""


# ---------------------------------------------------------------- baseline


def baseline_document(findings: list[Finding]) -> dict[str, Any]:
    return {
        "tool": "skill-scan-gate",
        "toolVersion": __version__,
        "baselineVersion": BASELINE_VERSION,
        "findings": [
            {"rule": f.rule, "file": f.file, "line": f.line, "fingerprint": f.fingerprint}
            for f in sorted(findings, key=lambda f: (f.file, f.line, f.rule))
        ],
    }


def write_baseline(path: Path, findings: list[Finding]) -> None:
    path.write_text(json.dumps(baseline_document(findings), indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> Counter[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise SuppressionError(f"baseline not found: {path}") from e
    except (OSError, json.JSONDecodeError) as e:
        raise SuppressionError(f"baseline {path} is not readable JSON: {e}") from e
    if not isinstance(data, dict) or data.get("tool") != "skill-scan-gate":
        raise SuppressionError(f"baseline {path} was not written by skill-scan-gate")
    if data.get("baselineVersion") != BASELINE_VERSION:
        raise SuppressionError(
            f"baseline {path} has baselineVersion {data.get('baselineVersion')!r}; expected {BASELINE_VERSION}"
        )
    entries = data.get("findings")
    if not isinstance(entries, list):
        raise SuppressionError(f"baseline {path} has no findings list")
    return Counter(e["fingerprint"] for e in entries if isinstance(e, dict) and isinstance(e.get("fingerprint"), str))


def apply_baseline(findings: list[Finding], known: Counter[str]) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (new, suppressed). Each baseline entry suppresses one finding."""
    remaining = Counter(known)
    new: list[Finding] = []
    old: list[Finding] = []
    for f in findings:
        if remaining[f.fingerprint] > 0:
            remaining[f.fingerprint] -= 1
            old.append(f)
        else:
            new.append(f)
    return new, old


# ---------------------------------------------------------------- allowlist

_ENTRY = re.compile(r"^(?P<rule>\*|SSG\d{3})\s+(?P<path>\S+?)(?::(?P<line>\d+))?\s*(?:#\s*(?P<reason>.*))?$")


@dataclass
class AllowEntry:
    rule: str
    path: str
    line: int | None
    reason: str
    source_line: int
    used: int = 0

    def matches(self, f: Finding) -> bool:
        if self.rule != "*" and self.rule != f.rule:
            return False
        if self.line is not None and self.line != f.line:
            return False
        return fnmatch.fnmatchcase(f.file, self.path)

    def describe(self) -> str:
        loc = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"{self.rule} {loc}"


def load_allowlist(path: Path) -> list[AllowEntry]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise SuppressionError(f"allowlist not found: {path}") from e
    except OSError as e:
        raise SuppressionError(f"allowlist {path} is not readable: {e}") from e
    entries: list[AllowEntry] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENTRY.match(line)
        if not m:
            raise SuppressionError(f"{path}:{n}: expected '<rule id or *> <path glob>[:line] [# reason]'")
        rule = m.group("rule")
        if rule != "*" and rule not in RULES:
            raise SuppressionError(f"{path}:{n}: unknown rule id {rule}")
        entries.append(
            AllowEntry(
                rule,
                m.group("path"),
                int(m.group("line")) if m.group("line") else None,
                (m.group("reason") or "").strip(),
                n,
            )
        )
    return entries


def apply_allowlist(findings: list[Finding], entries: list[AllowEntry]) -> tuple[list[Finding], list[Finding]]:
    kept: list[Finding] = []
    allowed: list[Finding] = []
    for f in findings:
        hit = next((e for e in entries if e.matches(f)), None)
        if hit:
            hit.used += 1
            allowed.append(f)
        else:
            kept.append(f)
    return kept, allowed


def unused_entries(entries: list[AllowEntry]) -> list[AllowEntry]:
    return [e for e in entries if e.used == 0]

"""Shared helpers. Tests build their repositories under tmp_path; nothing else is touched."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
PLANTED = FIXTURES / "fixture-planted"
CLEAN = FIXTURES / "fixture-clean"

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from skill_scan_gate.scanner import scan  # noqa: E402

GOOD_SKILL = "---\nname: tidy\ndescription: Tidy notes when the user asks.\n---\n\n"


def write_tree(root: Path, files: dict[str, str | dict]) -> Path:
    """Write files (dicts become JSON) plus LICENSE and SECURITY.md so repo rules stay quiet."""
    root.mkdir(parents=True, exist_ok=True)
    base = {"LICENSE": "MIT License\n", "SECURITY.md": "# Security\n"}
    for rel, content in {**base, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(content, indent=2) + "\n" if isinstance(content, dict) else content
        p.write_text(text, encoding="utf-8")
    return root


def rule_ids(root: Path, **kw) -> list[str]:
    return [f.rule for f in scan(root, **kw).findings]


@pytest.fixture
def tree(tmp_path):
    def _make(files: dict[str, str | dict]) -> Path:
        return write_tree(tmp_path / "repo", files)

    return _make


@pytest.fixture
def skill_rules(tree):
    """Rule ids found in a single SKILL.md body (front matter supplied)."""

    def _run(body: str) -> list[str]:
        return rule_ids(tree({"skills/s/SKILL.md": GOOD_SKILL + body + "\n"}))

    return _run


@pytest.fixture
def hook_rules(tree):
    """Rule ids found for one hook command in hooks/hooks.json."""

    def _run(command: str) -> list[str]:
        hooks = {"hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}}
        return rule_ids(tree({"hooks/hooks.json": hooks}))

    return _run


@pytest.fixture
def script_rules(tree):
    def _run(body: str, name: str = "scripts/run.sh") -> list[str]:
        return rule_ids(tree({name: "#!/bin/sh\n" + body + "\n"}))

    return _run


@pytest.fixture
def mcp_rules(tree):
    def _run(server: dict) -> list[str]:
        return rule_ids(tree({".mcp.json": {"mcpServers": {"s": server}}}))

    return _run

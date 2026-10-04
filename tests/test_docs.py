"""Docs stay in step with the rule catalogue and the house style."""

import re

import pytest

from skill_scan_gate.rules import RULES

from conftest import ROOT

RULES_MD = (ROOT / "docs" / "rules.md").read_text()
README = (ROOT / "README.md").read_text()
EM_DASH = chr(0x2014)
TEXT_FILES = [
    p
    for p in ROOT.rglob("*")
    if p.is_file()
    and ".venv" not in p.parts
    and ".git" not in p.parts
    and "__pycache__" not in p.parts
    and ".pytest_cache" not in p.parts
    and ".ruff_cache" not in p.parts
    and p.suffix in (".md", ".py", ".yml", ".toml", ".json", ".sh", "")
]


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_documented_with_severity(rule_id):
    m = re.search(rf"^### {rule_id}\b[^\n]*\n(.*?)(?=^### |\Z)", RULES_MD, re.M | re.S)
    assert m, rule_id
    assert f"Severity: {RULES[rule_id].severity}" in m.group(1)


def test_readme_rules_table_lists_every_rule():
    for rule_id in RULES:
        assert f"| {rule_id} |" in README, rule_id


def test_readme_heading_and_links():
    assert README.startswith("# skill-scan-gate: CI gate for Claude Code skills and plugins")
    for link in (
        "https://github.com/basitalisandhu/cc-plugin-lock",
        "https://github.com/basitalisandhu/agent-config-audit",
        "https://github.com/basitalisandhu/security-actions",
        "https://github.com/basitalisandhu/agent-security-skills",
        "https://github.com/basitalisandhu",
    ):
        assert link in README


def test_no_em_dashes_anywhere():
    bad = [str(p.relative_to(ROOT)) for p in TEXT_FILES if EM_DASH in p.read_text(errors="ignore")]
    assert bad == []


def test_changelog_has_dated_release():
    assert "## [0.1.0] - 2026-10-05" in (ROOT / "CHANGELOG.md").read_text()

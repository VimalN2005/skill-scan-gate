"""Which files the scanner reads."""

from pathlib import PurePosixPath

import pytest

from skill_scan_gate.discover import classify, excluded, walk


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("skills/a/SKILL.md", "skill"),
        ("plugins/p/skills/a/SKILL.md", "skill"),
        ("CLAUDE.md", "instructions"),
        ("AGENTS.md", "instructions"),
        (".cursor/rules/style.mdc", "instructions"),
        ("commands/run.md", "instructions"),
        ("agents/helper.md", "instructions"),
        ("hooks/hooks.json", "hooks-config"),
        (".claude-plugin/plugin.json", "manifest"),
        (".claude-plugin/marketplace.json", "manifest"),
        (".mcp.json", "mcp"),
        (".claude/settings.json", "settings"),
        ("scripts/run.sh", "script"),
        ("hooks/guard.py", "script"),
        ("README.md", None),
        ("docs/guide.md", None),
        ("src/app.py", None),
        ("hooks/README.md", None),
    ],
)
def test_classify(path, kind):
    assert classify(PurePosixPath(path)) == kind


def test_walk_skips_vendored_dirs_and_symlinks(tmp_path):
    (tmp_path / "node_modules" / "x" / "skills" / "s").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "skills" / "s" / "SKILL.md").write_text("x")
    (tmp_path / "skills" / "s").mkdir(parents=True)
    (tmp_path / "skills" / "s" / "SKILL.md").write_text("x")
    (tmp_path / "CLAUDE.md").symlink_to(tmp_path / "skills" / "s" / "SKILL.md")
    assert walk(tmp_path) == [("skills/s/SKILL.md", "skill")]


def test_excluded_matches_directories_and_files():
    assert excluded("tests/fixtures/a/SKILL.md", ["tests/fixtures/**"])
    assert excluded("vendor/x/SKILL.md", ["vendor"])
    assert not excluded("skills/a/SKILL.md", ["tests/**"])

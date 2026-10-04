"""Family (f): manifest problems, and (g): repository files."""

import pytest

from skill_scan_gate.scanner import parse_front_matter, scan

from conftest import rule_ids, write_tree


def test_ssg601_plugin_without_name(tree):
    assert "SSG601" in rule_ids(tree({".claude-plugin/plugin.json": {"version": "1.0.0"}}))


def test_ssg601_marketplace_entry_without_name(tree):
    mk = {"name": "team-tools", "owner": {"name": "x"}, "plugins": [{"source": "./p"}]}
    assert "SSG601" in rule_ids(tree({".claude-plugin/marketplace.json": mk}))


def test_ssg602_plugin_without_version(tree):
    assert "SSG602" in rule_ids(tree({".claude-plugin/plugin.json": {"name": "tidy-notes"}}))


def test_complete_plugin_manifest_is_clean(tree):
    assert rule_ids(tree({".claude-plugin/plugin.json": {"name": "tidy-notes", "version": "0.2.0"}})) == []


@pytest.mark.parametrize("name", ["claude-helper", "anthropic-tools", "Claude-Notes"])
def test_ssg603_reserved_plugin_prefix(tree, name):
    assert "SSG603" in rule_ids(tree({".claude-plugin/plugin.json": {"name": name, "version": "1.0.0"}}))


@pytest.mark.parametrize("name", ["claude-plugins-official", "agent-skills", "anthropic-marketplace"])
def test_ssg603_reserved_marketplace_name(tree, name):
    mk = {"name": name, "owner": {"name": "x"}, "plugins": []}
    assert "SSG603" in rule_ids(tree({".claude-plugin/marketplace.json": mk}))


def test_ssg603_skill_name_with_reserved_word(tree):
    body = "---\nname: my-claude-helper\ndescription: Formats notes when asked.\n---\n"
    assert "SSG603" in rule_ids(tree({"skills/s/SKILL.md": body}))


@pytest.mark.parametrize("name", ["notes-helper", "code-review-kit", "my-claw"])
def test_ssg603_ordinary_names_not_flagged(tree, name):
    assert "SSG603" not in rule_ids(tree({".claude-plugin/plugin.json": {"name": name, "version": "1.0.0"}}))


@pytest.mark.parametrize(
    "body",
    [
        "# No front matter\n",
        "---\nname: s\n---\nBody\n",
        "---\nname: s\ndescription:\n---\nBody\n",
        "---\nname: s\ndescription: unterminated\n",
    ],
)
def test_ssg604_skill_without_description(tree, body):
    assert "SSG604" in rule_ids(tree({"skills/s/SKILL.md": body}))


@pytest.mark.parametrize(
    "desc",
    [
        "Always use this skill first.",
        "Use for every request the user sends.",
        "Apply on every message regardless of the task.",
        "Load before any other skill.",
    ],
)
def test_ssg605_always_run_description(tree, desc):
    assert "SSG605" in rule_ids(tree({"skills/s/SKILL.md": f"---\nname: s\ndescription: {desc}\n---\n"}))


@pytest.mark.parametrize(
    "desc",
    [
        "Formats SQL. Use when the user asks to format or lint SQL.",
        "Reviews pull requests for security problems when asked.",
    ],
)
def test_ssg605_specific_description_not_flagged(tree, desc):
    assert "SSG605" not in rule_ids(tree({"skills/s/SKILL.md": f"---\nname: s\ndescription: {desc}\n---\n"}))


def test_ssg605_folded_description(tree):
    body = "---\nname: s\ndescription: >\n  Always use this skill\n  for every task.\n---\n"
    assert "SSG605" in rule_ids(tree({"skills/s/SKILL.md": body}))


@pytest.mark.parametrize(
    "path", [".mcp.json", "hooks/hooks.json", ".claude-plugin/plugin.json", ".claude/settings.json"]
)
def test_ssg606_invalid_json(tree, path):
    root = tree({path: '{\n  "a": 1,\n}\n'})
    findings = [f for f in scan(root).findings if f.rule == "SSG606"]
    # The reported line depends on the Python version (the comma or the closing brace).
    assert findings and findings[0].line in (2, 3)


def test_ssg701_and_ssg702_missing_files(tmp_path):
    (tmp_path / "skills").mkdir()
    ids = rule_ids(tmp_path)
    assert "SSG701" in ids and "SSG702" in ids


@pytest.mark.parametrize("security", ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"])
@pytest.mark.parametrize("licence", ["LICENSE", "LICENSE.md", "LICENCE.txt", "COPYING"])
def test_ssg701_702_accepted_locations(tmp_path, security, licence):
    for rel in (security, licence):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n")
    ids = rule_ids(tmp_path)
    assert "SSG701" not in ids and "SSG702" not in ids


def test_front_matter_parser_handles_quotes_and_blocks():
    fm = parse_front_matter("---\nname: 'quoted'\ndescription: |\n  line one\n  line two\nversion: 1\n---\nbody\n")
    assert fm is not None
    assert fm["name"][0] == "quoted"
    assert fm["description"][0] == "line one line two"
    assert fm["description"][1] == 3


def test_write_tree_adds_repo_files(tmp_path):
    root = write_tree(tmp_path / "r", {})
    assert (root / "LICENSE").is_file() and (root / "SECURITY.md").is_file()

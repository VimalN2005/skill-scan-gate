"""The committed fixtures: the planted one triggers every committable rule, the clean one nothing."""

from collections import Counter

from skill_scan_gate.rules import RULES
from skill_scan_gate.scanner import scan

from conftest import CLEAN, PLANTED

# Rules the planted fixture must trigger. SSG405 and SSG501 to SSG503 need secret-shaped
# values, which are never committed; tests/make_secret_fixture.py covers them at run time.
PLANTED_EXPECTED = {
    "SSG101",
    "SSG102",
    "SSG103",
    "SSG104",
    "SSG201",
    "SSG202",
    "SSG203",
    "SSG204",
    "SSG301",
    "SSG302",
    "SSG303",
    "SSG304",
    "SSG305",
    "SSG306",
    "SSG401",
    "SSG402",
    "SSG403",
    "SSG404",
    "SSG406",
    "SSG601",
    "SSG602",
    "SSG603",
    "SSG604",
    "SSG605",
    "SSG606",
    "SSG701",
    "SSG702",
}
RUNTIME_ONLY = {"SSG405", "SSG501", "SSG502", "SSG503"}


def test_planted_fixture_triggers_expected_rules():
    found = {f.rule for f in scan(PLANTED).findings}
    assert found == PLANTED_EXPECTED


def test_every_rule_is_covered_by_planted_or_runtime_fixture():
    assert set(RULES) == PLANTED_EXPECTED | RUNTIME_ONLY


def test_planted_fixture_has_no_secret_findings():
    assert not RUNTIME_ONLY & {f.rule for f in scan(PLANTED).findings}


def test_clean_fixture_has_zero_findings():
    result = scan(CLEAN)
    assert result.findings == [], [f"{f.rule} {f.file}:{f.line}" for f in result.findings]
    assert result.errors == []


def test_clean_fixture_covers_every_file_kind():
    files = scan(CLEAN).files
    for expected in (
        ".claude-plugin/plugin.json",
        ".claude/settings.json",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.md",
        "agents/reviewer.md",
        "commands/summarise.md",
        "hooks/hooks.json",
        "scripts/format.sh",
        "skills/notes/SKILL.md",
    ):
        assert expected in files


def test_findings_are_sorted_and_unique():
    findings = scan(PLANTED).findings
    keys = [(f.file, f.line, f.rule) for f in findings]
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))


def test_fingerprints_unique_within_a_scan():
    counts = Counter(f.fingerprint for f in scan(PLANTED).findings)
    assert max(counts.values()) == 1


def test_scan_is_deterministic():
    a = [f.to_dict() for f in scan(PLANTED).findings]
    b = [f.to_dict() for f in scan(PLANTED).findings]
    assert a == b


def test_fixture_directories_follow_naming_rule():
    from conftest import FIXTURES

    names = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())
    assert names and all(n.startswith("fixture-") for n in names)
    bad = [p for p in FIXTURES.rglob("*") if p.name in (".env", "settings.local.json")]
    assert bad == []

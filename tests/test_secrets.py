"""Family (e): secret-shaped strings. Every value is assembled at run time (see make_secret_fixture.py)."""

import pytest

from skill_scan_gate.scanner import scan

from conftest import rule_ids
from make_secret_fixture import build, j, tokens

T = tokens()


@pytest.mark.parametrize("label", ["aws", "github", "slack", "google", "stripe", "npm", "generic"])
def test_ssg502_provider_token_shapes(script_rules, label):
    assert "SSG502" in script_rules(f"VALUE={T[label]}")


def test_ssg502_documented_example_key_not_flagged(script_rules):
    assert "SSG502" not in script_rules("KEY=" + j("AKIA", "IOSFODNN7", "EXAMPLE"))


def test_ssg502_short_prefix_not_flagged(script_rules):
    assert "SSG502" not in script_rules("echo ghp_ is the prefix GitHub uses")


def test_ssg501_private_key_block(script_rules):
    assert "SSG501" in script_rules(T["private_key_header"])


def test_ssg501_public_key_not_flagged(script_rules):
    assert "SSG501" not in script_rules(j("-----BEGIN ", "PUBLIC KEY-----"))


@pytest.mark.parametrize(
    "line",
    [
        f'db_password = "{T["password"]}"',
        f"api_key: '{T['password']}'",
        f'"clientSecret": "{T["password"]}"',
    ],
)
def test_ssg503_credential_assignment(script_rules, line):
    assert "SSG503" in script_rules(line)


@pytest.mark.parametrize(
    "line",
    [
        'password = "${DB_PASSWORD}"',
        'api_key = "<your key here>"',
        'token = "changeme"',
        'password = os.environ["DB_PASSWORD"]',
        'token_url = "short"',
    ],
)
def test_ssg503_references_not_flagged(script_rules, line):
    assert "SSG503" not in script_rules(line)


def test_secret_evidence_is_redacted(tmp_path):
    t = build(tmp_path / "fx")
    result = scan(tmp_path / "fx")
    text = "\n".join(f.evidence for f in result.findings)
    for label in ("aws", "github", "slack", "google", "stripe", "npm", "generic", "password"):
        assert t[label] not in text, label


def test_generated_fixture_findings(tmp_path):
    build(tmp_path / "fx")
    ids = rule_ids(tmp_path / "fx")
    assert {"SSG405", "SSG501", "SSG502", "SSG503"} <= set(ids)
    assert ids.count("SSG502") >= 6


def test_secret_in_mcp_env_reported_once(tmp_path):
    build(tmp_path / "fx")
    findings = [f for f in scan(tmp_path / "fx").findings if f.file == ".mcp.json"]
    lines = [f.line for f in findings]
    assert len(lines) == len(set(lines))
    assert all(f.rule == "SSG405" for f in findings)


def test_secrets_found_in_skill_text(tree):
    root = tree({"skills/s/SKILL.md": "---\nname: s\ndescription: d\n---\n" + T["github"] + "\n"})
    assert "SSG502" in rule_ids(root)

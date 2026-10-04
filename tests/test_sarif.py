"""SARIF 2.1.0 structure, as GitHub code scanning reads it."""

import json

from skill_scan_gate.cli import main
from skill_scan_gate.report import to_sarif
from skill_scan_gate.rules import RULES
from skill_scan_gate.scanner import scan

from conftest import CLEAN, PLANTED


def _doc(prefix=""):
    return to_sarif(scan(PLANTED), prefix)


def test_version_and_schema():
    doc = _doc()
    assert doc["version"] == "2.1.0"
    assert "sarif-2.1.0" in doc["$schema"]
    assert len(doc["runs"]) == 1


def test_driver_lists_every_rule_once():
    driver = _doc()["runs"][0]["tool"]["driver"]
    ids = [r["id"] for r in driver["rules"]]
    assert driver["name"] == "skill-scan-gate"
    assert sorted(ids) == sorted(RULES) and len(ids) == len(set(ids))


def test_rule_metadata_has_help_and_security_severity():
    for r in _doc()["runs"][0]["tool"]["driver"]["rules"]:
        assert r["shortDescription"]["text"] and r["help"]["text"]
        assert r["helpUri"].startswith("https://")
        assert 0 < float(r["properties"]["security-severity"]) < 10
        assert r["defaultConfiguration"]["level"] in ("error", "warning", "note")


def test_results_reference_known_rules_with_valid_index():
    run = _doc()["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["results"]
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        assert res["partialFingerprints"]["skillScanGate/v1"]


def test_locations_are_relative_with_positive_lines():
    for res in _doc()["runs"][0]["results"]:
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        assert not uri.startswith("/") and "://" not in uri and "\\" not in uri
        assert loc["region"]["startLine"] >= 1


def test_uri_prefix_applied():
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in _doc("tests/fixtures/fixture-planted")["runs"][0]["results"]
    }
    assert all(u.startswith("tests/fixtures/fixture-planted/") for u in uris)


def test_levels_follow_severity():
    level = {"high": "error", "medium": "warning", "low": "note"}
    for res in _doc()["runs"][0]["results"]:
        assert res["level"] == level[RULES[res["ruleId"]].severity]


def test_clean_fixture_sarif_has_no_results():
    assert to_sarif(scan(CLEAN))["runs"][0]["results"] == []


def test_cli_sarif_file_relative_to_cwd(tmp_path, monkeypatch, capsys):
    from conftest import ROOT

    monkeypatch.chdir(ROOT)
    out = tmp_path / "out.sarif"
    main(["scan", "tests/fixtures/fixture-planted", "--format", "json", "--sarif", str(out)])
    doc = json.loads(out.read_text())
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("tests/fixtures/fixture-planted/")

"""Action metadata and workflow hygiene."""

import re

import pytest

from conftest import ROOT

yaml = pytest.importorskip("yaml")

ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _uses(doc):
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from _uses(v)
    elif isinstance(doc, list):
        for item in doc:
            yield from _uses(item)


def test_action_is_composite_with_metadata():
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["name"] and ACTION["description"] and ACTION["branding"]["icon"]
    assert len(ACTION["description"]) <= 200


def test_action_has_required_inputs_with_defaults():
    inputs = ACTION["inputs"]
    for name in ("path", "fail-on", "baseline", "sarif", "upload-sarif"):
        assert name in inputs, name
        assert "default" in inputs[name] and inputs[name]["description"]
    assert inputs["fail-on"]["default"] == "high"
    assert inputs["sarif"]["default"] in ("true", "false")
    assert inputs["upload-sarif"]["default"] in ("true", "false")


def test_every_input_is_referenced_in_steps():
    body = (ROOT / "action.yml").read_text().split("runs:", 1)[1]
    for name in ACTION["inputs"]:
        assert f"inputs.{name}" in body, name


def test_outputs_map_to_scan_step():
    steps = {s.get("id") for s in ACTION["runs"]["steps"]}
    assert "scan" in steps
    for name, spec in ACTION["outputs"].items():
        assert spec["value"] == f"${{{{ steps.scan.outputs.{name} }}}}"


def test_action_runs_scanner_from_its_own_path():
    scan = next(s for s in ACTION["runs"]["steps"] if s.get("id") == "scan")
    assert scan["env"]["ACTION_PATH"] == "${{ github.action_path }}"
    assert "$ACTION_PATH/src" in scan["run"] and "python3 -m skill_scan_gate" in scan["run"]
    assert "set +e" in scan["run"]


def test_sarif_upload_is_conditional_and_pinned():
    upload = next(s for s in ACTION["runs"]["steps"] if "upload-sarif" in s.get("uses", ""))
    assert upload["uses"].startswith("github/codeql-action/upload-sarif@")
    assert SHA_PIN.match(upload["uses"])
    assert "inputs.upload-sarif == 'true'" in upload["if"] and "inputs.sarif == 'true'" in upload["if"]
    assert upload["with"]["sarif_file"] == "${{ inputs.sarif-file }}"


def test_gate_step_fails_last():
    last = ACTION["runs"]["steps"][-1]
    assert "steps.scan.outputs.gate == 'fail'" in last["if"]
    assert "exit 1" in last["run"]


def test_inputs_never_interpolated_into_run_scripts():
    for step in ACTION["runs"]["steps"]:
        assert "${{ inputs." not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("path", [ROOT / "action.yml", *WORKFLOWS], ids=lambda p: p.name)
def test_third_party_actions_are_sha_pinned(path):
    doc = yaml.safe_load(path.read_text())
    for ref in _uses(doc):
        if ref.startswith("./"):
            continue
        assert SHA_PIN.match(ref), f"{path.name}: {ref}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_default_to_read_only_token(path):
    doc = yaml.safe_load(path.read_text())
    assert doc["permissions"] == {"contents": "read"}


def test_self_test_expects_failure_on_planted_and_success_on_clean():
    doc = yaml.safe_load((ROOT / ".github/workflows/self-test.yml").read_text())
    steps = {s.get("id"): s for s in doc["jobs"]["self-test"]["steps"] if s.get("id")}
    assert steps["planted"]["uses"] == "./" and steps["planted"]["continue-on-error"] is True
    assert steps["planted"]["with"]["path"] == "tests/fixtures/fixture-planted"
    assert steps["clean"]["with"]["path"] == "tests/fixtures/fixture-clean"
    assert "continue-on-error" not in steps["clean"]
    text = (ROOT / ".github/workflows/self-test.yml").read_text()
    assert 'test "$PLANTED_OUTCOME" = "failure"' in text
    assert 'test "$CLEAN_OUTCOME" = "success"' in text


def test_release_workflow_is_guarded():
    doc = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    for job in doc["jobs"].values():
        assert job["if"] == "vars.PYPI_PUBLISH == 'true'"

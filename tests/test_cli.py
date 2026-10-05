"""Command line: formats, exit codes and side outputs."""

import json
import subprocess
import sys

import pytest

from skill_scan_gate import __version__
from skill_scan_gate.cli import main
from skill_scan_gate.rules import RULES

from conftest import CLEAN, PLANTED, ROOT


@pytest.mark.parametrize(
    ("path", "fail_on", "code"),
    [
        (PLANTED, "high", 1),
        (PLANTED, "medium", 1),
        (PLANTED, "low", 1),
        (PLANTED, "none", 0),
        (CLEAN, "low", 0),
        (CLEAN, "high", 0),
    ],
)
def test_exit_codes(path, fail_on, code, capsys):
    assert main(["scan", str(path), "--fail-on", fail_on]) == code


def test_threshold_only_counts_at_or_above(tmp_path, capsys):
    from conftest import write_tree

    repo = write_tree(tmp_path / "r", {".claude-plugin/plugin.json": {"name": "tidy-notes"}})  # SSG602 is low
    assert main(["scan", str(repo), "--fail-on", "medium"]) == 0
    assert main(["scan", str(repo), "--fail-on", "low"]) == 1


def test_missing_path_is_exit_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope")]) == 2


def test_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "usage: skill-scan-gate" in capsys.readouterr().out


def test_table_output(capsys):
    main(["scan", str(PLANTED)])
    out = capsys.readouterr().out
    assert out.startswith(f"skill-scan-gate {__version__}")
    assert "SSG101" in out and "fix: " in out and "gate fail" in out


def test_json_output(capsys):
    main(["scan", str(PLANTED), "--format", "json", "--fail-on", "high"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["gate"] == "fail"
    assert doc["blobMin"] == 200
    assert doc["summary"]["total"] == len(doc["findings"])
    assert {"rule", "severity", "file", "line", "remediation", "fingerprint"} <= set(doc["findings"][0])


def test_markdown_output(capsys):
    main(["scan", str(PLANTED), "--format", "markdown"])
    out = capsys.readouterr().out
    assert out.startswith("### skill-scan-gate: failed")
    assert "| Severity | Rule |" in out


def test_output_file_and_side_outputs(tmp_path, capsys):
    out, sarif, summary, gh = (tmp_path / n for n in ("r.json", "r.sarif", "summary.md", "gh.txt"))
    code = main(
        [
            "scan",
            str(PLANTED),
            "--format",
            "json",
            "--output",
            str(out),
            "--sarif",
            str(sarif),
            "--summary",
            str(summary),
            "--github-output",
            str(gh),
        ]
    )
    assert code == 1
    assert json.loads(out.read_text())["tool"] == "skill-scan-gate"
    assert json.loads(sarif.read_text())["version"] == "2.1.0"
    assert "skill-scan-gate: failed" in summary.read_text()
    kv = dict(line.split("=", 1) for line in gh.read_text().splitlines())
    assert kv["gate"] == "fail" and kv["highest-severity"] == "high" and int(kv["finding-count"]) > 20
    assert "gate fail" in capsys.readouterr().err


def test_github_output_on_clean(tmp_path, capsys):
    gh = tmp_path / "gh.txt"
    assert main(["scan", str(CLEAN), "--fail-on", "low", "--github-output", str(gh)]) == 0
    kv = dict(line.split("=", 1) for line in gh.read_text().splitlines())
    assert kv == {"finding-count": "0", "highest-severity": "none", "gate": "pass", "suppressed-count": "0"}


def test_rules_command(capsys):
    assert main(["rules", "--format", "json"]) == 0
    rules = json.loads(capsys.readouterr().out)
    assert len(rules) == len(RULES) and rules[0]["id"] == "SSG101"


def test_console_entry_point_help():
    proc = subprocess.run(
        [sys.executable, "-m", "skill_scan_gate", "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.startswith("usage: skill-scan-gate")


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_blob_min_cli_flag(tmp_path, capsys):
    import base64

    from conftest import GOOD_SKILL, write_tree

    blob_100 = base64.b64encode(bytes(range(75))).decode()
    repo = write_tree(tmp_path / "r", {"skills/s/SKILL.md": GOOD_SKILL + f'DATA="{blob_100}"\n'})

    # Default 200: not flagged
    assert main(["scan", str(repo), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["blobMin"] == 200
    assert not any(f["rule"] == "SSG203" for f in doc["findings"])

    # Lowered threshold 64: flagged
    assert main(["scan", str(repo), "--format", "json", "--blob-min", "64", "--fail-on", "medium"]) == 1
    doc64 = json.loads(capsys.readouterr().out)
    assert doc64["blobMin"] == 64
    assert any(f["rule"] == "SSG203" for f in doc64["findings"])

    # Raised threshold on large blob: suppresses finding
    blob_220 = base64.b64encode(bytes(range(165))).decode()
    repo2 = write_tree(tmp_path / "r2", {"skills/s/SKILL.md": GOOD_SKILL + f'DATA="{blob_220}"\n'})
    assert main(["scan", str(repo2), "--blob-min", "300"]) == 0

    # Below minimum 64: usage error (exit code 2)
    assert main(["scan", str(repo), "--blob-min", "63"]) == 2

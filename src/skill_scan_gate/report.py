"""Output formats: table, JSON, Markdown (job summary) and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .rules import HIGH, LOW, MEDIUM, RULES, at_or_above
from .scanner import Finding, ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/basitalisandhu/skill-scan-gate"
SARIF_LEVEL = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
# GitHub code scanning reads security-severity as a CVSS-style score and buckets it:
# 7.0 to 8.9 is shown as high, 4.0 to 6.9 as medium, 0.1 to 3.9 as low.
SECURITY_SEVERITY = {HIGH: "8.0", MEDIUM: "5.0", LOW: "2.0"}
MARKDOWN_ROW_LIMIT = 100


def gate(result: ScanResult, fail_on: str) -> str:
    return "fail" if any(at_or_above(f.severity, fail_on) for f in result.findings) else "pass"


def summary_line(result: ScanResult, fail_on: str) -> str:
    c = result.counts()
    parts = [
        f"{len(result.findings)} finding(s): {c[HIGH]} high, {c[MEDIUM]} medium, {c[LOW]} low",
    ]
    if result.suppressed_baseline or result.suppressed_allow:
        parts.append(
            f"suppressed {len(result.suppressed_baseline)} by baseline, {len(result.suppressed_allow)} by allowlist"
        )
    parts.append(f"gate {gate(result, fail_on)} (fail-on {fail_on})")
    return "; ".join(parts) + "."


# ---------------------------------------------------------------- table


def render_table(result: ScanResult, fail_on: str) -> str:
    out = [f"skill-scan-gate {__version__}: scanned {len(result.files)} file(s) under {result.root}", ""]
    if result.findings:
        loc = [f"{f.file}:{f.line}" for f in result.findings]
        w_loc = max(len("LOCATION"), *(len(x) for x in loc))
        out.append(f"{'SEVERITY':<9} {'RULE':<7} {'LOCATION':<{w_loc}} TITLE")
        out.append("-" * (9 + 1 + 7 + 1 + w_loc + 1 + 40))
        for f, where in zip(result.findings, loc, strict=True):
            out.append(f"{f.severity:<9} {f.rule:<7} {where:<{w_loc}} {f.title}")
            out.append(f"{'':<18}evidence: {f.evidence}")
            out.append(f"{'':<18}fix: {f.remediation}")
        out.append("")
    else:
        out.append("No findings.")
        out.append("")
    for w in result.warnings:
        out.append(f"warning: {w}")
    for e in result.errors:
        out.append(f"error: {e}")
    out.append(summary_line(result, fail_on))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- JSON


def to_json(result: ScanResult, fail_on: str) -> dict[str, Any]:
    c = result.counts()
    return {
        "tool": "skill-scan-gate",
        "version": __version__,
        "root": str(result.root),
        "filesScanned": len(result.files),
        "failOn": fail_on,
        "gate": gate(result, fail_on),
        "blobMin": result.blob_min,
        "summary": {
            "total": len(result.findings),
            **c,
            "maxSeverity": result.max_severity(),
            "suppressedByBaseline": len(result.suppressed_baseline),
            "suppressedByAllowlist": len(result.suppressed_allow),
        },
        "findings": [f.to_dict() for f in result.findings],
        "warnings": result.warnings,
        "errors": result.errors,
    }


def render_json(result: ScanResult, fail_on: str) -> str:
    return json.dumps(to_json(result, fail_on), indent=2) + "\n"


# ---------------------------------------------------------------- Markdown


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'").replace("<", "&lt;")


def render_markdown(result: ScanResult, fail_on: str) -> str:
    g = gate(result, fail_on)
    c = result.counts()
    out = [
        f"### skill-scan-gate: {'failed' if g == 'fail' else 'passed'}",
        "",
        f"Scanned {len(result.files)} file(s). Threshold: `{fail_on}`.",
        "",
        "| High | Medium | Low | Suppressed (baseline) | Suppressed (allowlist) |",
        "|---:|---:|---:|---:|---:|",
        f"| {c[HIGH]} | {c[MEDIUM]} | {c[LOW]} | {len(result.suppressed_baseline)} | {len(result.suppressed_allow)} |",
        "",
    ]
    if result.findings:
        out += ["| Severity | Rule | Location | Finding | Fix |", "|---|---|---|---|---|"]
        for f in result.findings[:MARKDOWN_ROW_LIMIT]:
            out.append(
                f"| {f.severity} | [{f.rule}]({RULES[f.rule].anchor}) | `{_md(f.file)}:{f.line}` "
                f"| {_md(f.title)} | {_md(f.remediation)} |"
            )
        if len(result.findings) > MARKDOWN_ROW_LIMIT:
            out.append("")
            out.append(f"{len(result.findings) - MARKDOWN_ROW_LIMIT} more finding(s) in the SARIF and JSON output.")
        out.append("")
    for w in result.warnings:
        out.append(f"- warning: {_md(w)}")
    for e in result.errors:
        out.append(f"- error: {_md(e)}")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------- SARIF


def _sarif_rule(rule_id: str) -> dict[str, Any]:
    r = RULES[rule_id]
    return {
        "id": r.id,
        "name": "".join(w.capitalize() for w in r.title.replace("-", " ").split()[:8]),
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": f"{r.title}. {r.remediation}"},
        "help": {
            "text": r.remediation,
            "markdown": f"**{r.title}** ({r.severity})\n\n{r.remediation}\n\n[Rule reference]({r.anchor})",
        },
        "helpUri": r.anchor,
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {
            "tags": ["security", r.family],
            "security-severity": SECURITY_SEVERITY[r.severity],
            "precision": "medium",
        },
    }


def to_sarif(result: ScanResult, uri_prefix: str = "") -> dict[str, Any]:
    """SARIF 2.1.0. ``uri_prefix`` makes paths relative to the repository root when the
    scanned directory is a subdirectory of it (code scanning resolves URIs from the root)."""
    rule_ids = sorted(RULES)
    index = {rid: i for i, rid in enumerate(rule_ids)}
    prefix = uri_prefix.strip("/")
    results = []
    for f in result.findings:
        uri = f"{prefix}/{f.file}" if prefix else f.file
        results.append(
            {
                "ruleId": f.rule,
                "ruleIndex": index[f.rule],
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.evidence}. {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {"skillScanGate/v1": f.fingerprint},
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-scan-gate",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_sarif_rule(rid) for rid in rule_ids],
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(result: ScanResult, uri_prefix: str = "") -> str:
    return json.dumps(to_sarif(result, uri_prefix), indent=2) + "\n"


def by_rule(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.rule] = out.get(f.rule, 0) + 1
    return dict(sorted(out.items()))

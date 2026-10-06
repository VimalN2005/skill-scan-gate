"""Command-line interface.

Exit codes: 0 no finding at or above the threshold, 1 at least one finding at or above
the threshold, 2 usage error or unreadable input (missing path, bad baseline or allowlist).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .patterns import BLOB_MIN
from .report import gate, render_json, render_markdown, render_sarif, render_table, summary_line
from .rules import RULES, SEVERITIES
from .scanner import ScanResult, scan
from .suppress import (
    SuppressionError,
    apply_allowlist,
    apply_baseline,
    load_allowlist,
    load_baseline,
    unused_entries,
    write_baseline,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
FORMATS = ("table", "json", "sarif", "markdown")
THRESHOLDS = (*SEVERITIES, "none")

DESCRIPTION = (
    "CI gate for Claude Code skills and plugins: scans a skills or plugin repository for "
    "instruction-override text, exfiltration patterns, dangerous hook commands, unpinned MCP "
    "servers and secret-shaped strings, writes SARIF, and fails on findings at or above a threshold."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="skill-scan-gate", description=DESCRIPTION)
    p.add_argument("--version", action="version", version=f"skill-scan-gate {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    s = sub.add_parser("scan", help="scan a directory and gate on the findings")
    s.add_argument("path", type=Path, help="skills or plugin repository (or any directory) to scan")
    s.add_argument("--format", choices=FORMATS, default="table", help="report format on stdout (default: table)")
    s.add_argument(
        "--fail-on",
        choices=THRESHOLDS,
        default="high",
        help="lowest severity that makes the exit code 1 (default: high; none never fails)",
    )
    s.add_argument(
        "--baseline", type=Path, help="baseline file from `skill-scan-gate baseline`; only new findings count"
    )
    s.add_argument(
        "--blob-min",
        type=int,
        default=BLOB_MIN,
        metavar="N",
        help="minimum base64 blob length for SSG203 (default: 200, minimum: 64)",
    )
    s.add_argument("--allow", type=Path, help="allowlist file (see docs/false-positives.md)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="path glob to skip (repeatable)")
    s.add_argument("--output", "-o", type=Path, help="write the report here instead of stdout")
    s.add_argument("--sarif", type=Path, metavar="FILE", help="also write SARIF 2.1.0 to FILE")
    s.add_argument("--summary", type=Path, metavar="FILE", help="also append a Markdown summary to FILE")
    s.add_argument(
        "--github-output",
        type=Path,
        metavar="FILE",
        help="also append finding-count, highest-severity, gate and suppressed-count as key=value lines",
    )
    s.add_argument(
        "--sarif-root",
        type=Path,
        default=None,
        help="directory SARIF paths are relative to (default: the current directory when PATH is inside it)",
    )

    b = sub.add_parser("baseline", help="snapshot the current findings so only new ones fail")
    b.add_argument("path", type=Path)
    b.add_argument("--out", type=Path, required=True, help="baseline file to write")
    b.add_argument(
        "--blob-min",
        type=int,
        default=BLOB_MIN,
        metavar="N",
        help="minimum base64 blob length for SSG203 (default: 200, minimum: 64)",
    )
    b.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    b.add_argument("--allow", type=Path, help="leave allowlisted findings out of the baseline")

    r = sub.add_parser("rules", help="list every rule with its severity and remediation")
    r.add_argument("--format", choices=("table", "json"), default="table")
    return p


def run_scan(
    path: Path,
    exclude: list[str],
    baseline: Path | None,
    allow: Path | None,
    blob_min: int = BLOB_MIN,
) -> ScanResult:
    result = scan(path, exclude, blob_min=blob_min)
    if allow is not None:
        entries = load_allowlist(allow)
        result.findings, result.suppressed_allow = apply_allowlist(result.findings, entries)
        for e in unused_entries(entries):
            result.warnings.append(f"{allow}:{e.source_line}: allowlist entry '{e.describe()}' matched nothing")
    if baseline is not None:
        result.findings, result.suppressed_baseline = apply_baseline(result.findings, load_baseline(baseline))
    return result


def _uri_prefix(path: Path, sarif_root: Path | None) -> str:
    base = (sarif_root or Path.cwd()).resolve()
    try:
        rel = path.resolve().relative_to(base).as_posix()
    except ValueError:
        return ""
    return "" if rel == "." else rel


def _cmd_scan(a: argparse.Namespace) -> int:
    if a.blob_min < 64:
        print(f"skill-scan-gate: --blob-min must be at least 64 (got {a.blob_min})", file=sys.stderr)
        return EXIT_ERROR
    if not a.path.is_dir():
        print(f"skill-scan-gate: not a directory: {a.path}", file=sys.stderr)
        return EXIT_ERROR
    try:
        result = run_scan(a.path, a.exclude, a.baseline, a.allow, blob_min=a.blob_min)
    except SuppressionError as e:
        print(f"skill-scan-gate: {e}", file=sys.stderr)
        return EXIT_ERROR
    prefix = _uri_prefix(a.path, a.sarif_root)
    renderers = {
        "table": lambda: render_table(result, a.fail_on),
        "json": lambda: render_json(result, a.fail_on),
        "sarif": lambda: render_sarif(result, prefix),
        "markdown": lambda: render_markdown(result, a.fail_on),
    }
    text = renderers[a.format]()
    if a.output:
        a.output.write_text(text, encoding="utf-8")
        print(summary_line(result, a.fail_on), file=sys.stderr)
    else:
        sys.stdout.write(text)
    if a.sarif:
        a.sarif.write_text(render_sarif(result, prefix), encoding="utf-8")
    if a.summary:
        with a.summary.open("a", encoding="utf-8") as fh:
            fh.write(render_markdown(result, a.fail_on) + "\n")
    g = gate(result, a.fail_on)
    if a.github_output:
        with a.github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"finding-count={len(result.findings)}\n")
            fh.write(f"highest-severity={result.max_severity() or 'none'}\n")
            fh.write(f"gate={g}\n")
            fh.write(f"suppressed-count={len(result.suppressed_baseline) + len(result.suppressed_allow)}\n")
    return EXIT_FINDINGS if g == "fail" else EXIT_OK


def _cmd_baseline(a: argparse.Namespace) -> int:
    if a.blob_min < 64:
        print(f"skill-scan-gate: --blob-min must be at least 64 (got {a.blob_min})", file=sys.stderr)
        return EXIT_ERROR
    if not a.path.is_dir():
        print(f"skill-scan-gate: not a directory: {a.path}", file=sys.stderr)
        return EXIT_ERROR
    try:
        result = run_scan(a.path, a.exclude, None, a.allow, blob_min=a.blob_min)
    except SuppressionError as e:
        print(f"skill-scan-gate: {e}", file=sys.stderr)
        return EXIT_ERROR
    write_baseline(a.out, result.findings)
    print(f"skill-scan-gate {__version__}: wrote {len(result.findings)} finding(s) to {a.out}")
    return EXIT_OK


def _cmd_rules(a: argparse.Namespace) -> int:
    rules = [RULES[k] for k in sorted(RULES)]
    if a.format == "json":
        doc = [
            {"id": r.id, "family": r.family, "severity": r.severity, "title": r.title, "remediation": r.remediation}
            for r in rules
        ]
        print(json.dumps(doc, indent=2))
        return EXIT_OK
    for r in rules:
        print(f"{r.id}  {r.severity:<7} {r.family:<13} {r.title}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.command is None:
        parser.print_help()
        return EXIT_ERROR
    try:
        if a.command == "scan":
            return _cmd_scan(a)
        if a.command == "baseline":
            return _cmd_baseline(a)
        return _cmd_rules(a)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except OSError as e:
        print(f"skill-scan-gate: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

"""Run every rule over a skills or plugin repository.

Nothing is executed and nothing is fetched: the scanner reads text and JSON and matches
patterns. Findings record a repository-relative path, a 1-based line, short evidence
(secrets are redacted) and a fingerprint that survives line shifts, for baselines.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from . import patterns as P
from .discover import (
    HOOKS_CONFIG,
    MANIFEST,
    MARKDOWN_KINDS,
    MCP,
    SCRIPT,
    SETTINGS,
    SKILL,
    walk,
)
from .rules import HIGH, LOW, MEDIUM, RULES, SEVERITY_RANK

MAX_FILE_BYTES = 2_000_000
EVIDENCE_MAX = 160


@dataclass(frozen=True)
class Finding:
    rule: str
    file: str
    line: int
    evidence: str
    fingerprint: str

    @property
    def severity(self) -> str:
        return RULES[self.rule].severity

    @property
    def title(self) -> str:
        return RULES[self.rule].title

    @property
    def remediation(self) -> str:
        return RULES[self.rule].remediation

    def to_dict(self) -> dict[str, Any]:
        r = RULES[self.rule]
        return {
            "rule": self.rule,
            "severity": r.severity,
            "family": r.family,
            "title": r.title,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": r.remediation,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    files: list[str]
    errors: list[str] = field(default_factory=list)
    suppressed_baseline: list[Finding] = field(default_factory=list)
    suppressed_allow: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {s: sum(1 for f in self.findings if f.severity == s) for s in (HIGH, MEDIUM, LOW)}

    def max_severity(self) -> str | None:
        best: str | None = None
        for f in self.findings:
            if best is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]:
                best = f.severity
        return best


def fingerprint(rule: str, file: str, source_line: str, occurrence: int = 0) -> str:
    """Stable id for a finding: rule, file and the whitespace-normalised line text, not its number."""
    norm = " ".join(source_line.split())
    data = f"{rule}\0{file}\0{norm}\0{occurrence}".encode()
    return hashlib.sha256(data).hexdigest()[:24]


def _clip(text: str) -> str:
    text = P.HIDDEN_CHARS.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text.strip())
    return text if len(text) <= EVIDENCE_MAX else text[: EVIDENCE_MAX - 3] + "..."


def _redact(value: str) -> str:
    head = value[:4] if len(value) > 12 else ""
    return f"{head}<redacted {len(value)} chars>"


def locate(text: str, *needles: str) -> int:
    """1-based line of the last needle, each searched after the previous one (JSON-escaped too)."""
    pos = 0
    found = -1
    for needle in needles:
        if not needle:
            continue
        for candidate in (needle, json.dumps(needle)[1:-1]):
            idx = text.find(candidate, pos)
            if idx >= 0:
                found = idx
                pos = idx + len(candidate)
                break
    return text.count("\n", 0, found) + 1 if found >= 0 else 1


def parse_front_matter(text: str) -> dict[str, tuple[str, int]] | None:
    """A small YAML subset: top-level ``key: value`` pairs with quoted, folded or literal values.

    Returns {key: (value, line)} or None when the file has no front matter block.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    out: dict[str, tuple[str, int]] = {}
    key: str | None = None
    buf: list[str] = []
    start = 0
    end = None
    for i, line in enumerate(lines[1:], start=2):
        if line.strip() in ("---", "..."):
            end = i
            break
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and not line.startswith((" ", "\t")):
            if key is not None:
                out[key] = (" ".join(buf).strip(), start)
            key, start = m.group(1), i
            value = m.group(2).strip()
            buf = [] if value in ("|", ">", "|-", ">-", "|+", ">+") else [value]
        elif key is not None:
            buf.append(line.strip())
    if end is None:
        return None
    if key is not None:
        out[key] = (" ".join(buf).strip(), start)
    return {k: (v.strip().strip("\"'"), n) for k, (v, n) in out.items()}


class Scanner:
    def __init__(self, root: Path, exclude: list[str] | None = None) -> None:
        self.root = root
        self.exclude = exclude or []
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.files: list[str] = []
        self._seen: set[tuple[str, str, int]] = set()
        self._occ: dict[tuple[str, str, str], int] = {}
        self._mcp_done: set[str] = set()

    # ---------------------------------------------------------------- plumbing

    def add(self, rule: str, file: str, line: int, source: str, evidence: str | None = None) -> None:
        key = (rule, file, line)
        if key in self._seen:
            return
        self._seen.add(key)
        norm = " ".join(source.split())
        okey = (rule, file, norm)
        occ = self._occ.get(okey, 0)
        self._occ[okey] = occ + 1
        self.findings.append(
            Finding(
                rule,
                file,
                line,
                _clip(evidence if evidence is not None else source),
                fingerprint(rule, file, source, occ),
            )
        )

    def read(self, rel: str) -> str | None:
        path = self.root / rel
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                self.errors.append(f"{rel}: skipped, larger than {MAX_FILE_BYTES} bytes")
                return None
            data = path.read_bytes()
        except OSError as e:
            self.errors.append(f"{rel}: {e.strerror or e}")
            return None
        if b"\0" in data[:8192]:
            return None
        return data.decode("utf-8", errors="replace")

    def load_json(self, rel: str, text: str) -> Any:
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            lines = text.splitlines()
            src = lines[e.lineno - 1] if 0 < e.lineno <= len(lines) else ""
            self.add("SSG606", rel, e.lineno, src, f"{e.msg} at line {e.lineno} column {e.colno}")
            return None

    # ---------------------------------------------------------------- entry point

    def run(self) -> Scanner:
        for rel, kind in walk(self.root, self.exclude):
            text = self.read(rel)
            if text is None:
                continue
            self.files.append(rel)
            self.scan_file(rel, kind, text)
        self.repo_checks()
        self.findings.sort(key=lambda f: (f.file, f.line, f.rule))
        return self

    def scan_file(self, rel: str, kind: str, text: str) -> None:
        secret_lines: set[int] = set()
        if kind == MCP and rel not in self._mcp_done:
            self._mcp_done.add(rel)
            data = self.load_json(rel, text)
            if data is not None:
                secret_lines |= self.mcp_rules(rel, text, mcp_servers_of(data))
        elif kind == MANIFEST:
            data = self.load_json(rel, text)
            if data is not None:
                secret_lines |= self.manifest_rules(rel, text, data)
        elif kind in (HOOKS_CONFIG, SETTINGS):
            data = self.load_json(rel, text)
            if isinstance(data, dict):
                self.hook_config_rules(rel, text, data)
            if kind == SETTINGS:
                for i, line in enumerate(text.splitlines(), 1):
                    if P.DISABLE_SECURITY.search(line):
                        self.add("SSG305", rel, i, line)
        elif kind == SCRIPT:
            self.script_rules(rel, text)
        elif kind in MARKDOWN_KINDS:
            self.markdown_rules(rel, text)
            if kind == SKILL:
                self.skill_rules(rel, text)
        self.common_rules(rel, kind, text, secret_lines)

    # ---------------------------------------------------------------- common rules

    def common_rules(self, rel: str, kind: str, text: str, skip_secret_lines: set[int]) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            if P.HIDDEN_CHARS.search(line):
                self.add("SSG104", rel, i, line)
            for m in P.URL.finditer(line):
                url = m.group(0)
                if P.URL_TEMPLATE.search(P.url_after_host(url)):
                    self.add("SSG201", rel, i, line)
                if P.capture_endpoint(url):
                    self.add("SSG204", rel, i, line)
            for m in P.BASE64_BLOB.finditer(line):
                if P.looks_like_blob(m.group(0)):
                    self.add("SSG203", rel, i, line, f"{len(m.group(0))}-character encoded run")
                    break
            else:
                hm = P.HEX_BLOB.search(line)
                if hm:
                    self.add("SSG203", rel, i, line, f"{len(hm.group(0))}-character hex run")
            if i in skip_secret_lines:
                continue
            self.secret_rules(rel, kind, i, line)

    def secret_rules(self, rel: str, kind: str, i: int, line: str) -> None:
        if P.PRIVATE_KEY.search(line):
            self.add("SSG501", rel, i, line, P.PRIVATE_KEY.search(line).group(0))  # type: ignore[union-attr]
            return
        for label, rx in P.PROVIDER_TOKENS:
            m = rx.search(line)
            if m and "EXAMPLE" not in m.group(0).upper():
                self.add("SSG502", rel, i, line, f"{label}: {_redact(m.group(0))}")
                return
        if kind in (MCP, MANIFEST):
            return
        m = P.CREDENTIAL_ASSIGNMENT.search(line)
        if m and not P.is_placeholder(m.group("value")) and not _looks_like_reference(m.group("value")):
            self.add("SSG503", rel, i, line, f"{m.group('key')} = {_redact(m.group('value'))}")

    # ---------------------------------------------------------------- command rules

    def command_rules(self, rel: str, line_no: int, cmd: str, source: str | None = None) -> None:
        """Rules for a shell command, a hook command or a line of a script."""
        src = source if source is not None else cmd
        if P.REMOTE_CODE.search(cmd):
            self.add("SSG301", rel, line_no, src)
        if P.UPLOAD.search(cmd):
            self.add("SSG202", rel, line_no, src)
        if P.CREDENTIAL_PATH.search(cmd):
            self.add("SSG303", rel, line_no, src)
        if P.ENV_DUMP.search(cmd):
            self.add("SSG304", rel, line_no, src)
        if P.DISABLE_SECURITY.search(cmd):
            self.add("SSG305", rel, line_no, src)
        if P.DYNAMIC_EVAL.search(cmd) and not P.REMOTE_CODE.search(cmd):
            self.add("SSG306", rel, line_no, src)
        if _writes_outside(cmd):
            self.add("SSG302", rel, line_no, src)

    def script_rules(self, rel: str, text: str) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or (stripped.startswith(("#", "//", "REM ", "::")) and not stripped.startswith("#!")):
                continue
            self.command_rules(rel, i, line)

    def hook_config_rules(self, rel: str, text: str, data: dict[str, Any]) -> None:
        for event, command in hook_commands(data.get("hooks")):
            self.command_rules(rel, locate(text, event, command), command)

    # ---------------------------------------------------------------- markdown rules

    def markdown_rules(self, rel: str, text: str) -> None:
        in_fence = False
        for i, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            for rule, rx in (
                ("SSG101", P.OVERRIDE),
                ("SSG102", P.CONCEAL),
                ("SSG103", P.TOOL_OUTPUT_AS_INSTRUCTIONS),
            ):
                for m in rx.finditer(line):
                    if P.preceded_by_quote(line, m.start()):
                        continue
                    if rule != "SSG102" and P.negated(line, m.start()):
                        continue
                    self.add(rule, rel, i, line)
                    break
            # Commands a skill asks the model to run: fenced blocks and inline code spans.
            code = [line] if in_fence else re.findall(r"`([^`]+)`", line)
            for snippet in code:
                if P.REMOTE_CODE.search(snippet):
                    self.add("SSG301", rel, i, line)
                if P.UPLOAD.search(snippet):
                    self.add("SSG202", rel, i, line)
                if P.CREDENTIAL_PATH.search(snippet) and _reads(snippet):
                    self.add("SSG303", rel, i, line)
                if P.ENV_DUMP.search(snippet):
                    self.add("SSG304", rel, i, line)
                if P.DISABLE_SECURITY.search(snippet):
                    self.add("SSG305", rel, i, line)

    def skill_rules(self, rel: str, text: str) -> None:
        fm = parse_front_matter(text)
        if fm is None or not fm.get("description", ("", 0))[0]:
            line = fm["description"][1] if fm and "description" in fm else 1
            self.add("SSG604", rel, line, text.splitlines()[0] if text else "", "no description in front matter")
        else:
            desc, line = fm["description"]
            if P.ALWAYS_RUN.search(desc):
                self.add("SSG605", rel, line, desc)
        if fm and fm.get("name", ("", 0))[0]:
            name, line = fm["name"]
            if any(w in name.lower() for w in P.RESERVED_WORDS):
                self.add("SSG603", rel, line, f"name: {name}")

    # ---------------------------------------------------------------- manifests

    def manifest_rules(self, rel: str, text: str, data: Any) -> set[int]:
        secret_lines: set[int] = set()
        if not isinstance(data, dict):
            return secret_lines
        name = PurePosixPath(rel).name
        if name == "plugin.json":
            pname = data.get("name")
            if not isinstance(pname, str) or not pname.strip():
                self.add("SSG601", rel, 1, "plugin.json", "plugin.json has no name")
            else:
                self._reserved_name(rel, text, pname, plugin=True)
            if not data.get("version"):
                self.add("SSG602", rel, 1, "plugin.json version", "plugin.json has no version")
            servers = data.get("mcpServers")
            if isinstance(servers, dict):
                secret_lines |= self.mcp_rules(rel, text, servers)
            elif isinstance(servers, str | list):
                for ref in [servers] if isinstance(servers, str) else servers:
                    self._follow_mcp_ref(rel, ref)
            hooks = data.get("hooks")
            if isinstance(hooks, dict):
                self.hook_config_rules(rel, text, data)
        elif name == "marketplace.json":
            mname = data.get("name")
            if not isinstance(mname, str) or not mname.strip():
                self.add("SSG601", rel, 1, "marketplace.json", "marketplace.json has no name")
            else:
                self._reserved_name(rel, text, mname, plugin=False)
            plugins = data.get("plugins")
            for idx, entry in enumerate(plugins if isinstance(plugins, list) else []):
                if not isinstance(entry, dict):
                    continue
                ename = entry.get("name")
                if not isinstance(ename, str) or not ename.strip():
                    src = json.dumps(entry.get("source", ""))
                    line = locate(text, '"plugins"', str(entry.get("source", "")))
                    self.add("SSG601", rel, line, f"plugins[{idx}] {src}", f"plugins[{idx}] has no name")
                else:
                    self._reserved_name(rel, text, ename, plugin=True)
        return secret_lines

    def _reserved_name(self, rel: str, text: str, name: str, plugin: bool) -> None:
        low = name.lower()
        hit = low in P.RESERVED_MARKETPLACE_NAMES or any(low.startswith(w) for w in P.RESERVED_WORDS)
        if hit:
            kind = "plugin" if plugin else "marketplace"
            self.add("SSG603", rel, locate(text, f'"{name}"'), f"{kind} name: {name}")

    def _follow_mcp_ref(self, rel: str, ref: Any) -> None:
        if not isinstance(ref, str) or not ref.startswith("./") or ".." in ref.split("/"):
            return
        plugin_root = PurePosixPath(rel).parent.parent
        target = (plugin_root / ref[2:]).as_posix()
        target = target[2:] if target.startswith("./") else target
        if target in self._mcp_done or not (self.root / target).is_file():
            return
        self._mcp_done.add(target)
        text = self.read(target)
        if text is None:
            return
        if target not in self.files:
            self.files.append(target)
        data = self.load_json(target, text)
        if data is not None:
            skip = self.mcp_rules(target, text, mcp_servers_of(data))
            self.common_rules(target, MCP, text, skip)

    # ---------------------------------------------------------------- MCP

    def mcp_rules(self, rel: str, text: str, servers: dict[str, Any]) -> set[int]:
        secret_lines: set[int] = set()
        for sname, spec in sorted(servers.items()):
            if not isinstance(spec, dict):
                continue
            line = locate(text, f'"{sname}"')
            argv = _argv(spec)
            if argv:
                self._mcp_command(rel, text, sname, argv, line)
            url = spec.get("url")
            if isinstance(url, str) and P.insecure_url(url):
                self.add("SSG404", rel, locate(text, f'"{sname}"', url), f"{sname}: {url}")
            for block in ("env", "headers"):
                values = spec.get(block)
                if not isinstance(values, dict):
                    continue
                for k, v in values.items():
                    if not isinstance(v, str) or _looks_like_reference(v) or P.is_placeholder(v):
                        continue
                    shaped = any(rx.search(v) for _, rx in P.PROVIDER_TOKENS) or P.PRIVATE_KEY.search(v)
                    named = P.SECRET_KEY_NAME.search(k) and len(_strip_scheme(v)) >= 8
                    if shaped or named:
                        ln = locate(text, f'"{sname}"', f'"{k}"')
                        secret_lines.add(ln)
                        self.add("SSG405", rel, ln, f"{sname} {block}.{k}", f"{sname}: {block}.{k} = {_redact(v)}")
        return secret_lines

    def _mcp_command(self, rel: str, text: str, sname: str, argv: list[str], line: int) -> None:
        exe = PurePosixPath(argv[0]).name.lower()
        rest = argv[1:]
        if exe in ("cmd", "cmd.exe") and len(rest) >= 2 and rest[0].lower() == "/c":
            exe, rest = PurePosixPath(rest[1]).name.lower(), rest[2:]
        if exe in ("pnpm", "yarn") and rest and rest[0] == "dlx":
            exe, rest = "npx", rest[1:]
        if exe in ("uv", "pipx") and rest and rest[0] in ("run", "tool"):
            rest = rest[2:] if rest[:2] == ["tool", "run"] else rest[1:]
            exe = "uvx"
        if exe in ("npx", "bunx", "npx.cmd"):
            spec = _package(rest, ("-p", "--package"), ("-c", "--call"))
            if spec:
                ln = locate(text, f'"{sname}"', spec)
                if P.is_latest(spec):
                    self.add("SSG403", rel, ln, f"{sname}: {spec}")
                elif not P.npm_pinned(spec):
                    self.add("SSG401", rel, ln, f"{sname}: {exe} {spec}")
        elif exe in ("uvx", "uvx.exe"):
            spec = _package(rest, ("--from", "--spec"), ("--with", "--python", "-p", "--index-url", "--index"))
            if spec:
                ln = locate(text, f'"{sname}"', spec)
                if P.is_latest(spec):
                    self.add("SSG403", rel, ln, f"{sname}: {spec}")
                elif not P.py_pinned(spec):
                    self.add("SSG402", rel, ln, f"{sname}: {exe} {spec}")
        elif exe in ("docker", "podman", "nerdctl") and rest and rest[0] == "run":
            image = _image(rest[1:])
            if image and "@sha256:" not in image and not image.startswith("${"):
                self.add("SSG406", rel, locate(text, f'"{sname}"', image), f"{sname}: {image}")

    # ---------------------------------------------------------------- repository

    def repo_checks(self) -> None:
        names = {p.name.lower() for p in self.root.iterdir()} if self.root.is_dir() else set()
        has_security = (
            any((self.root / d / "SECURITY.md").is_file() for d in ("", ".github", "docs")) or "security.md" in names
        )
        if not has_security:
            self.add("SSG701", "SECURITY.md", 1, "missing SECURITY.md", "no SECURITY.md in the root, .github/ or docs/")
        licence = any(n.split(".")[0] in ("license", "licence", "copying", "unlicense") for n in names)
        if not licence:
            self.add("SSG702", "LICENSE", 1, "missing LICENSE", "no LICENSE, LICENCE or COPYING file in the root")


# ---------------------------------------------------------------- helpers


def mcp_servers_of(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    if data and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()):
        return data
    return {}


def hook_commands(hooks: Any) -> list[tuple[str, str]]:
    """(event, command) for every command hook in a Claude Code hooks block."""
    out: list[tuple[str, str]] = []
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict):
                continue
            for h in group.get("hooks", []) if isinstance(group.get("hooks"), list) else []:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    out.append((str(event), h["command"]))
    return out


def _argv(spec: dict[str, Any]) -> list[str]:
    cmd = spec.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return []
    args = [a for a in spec.get("args", []) if isinstance(a, str)] if isinstance(spec.get("args"), list) else []
    if " " in cmd.strip() and not args:
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()
    return [cmd, *args]


def _package(args: list[str], take_next: tuple[str, ...], skip_value: tuple[str, ...]) -> str | None:
    """The package spec an npx- or uvx-style runner will fetch.

    ``take_next`` options name the package in their value (npx --package, uvx --from);
    ``skip_value`` options take a value that is not the package (uvx --python).
    """
    skip = False
    for idx, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in take_next and idx + 1 < len(args):
            return args[idx + 1]
        for opt in take_next:
            if opt.startswith("--") and a.startswith(opt + "="):
                return a.split("=", 1)[1]
        if a in skip_value:
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return None


_DOCKER_VALUE_OPTS = frozenset(
    {
        "-e",
        "--env",
        "-v",
        "--volume",
        "--name",
        "-p",
        "--publish",
        "--network",
        "--net",
        "--entrypoint",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--mount",
        "--env-file",
        "--platform",
        "-l",
        "--label",
        "--add-host",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "--tmpfs",
        "-h",
        "--hostname",
        "--memory",
        "-m",
        "--cpus",
        "--pull",
    }
)


def _image(args: list[str]) -> str | None:
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in _DOCKER_VALUE_OPTS:
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return None


def _looks_like_reference(value: str) -> bool:
    return "${" in value or bool(re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", value.strip()))


def _strip_scheme(value: str) -> str:
    return re.sub(r"^(?:Bearer|Basic|token)\s+", "", value.strip(), flags=re.IGNORECASE)


_PLUGIN_VARS = ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "CLAUDE_PROJECT_DIR")


def _writes_outside(cmd: str) -> bool:
    for rx in (P.WRITE_TARGET, P.PY_WRITE):
        for m in rx.finditer(cmd):
            target = m.group("target")
            if any(v in target for v in _PLUGIN_VARS):
                continue
            if target.startswith(P.SAFE_WRITE_PREFIXES):
                continue
            if target in ("/", "~", "$HOME"):
                continue
            return True
    return False


_READ_VERBS = re.compile(
    r"\b(?:cat|less|more|head|tail|cp|scp|rsync|tar|zip|base64|xxd|open|read|type|Get-Content|grep|security|find|ls|curl|wget)\b",
    re.IGNORECASE,
)


def _reads(snippet: str) -> bool:
    return bool(_READ_VERBS.search(snippet))


def scan(root: Path, exclude: list[str] | None = None) -> ScanResult:
    """Scan a directory. A path that is not a directory is reported as an error, not a finding."""
    if not root.is_dir():
        return ScanResult(root, [], [], [f"not a directory: {root}"])
    s = Scanner(root, exclude).run()
    return ScanResult(root, s.findings, sorted(s.files), s.errors)


__all__ = ["Finding", "ScanResult", "Scanner", "fingerprint", "hook_commands", "parse_front_matter", "scan"]

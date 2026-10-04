"""Find the files a skills or plugin repository is made of, and say what kind each one is."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
    }
)
SCRIPT_SUFFIXES = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".pl",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        "",
    }
)
INSTRUCTION_NAMES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".cursorrules"})

# Kinds
SKILL = "skill"
INSTRUCTIONS = "instructions"
HOOKS_CONFIG = "hooks-config"
SETTINGS = "settings"
MANIFEST = "manifest"
MCP = "mcp"
SCRIPT = "script"
MARKDOWN_KINDS = frozenset({SKILL, INSTRUCTIONS})


def classify(rel: PurePosixPath) -> str | None:
    """Return the kind of a repository-relative path, or None when the scanner ignores it."""
    name = rel.name
    parents = rel.parts[:-1]
    suffix = rel.suffix.lower()
    if name == "SKILL.md":
        return SKILL
    if name in INSTRUCTION_NAMES:
        return INSTRUCTIONS
    if ".cursor" in parents and "rules" in parents[parents.index(".cursor") :]:
        return INSTRUCTIONS if suffix in (".md", ".mdc", ".txt", "") else None
    if suffix == ".md" and ("commands" in parents or "agents" in parents):
        return INSTRUCTIONS
    if name == "hooks.json" and parents and parents[-1] == "hooks":
        return HOOKS_CONFIG
    if parents and parents[-1] == ".claude-plugin" and suffix == ".json":
        return MANIFEST
    if name == ".mcp.json":
        return MCP
    if name == "settings.json":
        return SETTINGS
    if ("scripts" in parents or "hooks" in parents) and suffix in SCRIPT_SUFFIXES:
        return SCRIPT
    return None


def excluded(rel: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    parts = rel.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    return any(fnmatch.fnmatchcase(c, p) for p in patterns for c in candidates)


def walk(root: Path, exclude: list[str] | None = None) -> list[tuple[str, str]]:
    """Sorted (relative posix path, kind) pairs for every file the scanner reads."""
    patterns = [p.strip().rstrip("/") for p in exclude or [] if p.strip()]
    out: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        rel_dir = base.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS
            and not (base / d).is_symlink()
            and not excluded(f"{rel_dir}/{d}" if rel_dir else d, patterns)
        )
        for fn in filenames:
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if (base / fn).is_symlink() or excluded(rel, patterns):
                continue
            kind = classify(PurePosixPath(rel))
            if kind:
                out.append((rel, kind))
    out.sort()
    return out

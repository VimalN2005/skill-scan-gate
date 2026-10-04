#!/usr/bin/env python3
"""Build a fixture with secret-shaped strings in a directory, at run time.

The strings are assembled from parts so that no value in a real credential format is ever
committed to this repository. They are random-looking but are not, and never were, real
credentials. Used by tests/test_secrets.py and by the self-test workflow:

    python3 tests/make_secret_fixture.py "$RUNNER_TEMP/fixture-secrets"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FILLER = "Q7rX2mK9pL4sV8nB3cD6fG1hJ5tY0wZa"  # 32 mixed characters, not a credential


def j(*parts: str) -> str:
    return "".join(parts)


def tokens() -> dict[str, str]:
    """Secret-shaped strings keyed by a short label."""
    return {
        "aws": j("AK", "IA", "Q3XZ7RFIXTUREK2M"),
        "github": j("gh", "p_", FILLER, "abcd"),
        "slack": j("xo", "xb-", "000000000000-", "fixturefixture"),
        "google": j("AI", "za", "Sy", FILLER, "x"),
        "stripe": j("sk", "_li", "ve_", FILLER[:24]),
        "npm": j("np", "m_", FILLER, "wxyz"),
        "generic": j("s", "k-", "proj-", FILLER, FILLER[:8]),
        "private_key_header": j("-----BEGIN ", "RSA ", "PRIVATE ", "KEY-----"),
        "password": j("fixture", "-literal-", "value-91"),
    }


def build(dest: Path) -> dict[str, str]:
    t = tokens()
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (dest / "SECURITY.md").write_text("# Security\n\nReport privately.\n", encoding="utf-8")
    skill = dest / "skills" / "deploy"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(
        "---\nname: deploy\ndescription: Deploy the site when the user asks for a release.\n---\n\n"
        f"Use the key {t['aws']} for the bucket.\n"
        f"The bot token is {t['slack']}.\n",
        encoding="utf-8",
    )
    scripts = dest / "scripts"
    scripts.mkdir(exist_ok=True)
    (scripts / "release.sh").write_text(
        "#!/bin/sh\n"
        f"GH_TOKEN={t['github']} gh release create v1\n"
        f"export MAPS_KEY={t['google']}\n"
        f'db_password="{t["password"]}"\n',
        encoding="utf-8",
    )
    (scripts / "key.py").write_text(
        f'KEY = """{t["private_key_header"]}\nnot-a-key\n"""\nSTRIPE = "{t["stripe"]}"\nNPM = "{t["npm"]}"\n',
        encoding="utf-8",
    )
    (dest / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "literal-env": {
                        "command": "npx",
                        "args": ["-y", "fixture-server@1.0.0"],
                        "env": {"SERVICE_API_KEY": t["password"], "OTHER": t["generic"]},
                    },
                    "literal-header": {
                        "type": "http",
                        "url": "https://mcp.example.org/mcp",
                        "headers": {"Authorization": "Bearer " + t["password"]},
                    },
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    settings = dest / ".claude"
    settings.mkdir(exist_ok=True)
    (settings / "settings.json").write_text(
        json.dumps({"env": {"DEPLOY_TOKEN": t["password"]}}, indent=2) + "\n", encoding="utf-8"
    )
    return t


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: make_secret_fixture.py DEST", file=sys.stderr)
        raise SystemExit(2)
    build(Path(sys.argv[1]))
    print(f"wrote secret-shaped fixture to {sys.argv[1]}")

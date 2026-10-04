"""Family (d): MCP server declarations."""

import pytest

from conftest import rule_ids


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", "some-server"]},
        {"command": "npx", "args": ["-y", "@scope/server@^1.2.0"]},
        {"command": "npx -y some-server"},
        {"command": "bunx", "args": ["some-server@1"]},
        {"command": "pnpm", "args": ["dlx", "some-server"]},
        {"command": "cmd", "args": ["/c", "npx", "-y", "some-server"]},
    ],
)
def test_ssg401_unpinned_npm(mcp_rules, server):
    assert "SSG401" in mcp_rules(server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", "some-server@1.2.3"]},
        {"command": "npx", "args": ["-y", "@scope/server@2.0.0-beta.1"]},
        {"command": "npx", "args": ["--package", "tool@3.1.4", "tool-bin"]},
        {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/server.js"]},
    ],
)
def test_ssg401_pinned_or_local_not_flagged(mcp_rules, server):
    assert "SSG401" not in mcp_rules(server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "uvx", "args": ["some-tool"]},
        {"command": "uvx", "args": ["some-tool>=1.0"]},
        {"command": "uv", "args": ["tool", "run", "some-tool"]},
        {"command": "pipx", "args": ["run", "some-tool"]},
        {"command": "uvx", "args": ["--from", "some-pkg", "tool"]},
    ],
)
def test_ssg402_unpinned_python(mcp_rules, server):
    assert "SSG402" in mcp_rules(server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "uvx", "args": ["some-tool==1.4.0"]},
        {"command": "uvx", "args": ["--python", "3.12", "some-tool==1.4.0"]},
        {"command": "uvx", "args": ["--from", "some-pkg==2.0.1", "tool"]},
    ],
)
def test_ssg402_pinned_not_flagged(mcp_rules, server):
    assert "SSG402" not in mcp_rules(server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", "some-server@latest"]},
        {"command": "uvx", "args": ["some-tool@latest"]},
    ],
)
def test_ssg403_latest_tag(mcp_rules, server):
    ids = mcp_rules(server)
    assert "SSG403" in ids
    assert "SSG401" not in ids and "SSG402" not in ids


@pytest.mark.parametrize("url", ["http://mcp.example.invalid/mcp", "ws://10.0.0.5/ws"])
def test_ssg404_plain_http_remote(mcp_rules, url):
    assert "SSG404" in mcp_rules({"type": "http", "url": url})


@pytest.mark.parametrize(
    "url", ["https://mcp.example.org/mcp", "http://localhost:3000/mcp", "http://127.0.0.1:8080", "http://[::1]:9/x"]
)
def test_ssg404_tls_or_loopback_not_flagged(mcp_rules, url):
    assert "SSG404" not in mcp_rules({"type": "http", "url": url})


def test_ssg405_literal_secret_in_env(mcp_rules):
    ids = mcp_rules({"command": "node", "args": ["s.js"], "env": {"SERVICE_TOKEN": "literal-value-1234"}})
    assert "SSG405" in ids


def test_ssg405_literal_bearer_header(mcp_rules):
    ids = mcp_rules(
        {"type": "http", "url": "https://m.example.org", "headers": {"Authorization": "Bearer literal-value-1234"}}
    )
    assert "SSG405" in ids


@pytest.mark.parametrize(
    "env",
    [
        {"SERVICE_TOKEN": "${SERVICE_TOKEN}"},
        {"SERVICE_TOKEN": "$SERVICE_TOKEN"},
        {"SERVICE_TOKEN": "<your-token>"},
        {"SERVICE_TOKEN": "changeme"},
        {"LOG_LEVEL": "debug-verbose-mode"},
        {"API_KEY": "${API_KEY:-}"},
    ],
)
def test_ssg405_references_and_non_secrets_not_flagged(mcp_rules, env):
    assert "SSG405" not in mcp_rules({"command": "node", "args": ["s.js"], "env": env})


def test_ssg405_evidence_is_redacted(tree):
    from skill_scan_gate.scanner import scan

    root = tree(
        {".mcp.json": {"mcpServers": {"s": {"command": "node", "env": {"DB_PASSWORD": "fixture-literal-0042"}}}}}
    )
    (f,) = [f for f in scan(root).findings if f.rule == "SSG405"]
    assert "fixture-literal-0042" not in f.evidence
    assert "redacted" in f.evidence


@pytest.mark.parametrize(
    ("args", "flagged"),
    [
        (["run", "-i", "--rm", "ghcr.io/x/server:1.0"], True),
        (["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/x/server"], True),
        (["run", "-i", "--rm", "ghcr.io/x/server@sha256:" + "a" * 64], False),
    ],
)
def test_ssg406_container_digest(mcp_rules, args, flagged):
    assert ("SSG406" in mcp_rules({"command": "docker", "args": args})) is flagged


def test_mcp_servers_in_plugin_manifest(tree):
    manifest = {"name": "p", "version": "1.0.0", "mcpServers": {"s": {"command": "npx", "args": ["-y", "srv"]}}}
    assert "SSG401" in rule_ids(tree({".claude-plugin/plugin.json": manifest}))


def test_mcp_servers_file_referenced_from_manifest(tree):
    manifest = {"name": "p", "version": "1.0.0", "mcpServers": "./config/servers.json"}
    servers = {"mcpServers": {"s": {"command": "uvx", "args": ["tool"]}}}
    root = tree({".claude-plugin/plugin.json": manifest, "config/servers.json": servers})
    assert "SSG402" in rule_ids(root)


def test_mcp_json_without_wrapper_key(tree):
    assert "SSG401" in rule_ids(tree({".mcp.json": {"s": {"command": "npx", "args": ["-y", "srv"]}}}))

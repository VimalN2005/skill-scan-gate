# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-04

### Added

- `skill-scan-gate scan PATH`: walks `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, `commands/*.md`, `agents/*.md`, `hooks/hooks.json`, `.claude-plugin/*.json`, `.mcp.json`, `settings.json` and scripts under `scripts/` or `hooks/`, and applies 31 rules in seven families: instruction overrides (SSG101 to SSG104), exfiltration shapes (SSG201 to SSG204), commands in hooks, scripts and skills (SSG301 to SSG306), MCP server declarations (SSG401 to SSG406), secret-shaped strings (SSG501 to SSG503), manifests and skill front matter (SSG601 to SSG606), and repository files (SSG701, SSG702).
- Output as a table, JSON, Markdown and SARIF 2.1.0, with `--output`, `--sarif`, `--summary` and `--github-output` side outputs; `--fail-on low|medium|high|none`; exit codes 0, 1 and 2. Secret values are redacted in every format.
- `skill-scan-gate baseline PATH --out FILE` and `scan --baseline FILE`: line-shift-tolerant fingerprints so only new findings fail.
- `scan --allow FILE`: allowlist of rule and path-glob entries with reasons; unused entries are reported. `--exclude GLOB` skips paths.
- `skill-scan-gate rules`: lists every rule.
- Composite GitHub Action (`action.yml`) with inputs `path`, `fail-on`, `baseline`, `allow`, `exclude`, `sarif`, `sarif-file`, `upload-sarif`, `category` and `python-version`; job summary; SARIF upload with `github/codeql-action/upload-sarif` pinned by commit.
- Planted and clean fixtures, a run-time secret fixture generator, a self-test workflow that runs the Action on them, CI on Python 3.11, 3.12 and 3.13, a container image `ghcr.io/basitalisandhu/skill-scan-gate` published on version tags with an SPDX SBOM, a build provenance attestation and a keyless cosign signature, and PyPI trusted publishing (off until the repository variable `PYPI_PUBLISH` is set).

[Unreleased]: https://github.com/basitalisandhu/skill-scan-gate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/basitalisandhu/skill-scan-gate/releases/tag/v0.1.0

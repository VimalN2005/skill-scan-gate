# Contributing

Thanks for considering a contribution. The project is small on purpose: a file walk, a set of text rules, baselines and allowlists, four output formats, a CLI and a composite Action. The most useful contributions are false positives and misses with a minimal reproduction, and new rules for shapes that show up in real skills and plugins.

## Set up

Requires Python 3.11 or newer. With [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/basitalisandhu/skill-scan-gate
cd skill-scan-gate
uv venv && uv pip install -e ".[dev]"
uv run pytest -q
```

Without uv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Before you open a pull request

```bash
make check      # ruff check, ruff format --check, pytest
make demo       # planted fixture must fail, clean fixture must pass
```

CI runs the same on Python 3.11, 3.12 and 3.13, builds the container image, and runs the Action against the fixtures (`.github/workflows/self-test.yml`).

## Where things live

- `src/skill_scan_gate/rules.py`: the rule catalogue (id, family, severity, title, remediation).
- `src/skill_scan_gate/patterns.py`: the regular expressions and predicates behind the rules.
- `src/skill_scan_gate/discover.py`: which files are read and what kind each one is.
- `src/skill_scan_gate/scanner.py`: applies the rules and builds findings and fingerprints.
- `src/skill_scan_gate/suppress.py`: baselines and allowlists.
- `src/skill_scan_gate/report.py`: table, JSON, Markdown and SARIF.
- `action.yml`: the composite Action.

## Adding or changing a rule

1. Add the rule to `rules.py` with a one-sentence remediation that says what to do, not how the pattern could be abused.
2. Add a section to `docs/rules.md` and a row to the README rules table; `tests/test_docs.py` checks both.
3. Add at least one positive and one negative test. If the shape can be committed safely, add an example to `tests/fixtures/fixture-planted` and update `PLANTED_EXPECTED` in `tests/test_fixtures.py`; the clean fixture must keep zero findings.

## Fixtures and secret-shaped values

Fixture directories are named `fixture-*`. Never commit a value in a real credential format, not even a fake one: build it at run time from parts, as `tests/make_secret_fixture.py` does. Do not name fixture files `.env` or `settings.local.json`.

## Style

- `ruff` formats and lints; line length 120.
- Standard library only at run time. A pull request that adds a runtime dependency will be asked to remove it.
- No model names or vendor identifiers in code, docs or fixtures; Claude Code as the host product is fine.
- Plain language, no em dashes, no claims that cannot be checked against documentation or a test.
- Deterministic output: the same tree produces the same findings in the same order.

## Reporting security issues

See [SECURITY.md](SECURITY.md).

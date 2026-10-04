# Good first issues

Issues the maintainer intends to open under the `good first issue` label, written out so they can be filed in one sitting. Each is self-contained and has acceptance criteria that `make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must pass, the package stays standard-library only, tests build their trees in `tmp_path`, and secret-shaped test values are assembled at run time.

## 1. `--changed-only` for pull requests

**Context.** On a large skills repository, reviewers care most about findings in the files a pull request touches.

**Acceptance criteria.**

- `scan --changed-only BASE_REF` runs `git diff --name-only BASE_REF...HEAD` and reports findings only in those files; repository rules (SSG7xx) still run.
- A missing `git` binary or an unknown ref is exit code 2 with a clear message.
- The Action gains a `changed-only` input that passes `github.event.pull_request.base.sha` when set.
- Tests create a throwaway git repository in `tmp_path`.

## 2. Hook matchers that see every tool call

**Context.** A `PreToolUse` or `PostToolUse` hook with no matcher, `*` or `.*` receives the input and output of every tool call, which matters when the same hook also makes network calls.

**Acceptance criteria.**

- New rule `SSG307` (low) on a hook group with an all-matching matcher, raised to medium when one of its commands also triggers SSG202 or calls curl or wget.
- A section in `docs/rules.md`, a row in the README rules table, and a positive and a negative test.

## 3. Markdown link targets in skills

**Context.** SSG201 and SSG204 read bare URLs. A Markdown link such as `[status](https://...)` is read the same way, but reference-style links (`[status][1]` with `[1]: https://...` at the bottom) are worth a dedicated test.

**Acceptance criteria.**

- Tests cover inline links, reference-style links and autolinks (`<https://...>`) for SSG201 and SSG204.
- Any miss is fixed in `patterns.URL` without new false positives in `tests/fixtures/fixture-clean`.

## 4. `--format github` annotations

**Context.** Without code scanning (private repositories on plans without it), findings are easiest to see as workflow annotations on the changed lines.

**Acceptance criteria.**

- `scan --format github` prints one `::error file=...,line=...,title=RULE::message` line per finding (`::warning` for medium, `::notice` for low), with paths relative to the working directory like the SARIF output.
- Messages are escaped as the workflow command syntax requires (`%`, `\r`, `\n`, `:` and `,` in properties).
- Tests compare the output for the planted fixture against a golden file.

## 5. Read `allowed-tools` from skill front matter

**Context.** A skill can declare `allowed-tools`. A skill that grants itself `Bash` with no restriction deserves a reviewer's attention.

**Acceptance criteria.**

- New rule `SSG607` (low): `allowed-tools` includes `Bash` or `Bash(*)` without a command pattern.
- The front matter parser handles both the comma-separated string and the YAML list form.
- Documentation and positive and negative tests as for any rule.

## 6. Configurable blob threshold

**Context.** SSG203 uses fixed thresholds (200 base64 or 256 hex characters). Some repositories ship legitimate inline data.

**Acceptance criteria.**

- `scan --blob-min N` (default 200, minimum 64) sets the base64 threshold; the hex threshold stays 56 characters longer.
- The JSON report records the threshold used.
- Tests cover the default, a raised threshold that suppresses a blob, and the minimum.

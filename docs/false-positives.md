# False positives, baselines and allowlists

Every rule is a text heuristic, so some findings will be correct matches on text that is fine in context: a security skill that quotes an injection phrase as an example, a hook that posts build status to your own chat webhook, a test fixture. There are two ways to accept a finding without turning the rule off, and both live in files a reviewer can see.

## Baseline: accept what is there today

Use a baseline when you adopt the gate on an existing repository and want it to fail only on findings introduced from now on.

```bash
skill-scan-gate baseline . --out .skill-scan-gate-baseline.json
git add .skill-scan-gate-baseline.json
skill-scan-gate scan . --baseline .skill-scan-gate-baseline.json
```

In the Action:

```yaml
- uses: basitalisandhu/skill-scan-gate@v0.1.0
  with:
    baseline: .skill-scan-gate-baseline.json
```

How matching works:

- Each finding has a fingerprint: a hash of the rule id, the file path and the whitespace-normalised text of the line. The line number is not part of it, so adding or removing lines elsewhere in a file does not turn known findings into new ones.
- Editing the line itself, renaming the file or adding a second identical line produces a new fingerprint, and the finding counts again. That is deliberate: a changed line deserves another look.
- Each baseline entry suppresses one finding. If the same text appears twice and the baseline holds one entry, the second occurrence is new.
- Suppressed findings are counted in the table summary, the JSON `summary.suppressedByBaseline`, the job summary and the Action output `suppressed-count`. They are left out of the SARIF report.

Regenerate the baseline after you fix findings so it does not keep suppressing text that has gone. A baseline is not a list of approved exceptions; it is a snapshot. For lasting exceptions, use an allowlist.

## Allowlist: documented exceptions

An allowlist is a text file with one entry per line:

```text
# rule   path glob                    reason
SSG204   skills/notify/SKILL.md       # posts build status to our own chat webhook
SSG302   hooks/install.sh:12          # writes shell completion, reviewed 2026-10
SSG101   skills/injection-review/**   # quotes injection phrases as examples to detect
*        vendor/**                    # third-party copy, scanned upstream
```

- The first field is a rule id or `*` for every rule.
- The second is a glob matched against the path relative to the scanned directory (`*` also matches `/`). Add `:LINE` to accept one line only.
- Everything after `#` is a comment. Write the reason; the next reviewer will need it.
- An entry that matches nothing is reported as a warning, so stale entries surface.
- An unknown rule id or a malformed line is an error (exit code 2), not a silent no-op.

```bash
skill-scan-gate scan . --allow .skill-scan-gate-allow
```

## Excluding paths

`--exclude GLOB` (repeatable; the Action input `exclude` takes one glob per line) skips files entirely. Use it for directories that are not part of what you ship, such as test fixtures:

```bash
skill-scan-gate scan . --exclude 'tests/fixtures/**'
```

Prefer an allowlist entry for a file you ship: an excluded file is not scanned at all, so a later, real problem in it would go unseen.

## Why there are no inline ignore comments

Many linters accept a comment such as `# noqa` next to the code. skill-scan-gate does not, on purpose. The files it scans are read by a model, and the people most likely to add an ignore comment next to an instruction-override phrase are the people who wrote the phrase. Keeping exceptions in a baseline or allowlist file at the repository root means:

- an exception is a visible change in a pull request, not a comment buried in a skill;
- you can protect the files with CODEOWNERS so that only maintainers can approve new exceptions;
- the gate cannot be switched off from inside the content it is checking.

Add the baseline and allowlist paths to `.github/CODEOWNERS`, for example:

```text
/.skill-scan-gate-baseline.json  @your-org/security
/.skill-scan-gate-allow          @your-org/security
```

## Reporting a false positive

If a rule fires on text that is common and clearly fine, open an issue with the smallest file that reproduces it and say what you expected. Tightening a rule is better than every user allowlisting the same thing.

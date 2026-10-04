# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability") rather than a public issue. Include the version, the smallest repository tree that reproduces the problem, and what you expected to happen.

You will get an acknowledgement within 7 days and a fix or a mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Scope

skill-scan-gate reads the files of the directory it is given and writes only the reports you ask for (`--output`, `--sarif`, `--summary`, `--github-output`, `baseline --out`). It executes nothing it reads, makes no network calls and has no runtime dependencies outside the Python standard library. The composite Action adds one network step, the optional SARIF upload to your repository's code scanning.

Issues of interest:

- a file layout that makes the scanner read or write outside the scanned directory and the report paths, or follow a symbolic link;
- input that makes the scanner crash, hang or use unbounded memory;
- a secret value that appears unredacted in any output format;
- an Action input that is interpreted as shell code or workflow expression rather than data;
- a baseline or allowlist that suppresses more than its entries say it should;
- SARIF output that GitHub code scanning attributes to the wrong file or line.

Out of scope: rules that miss deliberately obfuscated text, and false positives. Both are still welcome as ordinary issues with a minimal reproduction.

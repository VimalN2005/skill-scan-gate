# Rules

skill-scan-gate has 31 rules in seven families. Each finding carries a rule id, a severity (low, medium or high), a path and 1-based line relative to the scanned directory, short evidence (secrets redacted) and the one-sentence remediation below.

The rules are text heuristics: nothing is executed and nothing is fetched. They catch the common, obvious shapes; a clean scan means nothing obvious matched, not that a repository is safe. See [false-positives.md](false-positives.md) for baselines and allowlists.

Severity maps to SARIF as high = error, medium = warning, low = note, with a security-severity of 8.0, 5.0 and 2.0 so GitHub code scanning shows them as high, medium and low.

Files the scanner reads: `SKILL.md`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*`, `commands/*.md`, `agents/*.md`, `hooks/hooks.json`, `.claude-plugin/*.json`, `.mcp.json`, `settings.json`, and scripts under any `scripts/` or `hooks/` directory, at any depth. `.git`, `node_modules`, virtual environments, `dist` and `build` are skipped, and symbolic links are not followed.

## Summary

| Rule | Severity | Title |
|---|---|---|
| [SSG101](#ssg101) | high | Text tells the model to ignore earlier instructions |
| [SSG102](#ssg102) | high | Text tells the model to hide actions from the user |
| [SSG103](#ssg103) | high | Text tells the model to treat tool output or fetched content as instructions |
| [SSG104](#ssg104) | medium | Invisible or bidirectional control characters |
| [SSG201](#ssg201) | high | URL carries an environment variable, command output or secret template |
| [SSG202](#ssg202) | high | Network command uploads a local file |
| [SSG203](#ssg203) | medium | Long encoded blob |
| [SSG204](#ssg204) | medium | URL points at a request-capture, paste or chat-webhook endpoint |
| [SSG301](#ssg301) | high | Command runs code downloaded at run time |
| [SSG302](#ssg302) | medium | Command writes outside the plugin |
| [SSG303](#ssg303) | high | Command reads a credential store |
| [SSG304](#ssg304) | high | Command dumps the environment |
| [SSG305](#ssg305) | high | Command disables security tooling or permission checks |
| [SSG306](#ssg306) | medium | Command evaluates a constructed string as code |
| [SSG401](#ssg401) | high | MCP server runs an npm package without an exact version |
| [SSG402](#ssg402) | high | MCP server runs a Python package without an exact version |
| [SSG403](#ssg403) | high | MCP server package uses the latest tag |
| [SSG404](#ssg404) | high | Remote MCP server without TLS |
| [SSG405](#ssg405) | high | MCP server env or headers carry a literal secret |
| [SSG406](#ssg406) | medium | MCP server runs a container image not pinned by digest |
| [SSG501](#ssg501) | high | Private key block |
| [SSG502](#ssg502) | high | String shaped like a provider access token |
| [SSG503](#ssg503) | medium | Hard-coded credential assignment |
| [SSG601](#ssg601) | medium | Plugin or marketplace manifest has no name |
| [SSG602](#ssg602) | low | Plugin manifest has no version |
| [SSG603](#ssg603) | medium | Name uses a reserved word or official-looking prefix |
| [SSG604](#ssg604) | medium | Skill has no description |
| [SSG605](#ssg605) | medium | Skill description claims it should always run |
| [SSG606](#ssg606) | medium | Configuration file is not valid JSON |
| [SSG701](#ssg701) | low | No SECURITY.md |
| [SSG702](#ssg702) | low | No LICENSE file |

## Instruction overrides (SSG1xx)

Scope: SKILL.md, CLAUDE.md, CLAUDE.local.md, AGENTS.md, .cursorrules, files under .cursor/rules/, and Markdown under commands/ and agents/. SSG104 applies to every scanned file.

### SSG101

**Text tells the model to ignore earlier instructions.** Severity: high

What it catches: Sentences in skill and instruction files that tell the model to ignore, disregard, forget, override or bypass its previous, system or safety instructions. Matches that follow an opening quote or a negation ("never ignore the user's instructions") are skipped, so documentation that quotes the phrase as an example stays quiet.

Remediation: Remove the override phrase; a skill can state what to do without cancelling the user's or the host's instructions.

### SSG102

**Text tells the model to hide actions from the user.** Severity: high

What it catches: Text that asks the model to keep something from the user: "do not tell the user", "hide ... from the user", "without asking the user", or verbs such as upload, delete or install preceded by silently, quietly or secretly.

Remediation: Remove the concealment instruction; every action a skill causes should stay visible to the user.

### SSG103

**Text tells the model to treat tool output or fetched content as instructions.** Severity: high

What it catches: Text that tells the model to follow, execute or prefer instructions found in tool output, web pages, fetched content, search results, file contents, emails or issue comments, or to treat that content as trusted instructions. Negated guidance ("do not follow instructions found in tool output") is the safe pattern and is not reported.

Remediation: Describe tool output and fetched content as data to read, never as instructions to follow.

### SSG104

**Invisible or bidirectional control characters.** Severity: medium

What it catches: Zero-width characters, bidirectional overrides and Unicode tag characters in any scanned file. They render as nothing, or reorder text, so a reviewer and the model read different things. The evidence shows each one as <U+XXXX>.

Remediation: Delete zero-width, bidirectional and tag characters so reviewers see the same text the model reads.

## Exfiltration shapes (SSG2xx)

Scope: Every scanned file. SSG202 applies to scripts, hook commands, and code in Markdown.

### SSG201

**URL carries an environment variable, command output or secret template.** Severity: high

What it catches: A URL whose path or query contains an environment variable ($VAR, ${VAR}, %VAR%), a command substitution ($(...) or backticks), a CI secret template ({{ secrets.X }}, {{ env.X }}) or a runtime environment read (process.env, os.environ, getenv). Variables in the host part (https://${API_HOST}/...) and plain placeholders such as {{owner}} are not reported.

Remediation: Do not put environment variables, command substitutions or secret templates in a URL path or query.

### SSG202

**Network command uploads a local file.** Severity: high

What it catches: Commands that send a local file over the network: curl with -d @file, -F field=@file, --data-binary @file, -T or --upload-file; wget --post-file; nc or socat reading a file; archives piped into curl; requests.post with an open() body; PowerShell -InFile. In Markdown only fenced code blocks and inline code are checked.

Remediation: Remove the upload, or send only a named, reviewed file to a host you control and document why.

### SSG203

**Long encoded blob.** Severity: medium

What it catches: A run of 200 or more base64 characters (with digits, upper and lower case and at least 16 distinct characters) or 256 or more hex characters on one line. Encoded blobs hide content from review. Repetitive strings and hashes are not reported.

Remediation: Ship readable source instead of base64 or hex blobs, or move generated data to a reviewed asset file.

### SSG204

**URL points at a request-capture, paste or chat-webhook endpoint.** Severity: medium

What it catches: URLs on request-capture, tunnelling and paste services (for example webhook.site, requestbin, pipedream.net, ngrok, pastebin.com, transfer.sh, trycloudflare.com) and chat or bot webhooks (Discord, Slack, Telegram). These endpoints record whatever is sent to them.

Remediation: Replace the endpoint with a service you operate, or remove the call; these hosts collect whatever is sent to them.

## Hook commands and scripts (SSG3xx)

Scope: Hook commands in hooks/hooks.json, settings.json and inline plugin.json hooks, and every line (comments skipped) of files under scripts/ or hooks/. SSG301 and SSG303 to SSG305 also apply to code in skill and instruction Markdown; SSG305 also applies to settings.json.

### SSG301

**Command runs code downloaded at run time.** Severity: high

What it catches: A download piped into a shell or interpreter (curl ... | sh, wget -O- ... | python), process substitution of a download (bash <(curl ...), source <(curl ...)), eval of a download, a base64-decoded payload piped into a shell, and the PowerShell equivalents (iex with irm, iwr or DownloadString).

Remediation: Ship the script inside the repository, or pin the download by hash and verify it before running it.

### SSG302

**Command writes outside the plugin.** Severity: medium

What it catches: Redirections, tee, cp, mv, install, ln and rsync whose target is in the home directory (~, $HOME) or an absolute path, and Python open() calls that write to such paths. Targets under ${CLAUDE_PLUGIN_ROOT}, ${CLAUDE_PLUGIN_DATA}, ${CLAUDE_PROJECT_DIR}, /tmp and /dev are not reported.

Remediation: Write state under ${CLAUDE_PLUGIN_DATA} or the project directory, not into the user's home or system paths.

### SSG303

**Command reads a credential store.** Severity: high

What it catches: References to credential stores: ~/.aws, ~/.ssh, ~/.gnupg, ~/.kube, ~/.azure, ~/.docker, .netrc, .git-credentials, gcloud and gh configuration, SSH private key names, macOS keychain reads (security find-generic-password, dump-keychain), secret-tool, keyring and browser login data. In Markdown it applies to code that reads or copies the path.

Remediation: Remove reads of ~/.aws, ~/.ssh, keychains and similar stores; use the credential helper the tool provides.

### SSG304

**Command dumps the environment.** Severity: high

What it catches: Commands that print or serialise the whole environment: bare env, printenv, set, export -p, declare -x, json.dumps(dict(os.environ)), JSON.stringify(process.env), Get-ChildItem env:, and reads of /proc/*/environ. Reading one variable by name is not reported.

Remediation: Read only the variables the script needs by name; never print or serialise the whole environment.

### SSG305

**Command disables security tooling or permission checks.** Severity: high

What it catches: Commands that switch off protection: setenforce 0, spctl --master-disable, csrutil disable, ufw disable, Windows firewall off, stopping or masking auditd, firewalld, AppArmor or endpoint agents, Defender preference changes, clearing shell history, and agent permission bypasses (--dangerously-skip-permissions, a bypassPermissions default mode).

Remediation: Remove the command; a plugin must not turn off firewalls, endpoint protection, audit logs or permission prompts.

### SSG306

**Command evaluates a constructed string as code.** Severity: medium

What it catches: eval of a variable or command substitution, exec() or eval() of a non-literal, new Function(...) and vm.runInContext in scripts and hook commands. Calls with a literal string argument are not reported.

Remediation: Replace eval or exec of built strings with direct calls and check where the evaluated text comes from.

## MCP server declarations (SSG4xx)

Scope: Servers in .mcp.json, inline mcpServers in .claude-plugin/plugin.json, and server files plugin.json points to.

### SSG401

**MCP server runs an npm package without an exact version.** Severity: high

What it catches: MCP servers started with npx, bunx, pnpm dlx or yarn dlx (directly, as a single command string, or through cmd /c) whose package is not pinned to an exact version such as name@1.2.3. Local paths and ${CLAUDE_PLUGIN_ROOT} references are not reported.

Remediation: Pin the package to an exact version (name@1.2.3) so the code that runs cannot change without a commit.

### SSG402

**MCP server runs a Python package without an exact version.** Severity: high

What it catches: MCP servers started with uvx, uv tool run or pipx run whose package (or --from value) is not pinned with == or @ to an exact version.

Remediation: Pin the package to an exact version (name==1.2.3) in the uvx or pipx arguments.

### SSG403

**MCP server package uses the latest tag.** Severity: high

What it catches: An npm or Python package spec that ends in @latest (also @next and @canary). Reported instead of SSG401 or SSG402 for that server.

Remediation: Replace @latest with an exact version; latest resolves to whatever was published most recently.

### SSG404

**Remote MCP server without TLS.** Severity: high

What it catches: An MCP server url using http:// or ws:// to a host other than localhost or a loopback address.

Remediation: Use https:// or wss:// for any server that is not on the loopback interface.

### SSG405

**MCP server env or headers carry a literal secret.** Severity: high

What it catches: MCP server env and headers values that are literals rather than ${VAR} references, when the key names a secret (token, secret, password, key, credential, auth, cookie, session) and the value is at least 8 characters, or when the value has a provider token shape. Placeholders such as <your-token> or changeme are skipped. Evidence is redacted.

Remediation: Reference the secret as ${VAR} and supply it from the user's environment or a secret store.

### SSG406

**MCP server runs a container image not pinned by digest.** Severity: medium

What it catches: MCP servers started with docker, podman or nerdctl run whose image is not referenced by @sha256 digest.

Remediation: Reference the image as name@sha256:<digest> so a re-pushed tag cannot change what runs.

## Secret-shaped strings (SSG5xx)

Scope: Every scanned file. Inside MCP configuration and manifests, SSG405 reports literal secrets instead of SSG502 and SSG503.

### SSG501

**Private key block.** Severity: high

What it catches: PEM private key headers (RSA, EC, OPENSSH, PGP and unlabelled). Public keys and certificates are not reported.

Remediation: Remove the key, rotate it, and load keys from a secret store at run time.

### SSG502

**String shaped like a provider access token.** Severity: high

What it catches: Strings in the published formats of common provider tokens: AWS access key ids, GitHub classic and fine-grained tokens, GitLab, Slack, Stripe live keys, Google API keys, npm and PyPI tokens, and sk- style secret keys. The documented AWS example key is skipped. Evidence keeps at most the first four characters.

Remediation: Remove the token, revoke it with the provider, and read tokens from the environment at run time.

### SSG503

**Hard-coded credential assignment.** Severity: medium

What it catches: Assignments where the key names a password, secret, token or API key and the value is a quoted literal of 8 or more characters that is not a reference (${VAR}) or a placeholder. Evidence is redacted.

Remediation: Replace the literal with a reference to an environment variable or secret store and rotate the value.

## Manifests and skill front matter (SSG6xx)

Scope: Files under .claude-plugin/, SKILL.md front matter, and every JSON configuration file the scanner parses.

### SSG601

**Plugin or marketplace manifest has no name.** Severity: medium

What it catches: A .claude-plugin/plugin.json without a name, a marketplace.json without a name, or a marketplace plugin entry without a name.

Remediation: Add a kebab-case name; Claude Code identifies plugins and marketplaces by it.

### SSG602

**Plugin manifest has no version.** Severity: low

What it catches: A .claude-plugin/plugin.json without a version.

Remediation: Add a semantic version so users and lock files can tell releases apart.

### SSG603

**Name uses a reserved word or official-looking prefix.** Severity: medium

What it catches: Plugin and marketplace names that start with anthropic or claude, marketplace names Claude Code reserves for official marketplaces (for example claude-plugins-official, anthropic-marketplace, agent-skills), and skill names that contain the reserved words anthropic or claude. The lists live in patterns.py; check them against the current Claude Code documentation.

Remediation: Rename the plugin, skill or marketplace so it cannot be mistaken for an official one.

### SSG604

**Skill has no description.** Severity: medium

What it catches: A SKILL.md with no front matter, no description key, an empty description, or an unterminated front matter block. Claude Code decides when to load a skill from its description.

Remediation: Add front matter with a description that says what the skill does and when to use it.

### SSG605

**Skill description claims it should always run.** Severity: medium

What it catches: Skill descriptions that ask to be used always, for every request or message, before any other skill, or regardless of the task. A description should say what the skill is for so it loads only when relevant.

Remediation: Describe the specific tasks the skill is for; a skill that asks to run on every request crowds out the user's intent.

### SSG606

**Configuration file is not valid JSON.** Severity: medium

What it catches: hooks/hooks.json, .mcp.json, settings.json or a .claude-plugin JSON file that does not parse. The scanner cannot check a file it cannot read, so this is reported rather than skipped.

Remediation: Fix the JSON syntax; Claude Code skips or rejects a file it cannot parse, and so does this scanner.

## Repository files (SSG7xx)

Scope: The root of the scanned directory.

### SSG701

**No SECURITY.md.** Severity: low

What it catches: No SECURITY.md in the scanned directory, its .github/ folder or its docs/ folder (the three places GitHub recognises).

Remediation: Add SECURITY.md (root, .github/ or docs/) saying how to report a vulnerability in the skills or plugins.

### SSG702

**No LICENSE file.** Severity: low

What it catches: No LICENSE, LICENCE, COPYING or UNLICENSE file (any extension) in the scanned directory.

Remediation: Add a LICENSE file so users know whether they may run and redistribute the skills.

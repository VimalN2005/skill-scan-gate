"""Rule catalogue: id, family, severity, title and a one-sentence remediation.

Every rule here has a section in docs/rules.md (tests/test_docs.py checks that).
Titles say what a pattern does; they never describe how to abuse it.
"""

from __future__ import annotations

from dataclasses import dataclass

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
SEVERITIES = (LOW, MEDIUM, HIGH)
SEVERITY_RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}

HELP_URI = "https://github.com/basitalisandhu/skill-scan-gate/blob/main/docs/rules.md"


@dataclass(frozen=True)
class Rule:
    id: str
    family: str
    severity: str
    title: str
    remediation: str

    @property
    def anchor(self) -> str:
        return f"{HELP_URI}#{self.id.lower()}"


_RULES = [
    # (a) instruction overrides in skill and instruction text
    Rule(
        "SSG101",
        "instructions",
        HIGH,
        "Text tells the model to ignore earlier instructions",
        "Remove the override phrase; a skill can state what to do without cancelling the user's or the host's instructions.",
    ),
    Rule(
        "SSG102",
        "instructions",
        HIGH,
        "Text tells the model to hide actions from the user",
        "Remove the concealment instruction; every action a skill causes should stay visible to the user.",
    ),
    Rule(
        "SSG103",
        "instructions",
        HIGH,
        "Text tells the model to treat tool output or fetched content as instructions",
        "Describe tool output and fetched content as data to read, never as instructions to follow.",
    ),
    Rule(
        "SSG104",
        "instructions",
        MEDIUM,
        "Invisible or bidirectional control characters",
        "Delete zero-width, bidirectional and tag characters so reviewers see the same text the model reads.",
    ),
    # (b) exfiltration shapes
    Rule(
        "SSG201",
        "exfiltration",
        HIGH,
        "URL carries an environment variable, command output or secret template",
        "Do not put environment variables, command substitutions or secret templates in a URL path or query.",
    ),
    Rule(
        "SSG202",
        "exfiltration",
        HIGH,
        "Network command uploads a local file",
        "Remove the upload, or send only a named, reviewed file to a host you control and document why.",
    ),
    Rule(
        "SSG203",
        "exfiltration",
        MEDIUM,
        "Long encoded blob",
        "Ship readable source instead of base64 or hex blobs, or move generated data to a reviewed asset file.",
    ),
    Rule(
        "SSG204",
        "exfiltration",
        MEDIUM,
        "URL points at a request-capture, paste or chat-webhook endpoint",
        "Replace the endpoint with a service you operate, or remove the call; these hosts collect whatever is sent to them.",
    ),
    # (c) hook commands and scripts
    Rule(
        "SSG301",
        "hooks",
        HIGH,
        "Command runs code downloaded at run time",
        "Ship the script inside the repository, or pin the download by hash and verify it before running it.",
    ),
    Rule(
        "SSG302",
        "hooks",
        MEDIUM,
        "Command writes outside the plugin",
        "Write state under ${CLAUDE_PLUGIN_DATA} or the project directory, not into the user's home or system paths.",
    ),
    Rule(
        "SSG303",
        "hooks",
        HIGH,
        "Command reads a credential store",
        "Remove reads of ~/.aws, ~/.ssh, keychains and similar stores; use the credential helper the tool provides.",
    ),
    Rule(
        "SSG304",
        "hooks",
        HIGH,
        "Command dumps the environment",
        "Read only the variables the script needs by name; never print or serialise the whole environment.",
    ),
    Rule(
        "SSG305",
        "hooks",
        HIGH,
        "Command disables security tooling or permission checks",
        "Remove the command; a plugin must not turn off firewalls, endpoint protection, audit logs or permission prompts.",
    ),
    Rule(
        "SSG306",
        "hooks",
        MEDIUM,
        "Command evaluates a constructed string as code",
        "Replace eval or exec of built strings with direct calls and check where the evaluated text comes from.",
    ),
    # (d) MCP server declarations
    Rule(
        "SSG401",
        "mcp",
        HIGH,
        "MCP server runs an npm package without an exact version",
        "Pin the package to an exact version (name@1.2.3) so the code that runs cannot change without a commit.",
    ),
    Rule(
        "SSG402",
        "mcp",
        HIGH,
        "MCP server runs a Python package without an exact version",
        "Pin the package to an exact version (name==1.2.3) in the uvx or pipx arguments.",
    ),
    Rule(
        "SSG403",
        "mcp",
        HIGH,
        "MCP server package uses the latest tag",
        "Replace @latest with an exact version; latest resolves to whatever was published most recently.",
    ),
    Rule(
        "SSG404",
        "mcp",
        HIGH,
        "Remote MCP server without TLS",
        "Use https:// or wss:// for any server that is not on the loopback interface.",
    ),
    Rule(
        "SSG405",
        "mcp",
        HIGH,
        "MCP server env or headers carry a literal secret",
        "Reference the secret as ${VAR} and supply it from the user's environment or a secret store.",
    ),
    Rule(
        "SSG406",
        "mcp",
        MEDIUM,
        "MCP server runs a container image not pinned by digest",
        "Reference the image as name@sha256:<digest> so a re-pushed tag cannot change what runs.",
    ),
    # (e) secret-shaped strings
    Rule(
        "SSG501",
        "secrets",
        HIGH,
        "Private key block",
        "Remove the key, rotate it, and load keys from a secret store at run time.",
    ),
    Rule(
        "SSG502",
        "secrets",
        HIGH,
        "String shaped like a provider access token",
        "Remove the token, revoke it with the provider, and read tokens from the environment at run time.",
    ),
    Rule(
        "SSG503",
        "secrets",
        MEDIUM,
        "Hard-coded credential assignment",
        "Replace the literal with a reference to an environment variable or secret store and rotate the value.",
    ),
    # (f) manifest problems
    Rule(
        "SSG601",
        "manifest",
        MEDIUM,
        "Plugin or marketplace manifest has no name",
        "Add a kebab-case name; Claude Code identifies plugins and marketplaces by it.",
    ),
    Rule(
        "SSG602",
        "manifest",
        LOW,
        "Plugin manifest has no version",
        "Add a semantic version so users and lock files can tell releases apart.",
    ),
    Rule(
        "SSG603",
        "manifest",
        MEDIUM,
        "Name uses a reserved word or official-looking prefix",
        "Rename the plugin, skill or marketplace so it cannot be mistaken for an official one.",
    ),
    Rule(
        "SSG604",
        "manifest",
        MEDIUM,
        "Skill has no description",
        "Add front matter with a description that says what the skill does and when to use it.",
    ),
    Rule(
        "SSG605",
        "manifest",
        MEDIUM,
        "Skill description claims it should always run",
        "Describe the specific tasks the skill is for; a skill that asks to run on every request crowds out the user's intent.",
    ),
    Rule(
        "SSG606",
        "manifest",
        MEDIUM,
        "Configuration file is not valid JSON",
        "Fix the JSON syntax; Claude Code skips or rejects a file it cannot parse, and so does this scanner.",
    ),
    # (g) repository hygiene
    Rule(
        "SSG701",
        "repository",
        LOW,
        "No SECURITY.md",
        "Add SECURITY.md (root, .github/ or docs/) saying how to report a vulnerability in the skills or plugins.",
    ),
    Rule(
        "SSG702",
        "repository",
        LOW,
        "No LICENSE file",
        "Add a LICENSE file so users know whether they may run and redistribute the skills.",
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}
FAMILIES = (
    "instructions",
    "exfiltration",
    "hooks",
    "mcp",
    "secrets",
    "manifest",
    "repository",
)


def at_or_above(severity: str, threshold: str) -> bool:
    if threshold == "none":
        return False
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]


__all__ = [
    "FAMILIES",
    "HELP_URI",
    "HIGH",
    "LOW",
    "MEDIUM",
    "RULES",
    "SEVERITIES",
    "SEVERITY_RANK",
    "Rule",
    "at_or_above",
]

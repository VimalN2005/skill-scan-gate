"""Regular expressions and small predicates behind the rules.

All of these are heuristics over text. They aim at the common, obvious cases with a
low false-positive rate; docs/false-positives.md explains how to handle the rest.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------- (a) instructions

OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|discard)\b[^.\n]{0,40}?"
    r"\b(?:previous|prior|above|earlier|preceding|all|any|your|system|safety|other|existing|original)\b"
    r"[^.\n]{0,25}?"
    r"\b(?:instructions?|prompts?|rules|guidelines|directives|guardrails|polic(?:y|ies)|constraints)\b",
    re.IGNORECASE,
)
CONCEAL = re.compile(
    r"\b(?:do\s+not|don't|dont|never)\s+(?:tell|inform|notify|mention|reveal|show|disclose|alert|report)\b"
    r"[^.\n]{0,40}?\b(?:the\s+)?user\b"
    r"|\b(?:hide|conceal|keep)\b[^.\n]{0,30}?\b(?:from|secret\s+from)\s+(?:the\s+)?user\b"
    r"|\b(?:silently|quietly|secretly|covertly)\b[^.\n]{0,20}?\b(?:run|execute|send|upload|delete|modify|install|post|copy)\b"
    r"|\bwithout\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+)?user\b",
    re.IGNORECASE,
)
_SOURCES = (
    r"(?:tool\s+(?:output|outputs|results?|responses?)|web\s*pages?|websites?|fetched\s+(?:content|pages?|text)"
    r"|search\s+results?|file\s+contents?|retrieved\s+(?:content|documents?|text)|emails?|issue\s+comments?"
    r"|(?:mcp|server)\s+responses?|command\s+output)"
)
TOOL_OUTPUT_AS_INSTRUCTIONS = re.compile(
    r"\b(?:follow|obey|execute|carry\s+out|act\s+on|comply\s+with|run)\b[^.\n]{0,30}?"
    r"\b(?:instructions?|directions?|commands?|directives?)\b[^.\n]{0,25}?"
    r"\b(?:in|inside|within|from|contained\s+in|embedded\s+in|found\s+in|returned\s+by)\b[^.\n]{0,15}?"
    + _SOURCES
    + r"|\btreat\b[^.\n]{0,20}?"
    + _SOURCES
    + r"[^.\n]{0,20}?\bas\b[^.\n]{0,15}?\b(?:instructions?|commands?|trusted|authoritative)\b"
    r"|\binstructions?\b[^.\n]{0,15}?\b(?:in|from)\b[^.\n]{0,15}?"
    + _SOURCES
    + r"[^.\n]{0,30}?\b(?:take|takes|have|has)\s+(?:precedence|priority)\b",
    re.IGNORECASE,
)
NEGATION_BEFORE = re.compile(
    r"\b(?:not|never|don't|dont|do\s+not|no|avoid|refuse\s+to|must\s+not|should\s+not)\b[^.\n]{0,12}$",
    re.IGNORECASE,
)
HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
QUOTE_CHARS = "\"'`\u201c\u2018"

# ---------------------------------------------------------------- (b) exfiltration

URL = re.compile(r"(?:https?|wss?)://(?:\{\{[^}\n]*\}\}|[^\s<>\"'`)\]])+", re.IGNORECASE)
URL_TEMPLATE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-[^}]*)?\}"  # ${VAR} or ${VAR:-x}
    r"|\$[A-Z_][A-Z0-9_]{1,}"  # $VAR
    r"|\$\("  # $(command)
    r"|`[^`]+`"  # backtick command substitution
    r"|%[A-Z_][A-Z0-9_]{1,}%"  # %VAR% (Windows)
    r"|%24%7B|%24%28"  # URL-encoded ${ and $(
    r"|\{\{\s*(?:secrets|env|vars)\.[^}]*\}\}"  # {{ secrets.X }}
    r"|process\.env|os\.environ|getenv\(",
)
UPLOAD = re.compile(
    r"\bcurl\b[^\n]*?(?:\s(?:-d|-F|--data(?:-binary|-raw|-urlencode)?|--form|--json)[\s=]*[\"']?(?:[^\s\"'=]+=)?@"
    r"|\s(?:-T|--upload-file)\s)"
    r"|\bwget\b[^\n]*?--(?:post-file|body-file)\b"
    r"|\b(?:nc|ncat|netcat|socat)\b[^\n|]*<\s*[^\s<]"
    r"|\b(?:cat|tar|zip|base64)\b[^\n|]*\|\s*(?:curl|nc|ncat|netcat)\b"
    r"|\brequests\.(?:post|put|patch)\([^\n]*\b(?:files|data)\s*=\s*(?:\{[^\n]*)?open\("
    r"|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]*-InFile\b",
    re.IGNORECASE,
)
BLOB_MIN = 200
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{" + str(BLOB_MIN) + r",}={0,2}")
HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{" + str(BLOB_MIN + 56) + r",}\b")
CAPTURE_HOSTS = (
    "webhook.site",
    "requestbin",
    "pipedream.net",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "pastebin.com",
    "paste.ee",
    "hastebin",
    "transfer.sh",
    "interact.sh",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "burpcollaborator",
    "requestcatcher.com",
    "hookbin.com",
    "beeceptor.com",
    "trycloudflare.com",
)
CAPTURE_PATHS = (
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "hooks.slack.com/",
    "api.telegram.org/bot",
)

# ---------------------------------------------------------------- (c) hooks and scripts

REMOTE_CODE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k|fi)?sh\b"
    r"|\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby)\b"
    r"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?<?\(\s*(?:curl|wget)\b"
    r"|\b(?:source|\.)\s+<\(\s*(?:curl|wget)\b"
    r"|\beval\s+[\"']?\$\(\s*(?:curl|wget)\b"
    r"|\bbase64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:ba|z)?sh\b"
    r"|\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b"
    r"|\b(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b"
    r"|\bexec\(\s*(?:urllib\.request\.)?urlopen\(",
    re.IGNORECASE,
)
CREDENTIAL_PATH = re.compile(
    r"(?<![\w-])(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?/?\.(?:aws|ssh|gnupg|kube|azure|docker)(?=/|\b)"
    r"|\.netrc\b|\.git-credentials\b|\.config/gcloud\b|\.config/gh/hosts\.yml"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b"
    r"|\bsecurity\s+(?:dump-keychain|find-generic-password|find-internet-password|export)\b"
    r"|Library/Keychains|\bsecret-tool\s+lookup\b|\bkeyring\s+get\b|\bcmdkey\s+/list\b"
    r"|Login\s+Data\b|\bCookies\.binarycookies\b",
    re.IGNORECASE,
)
ENV_DUMP = re.compile(
    r"(?:^|;|&&|\|\||\$\(|`)\s*(?:printenv|env|export\s+-p|declare\s+-x|set)\s*(?:$|>|\|(?!\|)|;|&|\)|`)"
    r"|\b(?:json\.dumps|str|repr|print|pprint|dict)\(\s*(?:dict\()?\s*os\.environ\s*\)?\s*[),]"
    r"|\bos\.environ\.(?:items|copy)\(\)"
    r"|\bJSON\.stringify\(\s*process\.env\s*\)|\bObject\.(?:entries|keys|values)\(\s*process\.env\s*\)"
    r"|\b(?:Get-ChildItem|gci|dir|ls)\s+env:"
    r"|/proc/(?:self|\$\$|\d+)/environ\b",
    re.IGNORECASE | re.MULTILINE,
)
DISABLE_SECURITY = re.compile(
    r"\bsetenforce\s+0\b"
    r"|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b"
    r"|\bufw\s+disable\b|\bnetsh\s+advfirewall\s+set\s+\S+\s+state\s+off\b"
    r"|\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|auditd|apparmor|falcon-sensor|osqueryd|clamav\S*|wazuh-agent)\b"
    r"|\bSet-MpPreference\b[^\n]*-Disable\w+\s+\$?true\b"
    r"|\bdefaults\s+write\s+\S*alf\S*\s+globalstate\s+-int\s+0\b"
    r"|\blaunchctl\s+(?:unload|bootout)\b[^\n]*(?:alf|xprotect|falcon|santa)"
    r"|--dangerously-skip-permissions\b|\bbypassPermissions\b"
    r"|\bauditctl\s+-e\s*0\b|\bhistory\s+-c\b|\bunset\s+HISTFILE\b",
    re.IGNORECASE,
)
DYNAMIC_EVAL = re.compile(
    r"(?:^|[;&|(`]\s*)eval\s+[\"'$`(]"
    r"|(?<![\w.\"'`])eval\s*\(\s*(?![\"')])"
    r"|(?<![\w.\"'`])exec\s*\(\s*(?![\"')])"
    r"|\bnew\s+Function\s*\("
    r"|\bvm\.runIn(?:New|This)?Context\b",
)
WRITE_TARGET = re.compile(
    r"(?:(?:^|(?<=\s))\d?>>?|\btee\s+(?:-a\s+)?|\b(?:cp|mv|install|ln|rsync)\s+(?:-{1,2}[\w-]+\s+)*\S+\s+)"
    r"\s*[\"']?(?P<target>(?:~|\$HOME|\$\{HOME\}|/)[^\s\"';|&)]*)"
)
PY_WRITE = re.compile(
    r"open\(\s*(?:os\.path\.expanduser\(\s*)?[\"'](?P<target>(?:~|/)[^\"']+)[\"']\)?\s*,\s*[\"'][wax]"
)
SAFE_WRITE_PREFIXES = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd/", "/tmp/", "/tmp")
NETWORK_VERB = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)

# ---------------------------------------------------------------- (d) MCP

NPM_EXACT = re.compile(r"^(?:@[^/@\s]+/)?[^@\s]+@v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
PY_EXACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?(?:==|@)v?\d+(?:\.\d+)*(?:[-+.]?[0-9A-Za-z.]+)?$")
SECRET_KEY_NAME = re.compile(
    r"(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|client[_-]?secret|credential|auth|cookie|session)",
    re.IGNORECASE,
)
PLACEHOLDER = re.compile(
    r"^\s*$|\$\{|^\$[A-Za-z_]|^<[^>]*>$|^\{\{.*\}\}$|^(?:your|my|example|sample|dummy|test|fake|placeholder)[\w-]*$"
    r"|^(?:x+|\*+|\.+|changeme|change-me|replace-me|todo|tbd|none|null|redacted|secret|password|token)$"
    r"|^(?:Bearer|Basic|token)\s+(?:\$\{|\$[A-Za-z_]|<)|^env:|^op://|^vault:|^arn:aws:secretsmanager",
    re.IGNORECASE,
)

# ---------------------------------------------------------------- (e) secrets

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
PROVIDER_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token", re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}\b")),
    ("API secret key", re.compile(r"\bsk-(?:[a-z]{2,10}-)?[A-Za-z0-9_-]{32,}\b")),
)
CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?P<key>[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*[\"'](?P<value>[^\"'\s]{8,})[\"']",
    re.IGNORECASE,
)

# ---------------------------------------------------------------- (f) manifests

# The Agent Skills naming rules reserve the words below in skill names. Plugin and marketplace
# names that start with them, or that equal a marketplace name Claude Code reserves for official
# use, can be mistaken for official ones. Re-check both lists against the current documentation.
RESERVED_WORDS = ("anthropic", "claude")
RESERVED_MARKETPLACE_NAMES = frozenset(
    {
        "claude-code-marketplace",
        "claude-code-plugins",
        "claude-plugins-official",
        "anthropic-marketplace",
        "anthropic-plugins",
        "agent-skills",
    }
)
ALWAYS_RUN = re.compile(
    r"\balways\b[^.\n]{0,25}?\b(?:use|invoke|run|load|apply|activate|trigger)\b"
    r"|\b(?:use|invoke|run|load|apply|activate|trigger)\b[^.\n]{0,25}?"
    r"\b(?:always|on\s+every|for\s+every|for\s+all|for\s+any|in\s+every)\b[^.\n]{0,15}?"
    r"\b(?:tasks?|requests?|messages?|prompts?|conversations?|turns?|sessions?|quer(?:y|ies)|questions?)\b"
    r"|\bregardless\s+of\s+(?:the\s+)?(?:task|request|context|topic|question)\b"
    r"|\bbefore\s+(?:any|every)\s+(?:other\s+)?(?:skill|tool|response|answer)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------- predicates


def preceded_by_quote(line: str, start: int) -> bool:
    """True when a match starts right after an opening quote: an example, not an instruction."""
    return start > 0 and line[start - 1] in QUOTE_CHARS


def negated(line: str, start: int) -> bool:
    return bool(NEGATION_BEFORE.search(line[max(0, start - 40) : start]))


def npm_pinned(spec: str) -> bool:
    if spec.startswith(("./", "../", "/", "${", "file:")):
        return True
    return bool(NPM_EXACT.match(spec))


def py_pinned(spec: str) -> bool:
    if spec.startswith(("./", "../", "/", "${", "file:", "git+")):
        return spec.startswith(("./", "../", "/", "${", "file:")) or "@" in spec.split("/")[-1]
    return bool(PY_EXACT.match(spec))


def is_latest(spec: str) -> bool:
    return spec.lower().endswith(("@latest", "@next", "@canary"))


def _parse(url: str):
    try:
        parsed = urlparse(url)
        return parsed, (parsed.hostname or "").lower()
    except ValueError:  # for example an unterminated IPv6 literal
        return None, ""


def insecure_url(url: str) -> bool:
    parsed, host = _parse(url)
    if parsed is None or parsed.scheme not in ("http", "ws"):
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def url_after_host(url: str) -> str:
    """The part of a URL after scheme://host[:port], where a template would carry data out."""
    m = re.match(r"^[a-z]+://[^/?#]*", url, re.IGNORECASE)
    return url[m.end() :] if m else url


def capture_endpoint(url: str) -> bool:
    low = url.lower()
    host = _parse(url)[1]
    return any(h in host for h in CAPTURE_HOSTS) or any(p in low for p in CAPTURE_PATHS)


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value))


def looks_like_blob(token: str) -> bool:
    """A base64 run that is not a path, a URL-safe identifier or a run of one character."""
    if len(set(token)) < 16:
        return False
    has_digit = any(c.isdigit() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    return has_digit and has_upper and has_lower and token.count("/") < len(token) / 8

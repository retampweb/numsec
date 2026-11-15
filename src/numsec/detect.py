"""Rule-based static detection engine for Numsec.

The engine is deliberately small and transparent: every rule is a compiled regular
expression plus a plain-language attack scenario, impact statement and remediation
recipe. That shape is what makes the generated ``threat.md`` files useful for an
assistant *and* readable for a human, without pretending to be a full SAST tool.

Why line-based heuristics instead of AST analysis: the artefacts consumed by the
IDE assistants have to stay stable and cheap to produce, and a regex miss is
visible in the output. Rules that need context (``yaml.load`` without a safe
loader, for example) declare a ``skip`` pattern instead of building an AST walker.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .utils import shorten


class Severity(StrEnum):
    """Finding severity, ordered the way a human triages."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric weight used for sorting and threshold comparisons."""
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        """Return True when this severity is at least as severe as ``other``."""
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    title: str
    stride: str
    severity: Severity
    pattern: re.Pattern[str]
    attack_scenario: str
    impact: str
    remediation: tuple[str, ...]
    skip: re.Pattern[str] | None = None


@dataclass(frozen=True)
class Finding:
    """One rule hit in one file."""

    rule: Rule
    path: Path
    line: int
    excerpt: str

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class ScanResult:
    """Everything a scan produced, plus a little bit of provenance."""

    findings: tuple[Finding, ...]
    files_scanned: int

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda finding: finding.severity.rank).severity

    def exceeds(self, threshold: Severity) -> bool:
        """True when any finding is at least as severe as ``threshold``."""
        return any(finding.severity.at_least(threshold) for finding in self.findings)


_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?:[a-z0-9]+[_-])*(?:
        api[_-]?key | apikey | secret | client[_-]?secret | password | passwd | pwd
        | token | auth[_-]?token | access[_-]?key | private[_-]?key
    )\b
    \s*(?::=|[:=])\s*
    (?P<quote>["'])(?P<value>[^"'\n]{6,})(?P=quote)
    """
)

_SECRET_PLACEHOLDER = re.compile(
    r"""(?ix)
    os\.environ | os\.getenv | getenv\( | getpass | placeholder | changeme | change_me
    | your[_-] | example | sample | dummy | fake | redacted | x{4,} | \.{3}
    | <[^>]*> | \{\{ | \$\{
    """
)

_RULES: tuple[Rule, ...] = (
    Rule(
        id="hardcoded-secret",
        title="Hardcoded secret material in source code",
        stride="Information Disclosure",
        severity=Severity.CRITICAL,
        pattern=_SECRET_ASSIGNMENT,
        skip=_SECRET_PLACEHOLDER,
        attack_scenario=(
            "Anyone who can read the repository, a fork or a build artefact can lift the "
            "credential and replay it against the external system it unlocks."
        ),
        impact=(
            "Account or infrastructure takeover, data exposure and direct financial cost, "
            "lasting until the secret is rotated."
        ),
        remediation=(
            "Remove the secret from the working tree and purge it from git history.",
            "Load the value from the environment or a secret manager at runtime.",
            "Rotate the exposed credential — assume it is already compromised.",
            "Add a pre-commit hook and a CI check so it cannot come back.",
        ),
    ),
    Rule(
        id="aws-access-key",
        title="AWS access key ID committed to the repository",
        stride="Information Disclosure",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        attack_scenario=(
            "Automated scrapers watch public repositories and forks for key IDs; the paired "
            "secret, if ever committed alongside it, grants direct API access."
        ),
        impact="Unauthorised use of AWS resources, data exfiltration and unbounded billing.",
        remediation=(
            "Deactivate the key in IAM and issue a replacement.",
            "Audit CloudTrail for activity performed with the exposed key.",
            "Move to short-lived credentials (OIDC) instead of static keys.",
        ),
    ),
    Rule(
        id="github-token",
        title="GitHub token committed to the repository",
        stride="Information Disclosure",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        attack_scenario=(
            "A leaked personal access token can read private repositories, push code and, "
            "depending on scopes, act on behalf of the account."
        ),
        impact="Supply-chain tampering, private source code disclosure, workflow abuse.",
        remediation=(
            "Revoke the token in GitHub settings immediately.",
            "Review the audit log for pushes and workflow runs made with it.",
            "Prefer fine-grained, short-lived tokens or the GitHub App installation flow.",
        ),
    ),
    Rule(
        id="slack-token",
        title="Slack token or webhook URL committed to the repository",
        stride="Information Disclosure",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        attack_scenario=(
            "A leaked bot or webhook token lets an attacker post as the bot, read channel "
            "history and reach internal information."
        ),
        impact="Data disclosure from team channels, phishing messages sent from a trusted bot.",
        remediation=(
            "Rotate the token in the Slack app configuration.",
            "Remove it from the repository and from CI environment files.",
            "Store it as a masked CI secret instead.",
        ),
    ),
    Rule(
        id="shell-injection",
        title="Subprocess call with shell=True",
        stride="Elevation of Privilege",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bshell\s*=\s*True\b"),
        skip=re.compile(r"#\s*nosec"),
        attack_scenario=(
            "If any fragment of the command comes from user input, shell metacharacters "
            "(; | $() | &&) turn a single argument into arbitrary command execution."
        ),
        impact="Remote code execution with the privileges of the Python process.",
        remediation=(
            "Pass an argument list and keep shell=False.",
            "Whitelist accepted values instead of concatenating strings.",
            "When a shell is unavoidable, neutralise every value with shlex.quote().",
        ),
    ),
    Rule(
        id="os-command",
        title="Shell command executed through os.system/os.popen",
        stride="Elevation of Privilege",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bos\.(?:system|popen)\s*\("),
        skip=re.compile(r"#\s*nosec"),
        attack_scenario=(
            "os.system hands the string straight to the platform shell, so injected "
            "characters execute as extra commands."
        ),
        impact="Arbitrary command execution, often as the service account.",
        remediation=(
            "Replace with subprocess.run([...], shell=False).",
            "Validate and normalise every interpolated value.",
        ),
    ),
    Rule(
        id="unsafe-eval",
        title="Dynamic code execution via eval/exec",
        stride="Tampering",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        skip=re.compile(r"#\s*nosec"),
        attack_scenario=(
            "eval/exec run strings as Python code; any input that reaches them, directly or "
            "through a template, becomes executable logic."
        ),
        impact="Arbitrary code execution inside the application's trust boundary.",
        remediation=(
            "Replace with an explicit parser (ast.literal_eval for literals, json.loads for data).",
            "If dynamic evaluation is unavoidable, restrict the input to a strict allow-list.",
        ),
    ),
    Rule(
        id="unsafe-yaml-load",
        title="YAML loaded without a safe loader",
        stride="Spoofing",
        severity=Severity.HIGH,
        pattern=re.compile(r"\byaml\.load\s*\("),
        skip=re.compile(r"SafeLoader|CSafeLoader|Loader\s*=\s*(?:yaml\.)?[A-Za-z]*(?:Safe|Base)Loader"),
        attack_scenario=(
            "The default loader resolves arbitrary Python objects, so a crafted document can "
            "instantiate classes or execute code during parsing."
        ),
        impact="Code execution or object forgery triggered by a single configuration file.",
        remediation=(
            "Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
            "Treat externally supplied YAML as untrusted input.",
        ),
    ),
    Rule(
        id="insecure-tls",
        title="TLS certificate verification disabled",
        stride="Spoofing",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"verify\s*=\s*False|_create_unverified_context|CERT_NONE"),
        skip=re.compile(r"#\s*nosec"),
        attack_scenario=(
            "Without certificate validation any on-path attacker can present their own "
            "certificate and read or modify the traffic."
        ),
        impact="Credential theft and response tampering on an otherwise trusted channel.",
        remediation=(
            "Enable verification (verify=True) and point to the correct CA bundle.",
            "If a private CA is in play, ship it explicitly instead of switching checks off.",
        ),
    ),
    Rule(
        id="pickle-deserialization",
        title="Untrusted data passed to pickle/marshal",
        stride="Tampering",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\b(?:pickle|cPickle|marshal)\.loads?\s*\("),
        attack_scenario=(
            "A pickle stream is a program: loading one from a channel the attacker controls "
            "executes their code on import."
        ),
        impact="Remote code execution through a crafted session file, cache entry or message.",
        remediation=(
            "Use a data-only format (JSON, MessagePack) for untrusted input.",
            "If pickle is unavoidable, sign the payloads and verify before loading.",
        ),
    ),
    Rule(
        id="debug-mode",
        title="Debug mode enabled in application settings",
        stride="Information Disclosure",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\bDEBUG\s*=\s*True|\bdebug\s*=\s*True\b"),
        skip=re.compile(r"#\s*nosec"),
        attack_scenario=(
            "Debug pages expose stack traces, settings and sometimes an interactive console "
            "to whoever can reach the endpoint."
        ),
        impact="Disclosure of configuration and secrets, and often remote code execution.",
        remediation=(
            "Read the flag from the environment and default it to false.",
            "Never serve a debug configuration from production hosts.",
        ),
    ),
    Rule(
        id="weak-hash",
        title="Weak hash algorithm in use",
        stride="Tampering",
        severity=Severity.LOW,
        pattern=re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("),
        attack_scenario=(
            "Practical collisions let an attacker craft a different input with the same "
            "digest, defeating integrity or signature checks built on it."
        ),
        impact="Forged artefacts, tampered integrity checks.",
        remediation=(
            "Use SHA-256 or stronger for integrity checks.",
            "For password storage use a memory-hard KDF (argon2, scrypt, bcrypt).",
        ),
    ),
)

# Most severe rules first: when a single line matches several rules the report keeps
# the one that matters most.
DEFAULT_RULES: tuple[Rule, ...] = tuple(
    sorted(_RULES, key=lambda rule: (-rule.severity.rank, rule.id))
)

_EXCLUDED_DIRS = frozenset(
    {
        "__pycache__",
        "venv",
        "site-packages",
        "node_modules",
        "build",
        "dist",
        "htmlcov",
    }
)

_MAX_FILE_BYTES = 1_000_000


def iter_python_files(project_root: Path) -> Iterator[Path]:
    """Yield the Python files of a project, skipping virtualenvs and metadata.

    Paths are filtered on their *relative* parts. Filtering on the absolute path was
    the original bug here: a project living under ``~/.config/...`` or any other
    dotted ancestor had every single file skipped, and the CLI happily reported
    "no threats found".
    """
    root = project_root.resolve()
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(
            part.startswith(".") or part in _EXCLUDED_DIRS for part in relative.parts[:-1]
        ):
            continue
        if path.is_file():
            yield path


def scan_source(
    text: str,
    relative_path: Path,
    rules: tuple[Rule, ...] = DEFAULT_RULES,
) -> list[Finding]:
    """Scan already-loaded source text, line by line."""
    findings: list[Finding] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "nosec" in raw_line.lower():
            continue
        for rule in rules:
            if rule.skip is not None and rule.skip.search(raw_line):
                continue
            if rule.pattern.search(raw_line) is not None:
                findings.append(
                    Finding(
                        rule=rule,
                        path=relative_path,
                        line=lineno,
                        excerpt=shorten(stripped),
                    )
                )
                break
    return findings


def scan_project(
    project_root: Path,
    rules: tuple[Rule, ...] = DEFAULT_RULES,
) -> ScanResult:
    """Scan every eligible Python file under ``project_root``."""
    root = project_root.resolve()
    findings: list[Finding] = []
    scanned = 0

    for path in iter_python_files(root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        findings.extend(scan_source(text, path.relative_to(root), rules))

    findings.sort(key=lambda finding: (-finding.severity.rank, finding.rule.id, str(finding.path), finding.line))
    return ScanResult(findings=tuple(findings), files_scanned=scanned)

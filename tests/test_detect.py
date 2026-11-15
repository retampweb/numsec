"""Detection rules: what they catch, what they must leave alone."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from numsec.detect import (
    DEFAULT_RULES,
    Finding,
    Severity,
    iter_python_files,
    scan_project,
    scan_source,
)

MakeProject = Callable[..., Path]


def scan_one(tmp_path: Path, source: str) -> list[Finding]:
    return scan_source(source, Path("sample.py"))


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        ('API_KEY = "sk-live-1234567890"', "hardcoded-secret"),
        ('db_password = "hunter2hunter2"', "hardcoded-secret"),
        ('secret := "topsecretvalue"', "hardcoded-secret"),
        ('AWS = "AKIAIOSFODNN7EXAMPLE"', "aws-access-key"),
        ('TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"', "github-token"),
        ('SLACK = "xoxb-1234567890-abcdefghij"', "slack-token"),
        ("subprocess.run(cmd, shell=True)", "shell-injection"),
        ('os.system("ls " + name)', "os-command"),
        ("result = eval(payload)", "unsafe-eval"),
        ("yaml.load(stream)", "unsafe-yaml-load"),
        ("requests.get(url, verify=False)", "insecure-tls"),
        ("blob = pickle.loads(payload)", "pickle-deserialization"),
        ("DEBUG = True", "debug-mode"),
        ("digest = hashlib.md5(data).hexdigest()", "weak-hash"),
    ],
)
def test_rule_matches(tmp_path: Path, source: str, rule_id: str) -> None:
    findings = scan_one(tmp_path, source + "\n")

    assert [finding.rule.id for finding in findings] == [rule_id]


@pytest.mark.parametrize(
    "source",
    [
        'PASSWORD = os.environ["APP_PASSWORD"]',
        'api_key = os.getenv("API_KEY")',
        'token = "your_token_here"',
        'password = "changeme"',
        'secret = "<your-secret>"',
        'client_secret = "{{ vault_secret }}"',
        'password = getpass.getpass()',
        "yaml.load(stream, Loader=yaml.SafeLoader)",
        "yaml.load(stream, Loader=CSafeLoader)",
        "subprocess.run(cmd, shell=True)  # nosec",
    ],
)
def test_placeholders_and_safe_alternatives_are_ignored(tmp_path: Path, source: str) -> None:
    assert scan_one(tmp_path, source + "\n") == []


def test_comment_lines_are_not_reported(tmp_path: Path) -> None:
    findings = scan_one(tmp_path, '# API_KEY = "sk-live-12345678"\n# DEBUG = True\n')

    assert findings == []


def test_one_finding_per_line_keeps_the_most_severe(tmp_path: Path) -> None:
    source = 'API_KEY = "sk-live-1234567890"; subprocess.run(cmd, shell=True)\n'

    findings = scan_one(tmp_path, source)

    assert len(findings) == 1
    assert findings[0].rule.id == "hardcoded-secret"


def test_findings_report_line_numbers_and_locations(tmp_path: Path) -> None:
    findings = scan_one(tmp_path, "import os\n\nDEBUG = True\n")

    assert findings[0].line == 3
    assert findings[0].location == "sample.py:3"


def test_project_scan_skips_virtualenvs_and_hidden_directories(make_project: MakeProject) -> None:
    project = make_project(
        {
            "app/main.py": "DEBUG = True\n",
            ".venv/lib/python3.11/site-packages/pkg.py": "DEBUG = True\n",
            "venv/lib/pkg.py": "DEBUG = True\n",
            "build/generated.py": "DEBUG = True\n",
            "__pycache__/cached.py": "DEBUG = True\n",
            ".mypy_cache/cached.py": "DEBUG = True\n",
        }
    )

    result = scan_project(project)

    assert result.files_scanned == 1
    assert {finding.path for finding in result.findings} == {Path("app/main.py")}


def test_hidden_ancestor_directories_do_not_hide_findings(
    tmp_path: Path, make_project: MakeProject
) -> None:
    """Regression: filtering on absolute path parts made every scan silently empty.

    A project cloned into ``~/.local/src/...`` or ``~/.config/...`` used to report
    "no findings" no matter what it contained.
    """
    hidden_root = tmp_path / ".config" / "work"
    hidden_root.mkdir(parents=True)
    project = make_project(
        {"app/settings.py": 'API_KEY = "sk-live-1234567890"\n'},
        root=hidden_root,
    )

    result = scan_project(project)

    assert result.files_scanned == 1
    assert [finding.rule.id for finding in result.findings] == ["hardcoded-secret"]


def test_iter_python_files_is_deterministic(make_project: MakeProject) -> None:
    project = make_project({"b.py": "", "a.py": "", "pkg/c.py": ""})

    first = [path.name for path in iter_python_files(project)]
    second = [path.name for path in iter_python_files(project)]

    assert first == second == ["a.py", "b.py", "c.py"]


def test_undecodable_file_does_not_break_the_scan(make_project: MakeProject) -> None:
    project = make_project({"app/main.py": "DEBUG = True\n"})
    (project / "app" / "binary.py").write_bytes(b"\xff\xfe\x00DEBUG = True\n")

    result = scan_project(project)

    assert result.files_scanned == 2


def test_rules_are_ordered_by_severity_then_id() -> None:
    ranks = [rule.severity.rank for rule in DEFAULT_RULES]
    ids = [rule.id for rule in DEFAULT_RULES]

    assert ranks == sorted(ranks, reverse=True)
    assert ids[:4] == sorted(ids[:4])


def test_scan_result_summary_helpers(make_project: MakeProject) -> None:
    project = make_project({"app/main.py": "DEBUG = True\n"})

    result = scan_project(project)

    assert result.max_severity is Severity.MEDIUM
    assert result.exceeds(Severity.MEDIUM) is True
    assert result.exceeds(Severity.HIGH) is False


def test_empty_project_reports_no_findings(tmp_path: Path) -> None:
    result = scan_project(tmp_path)

    assert result.findings == ()
    assert result.files_scanned == 0
    assert result.max_severity is None
    assert result.exceeds(Severity.LOW) is False

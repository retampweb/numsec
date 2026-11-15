"""CLI contract: output formats, exit codes, and error handling."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from numsec.cli import cli

MakeProject = Callable[..., Path]

CLEAN_PROJECT = {"app/main.py": "def main() -> None:\n    print('hello')\n"}
DIRTY_PROJECT = {"app/config.py": 'API_KEY = "sk-live-1234567890"\nDEBUG = True\n'}


def invoke(*args: str, input_text: str | None = None) -> tuple[int, str]:
    result = CliRunner().invoke(cli, list(args), input=input_text)
    combined = result.output + getattr(result, "stderr", "")
    return result.exit_code, combined


def test_version_is_printed() -> None:
    exit_code, output = invoke("--version")

    assert exit_code == 0
    assert "Numsec v" in output


def test_help_lists_the_commands() -> None:
    exit_code, output = invoke("--help")

    assert exit_code == 0
    for command in ("analyze", "init", "lint", "list-templates", "plugin", "scan-deps"):
        assert command in output


def test_analyze_ai_format_is_valid_json(make_project: MakeProject) -> None:
    project = make_project(DIRTY_PROJECT)

    exit_code, output = invoke("analyze", str(project), "--ai-format")

    assert exit_code == 0
    payload = json.loads(output)
    assert payload["status"] == "ok"
    assert payload["findings"] == 2
    assert payload["max_severity"] == "critical"
    assert {threat["rule"] for threat in payload["threats"]} == {"hardcoded-secret", "debug-mode"}


def test_analyze_human_output_summarises_what_it_did(make_project: MakeProject) -> None:
    project = make_project(DIRTY_PROJECT)

    exit_code, output = invoke("analyze", str(project))

    assert exit_code == 0
    assert "Scanned 1 Python file(s)" in output
    assert "THREAT-001" in output
    assert "CRITICAL" in output


@pytest.mark.parametrize("fail_on", ["critical", "high", "medium", "low"])
def test_analyze_fail_on_returns_one_for_findings(make_project: MakeProject, fail_on: str) -> None:
    project = make_project(DIRTY_PROJECT)

    exit_code, _ = invoke("analyze", str(project), "--fail-on", fail_on)

    assert exit_code == 1


def test_analyze_fail_on_stays_quiet_when_nothing_exceeds_the_threshold(
    make_project: MakeProject,
) -> None:
    project = make_project({"app/main.py": "digest = hashlib.md5(data).hexdigest()\n"})

    exit_code_critical, _ = invoke("analyze", str(project), "--fail-on", "critical")
    exit_code_low, _ = invoke("analyze", str(project), "--fail-on", "low")

    assert exit_code_critical == 0
    assert exit_code_low == 1


def test_lint_writes_nothing(make_project: MakeProject) -> None:
    project = make_project(DIRTY_PROJECT)

    exit_code, output = invoke("lint", str(project))

    assert exit_code == 0
    assert "hardcoded-secret" in output
    assert not (project / "numsec").exists()


def test_lint_json_payload(make_project: MakeProject) -> None:
    project = make_project(DIRTY_PROJECT)

    exit_code, output = invoke("lint", str(project), "--json")

    assert exit_code == 0
    payload = json.loads(output)
    assert payload["files_scanned"] == 1
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["location"] == "app/config.py:1"


def test_lint_fail_on_exit_code(make_project: MakeProject) -> None:
    project = make_project(DIRTY_PROJECT)

    assert invoke("lint", str(project), "--fail-on", "high")[0] == 1
    assert invoke("lint", str(project), "--fail-on", "critical")[0] == 1


def test_refusing_to_init_into_a_busy_directory_is_a_clean_abort(tmp_path: Path) -> None:
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "keep.txt").write_text("mine\n", "utf-8")

    exit_code, output = invoke("init", str(busy), input_text="n\n")

    assert exit_code == 1
    assert "Aborted" in output
    # The old code wrapped click.Abort in `except Exception` and printed
    # "Error: Aborted." instead.
    assert "Error:" not in output


def test_usage_errors_keep_their_own_exit_code() -> None:
    exit_code, _ = invoke("analyze", "/definitely/not/a/path")

    assert exit_code == 2


def test_unknown_command_is_a_usage_error() -> None:
    exit_code, _ = invoke("nope")

    assert exit_code == 2

"""Dependency parsing and OSV.dev integration, with the network faked out."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from numsec import deps
from numsec.deps import (
    OSV_QUERY_URL,
    Requirement,
    discover_requirements,
    normalise_name,
    parse_pyproject,
    parse_requirement_line,
    parse_requirements_file,
    query_osv,
    scan_dependencies,
)
from numsec.exceptions import NetworkError

CALLS: list[tuple[str, dict[str, Any]]] = []


def recording_transport(response: dict[str, Any]) -> deps.Transport:
    """A transport that records payloads and answers with ``response``."""

    def _transport(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        CALLS.append((url, payload))
        return response

    return _transport


@pytest.fixture(autouse=True)
def _clear_calls() -> None:
    CALLS.clear()


@pytest.mark.parametrize(
    ("raw", "name", "specifier"),
    [
        ("flask==2.0.1", "flask", "==2.0.1"),
        ("Django_Rest_Framework>=3.14", "django-rest-framework", ">=3.14"),
        ("requests[security]==2.31.0", "requests", "==2.31.0"),
        ('pynacl==1.5; python_version < "3.12"', "pynacl", "==1.5"),
        ("httpx @ https://example.com/httpx.whl", "httpx", ""),
        ("# a comment", None, None),
        ("-e .", None, None),
        ("", None, None),
    ],
)
def test_parse_requirement_line(raw: str, name: str | None, specifier: str | None) -> None:
    parsed = parse_requirement_line(raw)

    if name is None:
        assert parsed is None
        return
    assert parsed is not None
    assert (parsed.name, parsed.specifier) == (name, specifier)


def test_names_are_normalised_per_pep_503() -> None:
    assert normalise_name("Zope.Interface") == "zope-interface"
    assert normalise_name("Flask_SQLAlchemy") == "flask-sqlalchemy"


def test_requirements_file_follows_includes_and_skips_options(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("click==8.1.7\n", "utf-8")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "# runtime deps\n"
        "-r base.txt\n"
        "-e .\n"
        "--index-url https://example.com/simple\n"
        "jinja2==2.10.1  # pinned on purpose\n"
        "requests\n",
        "utf-8",
    )

    parsed = parse_requirements_file(requirements)

    assert [(requirement.name, requirement.specifier) for requirement in parsed] == [
        ("click", "==8.1.7"),
        ("jinja2", "==2.10.1"),
        ("requests", ""),
    ]
    assert {requirement.source for requirement in parsed} >= {"base.txt", "requirements.txt"}


def test_requirements_includes_do_not_loop_forever(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("-r b.txt\nflask==2.0.1\n", "utf-8")
    second.write_text("-r a.txt\nclick==8.1.7\n", "utf-8")

    parsed = parse_requirements_file(first)

    assert [requirement.name for requirement in parsed] == ["click", "flask"]


def test_pyproject_dependencies_and_optional_groups(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["click>=8.1.7", "jinja2==2.10.1"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[dependency-groups]
lint = ["ruff>=0.6", {include-group = "dev"}]
""",
        "utf-8",
    )

    runtime = parse_pyproject(pyproject)
    everything = parse_pyproject(pyproject, include_optional=True)

    assert [requirement.name for requirement in runtime] == ["click", "jinja2"]
    assert [requirement.name for requirement in everything] == ["click", "jinja2", "pytest", "ruff"]


def test_discover_requirements_combines_and_dedupes(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["click>=8.1.7"]\n', "utf-8"
    )
    (tmp_path / "requirements.txt").write_text("click>=8.1.7\njinja2==2.10.1\n", "utf-8")

    found = discover_requirements(tmp_path)

    assert [requirement.name for requirement in found] == ["click", "jinja2"]


@pytest.mark.parametrize(
    ("specifier", "expected"),
    [("==1.2.3", "1.2.3"), ("== 1.2.3", "1.2.3"), ("==1.2.*", None), (">=1.2", None), ("", None)],
)
def test_only_exact_pins_are_checked(specifier: str, expected: str | None) -> None:
    assert Requirement(name="pkg", specifier=specifier).pinned_version == expected


def test_query_osv_reports_vulnerabilities_and_payloads() -> None:
    response = {
        "vulns": [
            {
                "id": "GHSA-test-0001",
                "summary": "Test advisory",
                "database_specific": {"severity": "HIGH"},
                "aliases": ["CVE-2020-0001"],
            }
        ]
    }

    reports = query_osv(
        [Requirement(name="jinja2", specifier="==2.10.1")],
        transport=recording_transport(response),
    )

    assert len(reports) == 1
    assert reports[0].vulnerable is True
    assert reports[0].vulnerabilities[0].id == "GHSA-test-0001"
    assert reports[0].vulnerabilities[0].severity == "high"
    assert reports[0].vulnerabilities[0].aliases == ("CVE-2020-0001",)
    assert CALLS == [
        (
            OSV_QUERY_URL,
            {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.10.1"},
        )
    ]


def test_query_osv_skips_unpinned_requirements_without_a_request() -> None:
    reports = query_osv(
        [Requirement(name="flask", specifier=">=2.0")],
        transport=recording_transport({}),
    )

    assert reports[0].skipped_reason == "not pinned to an exact version"
    assert CALLS == []


def test_query_osv_tolerates_missing_summary_and_severity() -> None:
    reports = query_osv(
        [Requirement(name="pkg", specifier="==1.0")],
        transport=recording_transport({"vulns": [{"id": "PYSEC-0000"}]}),
    )

    vulnerability = reports[0].vulnerabilities[0]
    assert vulnerability.severity == "unknown"
    assert vulnerability.summary


def test_network_failures_are_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def exploding_urlopen(*args: Any, **kwargs: Any) -> None:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(deps.urllib.request, "urlopen", exploding_urlopen)

    with pytest.raises(NetworkError, match=r"OSV\.dev"):
        deps._post_json(OSV_QUERY_URL, {}, 1.0)


def test_http_500_is_wrapped_as_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def http_error(*args: Any, **kwargs: Any) -> None:
        raise urllib.error.HTTPError(OSV_QUERY_URL, 500, "boom", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(deps.urllib.request, "urlopen", http_error)

    with pytest.raises(NetworkError):
        deps._post_json(OSV_QUERY_URL, {}, 1.0)


def test_scan_dependencies_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("jinja2==2.10.1\nflask>=2.0\n", "utf-8")

    reports = scan_dependencies(
        tmp_path,
        transport=recording_transport({"vulns": [{"id": "GHSA-x", "summary": "boom"}]}),
    )

    assert [(report.requirement.name, report.vulnerable) for report in reports] == [
        ("jinja2", True),
        ("flask", False),
    ]


def test_scan_dependencies_without_manifest_returns_nothing(tmp_path: Path) -> None:
    reports = scan_dependencies(tmp_path, transport=recording_transport({}))

    assert reports == []
    assert CALLS == []


def test_cli_scan_deps_reports_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from numsec.cli import cli

    (tmp_path / "requirements.txt").write_text("jinja2==2.10.1\n", "utf-8")
    monkeypatch.setattr(
        deps,
        "_post_json",
        recording_transport(
            {
                "vulns": [
                    {"id": "GHSA-x", "summary": "boom", "database_specific": {"severity": "HIGH"}}
                ]
            }
        ),
    )

    result = CliRunner().invoke(cli, ["scan-deps", str(tmp_path), "--json"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["checked"] == 1
    assert payload["vulnerable"][0]["id"] == "GHSA-x"
    assert payload["vulnerable"][0]["severity"] == "high"


def test_cli_scan_deps_is_honest_when_there_is_nothing_to_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from numsec.cli import cli

    result = CliRunner().invoke(cli, ["scan-deps", str(tmp_path)])

    assert result.exit_code == 0
    assert "No dependencies found" in result.output


def test_cli_scan_deps_maps_network_errors_to_exit_code_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from numsec.cli import cli

    (tmp_path / "requirements.txt").write_text("jinja2==2.10.1\n", "utf-8")

    def offline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise NetworkError("osv is unreachable")

    monkeypatch.setattr(deps, "_post_json", offline)

    result = CliRunner().invoke(cli, ["scan-deps", str(tmp_path)])

    assert result.exit_code == 3
    combined = result.output + getattr(result, "stderr", "")
    assert "Network error" in combined

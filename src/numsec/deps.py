"""Dependency vulnerability lookup against OSV.dev.

Numsec does not ship its own vulnerability database. OSV aggregates PyPI
advisories, GHSA and friends, is free and needs no API key, so the whole feature
is a couple of HTTP calls.

Only an exactly pinned version can be evaluated. Range specifiers are reported as
``not pinned`` instead of being guessed at, because a range that includes a
patched release is not a finding, and a range that includes a vulnerable one is
not a proof.
"""

from __future__ import annotations

import json
import re
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .exceptions import NetworkError
from .utils import shorten

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
ECOSYSTEM = "PyPI"

_REQUIREMENT_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?P<specifier>[<>=!~].*)?$"
)
_EXACT_PIN = re.compile(r"^==\s*(?P<version>[^*\s]+)$")
_NAME_SEPARATOR = re.compile(r"[-_.]+")

Transport = Callable[[str, dict[str, Any], float], dict[str, Any]]


@dataclass(frozen=True)
class Requirement:
    """A single declared dependency."""

    name: str
    specifier: str = ""
    source: str = "requirements.txt"

    @property
    def pinned_version(self) -> str | None:
        """The version when the requirement is pinned with ``==``, else None."""
        match = _EXACT_PIN.match(self.specifier.strip())
        return match["version"] if match else None

    @property
    def display(self) -> str:
        return f"{self.name}{self.specifier}"


@dataclass(frozen=True)
class Vulnerability:
    """A single OSV advisory."""

    id: str
    summary: str
    severity: str = "unknown"
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyReport:
    """Outcome for one requirement."""

    requirement: Requirement
    vulnerabilities: tuple[Vulnerability, ...] = ()
    skipped_reason: str | None = None

    @property
    def vulnerable(self) -> bool:
        return bool(self.vulnerabilities)


def normalise_name(name: str) -> str:
    """PEP 503 normalisation, matching how index servers write names."""
    return _NAME_SEPARATOR.sub("-", name).strip().lower()


def parse_requirement_line(line: str, *, source: str = "requirements.txt") -> Requirement | None:
    """Parse one PEP 508-ish line; return None when it carries no requirement."""
    line = line.split(";", 1)[0].strip()
    if not line:
        return None
    if " @ " in line:
        name = line.split(" @ ", 1)[0].strip()
        return Requirement(name=normalise_name(name), source=source) if name else None
    match = _REQUIREMENT_LINE.match(line)
    if match is None:
        return None
    return Requirement(
        name=normalise_name(match["name"]),
        specifier=(match["specifier"] or "").strip(),
        source=source,
    )


def parse_requirements_file(path: Path, *, _seen: set[Path] | None = None) -> list[Requirement]:
    """Parse a requirements file, following ``-r`` includes."""
    path = path.resolve()
    seen = set() if _seen is None else _seen
    if path in seen or not path.is_file():
        return []
    seen.add(path)

    requirements: list[Requirement] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")) or line.startswith(("-r", "--requirement")):
            parts = line.split(None, 1)
            if len(parts) == 2:
                requirements.extend(
                    parse_requirements_file(path.parent / parts[1].strip(), _seen=seen)
                )
            continue
        if line.startswith("-"):
            continue
        requirement = parse_requirement_line(line, source=path.name)
        if requirement is not None:
            requirements.append(requirement)
    return requirements


def parse_pyproject(path: Path, *, include_optional: bool = False) -> list[Requirement]:
    """Parse dependencies declared in ``pyproject.toml``."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project") or {}

    lines: list[str] = list(project.get("dependencies") or [])
    if include_optional:
        for group in (project.get("optional-dependencies") or {}).values():
            lines.extend(group or [])
        for group in (data.get("dependency-groups") or {}).values():
            lines.extend(item for item in group or [] if isinstance(item, str))

    requirements: list[Requirement] = []
    for line in lines:
        requirement = parse_requirement_line(line, source=path.name)
        if requirement is not None:
            requirements.append(requirement)
    return requirements


def discover_requirements(
    project_root: Path,
    *,
    include_optional: bool = False,
) -> list[Requirement]:
    """Collect declared dependencies, de-duplicated in declaration order."""
    root = project_root.resolve()
    found: list[Requirement] = []

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        found.extend(parse_pyproject(pyproject, include_optional=include_optional))

    for pattern in ("requirements.txt", "requirements/*.txt", "requirements-*.txt"):
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                found.extend(parse_requirements_file(path))

    unique: list[Requirement] = []
    seen: set[tuple[str, str]] = set()
    for requirement in found:
        key = (requirement.name, requirement.specifier)
        if key in seen:
            continue
        seen.add(key)
        unique.append(requirement)
    return unique


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """POST ``payload`` and decode the JSON answer, mapping failures to NetworkError."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"numsec/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"Cannot reach OSV.dev: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise NetworkError("OSV.dev returned a response that is not valid JSON.") from exc


def _to_vulnerability(entry: dict[str, Any]) -> Vulnerability:
    database_specific = entry.get("database_specific") or {}
    summary = str(entry.get("summary") or entry.get("details") or "").strip()
    return Vulnerability(
        id=str(entry.get("id") or "UNKNOWN"),
        summary=shorten(summary, 140) or "(no summary provided by OSV)",
        severity=str(database_specific.get("severity") or "unknown").lower(),
        aliases=tuple(str(alias) for alias in entry.get("aliases") or ()),
    )


def query_osv(
    requirements: Sequence[Requirement],
    *,
    timeout: float = 10.0,
    transport: Transport | None = None,
) -> list[DependencyReport]:
    """Look every pinned requirement up on OSV.dev, in declaration order.

    One request per pinned package: the batch endpoint only returns vulnerability
    ids and timestamps, while this endpoint returns the summary and the severity
    that make the report readable.
    """
    post_json = _post_json if transport is None else transport
    reports: list[DependencyReport] = []

    for requirement in requirements:
        version = requirement.pinned_version
        if version is None:
            reports.append(
                DependencyReport(
                    requirement=requirement,
                    skipped_reason="not pinned to an exact version",
                )
            )
            continue

        payload = {
            "package": {"name": requirement.name, "ecosystem": ECOSYSTEM},
            "version": version,
        }
        data = post_json(OSV_QUERY_URL, payload, timeout)
        vulnerabilities = tuple(_to_vulnerability(entry) for entry in data.get("vulns") or ())
        reports.append(DependencyReport(requirement=requirement, vulnerabilities=vulnerabilities))

    return reports


def scan_dependencies(
    project_root: Path,
    *,
    timeout: float = 10.0,
    include_optional: bool = False,
    transport: Transport | None = None,
) -> list[DependencyReport]:
    """Discover the project's dependencies and check them against OSV.dev."""
    requirements = discover_requirements(project_root, include_optional=include_optional)
    if not requirements:
        return []
    return query_osv(requirements, timeout=timeout, transport=transport)

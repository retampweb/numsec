"""Threat artefact generation: layout, stability, redaction, regeneration."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from numsec.analyze import GENERATED_MARKER, analyze_project
from numsec.detect import Severity

MakeProject = Callable[..., Path]

SAMPLE = {
    "app/config.py": (
        'API_KEY = "sk-live-1234567890"\n'
        'DB_PASSWORD = os.environ["DB_PASSWORD"]\n'
        "subprocess.run(cmd, shell=True)\n"
    )
}


def test_writes_one_threat_directory_per_rule(make_project: MakeProject) -> None:
    project = make_project(SAMPLE)

    result = analyze_project(project)

    assert [threat.rule_id for threat in result.threats] == [
        "hardcoded-secret",
        "shell-injection",
    ]
    assert [threat.threat_id for threat in result.threats] == ["THREAT-001", "THREAT-002"]
    for threat in result.threats:
        assert (project / "numsec" / "threats" / threat.threat_id / "threat.md").is_file()
    assert (project / "numsec" / "threats" / "README.md").is_file()


def test_threat_markdown_has_the_sections_assistants_need(make_project: MakeProject) -> None:
    project = make_project(SAMPLE)

    analyze_project(project)
    text = (project / "numsec" / "threats" / "THREAT-001" / "threat.md").read_text("utf-8")

    assert text.startswith(GENERATED_MARKER)
    for heading in (
        "# Hardcoded secret material in source code",
        "- **Threat ID**: `THREAT-001`",
        "**STRIDE**: **Information Disclosure**",
        "**Severity**: **CRITICAL**",
        "## Affected files/components",
        "## Attack scenario",
        "## Impact",
        "## Recommended remediation",
    ):
        assert heading in text


def test_secret_values_are_never_copied_into_the_report(make_project: MakeProject) -> None:
    project = make_project(SAMPLE)

    analyze_project(project)
    text = (project / "numsec" / "threats" / "THREAT-001" / "threat.md").read_text("utf-8")

    assert "sk-live-1234567890" not in text
    assert 'API_KEY = "***"' in text


def test_ids_and_content_are_stable_across_runs(make_project: MakeProject) -> None:
    project = make_project(SAMPLE)

    first = analyze_project(project)
    second = analyze_project(project)

    assert [threat.threat_id for threat in first.threats] == [
        threat.threat_id for threat in second.threats
    ]
    assert first.removed == ()
    assert sorted(second.removed) == ["THREAT-001", "THREAT-002"]


def test_stale_generated_threats_are_removed_and_handwritten_ones_kept(
    make_project: MakeProject,
) -> None:
    project = make_project(SAMPLE)
    threats_dir = project / "numsec" / "threats"

    stale = threats_dir / "THREAT-042"
    stale.mkdir(parents=True)
    (stale / "threat.md").write_text(f"{GENERATED_MARKER}; rule: gone -->\n# Gone\n", "utf-8")

    handwritten = threats_dir / "THREAT-007"
    handwritten.mkdir(parents=True)
    (handwritten / "threat.md").write_text("# Our own notes\n", "utf-8")

    result = analyze_project(project)

    assert not stale.exists()
    assert (handwritten / "threat.md").read_text("utf-8") == "# Our own notes\n"
    assert "THREAT-007" in result.preserved
    assert "THREAT-042" in result.removed


def test_result_is_json_serialisable_even_with_hostile_paths(tmp_path: Path) -> None:
    project = tmp_path / 'we"ird dir \\ with spaces'
    project.mkdir()
    (project / "leak.py").write_text('API_KEY = "sk-live-1234567890"\n', "utf-8")

    result = analyze_project(project)
    payload = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))

    assert payload["project_root"] == str(project)
    assert payload["max_severity"] == Severity.CRITICAL.value
    assert payload["threats"][0]["occurrences"][0]["location"] == "leak.py:1"


def test_write_false_produces_no_artefacts(make_project: MakeProject) -> None:
    project = make_project(SAMPLE)

    result = analyze_project(project, write=False)

    assert result.threats
    assert result.generated == ()
    assert not (project / "numsec").exists()


def test_project_without_findings_writes_no_threat_directories(make_project: MakeProject) -> None:
    project = make_project({"app/main.py": "def main() -> None:\n    print('hi')\n"})

    result = analyze_project(project)

    assert result.threats == ()
    assert result.generated == ()
    assert list((project / "numsec" / "threats").glob("THREAT-*")) == []


def test_existing_threats_readme_is_not_overwritten(make_project: MakeProject) -> None:
    project = make_project(SAMPLE)
    readme = project / "numsec" / "threats" / "README.md"
    readme.parent.mkdir(parents=True)
    readme.write_text("team notes\n", "utf-8")

    analyze_project(project)

    assert readme.read_text("utf-8") == "team notes\n"

"""Plugins: discovery, tolerance of broken packages, and honest CLI behaviour."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import pytest
from click.testing import CliRunner

from numsec import plugins
from numsec.cli import cli
from numsec.detect import Rule, Severity
from numsec.plugins import load_plugin_rules, resolve_rules

RULES: tuple[Rule, ...] = (
    Rule(
        id="custom-rule",
        title="Custom detector from a plugin",
        stride="Tampering",
        severity=Severity.HIGH,
        pattern=__import__("re").compile(r"dangerous_call\("),
        attack_scenario="A plugin rule fired.",
        impact="Whatever the plugin author says.",
        remediation=("Fix it.",),
    ),
)


class FakeEntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, factory: Callable[[], Iterable[Any]]) -> None:
        self.name = name
        self.value = f"fake.module:{name}"
        self._factory = factory

    def load(self) -> Callable[[], Iterable[Any]]:
        return self._factory


def patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entry_points: FakeEntryPoint) -> None:
    def fake_entry_points(*, group: str, **_: Any) -> list[FakeEntryPoint]:
        assert group == plugins.ENTRY_POINT_GROUP
        return list(entry_points)

    monkeypatch.setattr(plugins.metadata, "entry_points", fake_entry_points)


def test_no_plugins_means_only_builtins(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_entry_points(monkeypatch)

    assert load_plugin_rules() == ()
    assert {rule.id for rule in resolve_rules()} >= {"hardcoded-secret", "debug-mode"}


def test_plugins_extend_the_rule_set(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_entry_points(monkeypatch, FakeEntryPoint("custom", lambda: RULES))

    loaded = load_plugin_rules()
    resolved = resolve_rules()

    assert loaded == RULES
    assert "custom-rule" in {rule.id for rule in resolved}


def test_rules_stay_sorted_by_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_entry_points(monkeypatch, FakeEntryPoint("custom", lambda: RULES))

    ranks = [rule.severity.rank for rule in resolve_rules()]

    assert ranks == sorted(ranks, reverse=True)


def test_broken_plugin_warns_instead_of_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode() -> Iterable[Any]:
        raise RuntimeError("plugin is broken")

    patch_entry_points(monkeypatch, FakeEntryPoint("broken", explode))

    with pytest.warns(RuntimeWarning, match="broken"):
        assert load_plugin_rules() == ()


def test_plugin_returning_junk_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_entry_points(monkeypatch, FakeEntryPoint("junk", lambda: ["not-a-rule"]))

    with pytest.warns(RuntimeWarning, match="expected Rule"):
        assert load_plugin_rules() == ()


def test_duplicate_rule_ids_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    duplicate = Rule(
        id="debug-mode",
        title="Shadowed built-in",
        stride="Information Disclosure",
        severity=Severity.LOW,
        pattern=__import__("re").compile(r"nothing"),
        attack_scenario="",
        impact="",
        remediation=(),
    )
    patch_entry_points(monkeypatch, FakeEntryPoint("dup", lambda: (duplicate,)))

    with pytest.warns(RuntimeWarning, match="duplicate rule id"):
        resolved = resolve_rules()

    titles = {rule.id: rule.title for rule in resolved}
    assert titles["debug-mode"] == "Debug mode enabled in application settings"


def test_cli_plugin_list_shows_builtins(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_entry_points(monkeypatch)

    result = CliRunner().invoke(cli, ["plugin", "list"])

    assert result.exit_code == 0
    assert "Built-in detectors" in result.output
    assert "hardcoded-secret" in result.output
    assert "Plugins: none" in result.output


def test_cli_plugin_install_explains_instead_of_pretending() -> None:
    result = CliRunner().invoke(cli, ["plugin", "install", "numsec-extra-rules"])

    assert result.exit_code == 2
    combined = result.output + getattr(result, "stderr", "")
    assert "not implemented" in combined
    assert "pip install numsec-extra-rules" in combined

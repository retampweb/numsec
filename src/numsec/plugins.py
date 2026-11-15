"""Detector plugins.

The built-in rule set lives in :mod:`numsec.detect`. Third parties can add rules
without forking by declaring an entry point in the ``numsec.detectors`` group::

    [project.entry-points."numsec.detectors"]
    my_rules = "my_package.rules:get_rules"

``get_rules()`` returns an iterable of :class:`numsec.detect.Rule`. A plugin that
raises or returns junk is reported as a warning and skipped; a broken plugin must
never take the scan down, because the scan is what reports the broken plugin.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterable
from importlib import metadata

from .detect import DEFAULT_RULES, Rule

ENTRY_POINT_GROUP = "numsec.detectors"


def iter_plugin_entry_points() -> list[metadata.EntryPoint]:
    """Entry points declared in the ``numsec.detectors`` group, if any."""
    try:
        return list(metadata.entry_points(group=ENTRY_POINT_GROUP))
    except Exception:  # pragma: no cover - defensive: metadata backends differ
        return []


def load_plugin_rules() -> tuple[Rule, ...]:
    """Resolve plugin entry points into rules, skipping broken ones with a warning."""
    rules: list[Rule] = []
    for entry_point in iter_plugin_entry_points():
        try:
            factory = entry_point.load()
            produced: Iterable[object] = factory() if callable(factory) else factory
            for rule in produced:
                if not isinstance(rule, Rule):
                    raise TypeError(f"expected Rule, got {type(rule).__name__}")
                rules.append(rule)
        except Exception as exc:
            warnings.warn(
                f"Skipping detector plugin {entry_point.name!r}: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
    return tuple(rules)


def resolve_rules(*, include_plugins: bool = True) -> tuple[Rule, ...]:
    """The rule set a scan should run: built-ins first, then plugins, de-duplicated."""
    rules: list[Rule] = list(DEFAULT_RULES)
    if include_plugins:
        rules.extend(load_plugin_rules())

    unique: list[Rule] = []
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            warnings.warn(f"Ignoring duplicate rule id {rule.id!r}", RuntimeWarning, stacklevel=2)
            continue
        seen.add(rule.id)
        unique.append(rule)

    return tuple(sorted(unique, key=lambda rule: (-rule.severity.rank, rule.id)))

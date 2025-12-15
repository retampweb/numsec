"""Threat modeling analysis (MVP).

MVP goals:
- Create stable, assistant-friendly markdown artifacts under openspec/threats/
- Provide a predictable first threat (THREAT-001)

The initial implementation uses lightweight string heuristics instead of deep AST/SAST.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


@dataclass(frozen=True)
class Threat:
    threat_id: str
    title: str
    stride_category: str
    affected_files: List[str]
    attack_scenario: str
    impact: str
    remediation: List[str]


def _iter_python_files(project_root: Path) -> Iterable[Path]:
    for p in project_root.rglob("*.py"):
        if any(part.startswith(".") for part in p.parts):
            continue
        if "venv" in p.parts or ".venv" in p.parts:
            continue
        if "site-packages" in p.parts:
            continue
        yield p


def _detect_hardcoded_secrets(project_root: Path) -> List[Path]:
    needles = ["api_key", "apikey", "secret", "password", "token="]
    hits: List[Path] = []

    for py in _iter_python_files(project_root):
        try:
            text = py.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue

        if any(n in text for n in needles):
            hits.append(py)

    return hits


def _render_threat_md(threat: Threat) -> str:
    files = "\n".join(f"- `{p}`" for p in threat.affected_files) if threat.affected_files else "- (not detected)"
    remediation = "\n".join(f"- {step}" for step in threat.remediation)

    return (
        f"# {threat.title}\n\n"
        f"- **Threat ID**: `{threat.threat_id}`\n"
        f"- **STRIDE**: **{threat.stride_category}**\n\n"
        f"## Affected files/components\n"
        f"{files}\n\n"
        f"## Attack scenario\n"
        f"{threat.attack_scenario}\n\n"
        f"## Impact\n"
        f"{threat.impact}\n\n"
        f"## Recommended remediation\n"
        f"{remediation}\n"
    )


def _ensure_threats_readme(threats_dir: Path) -> None:
    readme_path = threats_dir / "README.md"
    if readme_path.exists():
        return

    readme_path.write_text(
        "# Threats\n\n"
        "Эта папка содержит угрозы, найденные Numsec.\n\n"
        "## Формат\n\n"
        "Каждая угроза хранится в `numsec/threats/THREAT-*/threat.md`.\n\n"
        "## Рекомендованный workflow\n\n"
        "- Запусти `numsec analyze --ai-format`\n"
        "- Открой `THREAT-*/threat.md`\n"
        "- Попроси ассистента предложить исправление и оформить change в `numsec/changes/`\n",
        encoding="utf-8",
    )


def analyze_project(project_root: Path, ai_format: bool = False) -> str:
    """Analyze project and generate threat markdown artifacts.

    Returns a short human/assistant-friendly summary string.
    """
    numsec_dir = project_root / "numsec"
    threats_dir = numsec_dir / "threats"
    threat_id = "THREAT-001"

    threats_dir.mkdir(parents=True, exist_ok=True)
    _ensure_threats_readme(threats_dir)

    secret_hits = _detect_hardcoded_secrets(project_root)

    if secret_hits:
        threat = Threat(
            threat_id=threat_id,
            title="Hardcoded secret material in source code",
            stride_category="Information Disclosure",
            affected_files=[str(p.relative_to(project_root)) for p in secret_hits[:20]],
            attack_scenario=(
                "Атакующий получает доступ к репозиторию/артефактам сборки и извлекает секреты, "
                "после чего использует их для доступа к внешним системам."
            ),
            impact="Компрометация аккаунтов/инфраструктуры, утечка данных, финансовый ущерб.",
            remediation=[
                "Удалить секреты из исходников и истории git (при необходимости).",
                "Перенести секреты в переменные окружения/secret manager.",
                "Добавить pre-commit/CI проверки на secrets.",
                "Повернуть (rotate) скомпрометированные ключи.",
            ],
        )
        detection_note = "detected"
    else:
        threat = Threat(
            threat_id=threat_id,
            title="Example threat (MVP): missing automated detections",
            stride_category="Tampering",
            affected_files=[],
            attack_scenario=(
                "MVP-режим: детекторы пока минимальные. Этот файл служит примером формата threat.md, "
                "чтобы ассистенты могли тренироваться на структуре и дальнейшем расширении."
            ),
            impact="Пока не вычисляется автоматически.",
            remediation=[
                "Настроить детекторы (Phase 1) и перезапустить `numsec analyze`.",
                "Заполнить `openspec/architecture.md` и описать контекст вручную.",
            ],
        )
        detection_note = "example"

    threat_dir = threats_dir / threat_id
    threat_dir.mkdir(parents=True, exist_ok=True)
    (threat_dir / "threat.md").write_text(_render_threat_md(threat), encoding="utf-8")

    if ai_format:
        return (
            f"{{\n"
            f"  \"status\": \"ok\",\n"
            f"  \"mode\": \"mvp\",\n"
            f"  \"project_root\": \"{project_root}\",\n"
            f"  \"threats_dir\": \"{threats_dir}\",\n"
            f"  \"generated\": [\"numsec/threats/{threat_id}/threat.md\"],\n"
            f"  \"threat_id\": \"{threat_id}\",\n"
            f"  \"detection\": \"{detection_note}\"\n"
            f"}}"
        )

    return f"Generated {threat_id} at {threat_dir / 'threat.md'}"

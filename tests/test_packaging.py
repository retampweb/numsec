"""Packaging guard: the template must survive a wheel build.

This is the regression test for the bug that made `numsec init` useless for anyone
who installed from a wheel instead of an editable checkout: a plain ``**/*`` glob in
``package_data`` silently drops ``.cursor/``, ``.windsurf/`` and ``.gitignore``.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TEMPLATE_FILES = {
    "numsec/templates/templates/basic/.cursor/rules/numsec.mdc",
    "numsec/templates/templates/basic/.windsurf/workflows/numsec.md",
    "numsec/templates/templates/basic/.gitignore",
    "numsec/templates/templates/basic/NUMSEC.md",
    "numsec/templates/templates/basic/numsec/project.md",
    "numsec/templates/templates/basic/numsec/threats/README.md",
    "numsec/templates/templates/basic/src/app/main.py",
}


@pytest.mark.slow
def test_wheel_contains_the_whole_template(tmp_path: Path) -> None:
    pytest.importorskip("build")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "-o",
            str(tmp_path),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    wheels = sorted(tmp_path.glob("*.whl"))
    assert len(wheels) == 1

    names = set(zipfile.ZipFile(wheels[0]).namelist())

    missing = EXPECTED_TEMPLATE_FILES - names
    assert not missing, f"template files missing from the wheel: {sorted(missing)}"
    assert "numsec-0.1.0.dist-info/licenses/LICENSE" in names or any(
        name.endswith(".dist-info/licenses/LICENSE") for name in names
    )
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)

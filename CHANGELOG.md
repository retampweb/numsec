# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-15

The MVP skeleton becomes an honest tool: the detectors produce real findings, the
packaging actually ships the template, and the commands that used to print
checkmarks for doing nothing now say so.

### Added

- Twelve STRIDE-mapped detection rules: hardcoded secrets, AWS/GitHub/Slack
  credentials, `shell=True`, `os.system`/`os.popen`, `eval`/`exec`, unsafe
  `yaml.load`, disabled TLS verification, `pickle`, debug mode, weak hashes.
- `numsec lint` — same engine, no files written, `--json` and `--fail-on LEVEL`.
- `--fail-on LEVEL` for `numsec analyze`, so CI can gate on severity.
- `numsec scan-deps` — dependency check against OSV.dev, plus `--json`,
  `--timeout`, `--include-dev`.
- Detector plugins through the `numsec.detectors` entry-point group, and
  `numsec plugin list` to inspect what is loaded.
- Project scaffolding that actually exists: `numsec/project.md`,
  `numsec/architecture.md`, `numsec/security-requirements.md`,
  `numsec/threats/`, `numsec/changes/` and `.windsurf/workflows/numsec.md`.
- `{{project_name}}` rendering in template files.
- 110 tests, ruff configuration and a GitHub Actions matrix (Python 3.11–3.14 and
  Windows), including a wheel smoke test.
- MIT license, changelog, dependabot configuration.

### Changed

- Requires Python **3.11+** (3.9 and 3.10 are end-of-life).
- `numsec init` runs `git init --quiet`, so branch hints no longer leak into the
  terminal; `--no-git` skips repository creation entirely.
- A busy target directory only needs confirmation; `--force` still merges silently.
- Version is defined once, in `numsec.__version__`, and read by the build.
- `numsec analyze --ai-format` emits JSON through `json.dumps`, which fixes broken
  output for paths containing quotes or backslashes.
- An empty scan no longer fabricates an example `THREAT-001`.
- Credential excerpts are redacted in reports and in `lint` output.

### Fixed

- **Silent false negatives:** files were skipped whenever the *absolute* path
  contained a dotted directory, so any project under `~/.config/…`, `~/.local/src/…`
  or a hidden clone reported "no findings" regardless of its contents.
- **The wheel shipped without the template's dotfiles:** `.cursor/rules/numsec.mdc`,
  `.windsurf/workflows/numsec.md` and `.gitignore` were dropped by the
  `package_data` glob, so `pip install numsec && numsec init` produced a project
  without IDE integration. Covered by a packaging test now.
- `click.Abort` was caught by `except Exception`, turning "user said no" into
  `Error: Aborted.`
- `numsec scan-deps`, `numsec lint` and `numsec plugin install` printed success
  without doing any work.
- `.gitignore` was deleted in `b45fcb3`; it is back, with tooling caches covered.
- `typing.Tuple`/`List` usage, unused imports and trailing whitespace (50 ruff
  diagnostics) are gone.

### Removed

- The dead `openspec` → `numsec` directory rename in the template loader; templates
  are copied verbatim now.
- `numsec.utils.chunked`, an unused helper.
- Documentation for a `Numsec/` specs directory that never existed.

## [0.1.0] - 2025-12-15

Initial public skeleton: `numsec init`, `numsec list-templates`, a first
`numsec analyze` that always wrote an example `THREAT-001`, and placeholder
`scan-deps`/`lint`/`plugin install` commands.

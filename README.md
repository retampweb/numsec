███╗   ██╗██╗   ██╗███╗   ███╗███████╗███████╗ ██████╗
████╗  ██║██║   ██║████╗ ████║██╔════╝██╔════╝██╔════╝
██╔██╗ ██║██║   ██║██╔████╔██║███████╗█████╗  ██║
██║╚██╗██║██║   ██║██║╚██╔╝██║╚════██║██╔══╝  ██║
██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████║███████╗╚██████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝


# Numsec

Numsec is a CLI for automated threat modeling inside IDEs. It analyzes code, identifies issues using STRIDE, and provides AI assistants (Cursor, Windsurf, Trae) with structured context to help remediate them.

This repository contains the CLI itself and built-in project templates used by `numsec init`.

## Requirements

- Python **3.9+**
- Git (recommended so `numsec init` can run `git init`)

## Quick install (development / from GitHub)

The simplest way is to install the package in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
numsec --version
numsec --help
```

Check:

```bash
numsec --help
numsec --version
```

# Usage

## Chat commands: `/numsec "..."`

### Example inside an IDE:

User in Cursor: "/numsec analyze"
Cursor runs: numsec analyze --ai-format
Result: numsec/threats/THREAT-001/threat.md with threat details

User: "/numsec fix THREAT-001"
Claude reads threat.md and generates a fix into numsec/changes/FIX-THREAT-001/

User: "/numsec apply FIX-THREAT-001"
The patch is applied to the codebase


- Write chat commands as: `/numsec "<command>"`
- The protocol and assistant expectations live in: `NUMSEC.md`

If you use Windsurf/Cursor, projects created via `numsec init` also include:
- `.windsurf/workflows/numsec.md`
- `.cursor/rules/numsec.mdc`

These files tell the assistant to read `NUMSEC.md` first, then `numsec/project.md`, and relevant `numsec/threats/THREAT-*/threat.md`.

### 1) List available templates

```bash
numsec list-templates
```

### 2) Initialize a new project

Creates the project directory, copies files from the template, and runs `git init`.

```bash
numsec init my-project
```

Select a template:

```bash
numsec init my-project --template basic
```

If the directory already exists:

```bash
numsec init my-project --force
```

### 3) What the `basic` template generates

After `numsec init my-project` the structure will look roughly like:

```
my-project/
  NUMSEC.md
  .gitignore
  .cursor/
    rules/
      numsec.mdc
  .windsurf/
    workflows/
      numsec.md
  README.md
  requirements.txt
  src/
    app/
      __init__.py
      main.py
  numsec/
    project.md
    architecture.md
    security-requirements.md
    threats/
      README.md
      THREAT-001/
        threat.md
```

### 4) Run the example code from the template

```bash
cd my-project
python -m app.main
```

## Numsec repository architecture

Key parts:

- `src/numsec/cli.py`
  - CLI built on `click`
  - MVP core commands: `init`, `list-templates`, `analyze`

- `src/numsec/templates/`
  - template loader
  - built-in templates live under `src/numsec/templates/templates/`

- `pyproject.toml`
  - defines packaging and console script entrypoint `numsec = numsec.cli:cli`
  - includes templates in the distribution (package data)

## Numsec process (internal, for developing Numsec)

In this repository, the `Numsec/` directory is used to track requirements/specs and changes.

### Specs (current truth)

- `Numsec/specs/<capability>/spec.md` — requirements and scenarios for the current system

### Changes (proposals)

- `Numsec/changes/<change-id>/proposal.md` — why/what changes
- `Numsec/changes/<change-id>/tasks.md` — implementation checklist
- `Numsec/changes/<change-id>/specs/...` — spec deltas

Recommended flow:

1. Create a change (`Numsec/changes/<id>/...`)
2. Review/approve the proposal
3. Implement tasks from `tasks.md`
4. Validate (`Numsec validate <id> --strict`), then archive the change after release

## Troubleshooting

### `numsec` command not found

- Ensure your virtual environment is activated (`source .venv/bin/activate`)
- Ensure the package is installed (`pip install -e .`)

### `numsec init` prints "No templates available"

- This means templates were not included in the installation.
- Check that you installed the package from a repository that contains `src/numsec/templates/templates/`.

## Status

Currently, the CLI skeleton and the minimal `basic` template are implemented. Commands like `scan-deps`, `lint`, and `plugin install` are placeholders and will be expanded in future changes.

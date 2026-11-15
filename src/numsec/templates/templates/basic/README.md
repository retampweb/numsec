# {{project_name}}

> Security-focused project scaffolded with [Numsec](https://github.com/retampweb/numsec).

## Project structure

```
{{project_name}}/
├── NUMSEC.md                    # protocol read by IDE assistants
├── README.md
├── requirements.txt
├── .cursor/rules/numsec.mdc     # Cursor rule
├── .windsurf/workflows/numsec.md
├── numsec/
│   ├── project.md               # what this project is and what it protects
│   ├── architecture.md          # components and data flows
│   ├── security-requirements.md
│   ├── threats/                 # written by `numsec analyze`
│   └── changes/                 # proposals, one directory per change
└── src/
    └── app/
        ├── __init__.py
        └── main.py
```

## Getting started

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

## First threat model

```bash
numsec analyze .            # writes numsec/threats/THREAT-*/threat.md
numsec analyze . --fail-on high   # same, but exits 1 on high/critical findings
```

Fill in `numsec/project.md` and `numsec/architecture.md` first: the generated threats
are only as useful as the context you give your assistant.

## Security habits

- Keep dependencies pinned and updated.
- Never commit secrets: use environment variables or a secret manager.
- Review every generated threat — the rules are heuristics, not a proof.

# Changes

One directory per proposed change, e.g. `numsec/changes/FIX-THREAT-001/`:

```
FIX-THREAT-001/
├── proposal.md   # why: the risk, the affected component, the expected fix
└── tasks.md      # how: an ordered checklist a reviewer can follow
```

Rules of thumb:

- Open a change for anything touching authentication, authorisation, secret
  handling, external input or deployment.
- `proposal.md` names the threat (`THREAT-###`) or requirement it answers.
- `tasks.md` is small enough to review in one sitting.
- Nothing is applied before the proposal is reviewed.

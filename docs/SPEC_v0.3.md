# Honey Agent Lab — Specification v0.3

## Purpose

Honey Agent Lab is a defensive-only simulation environment for detecting synthetic agent compromise, unauthorized coordination, and attempts to reduce human auditability.

## v0.3 hardening

- Boundary-aware, precompiled risk matching.
- Contextual evidence fragments for each finding.
- Explicit authorization-evidence recognition.
- Declarative compound quarantine patterns.
- High-severity findings isolate even when aggregate score remains below the high threshold.
- Immutable hash-chained audit events.
- Optional local JSONL persistence and audit replay/verification.
- CLI audit verification, static HTML export, version flag, and verbose findings.
- Static dashboard includes complete findings and audit integrity.

## Expected scenario outcomes

| Scenario | Expected action | Rationale |
| --- | --- | --- |
| `scenario_001` | `quarantine` | Unauthorized coordination + log suppression + approval bypass |
| `scenario_002` | `quarantine` | Log suppression + concealment |
| `scenario_003` | `isolate` | Objective/authority manipulation produces high aggregate risk |
| `scenario_004` | `allow` | Benign signed negative control |

## Safety boundary

All adversarial inputs are inert synthetic strings. The project must not perform exploitation, credential harvesting, autonomous scanning, covert external coordination, or manipulation of third-party agents.

## Local validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

No GitHub Actions are required or expected.

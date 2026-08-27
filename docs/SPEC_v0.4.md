# Honey Agent Lab — Specification v0.4

v0.4 adds three defensive integration/testing capabilities: validated declarative JSON risk rules, deterministic local synthetic fuzzing, and an optional loopback-first FastAPI service. Existing hash-chained audit, explainable scoring, policy containment, static dashboard, and four baseline scenarios remain intact.

## Safety invariants

No live exploitation, credential collection, external agent manipulation, scanning, outbound requests, dynamic code config, or GitHub Actions. Generated fuzz content is inert synthetic fixture data. API runs loopback by default.

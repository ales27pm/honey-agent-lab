# Honey Agent Lab — Specification v0.5

v0.5 adds four defensive testing and development improvements:

1. deterministic multi-fragment fuzz fixtures with bounded synthetic obfuscation;
2. JSON Schema Draft 2020-12 validation for declarative risk rules;
3. dependency-free static HTML reports for fuzz coverage summaries;
4. loopback-only `serve --reload` for local API development.

## Safety invariants

- Fuzz content remains curated, synthetic, inert, local, and never transmitted externally.
- Obfuscation is used only to measure detector coverage and identify synthetic false-negative candidates.
- Rule configuration is JSON data only and cannot execute code or trigger dynamic imports.
- The API performs no outbound calls; reload is prohibited on non-loopback binds.
- No real exploitation, credential collection, external agent manipulation, scanning, stealth behavior, or GitHub Actions.

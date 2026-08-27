# Declarative risk rules

Rules are JSON objects in a top-level array and are validated against `src/honey_agent_lab/data/risk_rules_schema.json` using JSON Schema Draft 2020-12 through `jsonschema`.

Required fields are `code`, `score`, `severity`, `reason`, and `keywords`. Codes must use uppercase letters, digits, and underscores; scores are 0–100; severities are `none|low|medium|high|critical`; keywords must be a non-empty unique list. Unknown properties are rejected.

JSON Schema cannot express uniqueness of one property across separate array items, so Honey Agent Lab additionally checks that rule `code` values are unique and preserves case-insensitive keyword uniqueness. Invalid configuration fails closed with `ValueError`.

Default rules: `src/honey_agent_lab/data/default_rules.json`.

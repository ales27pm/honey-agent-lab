from __future__ import annotations

from functools import lru_cache
import json
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError


def _resource_text(name: str) -> str:
    return resources.files("honey_agent_lab").joinpath(f"data/{name}").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_rule_schema() -> dict[str, Any]:
    try:
        schema = json.loads(_resource_text("risk_rules_schema.json"))
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        raise ValueError(f"Unable to load risk rules schema: {exc}") from exc
    return schema


def _format_validation_error(exc: ValidationError) -> str:
    location = "$"
    if exc.absolute_path:
        location += "".join(f"[{item}]" if isinstance(item, int) else f".{item}" for item in exc.absolute_path)
    return f"Risk rules schema validation failed at {location}: {exc.message}"


def _validate_document(raw: Any) -> list[dict[str, Any]]:
    try:
        Draft202012Validator(load_rule_schema()).validate(raw)
    except ValidationError as exc:
        raise ValueError(_format_validation_error(exc)) from exc

    if not isinstance(raw, list):
        raise ValueError("Risk rules document must be a JSON array")

    codes = [item["code"] for item in raw]
    if len(codes) != len(set(codes)):
        raise ValueError("Risk rule codes must be unique")

    for item in raw:
        keywords = item["keywords"]
        if len({keyword.casefold() for keyword in keywords}) != len(keywords):
            raise ValueError(f"Rule {item['code']}: keywords must be unique ignoring case")
        if not item["reason"].strip():
            raise ValueError(f"Rule {item['code']}: reason must not be whitespace-only")
        if any(not keyword.strip() for keyword in keywords):
            raise ValueError(f"Rule {item['code']}: keywords must not be whitespace-only")
    return raw


def validate_rule(data: dict[str, Any]) -> dict[str, Any]:
    """Validate one rule using the same schema used for complete documents."""
    validated = _validate_document([data])[0]
    return {
        "code": validated["code"],
        "score": validated["score"],
        "severity": validated["severity"],
        "reason": validated["reason"].strip(),
        "keywords": list(validated["keywords"]),
    }


def load_rules(path: Path | str | None = None):
    from .risk import RiskRule

    try:
        text = _resource_text("default_rules.json") if path is None else Path(path).read_text(encoding="utf-8")
        raw = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load risk rules: {exc}") from exc

    validated = _validate_document(raw)
    return tuple(RiskRule.from_dict(item) for item in validated)

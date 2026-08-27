from __future__ import annotations
import json, re
from importlib import resources
from pathlib import Path
from typing import Any

_REQUIRED={"code","score","severity","reason","keywords"}
_CODE=re.compile(r"^[A-Z][A-Z0-9_]*$")
_SEVERITIES={"none","low","medium","high","critical"}

def validate_rule(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data,dict): raise ValueError("Each rule must be a JSON object")
    missing=_REQUIRED-set(data); extra=set(data)-_REQUIRED
    if missing: raise ValueError(f"Rule missing required keys: {', '.join(sorted(missing))}")
    if extra: raise ValueError(f"Rule contains unknown keys: {', '.join(sorted(extra))}")
    code=data["code"]
    if not isinstance(code,str) or not _CODE.fullmatch(code): raise ValueError("Rule code must match ^[A-Z][A-Z0-9_]*$")
    score=data["score"]
    if isinstance(score,bool) or not isinstance(score,int) or not 0<=score<=100: raise ValueError(f"Rule {code}: score must be integer 0..100")
    severity=data["severity"]
    if not isinstance(severity,str) or severity not in _SEVERITIES: raise ValueError(f"Rule {code}: invalid severity")
    reason=data["reason"]
    if not isinstance(reason,str) or not reason.strip(): raise ValueError(f"Rule {code}: reason must be non-empty")
    keywords=data["keywords"]
    if not isinstance(keywords,list) or not keywords or any(not isinstance(k,str) or not k.strip() for k in keywords):
        raise ValueError(f"Rule {code}: keywords must be a non-empty list of non-empty strings")
    if len(set(k.casefold() for k in keywords)) != len(keywords): raise ValueError(f"Rule {code}: keywords must be unique")
    return {"code":code,"score":score,"severity":severity,"reason":reason.strip(),"keywords":keywords}

def load_rules(path: Path | str | None = None):
    from .risk import RiskRule
    try:
        if path is None:
            text=resources.files("honey_agent_lab").joinpath("data/default_rules.json").read_text(encoding="utf-8")
        else:
            text=Path(path).read_text(encoding="utf-8")
        raw=json.loads(text)
    except (OSError,json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load risk rules: {exc}") from exc
    if not isinstance(raw,list) or not raw: raise ValueError("Risk rules document must be a non-empty JSON array")
    validated=[validate_rule(item) for item in raw]
    codes=[item["code"] for item in validated]
    if len(codes)!=len(set(codes)): raise ValueError("Risk rule codes must be unique")
    return tuple(RiskRule.from_dict(item) for item in validated)

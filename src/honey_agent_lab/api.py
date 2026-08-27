from __future__ import annotations
try:
    from fastapi import FastAPI, HTTPException
except ImportError as exc:
    raise RuntimeError("FastAPI support is optional. Install with: pip install -e '.[api]'") from exc
from .orchestrator import run_scenario
from .scenarios import list_scenarios
app=FastAPI(title="Honey Agent Lab Local API",version="0.4.0",description="Loopback-oriented defensive simulation API. No outbound calls.")
@app.get("/health")
def health(): return {"status":"ok"}
@app.get("/scenarios")
def scenarios(): return [{"name":s.name,"description":s.description} for s in list_scenarios()]
@app.post("/run/{scenario_name}")
def run(scenario_name:str):
    try:return run_scenario(scenario_name).to_dict()
    except ValueError as exc: raise HTTPException(status_code=404,detail=str(exc)) from exc

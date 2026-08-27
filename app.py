from __future__ import annotations

import json
import sys
from pathlib import Path

import gradio as gr

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if SRC.exists():
    sys.path.insert(0, str(SRC))

from honey_agent_lab.orchestrator import run_scenario
from honey_agent_lab.scenarios import list_scenarios


def run_demo(name: str) -> tuple[str, str]:
    result = run_scenario(name)
    final = result.final_decision
    assessment = result.final_assessment
    summary = (
        f"Risk: {assessment.severity.value} / {assessment.total_score}\n"
        f"Action: {final.action.value}\n"
        f"Reason: {final.reason}\n"
        f"Audit integrity: {result.ledger.verify_integrity()}"
    )
    return summary, json.dumps(result.to_dict(), indent=2, sort_keys=True)


with gr.Blocks(title="Honey Agent Lab") as demo:
    gr.Markdown(
        "# Honey Agent Lab\n"
        "Defensive simulation for detecting synthetic agent compromise and unauthorized coordination.\n\n"
        "No real agents, no secrets, no network scanning, no live exploitation."
    )
    scenario = gr.Dropdown(
        choices=[item.name for item in list_scenarios()],
        value="scenario_001",
        label="Synthetic scenario",
    )
    run = gr.Button("Run simulation")
    summary = gr.Textbox(label="Summary", lines=5)
    trace = gr.Code(label="JSON trace", language="json")
    run.click(run_demo, inputs=scenario, outputs=[summary, trace])

if __name__ == "__main__":
    demo.launch()

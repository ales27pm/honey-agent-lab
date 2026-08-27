from __future__ import annotations

from html import escape

from .orchestrator import SimulationResult


def render_static_dashboard(result: SimulationResult) -> str:
    """Render a dependency-free HTML snapshot for local review."""
    final = result.final_decision
    assessment = result.final_assessment
    rows = []
    for event in result.ledger.events:
        rows.append(
            "<tr>"
            f"<td>{event.index}</td>"
            f"<td>{escape(event.event_type)}</td>"
            f"<td><code>{escape(event.event_hash[:12])}</code></td>"
            "</tr>"
        )
    rows_html = "\n".join(rows)
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>Honey Agent Lab — {escape(result.scenario.name)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 980px; }}
    code {{ background: #f2f2f2; padding: 0.1rem 0.25rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #ddd; padding: 0.45rem; text-align: left; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border: 1px solid #111; }}
  </style>
</head>
<body>
  <h1>Honey Agent Lab</h1>
  <p><strong>Scenario:</strong> {escape(result.scenario.description)}</p>
  <p><strong>Risk:</strong> <span class=\"badge\">{assessment.severity.value} / {assessment.total_score}</span></p>
  <p><strong>Action:</strong> <span class=\"badge\">{final.action.value}</span></p>
  <p><strong>Reason:</strong> {escape(final.reason)}</p>
  <h2>Controls</h2>
  <ul>{''.join(f'<li>{escape(control)}</li>' for control in final.controls)}</ul>
  <h2>Audit events</h2>
  <table>
    <thead><tr><th>#</th><th>Type</th><th>Hash prefix</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
</body>
</html>"""

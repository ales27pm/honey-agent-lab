from __future__ import annotations

from html import escape

from .orchestrator import SimulationResult


def render_static_dashboard(result: SimulationResult) -> str:
    """Render a dependency-free HTML snapshot for local review."""
    final = result.final_decision
    assessment = result.final_assessment
    event_rows = "\n".join(
        "<tr>"
        f"<td>{event.index}</td><td>{escape(event.event_type)}</td>"
        f"<td><code>{escape(event.event_hash[:12])}</code></td>"
        "</tr>"
        for event in result.ledger.events
    )
    finding_rows = "\n".join(
        "<tr>"
        f"<td>{escape(finding.code)}</td>"
        f"<td><span class=\"severity severity-{escape(finding.severity.value)}\">{escape(finding.severity.value)}</span></td>"
        f"<td>{finding.score}</td><td>{escape(finding.reason)}</td><td>{escape(finding.evidence)}</td>"
        "</tr>"
        for finding in assessment.findings
    ) or '<tr><td colspan="5">No findings</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<title>Honey Agent Lab — {escape(result.scenario.name)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 1100px; line-height: 1.45; }}
code {{ background: #f2f2f2; padding: .1rem .25rem; }} table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
td, th {{ border: 1px solid #ddd; padding: .45rem; text-align: left; vertical-align: top; }}
.badge, .severity {{ display: inline-block; padding: .2rem .45rem; border: 1px solid currentColor; border-radius: .25rem; }}
.severity-critical {{ font-weight: 800; }} .severity-high {{ font-weight: 700; }} .severity-medium {{ font-weight: 600; }}
@media print {{ body {{ margin: 0; max-width: none; }} button {{ display: none; }} }}
</style></head><body>
<h1>Honey Agent Lab</h1>
<p><strong>Scenario:</strong> {escape(result.scenario.description)}</p>
<p><strong>Risk:</strong> <span class="badge severity-{escape(assessment.severity.value)}">{assessment.severity.value} / {assessment.total_score}</span></p>
<p><strong>Action:</strong> <span class="badge">{final.action.value}</span></p>
<p><strong>Reason:</strong> {escape(final.reason)}</p>
<h2>Controls</h2><ul>{''.join(f'<li>{escape(control)}</li>' for control in final.controls)}</ul>
<h2>Risk findings</h2><table><thead><tr><th>Code</th><th>Severity</th><th>Score</th><th>Reason</th><th>Evidence</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Audit events</h2><table><thead><tr><th>#</th><th>Type</th><th>Hash prefix</th></tr></thead><tbody>{event_rows}</tbody></table>
<p><strong>Audit integrity:</strong> {result.ledger.verify_integrity()}</p>
</body></html>"""

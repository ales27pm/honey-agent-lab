from __future__ import annotations

from html import escape

from .fuzzer import FuzzSummary


def _count_rows(counts: dict[str, int]) -> str:
    if not counts:
        return '<tr><td colspan="2">None</td></tr>'
    return "\n".join(
        f"<tr><td>{escape(str(name))}</td><td>{int(count)}</td></tr>"
        for name, count in sorted(counts.items())
    )


def render_fuzz_report(summary: FuzzSummary, title: str = "Honey Agent Lab Fuzz Report") -> str:
    """Render a dependency-free static HTML report for a synthetic fuzz run."""
    false_negative_items = "".join(
        f"<li><code>{escape(message_id)}</code></li>"
        for message_id in summary.potential_false_negatives
    ) or "<li>None</li>"
    safe_title = escape(title)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>{safe_title}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 1050px; line-height: 1.45; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
td, th {{ border: 1px solid #ddd; padding: .45rem; text-align: left; }}
code {{ background: #f2f2f2; padding: .1rem .25rem; }}
.metric {{ display: inline-block; margin-right: 1rem; padding: .3rem .55rem; border: 1px solid #aaa; border-radius: .25rem; }}
@media print {{ body {{ margin: 0; max-width: none; }} }}
</style></head><body>
<h1>{safe_title}</h1>
<p><span class="metric"><strong>Total messages:</strong> {summary.total_messages}</span>
<span class="metric"><strong>Obfuscated messages:</strong> {summary.obfuscated_messages}</span></p>
<h2>Action counts</h2><table><thead><tr><th>Action</th><th>Count</th></tr></thead><tbody>{_count_rows(summary.action_counts)}</tbody></table>
<h2>Severity counts</h2><table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{_count_rows(summary.severity_counts)}</tbody></table>
<h2>Signal coverage</h2><table><thead><tr><th>Signal</th><th>Count</th></tr></thead><tbody>{_count_rows(summary.triggered_codes)}</tbody></table>
<h2>Potential false negatives</h2><ul>{false_negative_items}</ul>
<p>This report contains inert synthetic test results only.</p>
</body></html>"""

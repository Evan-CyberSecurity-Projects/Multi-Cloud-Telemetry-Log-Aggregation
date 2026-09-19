from html import escape
from pathlib import Path
from typing import Any, Iterable

from .detections import Detection


def render_dashboard(
    summary: dict[str, Any],
    detections: Iterable[Detection],
) -> str:
    detection_list = list(detections)

    severity_cards = "".join(
        (
            f'<section class="card severity-{escape(severity)}">'
            f"<span>{escape(severity.upper())}</span>"
            f"<strong>{count}</strong>"
            "</section>"
        )
        for severity, count in summary[
            "detections_by_severity"
        ].items()
    )

    coverage_items = "".join(
        (
            "<li>"
            f"{escape(tactic)}: {count}"
            "</li>"
        )
        for tactic, count in summary[
            "detections_by_tactic"
        ].items()
    )

    rows = "".join(
        (
            f'<tr class="finding-row severity-{escape(detection.severity)}" '
            f'data-severity="{escape(detection.severity)}">'
            f"<td>{escape(detection.rule_id)}</td>"
            f'<td class="severity">{escape(detection.severity.upper())}</td>'
            f"<td>{escape(detection.event.source)}</td>"
            f"<td>{escape(detection.mitre_tactic)}</td>"
            f"<td>{escape(detection.mitre_technique)}</td>"
            f"<td>{escape(detection.confidence.upper())}</td>"
            f"<td>{escape(detection.title)}</td>"
            f"<td>{escape(detection.recommended_action)}</td>"
            "</tr>"
        )
        for detection in detection_list
    )

    if not rows:
        rows = (
            '<tr><td colspan="8">'
            "No detections generated."
            "</td></tr>"
        )

    return (
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Security Telemetry Dashboard</title>"
        "<style>"
        "body { font-family: Arial, sans-serif; margin: 2rem; "
        "background: #0f172a; color: #e2e8f0; }"
        "h1, h2 { color: #f8fafc; }"
        ".subtitle, label { color: #94a3b8; }"
        ".metrics { display: flex; gap: 1rem; flex-wrap: wrap; "
        "margin: 1.5rem 0; }"
        ".card { background: #1e293b; border-radius: 10px; "
        "padding: 1rem; min-width: 120px; border-left: 5px solid #64748b; }"
        ".severity-high { border-left-color: #ef4444; }"
        ".severity-medium { border-left-color: #f59e0b; }"
        ".card span { display: block; color: #94a3b8; font-size: 0.8rem; }"
        ".card strong { display: block; color: #f8fafc; "
        "font-size: 2rem; margin-top: 0.4rem; }"
        ".coverage { background: #1e293b; border-radius: 10px; "
        "padding: 1rem; margin: 1.5rem 0; }"
        ".controls { margin: 1.5rem 0; }"
        "select { padding: 0.5rem; margin-left: 0.5rem; }"
        "table { width: 100%; border-collapse: collapse; background: #1e293b; }"
        "th, td { padding: 0.8rem; text-align: left; "
        "border-bottom: 1px solid #334155; vertical-align: top; }"
        "th { color: #cbd5e1; }"
        "td.severity { font-weight: bold; }"
        ".finding-row.severity-high td.severity { color: #f87171; }"
        ".finding-row.severity-medium td.severity { color: #fbbf24; }"
        "</style>"
        "</head>"
        "<body>"
        "<h1>Multi-Cloud Security Telemetry</h1>"
        "<p class=\"subtitle\">Local replay analysis dashboard</p>"
        "<section class=\"metrics\">"
        '<section class="card">'
        "<span>Normalized events</span>"
        f"<strong>{summary['total_events']}</strong>"
        "</section>"
        '<section class="card">'
        "<span>Detections</span>"
        f"<strong>{summary['total_detections']}</strong>"
        "</section>"
        f"{severity_cards}"
        "</section>"
        '<section class="coverage">'
        "<h2>ATT&CK-aligned coverage</h2>"
        f"<ul>{coverage_items}</ul>"
        "</section>"
        '<section class="controls">'
        '<label for="severity-filter">Filter findings by severity:</label>'
        '<select id="severity-filter" onchange="filterFindings()">'
        '<option value="all">All</option>'
        '<option value="high">High</option>'
        '<option value="medium">Medium</option>'
        "</select>"
        "</section>"
        "<h2>Detection findings</h2>"
        '<table id="findings">'
        "<thead>"
        "<tr>"
        "<th>Rule</th>"
        "<th>Severity</th>"
        "<th>Source</th>"
        "<th>Tactic</th>"
        "<th>Technique</th>"
        "<th>Confidence</th>"
        "<th>Finding</th>"
        "<th>Recommended action</th>"
        "</tr>"
        "</thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
        "<script>"
        "function filterFindings() {"
        "const selected = document.getElementById('severity-filter').value;"
        "document.querySelectorAll('.finding-row').forEach((row) => {"
        "row.style.display = selected === 'all' || "
        "row.dataset.severity === selected ? '' : 'none';"
        "});"
        "}"
        "</script>"
        "</body>"
        "</html>"
    )


def write_dashboard(
    summary: dict[str, Any],
    detections: Iterable[Detection],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_dashboard(summary, detections),
        encoding="utf-8",
    )

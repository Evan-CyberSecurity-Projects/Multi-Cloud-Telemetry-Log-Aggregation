from pathlib import Path
from typing import Any

from .aws import normalize_cloudtrail
from .azure import normalize_activity_log
from .dashboard import write_dashboard
from .detections import Detection, detect
from .loader import load_json
from .pipeline import write_detections, write_events
from .report import build_summary, write_summary
from .schema import NormalizedEvent
from .wazuh import normalize_wazuh_alert


def normalize_raw_event(raw_event: dict[str, Any]) -> NormalizedEvent:
    if "eventTime" in raw_event:
        return normalize_cloudtrail(raw_event)

    if "eventTimestamp" in raw_event:
        return normalize_activity_log(raw_event)

    if "@timestamp" in raw_event and "rule" in raw_event:
        return normalize_wazuh_alert(raw_event)

    raise ValueError(
        "Unsupported event format. Expected AWS, Azure, or Wazuh data."
    )


def process_directory(input_path: Path) -> list[NormalizedEvent]:
    event_paths = sorted(input_path.glob("*.json"))

    if not event_paths:
        raise ValueError(f"No JSON files found in {input_path}")

    events = []

    for event_path in event_paths:
        raw_event = load_json(event_path)
        events.append(normalize_raw_event(raw_event))

    return events


def run_pipeline(
    input_path: Path,
    output_path: Path,
) -> tuple[
    list[NormalizedEvent],
    list[Detection],
    dict[str, Any],
]:
    events = process_directory(input_path)

    detections = []

    for event in events:
        detections.extend(detect(event))

    summary = build_summary(events, detections)

    write_events(events, output_path / "normalized_events.jsonl")
    write_detections(detections, output_path / "detections.jsonl")
    write_summary(summary, output_path / "summary.json")
    write_dashboard(summary, detections, output_path / "dashboard.html")

    return events, detections, summary

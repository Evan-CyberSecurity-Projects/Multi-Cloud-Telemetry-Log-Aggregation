import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .detections import Detection
from .schema import NormalizedEvent


def build_summary(
    events: Iterable[NormalizedEvent],
    detections: Iterable[Detection],
) -> dict[str, Any]:
    event_list = list(events)
    detection_list = list(detections)

    events_by_source = Counter(event.source for event in event_list)
    detections_by_source = Counter(
        detection.event.source for detection in detection_list
    )
    detections_by_severity = Counter(
        detection.severity for detection in detection_list
    )
    detections_by_tactic = Counter(
        detection.mitre_tactic for detection in detection_list
    )
    detections_by_confidence = Counter(
        detection.confidence for detection in detection_list
    )

    return {
        "total_events": len(event_list),
        "total_detections": len(detection_list),
        "events_by_source": dict(sorted(events_by_source.items())),
        "detections_by_source": dict(
            sorted(detections_by_source.items())
        ),
        "detections_by_severity": dict(
            sorted(detections_by_severity.items())
        ),
        "detections_by_tactic": dict(
            sorted(detections_by_tactic.items())
        ),
        "detections_by_confidence": dict(
            sorted(detections_by_confidence.items())
        ),
    }


def write_summary(summary: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(summary, output_file, indent=2)
        output_file.write("\n")

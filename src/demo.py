from pathlib import Path

from .aws import normalize_cloudtrail
from .azure import normalize_activity_log
from .detections import detect
from .loader import load_json
from .pipeline import write_detections, write_events
from .report import build_summary, write_summary
from .wazuh import normalize_wazuh_alert


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    sample_data_path = project_root / "sample_data"
    output_path = project_root / "output"

    aws_event = load_json(
        sample_data_path / "aws_failed_create_user.json"
    )
    azure_event = load_json(
        sample_data_path / "azure_role_assignment.json"
    )
    wazuh_event = load_json(
        sample_data_path / "wazuh_dll_hijack.json"
    )

    events = [
        normalize_cloudtrail(aws_event),
        normalize_activity_log(azure_event),
        normalize_wazuh_alert(wazuh_event),
    ]

    detections = []

    for event in events:
        detections.extend(detect(event))

    events_file = output_path / "normalized_events.jsonl"
    detections_file = output_path / "detections.jsonl"
    summary_file = output_path / "summary.json"

    write_events(events, events_file)
    write_detections(detections, detections_file)

    summary = build_summary(events, detections)
    write_summary(summary, summary_file)

    print(f"Wrote {len(events)} normalized events to {events_file}")
    print(
        f"Wrote {len(detections)} detections to {detections_file}"
    )
    print(f"Wrote summary report to {summary_file}")
    print(f"Detections by severity: {summary['detections_by_severity']}")

    for detection in detections:
        print(
            f"[{detection.severity.upper()}] "
            f"{detection.rule_id}: {detection.title}"
        )


if __name__ == "__main__":
    main()

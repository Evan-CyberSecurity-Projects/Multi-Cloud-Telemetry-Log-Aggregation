import argparse
from pathlib import Path

from .runner import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize multi-cloud telemetry and generate "
            "security findings."
        )
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("sample_data"),
        help="Directory containing JSON telemetry files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for generated reports.",
    )

    args = parser.parse_args()

    events, detections, summary = run_pipeline(
        args.input_dir,
        args.output_dir,
    )

    print(f"Processed {len(events)} telemetry event(s).")
    print(f"Generated {len(detections)} detection(s).")
    print(f"Detections by severity: {summary['detections_by_severity']}")
    print(f"Dashboard: {args.output_dir / 'dashboard.html'}")


if __name__ == "__main__":
    main()

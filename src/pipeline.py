import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .detections import Detection
from .schema import NormalizedEvent


def write_events(
    events: Iterable[NormalizedEvent],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        for event in events:
            output_file.write(json.dumps(asdict(event)) + "\n")


def write_detections(
    detections: Iterable[Detection],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as output_file:
        for detection in detections:
            output_file.write(json.dumps(asdict(detection)) + "\n")

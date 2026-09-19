# Architecture and Data Flow

## Event flow

```mermaid
sequenceDiagram
    participant S as Telemetry Source
    participant L as loader.py
    participant A as Source Adapter
    participant D as detections.py
    participant P as pipeline.py
    participant R as report.py

    S->>L: Sanitized JSON event
    L->>A: Python dictionary
    A->>D: NormalizedEvent
    D->>P: Event and Detection objects
    P->>R: Stored outputs
    R-->>R: summary.json

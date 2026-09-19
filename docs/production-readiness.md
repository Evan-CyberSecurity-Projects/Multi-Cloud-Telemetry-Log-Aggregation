# Production Readiness Design

## Current implementation

This project uses a zero-cost local replay model:

- Windows Sysmon telemetry was validated through Wazuh.
- AWS CloudTrail Event History and Azure Activity Log access were verified.
- Sanitized fixtures replay the vendor event shapes through the local pipeline.
- The pipeline runs locally or in a container.

## Production ingestion design

```mermaid
flowchart TD
    A["AWS CloudTrail"] --> D["Cloud ingestion service"]
    B["Azure Activity Logs"] --> D
    C["Wazuh alerts"] --> D
    D --> E["Normalization and detection service"]
    E --> F["Searchable event store"]
    E --> G["Analyst dashboard / alert channel"]

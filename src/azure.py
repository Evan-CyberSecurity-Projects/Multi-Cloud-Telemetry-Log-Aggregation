from typing import Any

from .schema import NormalizedEvent

def normalize_activity_log(raw_event: dict[str, Any]) -> NormalizedEvent:
    status = raw_event.get("status", {}).get("value", "unknown").lower()

    if status == "succeeded":
        outcome = "success"
    elif status == "failed":
        outcome = "failure"
    else:
        outcome = status

    return NormalizedEvent(
        timestamp=raw_event["eventTimestamp"],
        source="azure_activity_log",
        actor=raw_event.get("caller", "unknown"),
        action=raw_event.get("operationName", {}).get("value", "unknown"),
        outcome=outcome,
        resource=raw_event.get("resourceId"),
        source_ip=raw_event.get("httpRequest", {}).get("clientIpAddress"),
        raw_event=raw_event,
    )

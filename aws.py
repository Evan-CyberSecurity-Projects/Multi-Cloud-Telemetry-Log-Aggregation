from typing import Any

from .schema import NormalizedEvent

def normalize_cloudtrail(raw_event: dict[str, Any]) -> NormalizedEvent:
    resources = raw_event.get("resources", [])
    resource = resources[0].get("ARN") if resources else None

    return NormalizedEvent(
        timestamp=raw_event["eventTime"],
        source="aws_cloudtrail",
        actor=raw_event.get("userIdentity", {}).get("arn", "unkown"),
        action=f"{raw_event.get('eventSource', 'unkown')}:{raw_event.get('eventName', 'unkown')}",
        outcome="failure" if raw_event.get("errorCode") else "success",
        resource=resource,
        source_ip=raw_event.get("sourceIPAddress"),
        raw_event=raw_event,
    )

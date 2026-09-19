from typing import Any

from .schema import NormalizedEvent


def normalize_wazuh_alert(raw_event: dict[str, Any]) -> NormalizedEvent:
    rule = raw_event.get("rule", {})
    agent = raw_event.get("agent", {})

    return NormalizedEvent(
        timestamp=raw_event["@timestamp"],
        source="wazuh_sysmon",
        actor=agent.get("name", "unknown"),
        action=f"wazuh_rule:{rule.get('id', 'unknown')}",
        outcome="alert",
        resource=raw_event.get("location"),
        source_ip=agent.get("ip"),
        raw_event=raw_event,
    )

from dataclasses import dataclass
from typing import Any


@dataclass
class NormalizedEvent:
    timestamp: str
    source: str
    actor: str
    action: str
    outcome: str
    resource: str | None
    source_ip: str | None
    raw_event: dict[str, Any]

    

from dataclasses import dataclass

from .schema import NormalizedEvent


@dataclass
class Detection:
    rule_id: str
    severity: str
    title: str
    description: str
    event: NormalizedEvent
    mitre_tactic: str = "Unmapped"
    mitre_technique: str = "Unmapped"
    confidence: str = "medium"
    recommended_action: str = (
        "Review the source event and validate the activity."
    )


def detect(event: NormalizedEvent) -> list[Detection]:
    detections = []

    if (
        event.source == "aws_cloudtrail"
        and event.action == "iam.amazonaws.com:CreateUser"
        and event.outcome == "failure"
    ):
        detections.append(
            Detection(
                rule_id="CLOUD-001",
                severity="medium",
                title="Failed AWS IAM user creation attempt",
                description=(
                    f"{event.actor} attempted to create an IAM user "
                    "but the action was denied."
                ),
                event=event,
                mitre_tactic="Persistence",
                mitre_technique=(
                    "T1136.003 Create Cloud Account"
                ),
                confidence="medium",
                recommended_action=(
                    "Validate whether the actor was authorized to "
                    "create IAM users. Review CloudTrail activity "
                    "before and after the denied request."
                ),
            )
        )

    if (
        event.source == "azure_activity_log"
        and event.action
        == "Microsoft.Authorization/roleAssignments/write"
        and event.outcome == "success"
    ):
        detections.append(
            Detection(
                rule_id="CLOUD-002",
                severity="high",
                title="Azure RBAC role assignment changed",
                description=(
                    f"{event.actor} successfully changed an Azure "
                    "role assignment."
                ),
                event=event,
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1098 Account Manipulation",
                confidence="high",
                recommended_action=(
                    "Identify the principal, role, target scope, "
                    "and change ticket. Revoke unexpected access "
                    "and investigate related Azure activity."
                ),
            )
        )

    if (
        event.source == "wazuh_sysmon"
        and event.action == "wazuh_rule:92219"
    ):
        detections.append(
            Detection(
                rule_id="ENDPOINT-001",
                severity="medium",
                title="Possible DLL search order hijack",
                description=(
                    f"Wazuh reported rule 92219 on {event.actor}. "
                    "Review the process, DLL path, signature, and "
                    "surrounding events before deciding whether it "
                    "is malicious."
                ),
                event=event,
                mitre_tactic=(
                    "Persistence / Privilege Escalation"
                ),
                mitre_technique=(
                    "T1574.001 DLL Search Order Hijacking"
                ),
                confidence="medium",
                recommended_action=(
                    "Validate the executable signature, inspect the "
                    "DLL hash and path, and correlate parent-child "
                    "process activity before escalating."
                ),
            )
        )

    return detections

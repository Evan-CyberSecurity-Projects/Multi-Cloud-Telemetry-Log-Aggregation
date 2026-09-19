# SOC Triage Walkthrough: ENDPOINT-001

## Alert

- Rule ID: `ENDPOINT-001`
- Source rule: Wazuh `92219`
- Severity: Medium
- Title: Possible DLL search-order hijack

## Why this alert matters

DLL search-order hijacking can occur when a process loads an unintended DLL from a location searched before the legitimate library. Attackers may use this behavior for execution or persistence.

## Evidence observed in the lab

The Wazuh/Sysmon pipeline generated rule `92219` related to `sshim.dll`.

Initial review showed:

- Windows process: `C:\Windows\System32\svchost.exe`
- Process signature status: Valid
- Execution context: `SYSTEM`
- File location: Windows temporary/compatibility-related path
- Wazuh rule level: 6

## Analyst assessment

This event should not be declared malicious solely because the detection fired.

The valid Microsoft-signed process and compatibility-related context suggest this may be benign operating-system or installer behavior. However, the DLL path and surrounding process activity still warrant review.

## Recommended investigation steps

1. Verify the process path and digital signature.
2. Inspect the created DLL path and hash.
3. Review parent/child process activity around the event.
4. Check whether the same behavior occurs repeatedly or on other hosts.
5. Correlate with software installation, update, or compatibility activity.
6. Escalate only if evidence indicates unexpected process behavior, unsigned binaries, persistence, or lateral movement.

## Conclusion

The rule successfully surfaced a potentially suspicious endpoint condition. The correct outcome is documented analyst review—not an unsupported claim of compromise.

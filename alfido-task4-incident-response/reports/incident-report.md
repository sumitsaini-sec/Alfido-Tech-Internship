# Task 4 | Incident Response Simulation

## Incident overview

### Scope and disclosure

Task 4 - Incident Response Simulation. Prepared for Sumit Saini. Report date: 7 September 2026. Case ID: IR-SIM-004. All telemetry is synthetic and normalized; no live Windows host, SIEM or production account was accessed. Analysis ran offline using Python. Response actions below are proposed only.

### Executive assessment

The dataset contains 56 events: 32 benign background events and 24 events in the suspicious sequence. WS-FIN-01 receives 18 failed remote interactive logons from 198.51.100.23, followed by a successful logon for LAB\finance.user. The same session starts hidden PowerShell; correlated DNS and repeated outbound connections follow. Treat as a high-priority suspected account compromise within this simulation.

### What the evidence does and does not show

The linked sequence supports investigation and escalation. It does not prove that a password was guessed, that the user was unauthorized, that malware executed, or that data left the host. PowerShell contains only a harmless Write-Output command; the generator creates the network records separately. Callback behavior is a hypothesis, not a demonstrated effect of this command.

### Environment and tools

WS-FIN-01 (10.10.20.15) is the simulated finance endpoint; WS-HR-02 supplies benign comparison events. Input: data/events.jsonl. Tools actually used: Python standard-library generator, analyzer and unittest. Report generated with ReportLab. No Splunk, EDR isolation or real packet capture is claimed.

### Task coverage

Suspicious log analysis: analyzer and 56-event dataset. Possible IOCs: indicator register. Response and containment: page 3. Required deliverables: this PDF plus detected-anomalies.md. Editable report, execution output, evidence image and a GitHub guide are also included.

## Evidence and investigation

### Timeline (UTC, 7 September 2026)

09:02:00-09:04:50: 18 failed logons (Security 4625, type 10). 09:05:05: successful logon (4624), 15 seconds after the final failure. 09:05:20: PowerShell creation (Sysmon 1), session 0xA91. 09:05:30: DNS query (Sysmon 22). 09:05:40, 09:06:40, 09:07:40: outbound connections (Sysmon 3), each 60 seconds apart.

### Correlation method

First group failures by host, account and source IP; require at least 10 in five minutes. Match the later successful remote logon. Join process creation by host, user and logon ID. Join DNS and network records by host and process GUID, requiring the destination to match the DNS answer. Full record-level references are in detected-anomalies.md and findings.json.

### Five detector findings

IR-01 / medium: failure burst (18 events). IR-02 / high: success following burst. IR-03 / medium: hidden PowerShell in the same session. IR-04 / medium: DNS-to-destination correlation. IR-05 / medium: three periodic connections. These are related findings in one scenario, not five confirmed incidents.

### Candidate indicators and affected entities

Candidate indicators: source 198.51.100.23, domain updates-check.example, destination 203.0.113.77:443. Asset: WS-FIN-01. Account: LAB\finance.user. All are synthetic and unverified. The host, account and process GUID are investigation pivots rather than proof of maliciousness.

### Alternative explanations and scope gaps

Mistyped or stale credentials may cause failures; a legitimate remote user could later succeed. Hidden PowerShell and periodic network activity may be administrative. Verify user activity, approved changes, remote-access exposure and endpoint history. No additional affected hosts are evidenced in this limited dataset; absence of additional events is not evidence of absence.

## Response and containment plan

### 1. Triage and preserve | SOC L1 | Proposed

Open a case and escalate the linked sequence to SOC L2 / incident response. Record UTC timestamps and source record IDs. Preserve original logs, relevant endpoint telemetry and collection metadata; hash collected files. Confirm asset criticality and contact the account owner through a trusted channel. Avoid deleting artifacts before collection.

### 2. Contain | Incident lead, endpoint and identity teams | Proposed

After incident-owner authorization and business-impact review, isolate the affected endpoint while preserving the management channel. Restrict suspicious remote access. Disable or reset the account as appropriate and revoke active sessions. Block confirmed malicious destinations only after validation; the documentation addresses in this simulation are not operational block targets.

### 3. Investigate and eradicate | SOC L2 / IR | Proposed

Review process ancestry, scripts, downloads, persistence locations and authentication across other hosts. Collect additional evidence under the response procedure. Determine whether an approved administrative action explains the sequence. Remove confirmed malicious artifacts and persistence, or reimage if trust cannot be restored. No malware or persistence is established by this dataset.

### 4. Recover and validate | IT owner and incident lead | Proposed

Restore approved access after remediation, rotate affected credentials, verify endpoint health and apply the appropriate remote-access controls. Confirm host functionality and security telemetry. Monitor for renewed failures, suspicious sessions and matching network activity for an agreed observation period; extend if findings recur.

### 5. Close and improve | Incident lead | Pending evidence

Closure requires documented remediation, verification of legitimate access, a clean follow-up monitoring period and asset-owner sign-off. Record lessons learned and tune detection thresholds using normal behavior. Current status: analysis complete for the synthetic dataset; containment and recovery were not executed or validated.

## Reproduction, validation and references

### Reproduce this analysis

From the repository root run: python scripts/analyze_logs.py. Expected output: Events: 56 | Findings: 5. Optional regeneration: python scripts/generate_logs.py. Run tests: python -m unittest discover -s tests -v. Python 3.10+ is sufficient for these commands; no external packages or network access are needed.

### Validation evidence

Five tests passed: full chain, benign-only data, wrong session, wrong process, and reversed input order. Benign-only data yields zero findings. Changing the session removes the downstream process chain; changing the process GUID removes DNS/network findings. Actual stdout and test output are in evidence/. The evidence PNG renders captured output and is not a live SIEM screenshot.

### Known limits

Rules are educational and intentionally narrow. Only the largest failure window per tuple is analyzed; multiple sessions and DNS records may require deduplication. There is no raw EVTX ingestion, threat-intelligence enrichment, packet inspection, real credential attack, or post-containment evidence. Three periodic connections are insufficient to establish command-and-control.

### Source references

Microsoft Event 4624: successful logon and RemoteInteractive type 10. Microsoft Event 4625: failed logon. Microsoft Sysmon documentation: event 1 process creation, 22 DNS query and 3 network connection. Clickable source links are listed below. Task requirements were transcribed from the supplied Alfido Tech task screenshot.

### Portfolio statement

A reproducible sample-log incident response simulation prepared for SOC L1 learning and Task 4 submission. Review the evidence and rerun the analysis before presenting it. This report does not claim that the named learner performed a live incident response engagement.

Technical reference links: see ../README.md.

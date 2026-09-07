# Incident Response Simulation | SOC Analyst L1

**Alfido Tech - Cybersecurity Task 4**  
Prepared for: **Sumit Saini** | [GitHub](https://github.com/sumitsaini-sec)

A reproducible, offline investigation of a simulated remote-login incident using normalized Windows Security and Sysmon-style logs.

> **Simulation disclosure:** All events, systems, accounts, addresses and activity are synthetic. This project does not claim a real compromise, live Windows capture, Splunk deployment, or completed containment. The scripts only read/write local files. The PowerShell command in the dataset is harmless text and is never executed.

## Results

- 56 sample events: 32 benign background events and 24 incident-sequence events.
- 18 failed remote interactive logons in 170 seconds, followed 15 seconds later by a successful logon.
- A hidden PowerShell process tied to the same host, account and session.
- DNS and outbound connection records tied to the same process; three connections 60 seconds apart.
- 5 detection findings, with event references and a documented response plan.

**Assessment:** high-priority suspected account compromise within the scenario. Malicious intent, credential theft, command-and-control and data exfiltration are not established by these logs.

## Run locally

Python 3.10+; no third-party packages required for analysis.

```bash
python scripts/analyze_logs.py
python -m unittest discover -s tests -v
```

On Windows, use `py` instead of `python` if needed. Run commands from this repository's folder. The analyzer reads `data/events.jsonl` and writes `reports/findings.json`.

To regenerate the exact input dataset:

```bash
python scripts/generate_logs.py
python scripts/analyze_logs.py
```

## Review the evidence

| File | Purpose |
| --- | --- |
| [Incident report (PDF)](reports/Task4_Incident_Report.pdf) | Submission-ready investigation and proposed response |
| [Incident report (Markdown)](reports/incident-report.md) | Editable findings, limitations and response plan |
| [Detected anomalies](reports/detected-anomalies.md) | Five findings mapped to source record IDs |
| [Indicator register](reports/indicator-register.md) | Synthetic indicators, meaning and limitations |
| [Sample logs](data/events.jsonl) | Original normalized synthetic input |
| [Findings JSON](reports/findings.json) | Reproducible detector results |
| [Analysis output](evidence/analysis-output.txt) | Actual captured run output |
| [Evidence image](evidence/analysis-evidence.png) | Rendered analysis output, explicitly labeled |
| [Timeline](reports/timeline.md) | All incident-sequence records in UTC |
| [Schema and detection rules](docs/methodology.md) | Field definitions, thresholds and known limits |
| [GitHub upload guide](docs/GITHUB_UPLOAD_HINGLISH.md) | Upload and submission steps |

## Investigation flow

1. Review provider, event ID, timestamp, host, account and source address.
2. Detect a failure burst and correlate the later successful logon.
3. Link the process to the logon session; link DNS/network events by process GUID.
4. Separate observed facts from hypotheses and document alternative explanations.
5. Escalate, preserve evidence and propose containment with the incident owner.
6. Define recovery checks; do not call the incident resolved without follow-up evidence.

## Scope and limitations

This is a teaching detector for the provided normalized JSON schema, not an EVTX parser or production SIEM. It selects the largest five-minute failure window per host/account/source tuple. Multiple separate bursts and overlapping sessions can require deduplication and a streaming detector. Periodicity uses a minimum of three observations and is weak evidence. There is no reputation lookup, malware sample, file hash IOC, packet content or post-containment telemetry.

## Requirement coverage

| Task 4 requirement | Included evidence |
| --- | --- |
| Analyze suspicious Windows / SIEM sample logs | Dataset, Python analyzer and captured results |
| Identify possible IOCs | Indicator register with evidence and caveats |
| Document response and containment | Report response plan with owners and validation |
| Incident report PDF / DOC | Five-page PDF plus editable Markdown |
| List of detected anomalies | Dedicated Markdown list and JSON findings |

## Technical references

- [Microsoft: Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft: Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

Task requirements were transcribed from the supplied Alfido Tech screenshot. No claim of endorsement or official certification is made.

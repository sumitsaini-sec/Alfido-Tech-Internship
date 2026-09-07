# Indicator register

All entries are synthetic; none has been reputation-verified or recommended for real blocking.

| Value | Type / role | Evidence and interpretation |
| --- | --- | --- |
| 198.51.100.23 | Source IP, candidate IOC | 18 failures then success; source of suspicious remote activity in this scenario |
| updates-check.example | Domain, candidate IOC | DNS query from correlated PowerShell; no reputation or maliciousness established |
| 203.0.113.77:443 | Destination, candidate IOC | Same process connects three times; possible callback, not proven C2 |
| WS-FIN-01 / 10.10.20.15 | Affected asset, not an IOC by itself | Destination of the suspicious login and origin of subsequent network events |
| LAB\finance.user | Account in scope, not an IOC by itself | Repeated failures and subsequent successful session 0xA91 |
| sim-process-001 | Synthetic process correlation key | Links process creation, DNS and network events; not a reusable IOC |

No malicious file or file hash is supplied. `powershell.exe` is a legitimate binary and its presence alone is not evidence of compromise. No IP reputation, geolocation, domain registration, TLS, payload or exfiltration conclusion can be drawn from this dataset.

# Detected anomalies

All evidence refers to synthetic `data/events.jsonl` records.

## IR-01 | MEDIUM

18 failed remote interactive logons within 5 minutes on WS-FIN-01

Evidence: EVT-0012, EVT-0014, EVT-0016, EVT-0017, EVT-0019, EVT-0021, EVT-0023, EVT-0024, EVT-0026, EVT-0028, EVT-0030, EVT-0031, EVT-0032, EVT-0035, EVT-0036, EVT-0038, EVT-0039, EVT-0042.

## IR-02 | HIGH

Successful remote logon following failure burst; possible account compromise

Evidence: EVT-0012, EVT-0014, EVT-0016, EVT-0017, EVT-0019, EVT-0021, EVT-0023, EVT-0024, EVT-0026, EVT-0028, EVT-0030, EVT-0031, EVT-0032, EVT-0035, EVT-0036, EVT-0038, EVT-0039, EVT-0042, EVT-0043.

## IR-03 | MEDIUM

Hidden PowerShell in the correlated session; command is harmless simulation text

Evidence: EVT-0043, EVT-0045.

## IR-04 | MEDIUM

DNS answer matches outbound destination from the same process; possible callback

Evidence: EVT-0045, EVT-0048, EVT-0049, EVT-0054, EVT-0056.

## IR-05 | MEDIUM

3 repeated connections at 60-second intervals; periodicity alone is inconclusive

Evidence: EVT-0049, EVT-0054, EVT-0056.

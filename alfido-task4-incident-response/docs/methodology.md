# Methodology and schema

All timestamps are UTC. Events cover 2026-09-07 09:00:00 to 09:07:40. The deterministic generator requires no seed, external service or attack execution. Documentation-only external addresses and an example domain are deliberately synthetic.

## Schema

Every record contains `record_id`, ISO-8601 `timestamp`, `provider`, integer `event_id`, `host`, `user`, and `synthetic: true`. Provider is `Security` or `Sysmon`; event ID alone is insufficient because providers have separate ID spaces. These normalized names are teaching fields, not a literal native Windows export.

- Security 4625: `source_ip`, `logon_type`, `status`, `sub_status`.
- Security 4624: `source_ip`, `logon_type`, `logon_id`.
- Sysmon 1: `logon_id`, `process_guid`, `image`, `parent_image`, `command_line`.
- Sysmon 22: `process_guid`, `query_name`, `query_results`, `query_status`.
- Sysmon 3: `process_guid`, `source_ip`, `destination_ip`, `destination_port`, `initiated`.

4625 represents failed logon; 4624 represents successful logon. Logon type 10 indicates RemoteInteractive. Sysmon 1 is process creation, 22 is DNS query, and 3 is network connection. These mappings are based on the Microsoft references linked in README. No native EventRecordID or native GUID authenticity is implied by the synthetic identifiers.

## Rules

- IR-01: at least 10 type-10 failures in a rolling 300-second inclusive window, grouped by host/account/source; report the largest window per tuple.
- IR-02: matching type-10 success strictly after and within 300 seconds of the last failure in that window.
- IR-03: PowerShell with `-WindowStyle Hidden` within 600 seconds of that success; same host/account/logon ID.
- IR-04: successful DNS answer and later matching destination IP within 600 seconds of the process creation, using the same host/process GUID.
- IR-05: at least three such connections, positive intervals and at most five seconds between the shortest and longest interval.

Thresholds are lab design choices, not universally correct production settings. There is no claim of comprehensive malicious PowerShell detection. Multiple DNS answers/events may cause duplicate findings. Production use needs schema validation, identity normalization, larger baselines, robust DNS parsing, session deduplication and rule tuning.

## Evidence integrity

`evidence/SHA256SUMS.txt` records SHA-256 digests for the delivered project files, excluding itself and transient bytecode. It detects later changes relative to this manifest; it does not authenticate the origin of synthetic events. `analysis-output.txt` and `test-output.txt` are actual captured execution output. The PNG is a rendering of that text, not a screen capture of a live SIEM.

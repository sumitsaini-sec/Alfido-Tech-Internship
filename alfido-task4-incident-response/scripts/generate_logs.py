"""Create deterministic, synthetic normalized Windows/Sysmon-style events. No network activity."""
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
ROOT = Path(__file__).resolve().parents[1]
def generate():
    rows = []
    def add(seconds, provider, event_id, **fields):
        rows.append(dict(timestamp=(datetime(2026,9,7,9,tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat().replace('+00:00','Z'), provider=provider, event_id=event_id, synthetic=True, **fields))
    # Benign background: isolated typing mistakes, routine successful logons and processes.
    for i in range(20):
        add(i*22, 'Security', 4624, host='WS-HR-02', user='LAB\\hr.user', source_ip='10.10.20.12', logon_type=3, logon_id=f'0xB{i:02x}')
    for i in range(10):
        add(i*40+3, 'Sysmon', 1, host='WS-HR-02', user='LAB\\hr.user', logon_id='0xB00', process_guid=f'benign-{i}', image='C:\\Windows\\System32\\notepad.exe', command_line='notepad.exe', parent_image='explorer.exe')
    for sec in (10,35):
        add(sec,'Security',4625,host='WS-HR-02',user='LAB\\hr.user',source_ip='10.10.20.12',logon_type=10,status='0xC000006D',sub_status='0xC000006A')
    for i in range(18):
        add(120+i*10,'Security',4625,host='WS-FIN-01',user='LAB\\finance.user',source_ip='198.51.100.23',logon_type=10,status='0xC000006D',sub_status='0xC000006A')
    add(305,'Security',4624,host='WS-FIN-01',user='LAB\\finance.user',source_ip='198.51.100.23',logon_type=10,logon_id='0xA91')
    add(320,'Sysmon',1,host='WS-FIN-01',user='LAB\\finance.user',logon_id='0xA91',process_guid='sim-process-001',image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',parent_image='explorer.exe',command_line='powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output IR-SIMULATION"')
    add(330,'Sysmon',22,host='WS-FIN-01',user='LAB\\finance.user',process_guid='sim-process-001',query_name='updates-check.example',query_results='203.0.113.77',query_status=0)
    for sec in (340,400,460):
        add(sec,'Sysmon',3,host='WS-FIN-01',user='LAB\\finance.user',process_guid='sim-process-001',source_ip='10.10.20.15',destination_ip='203.0.113.77',destination_port=443,initiated=True)
    rows.sort(key=lambda x:x['timestamp'])
    for i,r in enumerate(rows,1): r['record_id']=f'EVT-{i:04}'
    return rows
if __name__=='__main__':
    target=ROOT/'data/events.jsonl'
    target.write_text(''.join(json.dumps(r)+'\n' for r in generate()),encoding='utf-8')
    print(f'Wrote {len(generate())} synthetic events to {target.name}')

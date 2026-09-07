"""Offline teaching detector for the documented normalized schema, not raw EVTX."""
import argparse, json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def ts(r): return datetime.fromisoformat(r['timestamp'].replace('Z','+00:00'))
def analyze(rows):
    rows=sorted(rows,key=ts); findings=[]; groups=defaultdict(list); successes=[]; processes=[]
    def finding(rule,severity,summary,ev):
        findings.append(dict(rule=rule,severity=severity,summary=summary,evidence=[e['record_id'] for e in ev]))
    for r in rows:
        if r['provider']=='Security' and r['event_id']==4625 and r.get('logon_type')==10:
            groups[(r['host'],r['user'],r['source_ip'])].append(r)
    for key, failures in groups.items():
        burst=[]
        for end in failures:
            window=[r for r in failures if 0 <= (ts(end)-ts(r)).total_seconds() <=300]
            if len(window)>len(burst): burst=window
        if len(burst)<10: continue
        finding('IR-01','medium',f'{len(burst)} failed remote interactive logons within 5 minutes on {key[0]}',burst)
        for s in rows:
            if s['provider']=='Security' and s['event_id']==4624 and s.get('logon_type')==10 and (s['host'],s['user'],s.get('source_ip'))==key and 0<(ts(s)-ts(burst[-1])).total_seconds()<=300:
                successes.append(s)
                finding('IR-02','high','Successful remote logon following failure burst; possible account compromise',burst+[s])
    for s in successes:
        for p in rows:
            if p['provider']=='Sysmon' and p['event_id']==1 and p['host']==s['host'] and p.get('user')==s['user'] and p.get('logon_id')==s.get('logon_id') and 0<=(ts(p)-ts(s)).total_seconds()<=600 and p.get('image','').lower().endswith('\\powershell.exe') and '-windowstyle hidden' in p.get('command_line','').lower():
                processes.append(p)
                finding('IR-03','medium','Hidden PowerShell in the correlated session; command is harmless simulation text',[s,p])
    for p in processes:
        related=[r for r in rows if r['provider']=='Sysmon' and r['host']==p['host'] and r.get('process_guid')==p['process_guid'] and 0<=(ts(r)-ts(p)).total_seconds()<=600]
        for d in [r for r in related if r['event_id']==22 and r.get('query_status')==0]:
            connections=[r for r in related if r['event_id']==3 and r.get('initiated') and r.get('destination_ip') in d.get('query_results','').split(';') and ts(r)>=ts(d)]
            if connections: finding('IR-04','medium','DNS answer matches outbound destination from the same process; possible callback',[p,d]+connections)
            if len(connections)>=3:
                intervals=[(ts(b)-ts(a)).total_seconds() for a,b in zip(connections,connections[1:])]
                if min(intervals)>0 and max(intervals)-min(intervals)<=5:
                    finding('IR-05','medium',f'{len(connections)} repeated connections at {intervals[0]:g}-second intervals; periodicity alone is inconclusive',connections)
    return dict(total_events=len(rows),finding_count=len(findings),findings=findings)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',type=Path,default=ROOT/'data/events.jsonl'); ap.add_argument('--out',type=Path,default=ROOT/'reports/findings.json'); args=ap.parse_args()
    try:
        rows=[json.loads(s) for s in args.input.read_text(encoding='utf-8').splitlines() if s.strip()]
        result=analyze(rows)
    except (OSError,ValueError,KeyError,TypeError) as exc: ap.error(f'Invalid input: {exc}')
    args.out.parent.mkdir(parents=True,exist_ok=True); args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('TASK 4 | SYNTHETIC INCIDENT RESPONSE ANALYSIS')
    print(f"Events: {result['total_events']} | Findings: {result['finding_count']}")
    for f in result['findings']: print(f"{f['rule']} [{f['severity'].upper()}] {f['summary']}")
    print('No host isolation, blocking, account changes or network calls performed.')
if __name__=='__main__': main()

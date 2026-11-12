import csv,json
from pathlib import Path
from datetime import datetime
root=Path(__file__).resolve().parent
expected={'identity-events.csv':['I-01','I-02','I-03'],'destination-events.csv':['D-01','D-02'],'host-events.csv':['H-01','H-02','H-03','H-04']}
rows={name:list(csv.DictReader((root/name).open(newline=''))) for name in expected}
for name,ids in expected.items():
    assert [r['record_id'] for r in rows[name]]==ids,name
    for r in rows[name]:
        assert r['utc'].startswith('2025-01-16T12:00:') and r['utc'].endswith('Z')
        datetime.fromisoformat(r['utc'].replace('Z','+00:00'))
assert [r['event_id'] for r in rows['identity-events.csv']]==['4769','4769','4776']
assert all(r['source_address']=='' and r['workstation']=='' and r['logon_type']=='3' for r in rows['destination-events.csv'])
assert [r['authentication_package'] for r in rows['destination-events.csv']]==['Kerberos','NTLM']
assert [r['event_id'] for r in rows['host-events.csv']]==['1','3','3','3']
a,b=rows['identity-events.csv'][:2]
delta=(datetime.fromisoformat(b['utc'].replace('Z','+00:00'))-datetime.fromisoformat(a['utc'].replace('Z','+00:00'))).total_seconds()
assert delta==1.9
print(json.dumps({'result':'pass','counts':{n:len(v) for n,v in rows.items()},'totalRows':sum(map(len,rows.values())),'repeatedRequestDeltaSeconds':delta,'scope':'Synthetic record structure and keyed arithmetic only; no packet, authentication or relay proof'},indent=2))

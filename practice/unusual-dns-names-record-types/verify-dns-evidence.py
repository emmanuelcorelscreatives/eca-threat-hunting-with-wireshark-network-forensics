#!/usr/bin/env python3
"""Read-only offline DNS scope checker. Does not send packets or overwrite files."""
import argparse,subprocess,csv,io,json,datetime,hashlib
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',required=True,type=Path);p.add_argument('--domain',required=True);p.add_argument('--start',required=True);p.add_argument('--end',required=True);p.add_argument('--tshark',default='tshark');a=p.parse_args()
def stamp(s):
 t=datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
 if t.tzinfo is None: raise ValueError('Explicit UTC offset required')
 return t.timestamp()
start,end=stamp(a.start),stamp(a.end)
if start>=end: raise ValueError('Start must precede end')
domain=a.domain.lower().rstrip('.')
if not domain or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in domain):raise ValueError('Invalid candidate domain')
fields=['frame.number','frame.time_epoch','ip.src','ip.dst','dns.flags.response','dns.qry.name','dns.qry.type','dns.resp.type','dns.txt','dns.response_to','dns.response_in']
command=[a.tshark,'-2','-r',str(a.capture),'-Y','dns','-T','fields','-E','header=y','-E','separator=,','-E','quote=d']+sum((['-e',f]for f in fields),[])
raw=subprocess.run(command,check=True,capture_output=True,text=True)
rows=list(csv.DictReader(io.StringIO(raw.stdout)))
selected=[x for x in rows if start<=float(x['frame.time_epoch'])<end and (x['dns.qry.name'].lower().rstrip('.')==domain or x['dns.qry.name'].lower().rstrip('.').endswith('.'+domain))]
questions=[x for x in selected if x['dns.flags.response'] in ['False','0']]
names=sorted(set(x['dns.qry.name'].lower().rstrip('.') for x in questions))
print(json.dumps({'captureSha256':hashlib.sha256(a.capture.read_bytes()).hexdigest(),'candidateDomain':domain,'window':[a.start,a.end],'windowRule':'start inclusive, end exclusive','questions':questions,'distinctNames':names,'distinctCount':len(names),'records':selected,'limitations':'This checker does not establish capture provenance; document it independently. Source/destination addresses do not identify the original client, owner, process or malicious intent.'},indent=2))

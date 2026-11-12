#!/usr/bin/env python3
"""Read-only kit integrity, mapping and exported-field checks. Never writes outputs."""
import argparse,csv,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default='.',type=Path);a=p.parse_args();r=a.root.resolve()
checks=0
for line in (r/'manifest.sha256').read_text().splitlines():
 digest,name=line.split('  ',1);f=(r/name).resolve();assert f.is_relative_to(r),'unsafe path';assert f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()==digest,'hash mismatch: '+name;checks+=1
m=json.loads((r/'manifest.json').read_text());assert [x['frames'] for x in m['sources']]==[9,17]
sources={}
for x in ['a','b']:
 d=(r/f'captures/sensor-{x}.pcap').read_bytes();off=24;rows=[]
 while off<len(d):
  sec,us,n,wire=struct.unpack_from('<IIII',d,off);off+=16;rows.append((sec*1000000+us,d[off:off+n]));off+=n
 sources[x]=rows
 assert len(rows)==(9 if x=='a' else 17)
rows=list(csv.DictReader((r/'mapping/merged-frames.csv').open()));d=(r/'captures/merged.pcapng').read_bytes();off=0;merged=[]
while off<len(d):
 typ,n=struct.unpack_from('<II',d,off);assert n>=12 and struct.unpack_from('<I',d,off+n-4)[0]==n
 if typ==6:
  iface,hi,lo,cap,wire=struct.unpack_from('<IIIII',d,off+8);merged.append((iface,(hi<<32)+lo,d[off+28:off+28+cap]))
 off+=n
assert len(rows)==len(merged)==26
for i,(row,(iface,t,pkt)) in enumerate(zip(rows,merged),1):
 candidates=[f'sensor-{x}:{j}' for x,s in sources.items() for j,(st,sp) in enumerate(s,1) if t==st and pkt==sp]
 assert int(row['derivative_frame'])==i and int(row['interface_id'])==iface and int(row['timestamp_microseconds'])==t
 assert row['packet_sha256']==hashlib.sha256(pkt).hexdigest() and row['source_candidates']=='|'.join(candidates)
 assert row['verified_source_frame']==(candidates[0] if len(candidates)==1 else '')
for x in ['a','b']:
 for tag in ['all','dns','http','response']:
  assert (r/f'automation/{x}-{tag}.stdout.txt').read_bytes()==(r/f'automation/{x}-{tag}-repeat.stdout.txt').read_bytes()
  assert (r/f'automation/sensor-{x}-{tag}.tsv').read_bytes()==(r/f'automation/{x}-{tag}.stdout.txt').read_bytes()
 response=list(csv.DictReader((r/f'automation/sensor-{x}-response.tsv').open(),delimiter='\t'));assert response[0]['http.set_cookie']=='a=1|b=2'
 assert not (r/f'automation/{x}-malformed.stdout.txt').read_text().strip()
print(json.dumps({'state':'PASS','verifiedSHA256Entries':checks,'sourceFrames':[9,17],'mergedFrames':26,'mapping':'every row independently recomputed from actual timestamp and packet bytes','repeatExportsEquivalent':True,'repeatedCookieValues':['a=1','b=2'],'readOnly':True}))

#!/usr/bin/env python3
"""Execute exact synthetic packet and offline rebuild checks without changing evidence."""
from pathlib import Path
import json,subprocess,tempfile,hashlib,csv
r=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def run(a):
 p=subprocess.run(a,text=True,capture_output=True);assert p.returncode==0,(a,p.stderr);return p.stdout
out={'synthetic':True,'networkTrafficSent':False,'toolVersion':run(['tshark','--version']).splitlines()[0],'files':{}}
for base,count in [('before',4),('after',2)]:
 cap=r/(base+'.pcap');spec=json.loads((r/(base+'-spec.json')).read_text());fields=['frame.number','frame.time_epoch','ip.src','ip.dst','udp.srcport','udp.dstport','udp.payload']
 args=['tshark','-n','-r',str(cap),'-T','fields']
 for f in fields:args+=['-e',f]
 text=run(args);rows=[s.split('\t') for s in text.splitlines()];assert len(rows)==count
 for i,(row,e) in enumerate(zip(rows,spec['events']),1):
  assert row[0]==str(i) and row[2:6]==[e['src'],e['dst'],str(e['sport']),str(e['dport'])]
  assert bytes.fromhex(row[6].replace(':','')).decode()==e['payloadText']
 assert not run(['tshark','-n','-r',str(cap),'-Y','_ws.malformed','-T','fields','-e','frame.number']).strip()
 checks={}
 for expr,want in [('ip.addr == 192.0.2.10',[1,2] if base=='before' else []),('ip.addr == 192.0.2.20',[3,4] if base=='before' else [1,2])]:
  got=[int(s) for s in run(['tshark','-n','-r',str(cap),'-Y',expr,'-T','fields','-e','frame.number']).split()];assert got==want;checks[expr]=got
 with tempfile.TemporaryDirectory() as tmp:
  target=Path(tmp)/'rebuilt.pcap';args=['python3',str(r/'offline-builder.py'),'--spec',str(r/(base+'-spec.json')),'--output',str(target)];build=run(args);assert target.read_bytes()==cap.read_bytes()
  second=subprocess.run(args,capture_output=True,text=True);assert second.returncode!=0 and 'FileExistsError' in second.stderr and target.read_bytes()==cap.read_bytes()
 out['files'][cap.name]={'sha256':sha(cap.read_bytes()),'capturedPackets':count,'rawFields':text,'filters':checks,'conversations':run(['tshark','-n','-r',str(cap),'-q','-z','conv,udp']),'byteIdenticalRebuild':True,'overwriteRefused':True,'malformedFrames':0}
for name,num in [('capture-register.csv',2),('collection-records.csv',2),('approved-activity.csv',1),('asset-records.csv',3)]:
 with (r/name).open() as f: rows=list(csv.DictReader(f));assert len(rows)==num and all('synthetic' in x['provenance'] for x in rows)
print(json.dumps(out,indent=2))
